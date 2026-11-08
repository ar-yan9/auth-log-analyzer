"""Synthetic CloudTrail records only; no real authentication data."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest

import analyzer
import cloudtrail_adapter as adapter

IAM = {'type': 'IAMUser', 'userName': 'demo-user',
       'principalId': 'AIDASAMPLEUSERID001',
       'arn': 'arn:aws:iam::123456789012:user/demo-user'}


def signin(outcome, address='192.0.2.10', identity=None, stamp='2026-10-17T12:00:01Z'):
    return {'eventTime': stamp, 'eventName': 'ConsoleLogin',
            'sourceIPAddress': address,
            'userIdentity': IAM if identity is None else identity,
            'responseElements': {'ConsoleLogin': outcome}}


class ParseRecordTests(unittest.TestCase):
    def test_success_and_failure(self):
        event, _ = adapter.parse_record(signin('Success'))
        self.assertEqual((event['result'], event['user'], event['ip']),
                         ('success', 'demo-user', '192.0.2.10'))
        self.assertEqual(event['timestamp'], '2026-10-17T12:00:01+00:00')
        event, _ = adapter.parse_record(signin('Failure'))
        self.assertEqual(event['result'], 'failure')

    def test_identity_fallback_without_username(self):
        root = {'type': 'Root', 'principalId': '123456789012',
                'arn': 'arn:aws:iam::123456789012:root'}
        event, _ = adapter.parse_record(signin('Failure', identity=root))
        self.assertEqual(event['user'], '123456789012')
        arn_only = {'type': 'AssumedRole',
                    'arn': 'arn:aws:sts::123456789012:assumed-role/Demo/session'}
        event, _ = adapter.parse_record(signin('Failure', identity=arn_only))
        self.assertTrue(event['user'].startswith('arn:aws:sts::'))

    def test_non_signin_and_unsupported(self):
        _, reason = adapter.parse_record({'eventName': 'AssumeRole'})
        self.assertEqual(reason, 'other_event')
        _, reason = adapter.parse_record(signin('MFA Required'))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(signin('Failure', stamp='not-a-date'))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(signin('Failure', stamp='2026-10-17 12:00:01'))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(signin('Failure', identity={'type': 'Root'}))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(['not', 'a', 'dict'])
        self.assertEqual(reason, 'unsupported')

    def test_non_ip_source_is_counted_separately(self):
        _, reason = adapter.parse_record(signin('Failure', address='AWSInternal'))
        self.assertEqual(reason, 'no_network_address')

    def test_ipv6_normalized(self):
        event, _ = adapter.parse_record(signin('Failure', address='2001:db8::1'))
        self.assertEqual(event['ip'], '2001:db8::1')


class ConvertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, document, gzipped=False):
        path = self.root / name
        raw = json.dumps(document).encode()
        path.write_bytes(gzip.compress(raw) if gzipped else raw)
        return path

    def test_convert_counts_and_output(self):
        source = self.write('trail.json', {'Records': [
            signin('Failure'), signin('Success', stamp='2026-10-17T12:00:06Z'),
            signin('Failure', address='AWSInternal'), {'eventName': 'GetObject'},
            'garbage', signin('Failure', stamp='bad'),
        ]})
        destination = self.root / 'out.jsonl'
        summary = adapter.convert(source, destination)
        self.assertEqual(summary, {'records_read': 6, 'signin_events': 2,
                                   'other_events': 1, 'no_network_address': 1,
                                   'skipped_records': 2})
        lines = destination.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])['result'], 'success')

    def test_gzip_input(self):
        source = self.write('trail.json.gz', {'Records': [signin('Success')]}, gzipped=True)
        destination = self.root / 'out.jsonl'
        self.assertEqual(adapter.convert(source, destination)['signin_events'], 1)

    def test_never_overwrites(self):
        source = self.write('trail.json', {'Records': [signin('Success')]})
        destination = self.root / 'out.jsonl'
        destination.write_text('keep me')
        with self.assertRaises(FileExistsError):
            adapter.convert(source, destination)
        self.assertEqual(destination.read_text(), 'keep me')
        self.assertEqual(list(self.root.glob('out.jsonl.*.tmp')), [])

    def test_same_file_rejected(self):
        source = self.write('trail.json', {'Records': [signin('Success')]})
        with self.assertRaises(ValueError):
            adapter.convert(source, source)

    def test_bad_inputs_exit_2(self):
        for name, content in (('empty.json', {}), ('junk.json', 'not json'),
                              ('bare.json', []), ('none.json', {'Records': []})):
            source = self.write(name, content) if name != 'junk.json' else (
                self.root / name)
            if name == 'junk.json':
                source.write_text('not json')
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    adapter.convert(source, self.root / (name + '.out'))
        bad_gz = self.root / 'fake.gz'
        bad_gz.write_bytes(b'\x1f\x8b' + b'not gzip')
        with self.assertRaises(ValueError):
            adapter.convert(bad_gz, self.root / 'gz.out')

    def test_record_limit(self):
        source = self.write('trail.json', {'Records': [signin('Failure')] * 3})
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'out.jsonl', max_records=2)

    def test_end_to_end_analyzer_exit_1(self):
        records = [signin('Failure', stamp='2026-10-17T12:00:0%dZ' % n) for n in range(1, 6)]
        records.append(signin('Success', stamp='2026-10-17T12:00:06Z'))
        source = self.write('trail.json', {'Records': records})
        destination = self.root / 'out.jsonl'
        adapter.convert(source, destination)
        with contextlib.redirect_stdout(io.StringIO()):
            code = analyzer.main([str(destination)])
        self.assertEqual(code, 1)
        events, errors, _ = analyzer.load_events(destination)
        self.assertEqual(errors, [])
        alerts = analyzer.analyze(events)
        rules = sorted(a['rule'] for a in alerts)
        self.assertEqual(rules, ['failure-burst', 'success-after-failures'])

    def test_main_reports_and_exit_codes(self):
        source = self.write('trail.json', {'Records': [signin('Success')]})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = adapter.main([str(source), str(self.root / 'ok.jsonl')])
        self.assertEqual(code, 0)
        with contextlib.redirect_stderr(err):
            code = adapter.main([str(source), str(self.root / 'ok.jsonl')])
        self.assertEqual(code, 2)
        self.assertIn('Adapter stopped', err.getvalue())


if __name__ == '__main__':
    unittest.main()
