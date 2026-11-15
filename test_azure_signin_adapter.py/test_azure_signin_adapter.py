"""Synthetic Entra sign-in records only; no real authentication data."""
import contextlib
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest

import analyzer
import azure_signin_adapter as adapter

USER = {'userPrincipalName': 'demo-user@example.invalid',
        'userDisplayName': 'Demo User',
        'userId': '00000000-0000-0000-0000-000000000001'}


def signin(error_code, address='192.0.2.10', identity=None, stamp='2026-10-17T12:00:01Z'):
    record = {'createdDateTime': stamp, 'ipAddress': address,
              'status': {'errorCode': error_code}}
    record.update(USER if identity is None else identity)
    return record


class ParseRecordTests(unittest.TestCase):
    def test_success_and_failure(self):
        event, _ = adapter.parse_record(signin(0))
        self.assertEqual((event['result'], event['user'], event['ip']),
                         ('success', 'demo-user@example.invalid', '192.0.2.10'))
        self.assertEqual(event['timestamp'], '2026-10-17T12:00:01+00:00')
        event, _ = adapter.parse_record(signin(50126))
        self.assertEqual(event['result'], 'failure')

    def test_identity_fallback_and_display_name_never_used(self):
        no_upn = {'userDisplayName': 'Demo User',
                  'userId': '00000000-0000-0000-0000-000000000001'}
        event, _ = adapter.parse_record(signin(50126, identity=no_upn))
        self.assertEqual(event['user'], '00000000-0000-0000-0000-000000000001')
        display_only = {'userDisplayName': 'Demo User'}
        _, reason = adapter.parse_record(signin(50126, identity=display_only))
        self.assertEqual(reason, 'unsupported')

    def test_unsupported_shapes(self):
        _, reason = adapter.parse_record(['not', 'a', 'dict'])
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(signin(50126, stamp='not-a-date'))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(signin(50126, stamp='2026-10-17 12:00:01'))
        self.assertEqual(reason, 'unsupported')
        record = signin(50126)
        record['status'] = {'failureReason': 'Invalid password'}
        _, reason = adapter.parse_record(record)
        self.assertEqual(reason, 'unsupported')
        record = signin(50126)
        record['status']['errorCode'] = '50126'
        _, reason = adapter.parse_record(record)
        self.assertEqual(reason, 'unsupported')

    def test_missing_and_empty_ip_counted_separately(self):
        _, reason = adapter.parse_record(signin(50126, address=''))
        self.assertEqual(reason, 'no_network_address')
        record = signin(50126)
        del record['ipAddress']
        _, reason = adapter.parse_record(record)
        self.assertEqual(reason, 'no_network_address')

    def test_ipv6_normalized(self):
        event, _ = adapter.parse_record(signin(50126, address='2001:db8::1'))
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
        source = self.write('signins.json', [
            signin(50126), signin(0, stamp='2026-10-17T12:00:06Z'),
            signin(50126, address=''), 'garbage', signin(50126, stamp='bad'),
        ])
        destination = self.root / 'out.jsonl'
        summary = adapter.convert(source, destination)
        self.assertEqual(summary, {'records_read': 5, 'signin_events': 2,
                                   'no_network_address': 1, 'skipped_records': 2})
        lines = destination.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])['result'], 'success')

    def test_gzip_input(self):
        source = self.write('signins.json.gz', [signin(0)], gzipped=True)
        destination = self.root / 'out.jsonl'
        self.assertEqual(adapter.convert(source, destination)['signin_events'], 1)

    def test_never_overwrites(self):
        source = self.write('signins.json', [signin(0)])
        destination = self.root / 'out.jsonl'
        destination.write_text('keep me')
        with self.assertRaises(FileExistsError):
            adapter.convert(source, destination)
        self.assertEqual(destination.read_text(), 'keep me')
        self.assertEqual(list(self.root.glob('out.jsonl.*.tmp')), [])

    def test_same_file_rejected(self):
        source = self.write('signins.json', [signin(0)])
        with self.assertRaises(ValueError):
            adapter.convert(source, source)

    def test_bad_inputs_exit_2(self):
        graph_shape = self.write('graph.json', {'value': [signin(0)]})
        with self.assertRaises(ValueError):
            adapter.convert(graph_shape, self.root / 'graph.out')
        empty = self.write('empty.json', [])
        with self.assertRaises(ValueError):
            adapter.convert(empty, self.root / 'empty.out')
        junk = self.root / 'junk.json'
        junk.write_text('not json')
        with self.assertRaises(ValueError):
            adapter.convert(junk, self.root / 'junk.out')
        bad_gz = self.root / 'fake.gz'
        bad_gz.write_bytes(b'\x1f\x8b' + b'not gzip')
        with self.assertRaises(ValueError):
            adapter.convert(bad_gz, self.root / 'gz.out')

    def test_record_limit(self):
        source = self.write('signins.json', [signin(50126)] * 3)
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'out.jsonl', max_records=2)

    def test_end_to_end_analyzer_exit_1(self):
        records = [signin(50126, stamp='2026-10-17T12:00:0%dZ' % n) for n in range(1, 6)]
        records.append(signin(0, stamp='2026-10-17T12:00:06Z'))
        source = self.write('signins.json', records)
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
        source = self.write('signins.json', [signin(0)])
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
