"""Synthetic Google Workspace login audit records only; no real authentication data."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest

import analyzer
import google_workspace_adapter as adapter

ACTOR = {'email': 'demo-user@example.invalid', 'profileId': '100000000000000000001'}


def activity(names, address='192.0.2.10', actor=None, stamp='2026-10-17T12:00:01.000Z'):
    record = {'id': {'time': stamp}, 'ipAddress': address,
              'events': [{'type': 'login', 'name': name} for name in names]}
    record['actor'] = dict(ACTOR if actor is None else actor)
    return record


class ParseRecordTests(unittest.TestCase):
    def test_success_and_failure(self):
        event, _ = adapter.parse_record(activity(['login_success']))
        self.assertEqual((event['result'], event['user'], event['ip']),
                         ('success', 'demo-user@example.invalid', '192.0.2.10'))
        self.assertEqual(event['timestamp'], '2026-10-17T12:00:01+00:00')
        event, _ = adapter.parse_record(activity(['login_failure']))
        self.assertEqual(event['result'], 'failure')

    def test_non_login_events_are_counted_separately(self):
        _, reason = adapter.parse_record(activity(['logout']))
        self.assertEqual(reason, 'not_login_event')
        _, reason = adapter.parse_record(activity(['login_challenge']))
        self.assertEqual(reason, 'not_login_event')

    def test_conflicting_outcomes_are_unsupported(self):
        _, reason = adapter.parse_record(activity(['login_success', 'login_failure']))
        self.assertEqual(reason, 'unsupported')

    def test_identity_fallback_and_display_name_never_used(self):
        no_email = {'profileId': '100000000000000000001', 'callerType': 'USER'}
        event, _ = adapter.parse_record(activity(['login_failure'], actor=no_email))
        self.assertEqual(event['user'], '100000000000000000001')
        _, reason = adapter.parse_record(activity(['login_failure'], actor={}))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(activity(['login_failure'], actor={'email': '   '}))
        self.assertEqual(reason, 'unsupported')

    def test_unsupported_shapes(self):
        _, reason = adapter.parse_record(['not', 'a', 'dict'])
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(activity(['login_failure'], stamp='not-a-date'))
        self.assertEqual(reason, 'unsupported')
        _, reason = adapter.parse_record(activity(['login_failure'], stamp='2026-10-17 12:00:01'))
        self.assertEqual(reason, 'unsupported')
        record = activity(['login_failure'])
        del record['id']
        _, reason = adapter.parse_record(record)
        self.assertEqual(reason, 'unsupported')
        record = activity(['login_failure'])
        record['events'] = 'login_failure'
        _, reason = adapter.parse_record(record)
        self.assertEqual(reason, 'unsupported')

    def test_missing_and_empty_ip_counted_separately(self):
        _, reason = adapter.parse_record(activity(['login_failure'], address=''))
        self.assertEqual(reason, 'no_network_address')
        record = activity(['login_failure'])
        del record['ipAddress']
        _, reason = adapter.parse_record(record)
        self.assertEqual(reason, 'no_network_address')

    def test_ipv6_normalized(self):
        event, _ = adapter.parse_record(activity(['login_failure'], address='2001:db8::1'))
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
        source = self.write('login.json', {'kind': 'admin#reports#activities', 'items': [
            activity(['login_failure']), activity(['login_success'], stamp='2026-10-17T12:00:06.000Z'),
            activity(['logout']), activity(['login_failure'], address=''),
            'garbage', activity(['login_failure'], stamp='bad'),
        ]})
        destination = self.root / 'out.jsonl'
        summary = adapter.convert(source, destination)
        self.assertEqual(summary, {'records_read': 6, 'signin_events': 2,
                                   'no_network_address': 1, 'not_login_events': 1,
                                   'skipped_records': 2})
        rows = [json.loads(line) for line in destination.read_text().splitlines()]
        self.assertEqual([row['result'] for row in rows], ['failure', 'success'])
        events, errors, _ = analyzer.load_events(destination)
        self.assertEqual(errors, [])
        self.assertEqual(len(events), 2)

    def test_gzip_input(self):
        source = self.write('login.json.gz', {'items': [activity(['login_failure'])]}, gzipped=True)
        summary = adapter.convert(source, self.root / 'out.jsonl')
        self.assertEqual(summary['signin_events'], 1)

    def test_rejects_non_envelope_shapes(self):
        source = self.write('list.json', [activity(['login_failure'])])
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'out.jsonl')
        source = self.write('single.json', activity(['login_failure']))
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'out2.jsonl')
        source = self.write('empty.json', {'items': []})
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'out3.jsonl')
        source = self.root / 'junk.json'
        source.write_bytes(b'not json')
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'out4.jsonl')

    def test_no_overwrite_and_limits(self):
        source = self.write('login.json', {'items': [activity(['login_failure'])]})
        destination = self.root / 'out.jsonl'
        destination.write_text('keep me')
        with self.assertRaises(FileExistsError):
            adapter.convert(source, destination)
        self.assertEqual(destination.read_text(), 'keep me')
        with self.assertRaises(ValueError):
            adapter.convert(source, self.root / 'other.jsonl', max_records=0)
        with self.assertRaises(ValueError):
            adapter.convert(source, source)


if __name__ == '__main__':
    unittest.main()
