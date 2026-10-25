"""Synthetic OpenSSH lines only; no real authentication data."""
from datetime import timezone, timedelta
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import analyzer
import ssh_adapter


FAILED = 'Oct 17 12:00:01 labhost sshd[411]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2'
FAILED_OTHER = 'Oct 17 12:00:02 labhost sshd[411]: Failed publickey for deploy from 2001:db8::10 port 22 ssh2'
SUCCESS = 'Oct 17 12:00:03 labhost sshd-session[412]: Accepted password for aryan from 192.0.2.10 port 22 ssh2'
NOISE = 'Oct 17 12:00:04 labhost CRON[9]: session opened for user aryan'


class ParseTests(unittest.TestCase):
    def test_failed_password(self):
        row = ssh_adapter.parse_line(FAILED, 2026, timezone.utc)
        self.assertEqual(row, {
            'timestamp': '2026-10-17T12:00:01+00:00',
            'ip': '192.0.2.10',
            'user': 'admin',
            'result': 'failure',
        })

    def test_success_and_offset(self):
        row = ssh_adapter.parse_line(SUCCESS, 2026, timezone(timedelta(hours=5, minutes=30)))
        self.assertEqual(row['timestamp'], '2026-10-17T06:30:03+00:00')
        self.assertEqual(row['result'], 'success')

    def test_ipv6_and_publickey(self):
        row = ssh_adapter.parse_line(FAILED_OTHER, 2026, timezone.utc)
        self.assertEqual(row['ip'], '2001:db8::10')
        self.assertEqual(row['user'], 'deploy')

    def test_unknown_and_unsafe_values_stay_out(self):
        for line in (
            NOISE,
            'Oct 17 12:00:04 labhost sshd[1]: Connection closed by 192.0.2.10 port 22',
            'Feb 30 12:00:04 labhost sshd[1]: Failed password for admin from 192.0.2.10 port 22',
            'Oct 17 12:00:04 labhost sshd[1]: Failed password for admin from not-an-ip port 22',
        ):
            self.assertIsNone(ssh_adapter.parse_line(line, 2026, timezone.utc))

    def test_offsets(self):
        self.assertEqual(ssh_adapter.utc_offset('Z'), timezone.utc)
        self.assertEqual(ssh_adapter.utc_offset('+0530').utcoffset(None), timedelta(hours=5, minutes=30))
        self.assertEqual(ssh_adapter.utc_offset('-05:00').utcoffset(None), -timedelta(hours=5))
        for value in ('+05', 'five-thirty', '+24:00', '+05:60'):
            with self.assertRaises(ValueError):
                ssh_adapter.utc_offset(value)


class ConvertTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'auth.log'
        self.destination = self.root / 'normalized.jsonl'

    def write_source(self, text):
        self.source.write_text(text, encoding='utf-8', newline='\n')

    def test_convert_preserves_line_numbers_and_integrates(self):
        self.write_source(FAILED + '\n' + NOISE + '\n' + FAILED_OTHER + '\n' + SUCCESS + '\n')
        summary = ssh_adapter.convert(self.source, self.destination, 2026, '+00:00')
        self.assertEqual(summary, {'lines_read': 4, 'auth_events': 3, 'skipped_lines': 1})
        lines = self.destination.read_text(encoding='utf-8').splitlines()
        self.assertEqual(lines[1], '')
        self.assertEqual(json.loads(lines[0])['user'], 'admin')
        events, errors, total = analyzer.load_events(self.destination)
        self.assertEqual((len(events), errors, total), (3, [], 4))
        self.assertEqual(events[0]['line'], 1)
        self.assertEqual(events[2]['line'], 4)

    def test_refuses_overwrite(self):
        self.write_source(FAILED + '\n')
        self.destination.write_text('keep', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            ssh_adapter.convert(self.source, self.destination, 2026, 'Z')
        self.assertEqual(self.destination.read_text(encoding='utf-8'), 'keep')

    def test_explicit_date_flags_are_required(self):
        self.write_source(FAILED + '\n')
        with self.assertRaises(ValueError):
            ssh_adapter.convert(self.source, self.destination, None, 'Z')
        with self.assertRaises(ValueError):
            ssh_adapter.convert(self.source, self.destination, 2026, None)
        self.assertFalse(self.destination.exists())

    def test_bounds_and_cleanup(self):
        self.write_source(FAILED + '\n' + FAILED_OTHER + '\n')
        with self.assertRaises(ValueError):
            ssh_adapter.convert(self.source, self.destination, 2026, 'Z', max_lines=1)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob('*.tmp')), [])

    def test_cli_summary_and_missing_input(self):
        self.write_source(FAILED + '\n' + NOISE + '\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ssh_adapter.main([str(self.source), str(self.destination), '--year', '2026', '--utc-offset', 'Z'])
        self.assertEqual(code, 0)
        self.assertIn('Wrote 1 auth event(s); skipped 1 unsupported line(s)', out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                ssh_adapter.main([str(self.source), str(self.destination), '--year', '2026', '--utc-offset', 'Z']),
                2,
            )


if __name__ == '__main__':
    unittest.main()
