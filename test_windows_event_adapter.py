"""Synthetic Windows Security events only; no real authentication data."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

import analyzer
import windows_event_adapter as adapter


NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


def event_xml(event_id, system_time, fields):
    data = ''.join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    return (f'<Event xmlns="{NS}"><System><EventID>{event_id}</EventID>'
            f'<TimeCreated SystemTime="{system_time}" /></System>'
            f'<EventData>{data}</EventData></Event>')


def parse(xml_text):
    return adapter.parse_event(ET.fromstring(xml_text))


FAILURE = event_xml('4625', '2026-01-01T00:00:01.1234567Z',
                    {'TargetUserName': 'administrator', 'IpAddress': '192.0.2.10'})
SUCCESS = event_xml('4624', '2026-01-01T00:00:05Z',
                    {'TargetUserName': 'deploy', 'IpAddress': '2001:DB8::10'})
LOCAL = event_xml('4625', '2026-01-01T00:00:09Z',
                  {'TargetUserName': 'demo.user', 'IpAddress': '-'})
SUCCESS_SAME = event_xml('4624', '2026-01-01T00:00:07Z',
                         {'TargetUserName': 'administrator', 'IpAddress': '192.0.2.10'})
LOGOFF = event_xml('4634', '2026-01-01T00:00:12Z',
                   {'TargetUserName': 'deploy', 'IpAddress': '192.0.2.10'})


class SystemTimeTests(unittest.TestCase):
    def test_seven_digit_fraction_truncates(self):
        self.assertEqual(adapter.parse_system_time('2026-01-01T00:00:01.1234567Z'),
                         '2026-01-01T00:00:01.123456+00:00')

    def test_no_fraction(self):
        self.assertEqual(adapter.parse_system_time('2026-01-01T00:00:01Z'),
                         '2026-01-01T00:00:01+00:00')

    def test_rejects_non_utc_and_garbage(self):
        for bad in ('2026-01-01T00:00:01+05:30', '2026-01-01 00:00:01Z', 'soon', '', None):
            self.assertIsNone(adapter.parse_system_time(bad))


class ParseEventTests(unittest.TestCase):
    def test_failure(self):
        row, reason = parse(FAILURE)
        self.assertEqual(row, {
            'timestamp': '2026-01-01T00:00:01.123456+00:00',
            'ip': '192.0.2.10',
            'user': 'administrator',
            'result': 'failure',
        })
        self.assertIsNone(reason)

    def test_success_ipv6_normalized(self):
        row, reason = parse(SUCCESS)
        self.assertEqual(row['result'], 'success')
        self.assertEqual(row['ip'], '2001:db8::10')

    def test_local_logon_without_address(self):
        row, reason = parse(LOCAL)
        self.assertIsNone(row)
        self.assertEqual(reason, 'no_network_address')

    def test_unsupported_event_id(self):
        row, reason = parse(LOGOFF)
        self.assertIsNone(row)
        self.assertEqual(reason, 'unsupported')

    def test_missing_or_bad_fields_stay_out(self):
        bad_user = event_xml('4625', '2026-01-01T00:00:01Z', {'IpAddress': '192.0.2.10'})
        big_user = event_xml('4625', '2026-01-01T00:00:01Z',
                             {'TargetUserName': 'x' * 257, 'IpAddress': '192.0.2.10'})
        blank_user = event_xml('4625', '2026-01-01T00:00:01Z',
                               {'TargetUserName': '   ', 'IpAddress': '192.0.2.10'})
        bad_ip = event_xml('4625', '2026-01-01T00:00:01Z',
                           {'TargetUserName': 'deploy', 'IpAddress': '999.0.0.1'})
        bad_time = event_xml('4625', 'yesterday',
                             {'TargetUserName': 'deploy', 'IpAddress': '192.0.2.10'})
        for xml_text in (bad_user, big_user, blank_user, bad_ip, bad_time):
            row, reason = parse(xml_text)
            self.assertIsNone(row)
            self.assertEqual(reason, 'unsupported')

    def test_missing_system_or_data(self):
        row, reason = parse(f'<Event xmlns="{NS}"><System><EventID>4625</EventID></System></Event>')
        self.assertIsNone(row)
        self.assertEqual(reason, 'unsupported')


class ConvertTests(unittest.TestCase):
    def write(self, directory, name, text):
        path = Path(directory) / name
        path.write_text(text, encoding='utf-8')
        return path

    def test_convert_and_end_to_end_analysis(self):
        body = ''.join([FAILURE] * 5 + [SUCCESS_SAME, LOCAL, LOGOFF])
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write(tmp, 'in.xml', f'<Events>{body}</Events>')
            destination = Path(tmp) / 'out.jsonl'
            summary = adapter.convert(source, destination)
            self.assertEqual(summary, {'events_read': 8, 'auth_events': 6,
                                       'no_network_address': 1, 'skipped_events': 1})
            rows = [json.loads(line) for line in destination.read_text().splitlines()]
            self.assertEqual([row['result'] for row in rows],
                             ['failure'] * 5 + ['success'])
            self.assertTrue(all(set(row) == {'timestamp', 'ip', 'user', 'result'} for row in rows))
            events, errors, total = analyzer.load_events(destination)
            self.assertEqual((total, errors), (6, []))
            alerts = analyzer.analyze(events)
            rules = {alert['rule'] for alert in alerts}
            self.assertEqual(rules, {'failure-burst', 'success-after-failures'})
            for alert in alerts:
                self.assertTrue(all(1 <= line <= 6 for line in alert['evidence_lines']))

    def test_rejects_existing_destination_and_same_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write(tmp, 'in.xml', f'<Events>{FAILURE}</Events>')
            with self.assertRaises(ValueError):
                adapter.convert(source, source)
            destination = self.write(tmp, 'out.jsonl', 'keep me')
            with self.assertRaises(FileExistsError):
                adapter.convert(source, destination)
            self.assertEqual(destination.read_text(), 'keep me')

    def test_rejects_garbage_and_eventless_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            garbage = self.write(tmp, 'in.xml', 'this is not xml at all')
            with self.assertRaises(ValueError):
                adapter.convert(garbage, Path(tmp) / 'a.jsonl')
            other = self.write(tmp, 'other.xml', '<html><body>none</body></html>')
            with self.assertRaises(ValueError):
                adapter.convert(other, Path(tmp) / 'b.jsonl')
            self.assertFalse((Path(tmp) / 'a.jsonl').exists())
            self.assertFalse((Path(tmp) / 'b.jsonl').exists())

    def test_event_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write(tmp, 'in.xml', f'<Events>{FAILURE * 3}</Events>')
            with self.assertRaises(ValueError):
                adapter.convert(source, Path(tmp) / 'out.jsonl', max_events=2)
            with self.assertRaises(ValueError):
                adapter.convert(source, Path(tmp) / 'out.jsonl', max_events=0)

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = self.write(tmp, 'in.xml', f'<Events>{FAILURE}</Events>')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = adapter.main([str(source), str(Path(tmp) / 'out.jsonl')])
            self.assertEqual(code, 0)
            self.assertIn('Wrote 1 logon event(s)', out.getvalue())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = adapter.main([str(source), str(Path(tmp) / 'out.jsonl')])
            self.assertEqual(code, 2)
            self.assertIn('Adapter stopped', err.getvalue())


class DemoFixtureTests(unittest.TestCase):
    def test_demo_xml_converts_and_alerts(self):
        demo = Path(__file__).with_name('demo_windows_security.xml')
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / 'demo.jsonl'
            summary = adapter.convert(demo, destination)
            self.assertEqual(summary['auth_events'], 7)
            self.assertEqual(summary['no_network_address'], 1)
            events, errors, _total = analyzer.load_events(destination)
            self.assertEqual(errors, [])
            rules = {alert['rule'] for alert in analyzer.analyze(events)}
            self.assertEqual(rules, {'failure-burst', 'success-after-failures'})


if __name__ == '__main__':
    unittest.main()
