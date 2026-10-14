"""Synthetic events only; no real authentication data."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
import analyzer


class DetectionTests(unittest.TestCase):
    def events(self, users, result='failure', start=0, ip='192.0.2.10'):
        return [{'timestamp': datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=start+i),
                 'user': user, 'ip': ip, 'result': result, 'line': start+i+1} for i, user in enumerate(users)]
    def rules(self, events, **kw):
        return {a['rule'] for a in analyzer.analyze(events, **kw)}
    def test_burst(self):
        self.assertEqual(self.rules(self.events(['demo']*5)), {'failure-burst'})
    def test_below_threshold(self):
        self.assertEqual(self.rules(self.events(['demo']*4)), set())
    def test_spray(self):
        self.assertEqual(self.rules(self.events(list('abcde'))), {'failure-burst', 'possible-password-spray'})
    def test_repeated_account_not_spray(self):
        self.assertNotIn('possible-password-spray', self.rules(self.events(['a']*8)))
    def test_success_same_account(self):
        events=self.events(['a']*5)+self.events(['a'], 'success', 6)
        self.assertIn('success-after-failures', self.rules(events))
    def test_success_other_account(self):
        events=self.events(['a']*5)+self.events(['b'], 'success', 6)
        self.assertNotIn('success-after-failures', self.rules(events))
    def test_success_after_expiry(self):
        events=self.events(['a']*5)+self.events(['a'], 'success', 310)
        self.assertNotIn('success-after-failures', self.rules(events))
    def test_sources_separate(self):
        self.assertEqual(self.rules(self.events(['a']*3)+self.events(['a']*3, ip='192.0.2.11')), set())
    def test_sort_and_dedupe(self):
        events=self.events(['a']*20)
        self.assertEqual(len(analyzer.analyze(list(reversed(events)))), 1)
    def test_inclusive_window(self):
        events=self.events(['a']*4)+self.events(['a'], start=300)
        self.assertIn('failure-burst', self.rules(events))
        events[-1]['timestamp'] += timedelta(seconds=1)
        self.assertNotIn('failure-burst', self.rules(events))
    def test_redaction_and_correlation(self):
        alerts=analyzer.analyze(self.events(['private-user']*5)+self.events(['private-user'],'success',6))
        text=json.dumps(alerts)
        self.assertNotIn('private-user',text)
        self.assertNotIn('192.0.2.10',text)
        self.assertEqual(alerts[0]['source'],alerts[1]['source'])
        self.assertNotEqual(alerts[0]['source'],analyzer.analyze(self.events(['private-user']*5))[0]['source'])
    def test_settings_validation(self):
        for kw in ({'window_seconds':0},{'failure_threshold':1},{'spray_users':1}):
            with self.assertRaises(ValueError): analyzer.analyze([],**kw)


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'fixture.jsonl'
    def write(self, rows):
        self.path.write_text('\n'.join(json.dumps(row) if not isinstance(row,str) else row for row in rows))
    def row(self, **kw):
        return dict(timestamp='2026-01-01T00:00:00Z',ip='2001:db8::1',user='demo',result='failure',**kw)
    def test_valid_ipv6_and_extra_fields(self):
        self.write([self.row(password='sensitive-extra')])
        events,errors,_=analyzer.load_events(self.path)
        self.assertEqual(len(events),1)
        self.assertEqual(errors,[])
        self.assertNotIn('sensitive-extra',str(events))
    def test_invalid_records_not_echoed(self):
        self.write(['private-raw-invalid',[],{},dict(self.row(),ip='bad-private-ip'),dict(self.row(),result='unknown'),dict(self.row(),timestamp='2026-01-01'),dict(self.row(),user='')])
        events,errors,_=analyzer.load_events(self.path)
        self.assertEqual(events,[])
        self.assertEqual(len(errors),7)
        self.assertNotIn('private',str(errors))
    def test_timezone_normalization(self):
        self.assertEqual(analyzer.timestamp('2026-01-01T05:30:00+05:30'),analyzer.timestamp('2026-01-01T00:00:00Z'))
    def test_limits(self):
        self.write([self.row(),self.row()])
        self.assertTrue(analyzer.load_events(self.path,max_lines=1)[1])
        self.assertTrue(analyzer.load_events(self.path,max_line_bytes=10)[1])
    def test_blank_lines(self):
        self.write(['',' ',self.row()])
        events,errors,total=analyzer.load_events(self.path)
        self.assertEqual((len(events),len(errors),total),(1,0,3))
    def test_cli_exit_states(self):
        self.write([])
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(analyzer.main([str(self.path)]),0)
        self.write([self.row()]*5)
        out=io.StringIO()
        with contextlib.redirect_stdout(out): self.assertEqual(analyzer.main([str(self.path),'--format','json']),1)
        self.assertEqual(json.loads(out.getvalue())['stats']['alerts'],1)
        self.write(['invalid'])
        with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(analyzer.main([str(self.path)]),2)
        with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(analyzer.main([str(self.path)+'missing']),2)
    def test_empty_file_not_secure_claim(self):
        self.write([])
        out=io.StringIO()
        with contextlib.redirect_stdout(out): analyzer.main([str(self.path),'--format','json'])
        self.assertIn('not confirmed attacks',json.loads(out.getvalue())['scope'])


if __name__ == '__main__': unittest.main()
