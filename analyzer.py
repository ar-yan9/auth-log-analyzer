#!/usr/bin/env python3
"""Offline heuristic analysis of normalized JSONL authentication events."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import secrets
import sys


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO 8601 string')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('timestamp needs a timezone offset')
    return parsed.astimezone(timezone.utc)


def load_events(path, max_lines=100000, max_line_bytes=16384):
    events, errors = [], []
    total = 0
    # Bounded binary reads prevent a single giant record exhausting memory.
    with Path(path).open('rb') as handle:
        while True:
            raw = handle.readline(max_line_bytes + 1)
            if not raw:
                break
            total += 1
            if total > max_lines:
                errors.append({'line': total, 'reason': 'input exceeds line limit'})
                break
            if len(raw) > max_line_bytes:
                errors.append({'line': total, 'reason': 'record exceeds byte limit; analysis stopped'})
                break
            if not raw.strip():
                continue
            try:
                row = json.loads(raw.decode('utf-8'))
                if not isinstance(row, dict):
                    raise ValueError('record must be an object')
                date = timestamp(row['timestamp'])
                ip = str(ipaddress.ip_address(row['ip']))
                user = row['user']
                if not isinstance(user, str) or not user.strip() or len(user) > 256:
                    raise ValueError('user must be a nonempty string of at most 256 characters')
                result = row['result']
                if result not in ('failure', 'success'):
                    raise ValueError('result must be failure or success')
                # Unknown fields are ignored and never copied into reports.
                events.append({'timestamp': date, 'ip': ip, 'user': user,
                               'result': result, 'line': total})
            except (ValueError, TypeError, KeyError, UnicodeError):
                errors.append({'line': total, 'reason': 'invalid normalized event'})
    events.sort(key=lambda e: (e['timestamp'], e['line']))
    return events, errors, total


def analyze(events, window_seconds=300, failure_threshold=5, spray_users=5):
    if window_seconds <= 0 or failure_threshold < 2 or spray_users < 2:
        raise ValueError('window must be positive; thresholds must be at least 2')
    # Per-report HMAC labels allow correlation without printing raw identities.
    # They are pseudonyms, not anonymization. A new key is used for every run.
    key = secrets.token_bytes(32)
    def label(kind, value):
        return kind + '-' + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]
    failures = defaultdict(deque)
    alerts, emitted = [], set()
    for event in sorted(events, key=lambda e: (e['timestamp'], e['line'])):
        ip, date, user = event['ip'], event['timestamp'], event['user']
        queue = failures[ip]
        while queue and (date - queue[0]['timestamp']).total_seconds() > window_seconds:
            queue.popleft()
        if event['result'] == 'failure':
            queue.append(event)
            rules = []
            if len(queue) >= failure_threshold:
                rules.append('failure-burst')
            if len({e['user'] for e in queue}) >= spray_users:
                rules.append('possible-password-spray')
        else:
            # A success on a DIFFERENT account is not treated as compromise.
            rules = ['success-after-failures'] if sum(e['user'] == user for e in queue) >= failure_threshold else []
        for rule in rules:
            # Deduplicate each rule per source (and account for successes) for this report.
            ident = (rule, ip, user if rule == 'success-after-failures' else '')
            if ident in emitted:
                continue
            emitted.add(ident)
            relevant = [e for e in queue if rule != 'success-after-failures' or e['user'] == user]
            alerts.append({'rule': rule, 'severity': 'high' if rule == 'success-after-failures' else 'medium',
                           'source': label('ip', ip),
                           'account': label('user', user) if rule == 'success-after-failures' else None,
                           'first_failure': relevant[0]['timestamp'].isoformat(),
                           'detected_at': date.isoformat(), 'failures_in_window': len(relevant),
                           'distinct_accounts': len({e['user'] for e in relevant}),
                           'evidence_lines': [e['line'] for e in relevant] + ([event['line']] if event['result'] == 'success' else [])})
    return alerts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--window', type=int, default=300, help='Window in seconds, inclusive')
    parser.add_argument('--failures', type=int, default=5)
    parser.add_argument('--spray-users', type=int, default=5)
    parser.add_argument('--max-lines', type=int, default=100000)
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    args = parser.parse_args(argv)
    if args.max_lines <= 0:
        parser.error('max-lines must be positive')
    try:
        events, errors, total = load_events(args.log, args.max_lines)
        alerts = analyze(events, args.window, args.failures, args.spray_users)
    except (OSError, ValueError):
        print('Error: input unavailable or invalid analysis settings', file=sys.stderr)
        return 2
    report = {'alerts': alerts, 'errors': errors,
              'stats': {'lines_read': total, 'valid_events': len(events), 'alerts': len(alerts)},
              'settings': {'window_seconds': args.window, 'failure_threshold': args.failures, 'spray_users': args.spray_users},
              'scope': 'Offline normalized JSONL only; heuristic alerts, not confirmed attacks. Identifiers are per-report pseudonyms.'}
    if args.format == 'json':
        print(json.dumps(report, indent=2))
    else:
        print('Auth Log Analyzer: %d alert(s), %d invalid/incomplete record notice(s)' % (len(alerts), len(errors)))
        for alert in alerts:
            print('{rule} [{severity}] {source} at {detected_at}; failures={failures_in_window}, accounts={distinct_accounts}'.format(**alert))
        for error in errors:
            print('NOTICE line {line}: {reason}'.format(**error))
    return 2 if errors else (1 if alerts else 0)


if __name__ == '__main__':
    sys.exit(main())
