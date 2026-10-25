#!/usr/bin/env python3
"""Convert common OpenSSH auth.log lines to normalized JSONL for analyzer.py.

RFC3164 syslog timestamps carry no year or timezone, so both must be supplied
explicitly. Unsupported lines stay blank in the output, preserving original
line numbers without copying raw log text.
"""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}
SYSLOG = re.compile(
    r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) '
    r'\S+ (sshd(?:-session)?)(?:\[\d+\])?: (.*)$'
)
AUTH = re.compile(
    r'^(Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) '
    r'for (?:invalid user )?([^\s]{1,128}) from (\S+) port \d+(?:\s|$)'
)
OFFSET = re.compile(r'^(Z|[+-])(?:(\d{2}):?(\d{2}))?$')


def utc_offset(value):
    match = OFFSET.fullmatch(value)
    if not match:
        raise ValueError('UTC offset must be Z, +05:30 or +0530')
    if match.group(1) == 'Z':
        return timezone.utc
    if match.group(2) is None:
        raise ValueError('UTC offset must be Z, +05:30 or +0530')
    hours, minutes = int(match.group(2)), int(match.group(3))
    if hours > 23 or minutes > 59:
        raise ValueError('UTC offset must be Z, +05:30 or +0530')
    sign = 1 if match.group(1) == '+' else -1
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def parse_line(text, year, offset):
    """Return one normalized event dict, or None for an unsupported line."""
    if not isinstance(text, str):
        return None
    match = SYSLOG.match(text.rstrip('\r\n'))
    if not match:
        return None
    month, day, hour, minute, second, _service, message = match.groups()
    auth = AUTH.match(message)
    if not auth:
        return None
    result_text, user, address = auth.groups()
    try:
        stamp = datetime(
            year, MONTHS[month], int(day), int(hour), int(minute), int(second),
            tzinfo=offset,
        ).astimezone(timezone.utc)
        ip = str(ipaddress.ip_address(address))
    except (ValueError, OverflowError, KeyError):
        return None
    return {
        'timestamp': stamp.isoformat(),
        'ip': ip,
        'user': user,
        'result': 'failure' if result_text == 'Failed' else 'success',
    }


def convert(source, destination, year, offset_text, max_lines=100000, max_line_bytes=4096):
    if year is None or offset_text is None:
        raise ValueError('auth.log dating needs both --year and --utc-offset')
    if not 1970 <= year <= 9999:
        raise ValueError('year must be between 1970 and 9999')
    if max_lines <= 0 or max_line_bytes < 256:
        raise ValueError('line limits are invalid')
    offset = utc_offset(offset_text)
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('source and destination must be different files')
    if destination.exists():
        raise FileExistsError('destination already exists')
    temp_name = None
    parsed = skipped = total = 0
    try:
        with source.open('rb') as src, tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', newline='\n', dir=destination.parent,
            prefix=destination.name + '.', suffix='.tmp', delete=False,
        ) as out:
            temp_name = out.name
            while True:
                raw = src.readline(max_line_bytes + 1)
                if not raw:
                    break
                total += 1
                if total > max_lines:
                    raise ValueError('input exceeds line limit')
                if len(raw) > max_line_bytes:
                    raise ValueError('input line exceeds byte limit')
                text = raw.decode('utf-8')
                event = parse_line(text, year, offset) if text.strip() else None
                if event:
                    parsed += 1
                    out.write(json.dumps(event, separators=(',', ':')) + '\n')
                else:
                    if text.strip():
                        skipped += 1
                    out.write('\n')
        os.replace(temp_name, destination)
        temp_name = None
    except (OSError, UnicodeError, ValueError):
        raise
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
    return {'lines_read': total, 'auth_events': parsed, 'skipped_lines': skipped}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Local auth.log copy; use only logs you own or may inspect')
    parser.add_argument('destination', help='New normalized JSONL file; existing files are never overwritten')
    parser.add_argument('--year', type=int, required=True,
                        help='Explicit year, because auth.log lines carry none')
    parser.add_argument('--utc-offset', required=True,
                        help='Explicit source offset, such as Z, +05:30 or +0530')
    parser.add_argument('--max-lines', type=int, default=100000)
    args = parser.parse_args(argv)
    try:
        summary = convert(args.source, args.destination, args.year, args.utc_offset, args.max_lines)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f'Adapter stopped: {exc}', file=sys.stderr)
        return 2
    print(
        'Wrote {auth_events} auth event(s); skipped {skipped_lines} unsupported line(s) '
        'across {lines_read} input line(s). Line numbers are preserved.'.format(**summary)
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
