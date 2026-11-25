#!/usr/bin/env python3
"""Convert Google Workspace login audit JSON to normalized JSONL for analyzer.py.

Reads the Admin SDK Reports API activities list for the login application:
the JSON body of an activities.list response, a top-level object with an
"items" array of activity records, plain or gzip-compressed. Only activities
whose events list contains a login outcome are converted: an event named
"login_success" maps to success and "login_failure" maps to failure, exactly
as the Reports API login reference names them. Activities carrying only other
event names (logout, login_challenge, suspicious login warnings, and so on)
are skipped and counted. The account is actor.email with actor.profileId as
fallback; actor names are display values and are never used as identifiers.
Records without a parseable network source address are skipped and counted.
This is not a line-preserving conversion: JSONL line numbers refer to the new
file, and skipped records leave no blank lines. BigQuery exports of the same
audit data, the Admin console CSV download, Gmail/Drive/other application
audits, and non-Google identity providers are unsupported; normalize those
separately.
"""
import argparse
from datetime import datetime, timezone
import gzip
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile

EXPORT_HINT = ('export the login audit via the Admin SDK Reports API '
               'activities.list (a top-level object with an "items" array)')
MAX_BYTES = 64 * 1024 * 1024
LOGIN_RESULTS = {'login_success': 'success', 'login_failure': 'failure'}


def read_export(source):
    raw = source.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError('input exceeds byte limit')
    if raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except OSError:
            raise ValueError('input is not valid gzip; ' + EXPORT_HINT) from None
        if len(raw) > MAX_BYTES:
            raise ValueError('decompressed input exceeds byte limit')
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError('input is not login audit JSON; ' + EXPORT_HINT) from None
    if not isinstance(document, dict) or not isinstance(document.get('items'), list):
        raise ValueError('input is not an activities list; ' + EXPORT_HINT)
    return document['items']


def parse_record(record):
    """Return (event, reason); reason labels a skipped record for the summary."""
    if not isinstance(record, dict):
        return None, 'unsupported'
    events = record.get('events')
    if not isinstance(events, list):
        return None, 'unsupported'
    names = {entry.get('name') for entry in events if isinstance(entry, dict)}
    outcomes = [result for name, result in LOGIN_RESULTS.items() if name in names]
    if not outcomes:
        # A real activity that is simply not a login success/failure.
        return None, 'not_login_event'
    # An activity cannot document both outcomes for one attempt; a conflicting
    # record is treated as an unsupported shape rather than guessing.
    if len(outcomes) != 1:
        return None, 'unsupported'
    result = outcomes[0]
    try:
        ip = str(ipaddress.ip_address(record.get('ipAddress')))
    except (TypeError, ValueError):
        return None, 'no_network_address'
    actor = record.get('actor')
    actor = actor if isinstance(actor, dict) else {}
    user = None
    # actor.email is the account identifier; actor.profileId is its stable
    # numeric ID. Display names are deliberately never used as identifiers.
    for key in ('email', 'profileId'):
        value = actor.get(key)
        if isinstance(value, str) and value.strip():
            user = value.strip()[:256]
            break
    if not user:
        return None, 'unsupported'
    identity = record.get('id')
    stamp = identity.get('time') if isinstance(identity, dict) else None
    if not isinstance(stamp, str):
        return None, 'unsupported'
    try:
        parsed_stamp = datetime.fromisoformat(stamp.strip().replace('Z', '+00:00'))
    except ValueError:
        return None, 'unsupported'
    if parsed_stamp.tzinfo is None or parsed_stamp.utcoffset() is None:
        return None, 'unsupported'
    return {
        'timestamp': parsed_stamp.astimezone(timezone.utc).isoformat(),
        'ip': ip,
        'user': user,
        'result': result,
    }, None


def convert(source, destination, max_records=100000):
    if max_records <= 0:
        raise ValueError('record limit is invalid')
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('source and destination must be different files')
    if destination.exists():
        raise FileExistsError('destination already exists')
    records = read_export(source)
    if not records:
        raise ValueError('no records found; ' + EXPORT_HINT)
    if len(records) > max_records:
        raise ValueError('input exceeds record limit')
    temp_name = None
    converted = no_address = not_login = skipped = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', newline='\n', dir=destination.parent,
            prefix=destination.name + '.', suffix='.tmp', delete=False,
        ) as out:
            temp_name = out.name
            for record in records:
                event, reason = parse_record(record)
                if event:
                    converted += 1
                    out.write(json.dumps(event, separators=(',', ':')) + '\n')
                elif reason == 'no_network_address':
                    no_address += 1
                elif reason == 'not_login_event':
                    not_login += 1
                else:
                    skipped += 1
        os.replace(temp_name, destination)
        temp_name = None
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
    return {'records_read': len(records), 'signin_events': converted,
            'no_network_address': no_address, 'not_login_events': not_login,
            'skipped_records': skipped}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Local Reports API login audit JSON or JSON.gz copy; use only logs you own or may inspect')
    parser.add_argument('destination', help='New normalized JSONL file; existing files are never overwritten')
    parser.add_argument('--max-records', type=int, default=100000)
    args = parser.parse_args(argv)
    try:
        summary = convert(args.source, args.destination, args.max_records)
    except (OSError, ValueError) as exc:
        print(f'Adapter stopped: {exc}', file=sys.stderr)
        return 2
    print(
        'Wrote {signin_events} sign-in event(s); skipped {no_network_address} without a '
        'network address, {not_login_events} non-login activities and {skipped_records} '
        'unsupported record(s) across {records_read} record(s). JSONL line numbers '
        'refer to the new file.'
        .format(**summary)
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
