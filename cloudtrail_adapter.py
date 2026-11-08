#!/usr/bin/env python3
"""Convert AWS CloudTrail ConsoleLogin records to normalized JSONL for analyzer.py.

Only sign-in events (eventName "ConsoleLogin") become auth events; every other
API call is skipped and counted. Reads a plain or gzip-compressed CloudTrail
export whose top level is a JSON object with a "Records" array, exactly as
CloudTrail delivers log files. This is not a line-preserving conversion:
JSONL line numbers refer to the new file, and skipped records leave no blank
lines. Organization trails, CloudTrail event-history CSV exports and other
clouds (GCP, Azure) are unsupported; normalize those separately.
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

EXPORT_HINT = 'export a CloudTrail log file (JSON or JSON.gz) with a top-level Records array'
MAX_BYTES = 64 * 1024 * 1024


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
        raise ValueError('input is not CloudTrail JSON; ' + EXPORT_HINT) from None
    if not isinstance(document, dict) or not isinstance(document.get('Records'), list):
        raise ValueError('input has no top-level Records array; ' + EXPORT_HINT)
    return document['Records']


def parse_record(record):
    """Return (event, reason); reason labels a skipped record for the summary."""
    if not isinstance(record, dict):
        return None, 'unsupported'
    if record.get('eventName') != 'ConsoleLogin':
        return None, 'other_event'
    response = record.get('responseElements')
    outcome = response.get('ConsoleLogin') if isinstance(response, dict) else None
    if outcome == 'Success':
        result = 'success'
    elif outcome == 'Failure':
        result = 'failure'
    else:
        return None, 'unsupported'
    try:
        ip = str(ipaddress.ip_address(record.get('sourceIPAddress')))
    except (TypeError, ValueError):
        return None, 'no_network_address'
    identity = record.get('userIdentity')
    user = None
    if isinstance(identity, dict):
        # IAM users carry userName; root and assumed roles usually do not.
        for key in ('userName', 'principalId', 'arn'):
            value = identity.get(key)
            if isinstance(value, str) and value.strip():
                user = value.strip()[:256]
                break
    if not user:
        return None, 'unsupported'
    stamp = record.get('eventTime')
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
    converted = other = no_address = skipped = 0
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
                elif reason == 'other_event':
                    other += 1
                elif reason == 'no_network_address':
                    no_address += 1
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
            'other_events': other, 'no_network_address': no_address,
            'skipped_records': skipped}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Local CloudTrail JSON or JSON.gz copy; use only logs you own or may inspect')
    parser.add_argument('destination', help='New normalized JSONL file; existing files are never overwritten')
    parser.add_argument('--max-records', type=int, default=100000)
    args = parser.parse_args(argv)
    try:
        summary = convert(args.source, args.destination, args.max_records)
    except (OSError, ValueError) as exc:
        print(f'Adapter stopped: {exc}', file=sys.stderr)
        return 2
    print(
        'Wrote {signin_events} sign-in event(s); skipped {other_events} non-sign-in record(s), '
        '{no_network_address} without a network address and {skipped_records} unsupported '
        'record(s) across {records_read} record(s). JSONL line numbers refer to the new file.'
        .format(**summary)
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
