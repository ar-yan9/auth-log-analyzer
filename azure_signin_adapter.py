#!/usr/bin/env python3
"""Convert Microsoft Entra (Azure AD) sign-in log JSON to normalized JSONL for analyzer.py.

Reads the portal "Download" JSON of the Entra ID sign-in logs: a top-level
JSON array of sign-in objects, plain or gzip-compressed. Every record in that
export is a sign-in event, so there is no event-type filter; records with an
unusable shape are skipped and counted. The result comes from
status.errorCode: 0 means success, any other integer means failure, exactly
as the export documents it. The account is userPrincipalName with userId as
fallback, never the display name, which is not an identifier. Records without
a parseable network source address are skipped and counted. This is not a
line-preserving conversion: JSONL line numbers refer to the new file, and
skipped records leave no blank lines. Microsoft Graph API responses (a
{"value": [...]} object), Log Analytics/Kusto exports, Azure Monitor
diagnostic formats, B2C and other clouds (AWS, GCP) are unsupported;
normalize those separately.
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

EXPORT_HINT = 'export the Entra ID sign-in logs as JSON from the portal (a top-level array)'
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
        raise ValueError('input is not sign-in log JSON; ' + EXPORT_HINT) from None
    if not isinstance(document, list):
        raise ValueError('input is not a top-level array; ' + EXPORT_HINT)
    return document


def parse_record(record):
    """Return (event, reason); reason labels a skipped record for the summary."""
    if not isinstance(record, dict):
        return None, 'unsupported'
    status = record.get('status')
    error_code = status.get('errorCode') if isinstance(status, dict) else None
    # The export documents errorCode 0 as success; anything else is a failure.
    if isinstance(error_code, bool) or not isinstance(error_code, int):
        return None, 'unsupported'
    result = 'success' if error_code == 0 else 'failure'
    try:
        ip = str(ipaddress.ip_address(record.get('ipAddress')))
    except (TypeError, ValueError):
        return None, 'no_network_address'
    user = None
    # userPrincipalName is the account identifier; userId is its stable GUID.
    # userDisplayName is deliberately not used: a display name is not an ID.
    for key in ('userPrincipalName', 'userId'):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            user = value.strip()[:256]
            break
    if not user:
        return None, 'unsupported'
    stamp = record.get('createdDateTime')
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
    converted = no_address = skipped = 0
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
            'no_network_address': no_address, 'skipped_records': skipped}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Local Entra sign-in JSON or JSON.gz copy; use only logs you own or may inspect')
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
        'network address and {skipped_records} unsupported record(s) across '
        '{records_read} record(s). JSONL line numbers refer to the new file.'
        .format(**summary)
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
