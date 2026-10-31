#!/usr/bin/env python3
"""Convert Windows Security logon events (4624/4625) to normalized JSONL for analyzer.py.

Export on the machine that owns the log with the built-in wevtutil tool,
from an elevated prompt:

    wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:XML /e:Events > security-logon.xml

The XML export carries full UTC timestamps, so unlike ssh_adapter.py no
--year or --utc-offset values are needed. Events without a network source
address (local logons report "-") are skipped and counted, because burst
and spray analysis needs a source address. XML exports are multi-line, so
output JSONL line numbers refer to the JSONL file itself, not the XML.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

SYSTEM_TIME = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$'
)
RESULT_BY_ID = {4624: 'success', 4625: 'failure'}
EXPORT_HINT = ('export with: wevtutil qe Security '
               '/q:"*[System[(EventID=4624 or EventID=4625)]]" /f:XML /e:Events')


def local_name(tag):
    """Element tag without its XML namespace."""
    return tag.rsplit('}', 1)[-1]


def parse_system_time(text):
    """Return a canonical UTC ISO string for a Windows SystemTime, or None.

    Windows writes seven fractional digits; the result is truncated to
    microseconds so every supported Python version parses it identically.
    """
    if not isinstance(text, str):
        return None
    match = SYSTEM_TIME.match(text.strip())
    if not match:
        return None
    year, month, day, hour, minute, second, fraction = match.groups()
    try:
        stamp = datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second),
            int((fraction or '0').ljust(6, '0')[:6]), tzinfo=timezone.utc,
        )
    except (ValueError, OverflowError):
        return None
    return stamp.isoformat()


def parse_event(element):
    """Return (event, skip_reason) for one Windows Event element.

    event is a normalized dict; when it is None, skip_reason is
    'no_network_address' or 'unsupported'.
    """
    system = data = None
    for child in element:
        name = local_name(child.tag)
        if name == 'System':
            system = child
        elif name == 'EventData':
            data = child
    if system is None or data is None:
        return None, 'unsupported'
    event_id = system_time = None
    for child in system:
        name = local_name(child.tag)
        if name == 'EventID':
            event_id = child.text
        elif name == 'TimeCreated':
            system_time = child.get('SystemTime')
    try:
        result = RESULT_BY_ID.get(int(str(event_id).strip()))
    except (TypeError, ValueError):
        result = None
    if result is None:
        return None, 'unsupported'
    fields = {}
    for item in data:
        if local_name(item.tag) == 'Data':
            name = item.get('Name')
            if name and name not in fields:
                fields[name] = item.text
    stamp = parse_system_time(system_time)
    user = fields.get('TargetUserName')
    if stamp is None or not isinstance(user, str) or not user.strip() or len(user) > 256:
        return None, 'unsupported'
    address = (fields.get('IpAddress') or '').strip()
    if address in ('', '-'):
        return None, 'no_network_address'
    try:
        ip = str(ipaddress.ip_address(address))
    except ValueError:
        return None, 'unsupported'
    return {'timestamp': stamp, 'ip': ip, 'user': user, 'result': result}, None


def convert(source, destination, max_events=100000):
    if max_events <= 0:
        raise ValueError('event limit is invalid')
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError('source and destination must be different files')
    if destination.exists():
        raise FileExistsError('destination already exists')
    temp_name = None
    converted = no_address = skipped = total = 0
    try:
        with source.open('rb') as src, tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', newline='\n', dir=destination.parent,
            prefix=destination.name + '.', suffix='.tmp', delete=False,
        ) as out:
            temp_name = out.name
            for _kind, element in ET.iterparse(src, events=('end',)):
                if local_name(element.tag) != 'Event':
                    continue
                total += 1
                if total > max_events:
                    raise ValueError('input exceeds event limit')
                event, reason = parse_event(element)
                element.clear()
                if event:
                    converted += 1
                    out.write(json.dumps(event, separators=(',', ':')) + '\n')
                elif reason == 'no_network_address':
                    no_address += 1
                else:
                    skipped += 1
        if total == 0:
            raise ValueError('no Event elements found; ' + EXPORT_HINT)
        os.replace(temp_name, destination)
        temp_name = None
    except ET.ParseError:
        raise ValueError('input is not Windows event XML; ' + EXPORT_HINT) from None
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
    return {'events_read': total, 'auth_events': converted,
            'no_network_address': no_address, 'skipped_events': skipped}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', help='Local wevtutil XML copy; use only logs you own or may inspect')
    parser.add_argument('destination', help='New normalized JSONL file; existing files are never overwritten')
    parser.add_argument('--max-events', type=int, default=100000)
    args = parser.parse_args(argv)
    try:
        summary = convert(args.source, args.destination, args.max_events)
    except (OSError, ValueError) as exc:
        print(f'Adapter stopped: {exc}', file=sys.stderr)
        return 2
    print(
        'Wrote {auth_events} logon event(s); skipped {no_network_address} without a network '
        'address and {skipped_events} unsupported record(s) across {events_read} event(s). '
        'JSONL line numbers refer to the new file.'.format(**summary)
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
