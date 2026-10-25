# Auth Log Analyzer

An offline, dependency-free Python CLI for investigating **normalized authentication events**. It flags failure bursts, possible password spraying, and a success on the same account after repeated failures from the same source. Alerts are heuristic leads for review, not proof of an attack or account compromise.

## Quick start

Requires Python 3.10+. No paid services, network access, third-party Python packages or administrator access.

```bash
python3 analyzer.py demo.jsonl
python3 analyzer.py demo.jsonl --format json
python3 analyzer.py demo.jsonl --window 300 --failures 5 --spray-users 5
python3 -m unittest -v
```

Convert a local copy of common Linux OpenSSH lines, then analyze the normalized copy:

```bash
python3 ssh_adapter.py demo_auth.log demo-from-auth.jsonl --year 2026 --utc-offset Z
python3 analyzer.py demo-from-auth.jsonl --format json
```

On Windows, use `py -3.11` instead of `python3` if that is your launcher. Both synthetic demos intentionally return analyzer exit **1** because they contain suspicious patterns. The adapter writes a new file and never overwrites an existing one.

Exit codes: **0** = no alerts in the valid input; **1** = alerts found; **2** = invalid input, incomplete analysis or invalid settings. Partial alerts remain available in the report when records are invalid. A zero exit is not a claim that a system is secure.

## Input contract

One JSON object per line (JSONL):

```json
{"timestamp":"2026-01-01T00:00:00Z","ip":"192.0.2.10","user":"demo-user","result":"failure"}
```

- `timestamp`: ISO 8601 timestamp with timezone offset, converted to UTC.
- `ip`: valid IPv4 or IPv6 address. Equivalent address spellings are normalized.
- `user`: nonempty, case-sensitive account identifier, at most 256 characters.
- `result`: exactly `failure` or `success`.
- Extra fields are ignored and are never copied to reports. Blank lines are ignored.

`ssh_adapter.py` converts common OpenSSH `Failed`/`Accepted` password, publickey and keyboard-interactive/PAM lines from Linux `auth.log` into this JSONL format. RFC3164 auth.log timestamps carry no year or timezone, so the adapter requires explicit `--year` and `--utc-offset` values rather than guessing. Unsupported lines become blank output lines, preserving the original line numbers used in analyzer evidence. Windows event logs, cloud audit exports, web-server logs and other Linux authentication messages are still unsupported; normalize those separately. Only analyze logs you own or have permission to inspect, and do not upload private logs or reports to this public repository.

## Detection rules

Defaults use an inclusive 300-second sliding window for each source IP:

| Rule | Condition | Severity |
| --- | --- | --- |
| `failure-burst` | At least 5 failed events from one source | Medium |
| `possible-password-spray` | Failures against at least 5 distinct accounts from one source | Medium |
| `success-after-failures` | A successful event after at least 5 failures for the same source and account | High |

Events are sorted by timestamp then original line number. A success does not clear previous failures. Each source/rule is reported once per analysis; success-after-failures is reported once per source/account. This deliberate deduplication means later separate bursts are not listed separately. Duplicate input records are counted as events, so deduplicate overlapping exports before analysis. A success on a different account is not treated as evidence of compromise.

Alerts record timestamps, counts and original evidence line numbers, not raw source lines. Source/account labels are keyed HMAC pseudonyms with a fresh random key per run. They correlate within one report but change across runs. Raw IPs and usernames are not printed; this is **pseudonymization, not anonymization**. Counts, timestamps and line numbers can still reveal sensitive activity. Keep reports private.

## Limits and review

At most 100,000 lines by default (`--max-lines` changes this), with a 16 KiB per-line limit. Oversized records stop analysis with exit 2. Malformed records are skipped with generic line-number notices and exit 2. The CLI holds valid events in memory for sorting. It does not tail a live log, send alerts, block IPs, alter accounts or contact servers.

Shared NAT IPs, user mistakes, retries, duplicate exports and legitimate testing can cause false positives. Distributed attacks, low-and-slow attempts, missing logs and events outside the configured window can evade these rules. The tool has no geolocation, threat intelligence, baseline learning or confirmed-compromise scoring.

When an alert appears, review the referenced lines locally, confirm the affected account and context, and follow your organization's incident process. Do not automatically block a shared IP or reset an account based only on this report.

## Tests and demonstration

`test_analyzer.py` and `test_ssh_adapter.py` use synthetic events, temporary files and documentation-only IP addresses. Tests cover thresholds, expiry, inclusive boundaries, source separation, same-account success correlation, sort/deduplication, redaction, IPv6, timezone conversion, invalid input, adapter bounds, no-overwrite behavior, line-number preservation and exit states.

`demo.jsonl` and `demo_auth.log` contain fictional accounts. Expected normalized-JSONL rules: failure-burst, possible-password-spray and success-after-failures. Expected OpenSSH demo rules: failure-burst and success-after-failures. No real logs or credentials are included.

## Next work

Add explicit adapters for Windows exports with fixtures, broader Linux auth-message coverage, interval grouping for repeated bursts, and performance benchmarks. This is a working starter, not a SIEM replacement. Understand the sliding-window code and demonstrate the tests before presenting it in an interview; do not claim production deployment or real incident-response experience.
