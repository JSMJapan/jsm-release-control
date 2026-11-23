"""Fixed archive entry. Import the producer only after validating the control context."""
import os
import sys
import time

from apache_parity_bridge import strict_json
from test_db_runtime_control_contract import REPORT_FIELDS, canonical, context_valid, report_valid, staging_valid


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 1:
        return 1
    try:
        raw = sys.stdin.buffer.read(4097)
        if not 0 < len(raw) <= 4096:
            return 1
        payload = strict_json(raw.decode('ascii'))
        if type(payload) is not dict or set(payload) != {'context', 'staging', 'deadline_ns'} or canonical(payload) != raw:
            return 1
        context, staging, deadline_ns = payload['context'], payload['staging'], payload['deadline_ns']
        if (not context_valid(context) or not staging_valid(staging) or type(deadline_ns) is not int
                or not 0 < deadline_ns - time.monotonic_ns() <= 4_000_000_000):
            return 1
        from test_db_runtime_producer import collect_control

        result = collect_control(context, staging, deadline_ns)
        report = {key: result[key] for key in REPORT_FIELDS}
        if not report_valid(report):
            return 1
        sys.stdout.buffer.write(canonical(report))
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
