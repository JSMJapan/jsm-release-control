"""Fixed archive entry. Import the producer only after validating the control context."""
import os
import sys

from apache_parity_bridge import strict_json
from test_db_runtime_control_contract import canonical, context_valid, report_valid


def main():
    if sys.platform != 'linux' or os.geteuid() != 0 or len(sys.argv) != 1:
        return 1
    try:
        raw = sys.stdin.buffer.read(2049)
        if not 0 < len(raw) <= 2048:
            return 1
        context = strict_json(raw.decode('ascii'))
        if not context_valid(context) or canonical(context) != raw:
            return 1
        from test_db_runtime_producer import collect_control

        result = collect_control(context)
        report = {key: result[key] for key in ('status', 'configured_runtime', 'local_peer', 'sql', 'metadata')}
        if not report_valid(report):
            return 1
        sys.stdout.buffer.write(canonical(report))
        return 0
    except Exception:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
