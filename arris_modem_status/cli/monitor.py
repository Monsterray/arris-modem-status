"""Conservative, finite modem sampling with one persistent login session."""

import argparse
import json
import sys
import time
from getpass import getpass
from pathlib import Path
from typing import Optional

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.cli.formatters import format_channel_data_for_display
from arris_modem_status.exceptions import (
    ArrisAuthenticationError,
    ArrisConnectionError,
    ArrisModemError,
    ArrisOperationError,
    ArrisTimeoutError,
)


def poll(client: ArrisModemStatusClient, samples: int, interval: int, channels_only: bool = False) -> None:
    """Print JSON lines, stopping immediately on errors or incomplete status."""
    for index in range(samples):
        status = client.get_status(include_logs=False, channels_only=channels_only)
        performance = status["_performance"]
        if (
            performance["requests_successful"] != performance["requests_total"]
            or not status.get("downstream_channels")
            or not status.get("upstream_channels")
        ):
            raise ArrisOperationError("Incomplete modem data; stopped without retrying or logging in again")
        print(json.dumps(format_channel_data_for_display(status), default=str), flush=True)
        if index + 1 < samples:
            time.sleep(interval)


def main(argv: Optional[list[str]] = None) -> int:
    """Read credentials locally and run bounded, serial modem sampling."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.100.1")
    parser.add_argument("--hmac-algorithm", required=True, choices=("md5", "sha256"))
    parser.add_argument("--password-file", type=Path)
    parser.add_argument("--interface", help="Bind modem sockets to an explicit LAN interface (macOS/Linux)")
    parser.add_argument(
        "--channels-only", action="store_true", help="Fetch signals in one request; omit metadata and logs"
    )
    parser.add_argument(
        "--relaxed-http", action="store_true", help="Use legacy raw-socket parsing for incompatible firmware"
    )
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=int, default=900, help="Seconds between samples; minimum 900")
    args = parser.parse_args(argv)
    if args.samples < 1 or args.interval < 900:
        parser.error("samples must be positive and interval must be at least 900 seconds")
    try:
        if args.password_file:
            with args.password_file.open(encoding="utf-8") as handle:
                password = handle.readline().rstrip("\r\n")
        else:
            password = getpass("Modem admin password: ")
        if not password:
            parser.error("password must not be empty")
        with ArrisModemStatusClient(
            password=password,
            host=args.host,
            hmac_algorithm=args.hmac_algorithm,
            concurrent=False,
            max_retries=0,
            enable_instrumentation=False,
            relaxed_http=args.relaxed_http,
            network_interface=args.interface,
        ) as client:
            poll(client, args.samples, args.interval, channels_only=args.channels_only)
    except (ArrisConnectionError, ArrisTimeoutError) as error:
        print(f"Stopped: {error}. Check modem connectivity; no automatic retry will be made.", file=sys.stderr)
        return 1
    except ArrisAuthenticationError as error:
        print(f"Stopped: {error}. Check the modem's login page before starting a new client.", file=sys.stderr)
        return 1
    except (ArrisModemError, OSError, EOFError, UnicodeError) as error:
        print(f"Stopped: {error}. No further modem requests will be made.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Monitoring stopped.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
