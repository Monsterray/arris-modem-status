"""Finite router-origin HTTPS benchmarks through pinned LuCI or optional SSH."""

import argparse
import hmac
import ipaddress
import json
import math
import re
import shlex
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from scripts.flint2_collect import Collector, redact
from scripts.flint2_credentials import DATA_DIR, SafeError, connect_socket, load_profile, private_write, ssh_fingerprint

READ_COMMANDS = {
    "board": "ubus call system board",
    "system": "ubus call system info",
    "wan": "ubus call network.interface.wan status",
    "route": "ip -4 route get 1.1.1.1",
    "cpu": "cat /proc/stat",
}
CURL_FORMAT = '{"status":%{http_code},"download_bytes":%{size_download},"upload_bytes":%{size_upload},"seconds":%{time_total},"download_Bps":%{speed_download},"upload_Bps":%{speed_upload},"connect_seconds":%{time_connect},"tls_seconds":%{time_appconnect},"remote_ip":"%{remote_ip}"}\n'


class LuCIRunner:
    """Reuse one pinned LuCI login for explicitly requested benchmark commands."""

    def __init__(self, profile):
        self.client = Collector(profile)

    def connect(self):
        """Authenticate once; command permissions remain controlled by the router."""
        self.client.authenticate_luci()

    def close(self):
        """Discard the HTTP session and cookies."""
        self.client.close()

    def run(self, command, timeout=30):
        """Execute generated commands using rpcd's existing file.exec permission."""
        result = self.client.rpc(
            self.client.rpc_path,
            "call",
            [self.client.sid, "file", "exec", {"command": "/bin/sh", "params": ["-c", command]}],
            ubus=True,
            timeout=(5, timeout + 5),
        )
        if (
            not isinstance(result, dict)
            or type(result.get("code")) is not int
            or not isinstance(result.get("stdout", ""), str)
            or not isinstance(result.get("stderr", ""), str)
            or len(result.get("stdout", "")) + len(result.get("stderr", "")) > 1048576
        ):
            raise SafeError("LuCI command returned an invalid result; stopped.")
        return result["code"], result.get("stdout", "")


class RouterSSH:
    """Verify the host key before one password authentication; no shell or forwarding."""

    def __init__(self, profile):
        self.profile = profile
        self.transport = None
        self.connection = None

    def connect(self):
        """Do not send the password until the expected server key has matched."""
        from urllib.parse import urlsplit

        host = urlsplit(self.profile["url"]).hostname
        self.connection = connect_socket(host, self.profile["ssh_port"], self.profile.get("interface"))
        self.transport = paramiko.Transport(self.connection)
        try:
            self.transport.start_client(timeout=10)
            observed = ssh_fingerprint(self.transport.get_remote_server_key())
            if not hmac.compare_digest(observed, self.profile["fingerprint"]):
                raise SafeError("SSH host key changed or did not match; no password was sent.")
            self.transport.auth_timeout = 15
            self.transport.auth_password(self.profile["username"], self.profile["password"], fallback=False)
            if not self.transport.is_authenticated():
                raise SafeError("SSH login failed; stopped after one attempt.")
        except BaseException:
            self.close()
            raise

    def close(self):
        """Release the SSH transport and its socket."""
        if self.transport:
            self.transport.close()
        if self.connection:
            self.connection.close()

    def run(self, command, timeout=30):
        """Run a fixed command with bounded time/output; never print remote errors."""
        channel = self.transport.open_session(timeout=10)
        channel.settimeout(5)
        deadline = time.monotonic() + timeout
        stdout, stderr = bytearray(), bytearray()
        try:
            # Only fixed commands and validated, shell-quoted values reach this transport.
            channel.exec_command(command)  # nosec B601
            while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
                if time.monotonic() > deadline:
                    raise SafeError("Router command timed out; stopped.")
                if channel.recv_ready():
                    stdout.extend(channel.recv(65536))
                if channel.recv_stderr_ready():
                    stderr.extend(channel.recv_stderr(65536))
                if len(stdout) + len(stderr) > 1048576:
                    raise SafeError("Router command output exceeded its limit; stopped.")
                time.sleep(0.02)
            return channel.recv_exit_status(), stdout.decode("utf-8", errors="replace")
        finally:
            channel.close()


def snapshot(ssh):
    """Read diagnostic state without retrieving configuration or private keys."""
    data = {}
    for name, command in READ_COMMANDS.items():
        status, output = ssh.run(command)
        if status:
            data[name] = {"unavailable": True, "exit_status": status}
        elif name in ("board", "system", "wan"):
            try:
                data[name] = json.loads(output)
            except ValueError:
                data[name] = {"unavailable": True}
        else:
            data[name] = output
    return data


def transfer_command(direction, amount, interface=None):
    """Build only a fixed Cloudflare transfer; never interpolate passwords or arbitrary URLs."""
    if direction not in ("download", "upload") or not 1 <= amount <= 1024 * 1024 * 1024:
        raise SafeError("Invalid transfer parameters.")
    if interface and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
        raise SafeError("Invalid WAN device name.")
    parts = [
        "curl",
        "--noproxy",
        "*",
        "--ipv4",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--fail",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "--output",
        "/dev/null",
        "--write-out",
        CURL_FORMAT,
    ]
    if interface:
        parts += ["--interface", interface]
    if direction == "download":
        parts.append(f"https://speed.cloudflare.com/__down?bytes={amount}")
        return " ".join(map(shlex.quote, parts))
    # BusyBox dd exists on stock OpenWrt. Only generated zeros enter the HTTPS upload.
    parts += [
        "--request",
        "POST",
        "--header",
        "Content-Type: application/octet-stream",
        "--header",
        "Transfer-Encoding:",
        "--header",
        f"Content-Length: {amount}",
        "--upload-file",
        "-",
        "https://speed.cloudflare.com/__up",
    ]
    return f"dd if=/dev/zero bs=1048576 count={amount // 1048576} 2>/dev/null | " + " ".join(map(shlex.quote, parts))


def measure(ssh, direction, mib, interface=None):
    """Keep completed transfers; reject HTTP errors, short reads, or failed commands."""
    amount = mib * 1048576
    status, output = ssh.run(transfer_command(direction, amount, interface), timeout=70)
    if status:
        raise SafeError(f"Router {direction} benchmark failed (exit {status}); no retry was made.")
    try:
        value = json.loads(output)
        count = value["download_bytes" if direction == "download" else "upload_bytes"]
        rate = value["download_Bps" if direction == "download" else "upload_Bps"]
        if (
            not isinstance(value["status"], int)
            or not 200 <= value["status"] < 300
            or type(count) not in (int, float)
            or count != amount
            or type(rate) not in (int, float)
            or not math.isfinite(rate)
            or rate <= 0
            or type(value["seconds"]) not in (int, float)
            or not math.isfinite(value["seconds"])
            or value["seconds"] <= 0
        ):
            raise ValueError("incomplete transfer")
        ipaddress.ip_address(value["remote_ip"])
        value.update(direction=direction, mbps=rate * 8 / 1000000)
        return value
    except (ValueError, KeyError, TypeError) as error:
        raise SafeError("Benchmark returned invalid or incomplete measurements; stopped.") from error


def benchmark(ssh, runs=3, download_mib=256, upload_mib=16, route="default"):
    """Use existing tools only; record routing and pre/post state along with finite transfers."""
    if (
        not 1 <= runs <= 5
        or not 1 <= download_mib <= 1024
        or not 1 <= upload_mib <= 128
        or route not in ("default", "wan")
    ):
        raise SafeError("Benchmark parameters exceed the supported finite limits.")
    status, _ = ssh.run("command -v curl >/dev/null && command -v dd >/dev/null")
    if status:
        raise SafeError("Router curl/dd is unavailable; no packages were installed.")
    before = snapshot(ssh)
    interface = None
    if route == "wan":
        interface = before.get("wan", {}).get("l3_device")
        if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
            raise SafeError("Cannot identify the WAN device; no test traffic was sent.")
    ping_status, ping = ssh.run("ping -c 5 -W 2 1.1.1.1", timeout=20)
    report = {
        "schema_version": 1,
        "collected_utc": datetime.now(timezone.utc).isoformat(),
        "origin": "router",
        "provider": "Cloudflare HTTPS transfers",
        "route_mode": route,
        "bound_device": interface,
        "before": before,
        "idle_ping": {"route_mode": "default", "exit_status": ping_status, "output": ping},
        "transfers": [],
        "limitations": [
            "Single-connection transfer benchmark; not an official Comcast or multi-connection capacity test.",
            "Default routing may traverse VPN or policy routing; WAN binding may be blocked by existing rules.",
            "Router CPU and configured SQM/QoS can limit results; this is not a bufferbloat grade.",
        ],
    }
    for _ in range(runs):
        for direction, mib in (("download", download_mib), ("upload", upload_mib)):
            report["transfers"].append(measure(ssh, direction, mib, interface))
    report["after"] = snapshot(ssh)
    report["median_mbps"] = {
        direction: statistics.median(row["mbps"] for row in report["transfers"] if row["direction"] == direction)
        for direction in ("download", "upload")
    }
    return report


def main(argv=None):
    """Run an explicitly requested router benchmark and save a private report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--via", choices=("luci", "ssh"), default="luci", help="Use existing LuCI access by default")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--download-mib", type=int, default=256)
    parser.add_argument("--upload-mib", type=int, default=16)
    parser.add_argument(
        "--route",
        choices=("default", "wan"),
        default="default",
        help="wan binds only test transfers to the detected WAN device; does not change routes",
    )
    parser.add_argument("--output-dir", type=Path, default=DATA_DIR)
    args = parser.parse_args(argv)
    if not 1 <= args.runs <= 5 or not 1 <= args.download_mib <= 1024 or not 1 <= args.upload_mib <= 128:
        parser.error("runs must be 1..5, download-mib 1..1024, and upload-mib 1..128")
    runner = None
    try:
        profile = load_profile(args.via)
        runner = LuCIRunner(profile) if args.via == "luci" else RouterSSH(profile)
        runner.connect()
        report = redact(
            benchmark(runner, args.runs, args.download_mib, args.upload_mib, args.route), (profile["password"],)
        )
        report["transport"] = args.via
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = args.output_dir / f"speedtest-{stamp}.json"
        private_write(path, json.dumps(report, ensure_ascii=False, indent=2).encode())
        print(f"Saved router-side benchmark: {path}")
        print(json.dumps(report["median_mbps"], sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130
    except Exception as error:
        print(
            (
                str(error)
                if isinstance(error, SafeError)
                else f"Router benchmark failed ({type(error).__name__}); no secret details printed."
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        if runner:
            runner.close()


if __name__ == "__main__":
    raise SystemExit(main())
