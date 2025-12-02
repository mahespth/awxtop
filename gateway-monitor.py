#!/usr/bin/env python3
"""
Gateway Health Monitor for AAP
==============================

Description
-----------
Simple terminal-based monitor for Red Hat Ansible Automation Platform (AAP)
Gateways and Load Balancer endpoints.

Features
--------
- Polls one or more AAP Gateway base URLs and checks either:
    * /api/gateway/v1/status/
    * /api/gateway/v1/ping/
- Uses a Bearer token for authentication.
- Polls endpoints at a configurable interval (default: 1 second).
- Displays a rolling ASCII "graph" of health per endpoint.
- Truncates FQDNs by default so domains are hidden (first label only).
  A flag allows the full hostname to be shown instead.
- Tracks, per endpoint:
    * Total requests
    * Percentage of requests that are NOT good (excluding unknown)
    * Per-error message counters.
- Requests can be executed concurrently with a flag using a thread pool.
- Clean exit on Ctrl-C.
- Status line shows the time and the hostname the monitor is running on.
- Logging of errors:
    * By default logs to a local file including time, hostname and error text.
    * Optional flag to log errors to syslog instead of a file.

Requirements
------------
- Python 3 standard library only (no external dependencies).
- Designed to work on typical AAP execution environments.

Usage
-----
    gateway-monitor.py --token MYTOKEN https://gw1.example.com https://gw2.example.com

Key flags
---------
    --token TOKEN           Bearer token to use for Authorization header (required).
    --interval SECONDS      Poll interval (default: 1.0).
    --timeout SECONDS       HTTP timeout per request (default: 5.0).
    --ping                  Use /api/gateway/v1/ping/ instead of /api/gateway/v1/status/.
    --async                 Fetch endpoints concurrently using a thread pool.
    --show-full             Show full FQDN / URL instead of truncated hostname.
    --insecure              Skip TLS certificate verification.
    --log-file PATH         Log errors to this file (default: ./gateway-monitor.log).
    --syslog                Log errors to syslog instead of file logging.

"""

import argparse
import json
import logging
import logging.handlers
import shutil
import socket
import ssl
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib import error, request
from urllib.parse import urlparse

from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

HOSTNAME = socket.gethostname()
LOGGER: Optional[logging.Logger] = None


class HostnameFilter(logging.Filter):
    """Inject the hostname into log records as `%(hostname)s`."""
    def filter(self, record: logging.LogRecord) -> bool:
        record.hostname = HOSTNAME
        return True


def setup_logger(log_file: Optional[str], use_syslog: bool) -> logging.Logger:
    """
    Configure a process-wide logger.

    If use_syslog is True, logs to syslog instead of a file.
    If use_syslog is False, logs to log_file (default path if None).
    """
    logger = logging.getLogger("gateway-monitor")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if called more than once
    if logger.handlers:
        return logger

    if use_syslog:
        try:
            handler = logging.handlers.SysLogHandler(address="/dev/log")
        except Exception:
            # Fallback to UDP localhost:514 if /dev/log is not available
            handler = logging.handlers.SysLogHandler(address=("localhost", 514))
    else:
        if not log_file:
            log_file = "gateway-monitor.log"
        handler = logging.FileHandler(log_file)

    fmt = logging.Formatter(
        "%(asctime)s %(hostname)s gateway-monitor[%(process)d]: "
        "%(levelname)s: %(message)s"
    )
    handler.setFormatter(fmt)
    handler.addFilter(HostnameFilter())
    logger.addHandler(handler)

    return logger


def log_error(msg: str) -> None:
    """Log an error message if logging is configured."""
    if LOGGER is not None:
        LOGGER.error(msg)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def build_ssl_context(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_request(
    base_url: str,
    path: str,
    token: str,
    timeout: float,
    insecure: bool,
) -> Tuple[int, str]:
    """
    Make a GET request to base_url + path.

    Returns (status_code, body_text).
    Raises HTTPError/URLError for network-level issues.
    """
    base = base_url.rstrip("/")
    url = f"{base}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    ctx = build_ssl_context(insecure)
    req = request.Request(url, headers=headers)
    with request.urlopen(req, timeout=timeout, context=ctx) as resp:
        code = resp.getcode()
        body = resp.read().decode("utf-8", errors="replace")
    return code, body


def interpret_status_response(body: str) -> str:
    """
    Interpret the JSON body from /api/gateway/v1/status/ and return
    'good', 'bad' or 'unknown'.
    """
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return "unknown"

    # Heuristics based on a typical gateway status payload that has:
    # {
    #   "services": [
    #       {"name": "...", "status": "good"},
    #       {"name": "...", "status": "bad"},
    #       ...
    #    ],
    #   "status": "good"
    # }
    if isinstance(data, dict):
        overall = data.get("status")
        if isinstance(overall, str):
            s = overall.lower()
            if s == "good":
                return "good"
            if s in ("bad", "error", "degraded"):
                return "bad"
        services = data.get("services")
        if isinstance(services, list) and services:
            bad_found = False
            good_found = False
            for svc in services:
                if not isinstance(svc, dict):
                    continue
                st = str(svc.get("status", "")).lower()
                if st == "good":
                    good_found = True
                elif st:
                    bad_found = True
            if bad_found:
                return "bad"
            if good_found:
                return "good"

    return "unknown"


def check_endpoint(
    endpoint: str,
    token: str,
    timeout: float,
    insecure: bool,
    use_ping: bool,
) -> Tuple[str, Optional[str]]:
    """
    Check the gateway endpoint.

    Returns (status, error_message):
      - status in {'good', 'bad', 'unknown'}
      - error_message is None on success, or a string describing the error
        (used for per-endpoint error counters and logging).
    """
    path = "/api/gateway/v1/ping/" if use_ping else "/api/gateway/v1/status/"
    try:
        code, body = make_request(endpoint, path, token, timeout, insecure)
    except error.HTTPError as e:
        msg = f"HTTP {e.code} on {endpoint}{path}: {e.reason}"
        log_error(msg)
        return "bad", msg
    except error.URLError as e:
        msg = f"URL error on {endpoint}{path}: {e.reason}"
        log_error(msg)
        return "bad", msg
    except Exception as e:
        msg = f"Exception on {endpoint}{path}: {type(e).__name__}: {e}"
        log_error(msg)
        return "bad", msg

    if use_ping:
        # For ping, treat 2xx as good, everything else bad
        if 200 <= code < 300:
            return "good", None
        msg = f"Ping returned HTTP {code} on {endpoint}{path}"
        log_error(msg)
        return "bad", msg
    else:
        # Interpret JSON status response
        status = interpret_status_response(body)
        if status == "unknown":
            msg = f"Unknown status response from {endpoint}{path}"
            log_error(msg)
            return status, msg
        return status, None


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

RESET = "\033[0m"
COLOR_GOOD = "\033[32m"      # green
COLOR_BAD = "\033[31m"       # red
COLOR_UNKNOWN = "\033[33m"   # yellow
COLOR_LABEL = "\033[36m"     # cyan for labels
COLOR_HEADER = "\033[37m"    # white/grey


def status_to_char_and_color(status: str) -> Tuple[str, str]:
    if status == "good":
        return ".", COLOR_GOOD
    if status == "bad":
        return "x", COLOR_BAD
    if status == "unknown":
        return "?", COLOR_UNKNOWN
    return " ", ""


def shorten_endpoint_name(endpoint: str, show_full: bool) -> str:
    """
    Produce a short display name for an endpoint.

    By default, truncates FQDNs so the domain is hidden:
      - https://gw1.example.com -> gw1
    If show_full is True, returns the host / netloc instead.
    """
    parsed = urlparse(endpoint)
    host = parsed.netloc or parsed.path or endpoint
    if show_full:
        return host

    # Truncate FQDN: take just the first label
    if "." in host:
        return host.split(".")[0]
    return host


def clear_screen() -> None:
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def format_bad_percent(stats: Dict[str, int]) -> str:
    """
    Calculate the percentage of non-good requests excluding unknown.
    stats keys: 'good', 'bad', 'unknown'.
    """
    good = stats.get("good", 0)
    bad = stats.get("bad", 0)
    unknown = stats.get("unknown", 0)
    denom = good + bad  # explicitly exclude unknown
    if denom == 0:
        return "0.0%"
    pct = (bad / denom) * 100.0
    return f"{pct:4.1f}%"


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def monitor_gateways(args: argparse.Namespace) -> None:
    global LOGGER

    LOGGER = setup_logger(args.log_file, args.syslog)

    endpoints: List[str] = args.endpoints
    token = args.token
    timeout = args.timeout
    insecure = args.insecure
    use_ping = args.ping
    interval = args.interval
    async_requests = args.async_requests

    # Per-endpoint history and stats
    histories: Dict[str, List[str]] = {ep: [] for ep in endpoints}
    stats: Dict[str, Dict[str, int]] = {
        ep: {"good": 0, "bad": 0, "unknown": 0} for ep in endpoints
    }
    error_counts: Dict[str, Dict[str, int]] = {
        ep: defaultdict(int) for ep in endpoints
    }

    # Precompute display names (can be recomputed if needed)
    display_names: Dict[str, str] = {
        ep: shorten_endpoint_name(ep, args.show_full) for ep in endpoints
    }

    monitor_host = HOSTNAME

    executor: Optional[ThreadPoolExecutor] = None    # type: ignore[type-arg]
    if async_requests:
        executor = ThreadPoolExecutor(max_workers=len(endpoints))

    try:
        while True:
            term_size = shutil.get_terminal_size(fallback=(80, 24))
            width = term_size.columns

            label_width = max((len(name) for name in display_names.values()), default=8)
            label_width = max(label_width, 8)
            # Leave room for " | " and at least 10 chars of graph plus stats
            history_width = max(10, width - label_width - 20)

            # Fetch statuses
            results: Dict[str, Tuple[str, Optional[str]]] = {}

            if async_requests and executor is not None:
                future_map = {
                    executor.submit(
                        check_endpoint, ep, token, timeout, insecure, use_ping
                    ): ep
                    for ep in endpoints
                }
                for fut in as_completed(future_map):
                    ep = future_map[fut]
                    try:
                        status, err = fut.result()
                    except Exception as e:
                        msg = f"Exception in worker for {ep}: {type(e).__name__}: {e}"
                        log_error(msg)
                        status, err = "bad", msg
                    results[ep] = (status, err)
            else:
                for ep in endpoints:
                    status, err = check_endpoint(ep, token, timeout, insecure, use_ping)
                    results[ep] = (status, err)

            # Update histories and stats
            for ep, (status, err) in results.items():
                # keep history length bounded
                history = histories[ep]
                history.append(status)
                if len(history) > history_width:
                    # Trim oldest entries
                    histories[ep] = history[-history_width:]

                if status not in ("good", "bad", "unknown"):
                    status = "unknown"
                stats[ep][status] += 1

                if err:
                    error_counts[ep][err] += 1

            # Render
            clear_screen()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            header = f"{COLOR_HEADER}Gateway Monitor  {now}  host:{monitor_host}{RESET}"
            print(header)
            mode_str = "PING" if use_ping else "STATUS"
            mode_info = f"Mode: {mode_str}  Interval: {interval:.1f}s  Timeout: {timeout:.1f}s"
            print(COLOR_HEADER + mode_info + RESET)
            print()

            # Per-endpoint rows
            for ep in endpoints:
                name = display_names[ep]
                history = histories[ep]
                bad_pct = format_bad_percent(stats[ep])

                label = f"{COLOR_LABEL}{name.ljust(label_width)}{RESET}"
                graph_chars = []
                for st in history[-history_width:]:
                    ch, color = status_to_char_and_color(st)
                    if color:
                        graph_chars.append(f"{color}{ch}{RESET}")
                    else:
                        graph_chars.append(ch)
                graph_str = "".join(graph_chars)

                line = f"{label} | {graph_str}"
                print(line)

                # Stats line
                total = sum(stats[ep].values())
                detail = (
                    f"{' ' * (label_width + 3)}"
                    f"good={stats[ep]['good']} "
                    f"bad={stats[ep]['bad']} "
                    f"unknown={stats[ep]['unknown']} "
                    f"total={total} "
                    f"not_good%={bad_pct}"
                )
                print(COLOR_HEADER + detail + RESET)

                print()

            # Error summary
            any_errors = any(error_counts[ep] for ep in endpoints)
            if any_errors:
                print(COLOR_HEADER + "Errors:" + RESET)
                for ep in endpoints:
                    ep_errors = error_counts[ep]
                    if not ep_errors:
                        continue
                    name = display_names[ep]
                    print(f"{COLOR_LABEL}{name}{RESET}:")
                    for msg, count in ep_errors.items():
                        print(f"  {count}x  {msg}")
                    print()

            # Sleep until next interval
            time.sleep(interval)

    except KeyboardInterrupt:
        # Clean exit on Ctrl-C
        print("\nExiting gateway monitor...")
    finally:
        if executor is not None:
            executor.shutdown(wait=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor AAP gateway health via /api/gateway/v1/status/ or /ping/."
    )
    parser.add_argument(
        "endpoints",
        nargs="+",
        help="Gateway base URLs, e.g. https://gw1.example.com",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Bearer token used for Authorization header.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--ping",
        action="store_true",
        help="Use /api/gateway/v1/ping/ instead of /api/gateway/v1/status/.",
    )
    parser.add_argument(
        "--async",
        dest="async_requests",
        action="store_true",
        help="Fetch endpoints concurrently using a thread pool.",
    )
    parser.add_argument(
        "--show-full",
        action="store_true",
        help="Show full hostname/FQDN instead of truncated host label.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification (use with caution).",
    )
    parser.add_argument(
        "--log-file",
        default="gateway-monitor.log",
        help="Log errors to this file (default: ./gateway-monitor.log). "
             "Ignored if --syslog is set.",
    )
    parser.add_argument(
        "--syslog",
        action="store_true",
        help="Log errors to syslog instead of a file.",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    monitor_gateways(args)


if __name__ == "__main__":
    main()

