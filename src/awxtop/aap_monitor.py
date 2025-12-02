#!/usr/bin/env python3
"""
AAP Environment Monitor (Controller Dashboard)
=============================================

Description
-----------
Curses-based terminal dashboard to monitor a Red Hat Ansible Automation Platform
(AAP) Controller environment (via Automation Gateway or directly, including AWX).

It:
- Connects to an AAP Controller using a Bearer token **or** a username/password
  (a token will be requested automatically).
- Polls the Controller every few seconds.
- Shows Controller topology (instances) and their health using a colored
  GOOD/WARN/BAD/UNKNOWN scheme, including:
    - Node type/state
    - Memory
    - Number of forks
    - Last health check time (when available)
    - Error reason if an instance reports errors (e.g. "Failed to connect to redis")
- Shows the last N jobs (configurable) including:
    - Job ID
    - Age since start (s/m/h/d)
    - Elapsed runtime
    - User who launched them
    - Status
    - Name
- Keeps recent jobs on screen even after they finish; their colour/status
  changes as they complete:
    - Running jobs: highlighted with reverse video.
    - Successful/completed jobs: dim grey.
    - Failed/error jobs: red.
- Jobs are displayed from newest to oldest by job ID, but grouped as:
    - all running/pending jobs first,
    - then a separator line,
    - then all other jobs.
- Interactive job list:
    - Use Up/Down/PgUp/PgDn to scroll through jobs.
    - Use Home / End to jump to the first / last page of jobs.
    - The selected job is marked with '>'.
    - Press 'v' to view the selected job (full-screen, with stdout).
    - Press 'i' to show/hide inline job details (same metadata as 'v', no stdout)
      in a panel below the jobs list.
    - If no selection has been made, 'v' or 'i' prompts for a job ID.
- Job detail view:
    - Shows job metadata and scrollable stdout.
    - q or ESC returns to main dashboard.
    - If the job is running, detail view auto-refreshes every 5 seconds.
- Uses only Python standard library modules (suitable for typical AAP installs).

Assumed API Endpoints (AAP 2.5)
-------------------------------
Base URL example (usually the Gateway):

    https://<gateway server name>/

Controller endpoints:

- Instances (topology):
    GET /api/controller/v2/instances/

- Recent jobs (all statuses):
    GET /api/controller/v2/jobs/?order_by=-started&page_size=N

- Job detail:
    GET /api/controller/v2/jobs/<id>/

- Job stdout:
    GET /api/controller/v2/jobs/<id>/stdout/?format=txt

Authentication
--------------
You can either supply a Bearer token directly or allow the tool to create one by
providing `--username` (and optionally `--password`).

- Direct token:

      Authorization: Bearer <YOUR_TOKEN>

- Username/password:
    A short-lived token is requested from
    `/api/controller/v2/tokens/` using HTTP Basic auth and then used for all
    subsequent requests.

If your environment uses a different auth header (e.g. "Token"), adjust
AUTH_SCHEME below.

Controls
--------
Main dashboard:
- Up/Down, PgUp/PgDn : move selection / scroll jobs list
- Home / End         : jump to first / last page of jobs
- v                  : view selected job (full-screen, with stdout);
                       if no selection, prompt for job ID
- i                  : show/hide inline job info (metadata only, no stdout);
                       if no selection, prompt for job ID
- q or ESC           : quit the program

Job view:
- Up/Down, PgUp/PgDn : scroll output
- q or ESC           : return to main dashboard
- Output for running jobs auto-refreshes every 5 seconds.

"""

import argparse
import base64
import curses
import getpass
import json
import ssl
import socket
import time
from urllib import request, error
from urllib.parse import urljoin, urlencode
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SCHEME = "Bearer"  # Change to "Token" if your AAP uses "Authorization: Token <token>"

DEFAULT_TIMEOUT = 5.0
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_PAGE_SIZE = 50

# API endpoint variants:
# - AAP 2.5+ via gateway uses /api/controller/v2/...
# - AAP 2.4 / AWX (no gateway) uses /api/v2/...
TOKEN_ENDPOINTS = [
    "/api/controller/v2/tokens/",
    "/api/v2/tokens/",
]
INSTANCE_ENDPOINTS = [
    "/api/controller/v2/instances/",
    "/api/v2/instances/",
]
JOBS_ENDPOINTS = [
    "/api/controller/v2/jobs/",
    "/api/v2/jobs/",
]
JOB_DETAIL_ENDPOINTS = [
    "/api/controller/v2/jobs/{id}/",
    "/api/v2/jobs/{id}/",
]
JOB_STDOUT_ENDPOINTS = [
    "/api/controller/v2/jobs/{id}/stdout/",
    "/api/v2/jobs/{id}/stdout/",
]

# Host running this monitor
MONITOR_HOST = socket.gethostname()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_status_text(status):
    """
    Map arbitrary *job* or *generic* status text to one of:
    good, warn, bad, unknown.
    """
    if status is None:
        return "unknown"

    s = str(status).lower()

    # Clearly good / healthy / running / done
    if s in (
        "good", "ok", "okay", "healthy", "green",
        "running", "successful", "completed", "finished"
    ):
        return "good"

    # Warnings / degraded
    if any(word in s for word in ("warn", "degrad", "yellow")):
        return "warn"

    # Failures / errors
    if any(word in s for word in ("bad", "down", "error", "fail", "failed", "critical", "red")):
        return "bad"

    return "unknown"


def classify_instance(instance):
    """
    Determine GOOD/WARN/BAD/UNKNOWN for a Controller instance.
    """
    if not isinstance(instance, dict):
        return "unknown"

    enabled = instance.get("enabled")
    errors = instance.get("errors")
    capacity = instance.get("capacity")
    node_state = instance.get("node_state")  # may exist on some versions

    # Explicitly disabled -> BAD
    if enabled is False:
        return "bad"

    # Non-empty errors -> WARN/BAD
    if errors:
        err_str = str(errors).lower()
        if any(word in err_str for word in ("unreachable", "failed", "error", "down", "offline")):
            return "bad"
        return "warn"

    # Capacity 0 but enabled -> WARN
    if capacity == 0:
        return "warn"

    # If node_state exists, use it as a hint
    if node_state:
        cls = classify_status_text(node_state)
        if cls != "unknown":
            return cls

    # Enabled or unknown but no errors -> GOOD
    if enabled in (True, None):
        return "good"

    return "unknown"


def parse_iso8601(dt_str):
    """
    Parse an ISO-8601-ish datetime string into a datetime.
    Returns None on failure.
    """
    if not dt_str:
        return None
    try:
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None


def format_elapsed(seconds):
    """
    Format elapsed seconds as H:MM:SS.
    """
    if seconds is None:
        return "--:--:--"
    try:
        seconds = int(seconds)
    except Exception:
        return "--:--:--"

    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:d}:{m:02d}:{s:02d}"


def format_age_from_start(started_dt):
    """
    Format how long ago 'started_dt' was, relative to now (UTC), as:
      - < 60s      -> 'Ns'
      - < 99 mins  -> 'Nm'
      - < 24h      -> 'Nh'
      - otherwise  -> 'Nd'
    """
    if not started_dt:
        return "--"
    delta = datetime.now(timezone.utc) - started_dt
    secs = int(delta.total_seconds())
    if secs < 0:
        secs = 0

    if secs < 60:
        return f"{secs}s"
    mins = secs // 60
    if mins < 99:
        return f"{mins}m"
    hours = secs // 3600
    if hours < 24:
        return f"{hours}h"
    days = secs // 86400
    return f"{days}d"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def build_ssl_context(insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def basic_auth_header(username, password):
    """
    Return an Authorization header value for HTTP Basic auth.
    """
    userpass = f"{username}:{password}"
    token_bytes = base64.b64encode(userpass.encode("utf-8"))
    return f"Basic {token_bytes.decode('ascii')}"


def request_token_with_password(base_url, username, password, timeout, insecure=False):
    """
    Request a short-lived token using HTTP Basic auth against the Controller.

    Returns (token, error_message).
    """
    base_url = base_url.rstrip("/") + "/"
    headers = {
        "Authorization": basic_auth_header(username, password),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = json.dumps({
        "description": f"awxtop session from {MONITOR_HOST}",
    }).encode("utf-8")

    ctx = build_ssl_context(insecure)
    last_err = None

    for endpoint in TOKEN_ENDPOINTS:
        url = urljoin(base_url, endpoint.lstrip("/"))
        req = request.Request(url, data=payload, headers=headers, method="POST")

        try:
            with request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                token = data.get("token") if isinstance(data, dict) else None
                if token:
                    return token, None
                last_err = "Token response missing 'token' field"
        except error.HTTPError as e:
            detail = ""
            try:
                detail_raw = e.read().decode("utf-8", errors="replace")
                if detail_raw:
                    detail_data = json.loads(detail_raw)
                    detail = f" ({detail_data})" if detail_data else ""
            except Exception:
                detail = ""
            last_err = f"HTTP {e.code} obtaining token via {endpoint}: {e.reason}{detail}"
        except error.URLError as e:
            last_err = f"URL error obtaining token via {endpoint}: {e.reason}"
        except Exception as e:
            last_err = f"Exception obtaining token via {endpoint}: {e}"

    return None, last_err


def api_get(base_url, path, token, timeout, insecure=False, query=None):
    """
    Make a GET request to base_url + path, with optional query dict.
    Returns parsed JSON on success.
    """
    base_url = base_url.rstrip("/") + "/"
    url = urljoin(base_url, path.lstrip("/"))
    if query:
        qs = urlencode(query)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{qs}"

    headers = {
        "Authorization": f"{AUTH_SCHEME} {token}",
        "Accept": "application/json",
    }

    ctx = build_ssl_context(insecure)
    req = request.Request(url, headers=headers)

    with request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)


def api_get_text(base_url, path, token, timeout, insecure=False, query=None):
    """
    GET a text endpoint (e.g. job stdout) and return the decoded text.
    """
    base_url = base_url.rstrip("/") + "/"
    url = urljoin(base_url, path.lstrip("/"))
    if query:
        qs = urlencode(query)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{qs}"

    headers = {
        "Authorization": f"{AUTH_SCHEME} {token}",
        "Accept": "text/plain,*/*",
    }

    ctx = build_ssl_context(insecure)
    req = request.Request(url, headers=headers)

    with request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_instances(base_url, token, timeout, insecure=False):
    """
    Fetch Controller instances (cluster topology).
    """
    last_err = None
    for endpoint in INSTANCE_ENDPOINTS:
        try:
            data = api_get(base_url, endpoint, token, timeout, insecure)
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                return data["results"], None
            if isinstance(data, list):
                return data, None
            last_err = f"Unexpected {endpoint} format"
        except error.HTTPError as e:
            last_err = f"HTTP {e.code} on {endpoint}: {e.reason}"
        except error.URLError as e:
            last_err = f"URL error on {endpoint}: {e.reason}"
        except Exception as e:
            last_err = f"Exception on {endpoint}: {e}"
    return [], last_err


def fetch_recent_jobs(base_url, token, timeout, insecure=False, page_size=DEFAULT_PAGE_SIZE):
    """
    Fetch recent jobs (all statuses) from Controller.
    """
    query = {
        "order_by": "-started",
        "page_size": page_size,
    }
    last_err = None
    for endpoint in JOBS_ENDPOINTS:
        try:
            data = api_get(base_url, endpoint, token, timeout, insecure, query=query)
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                last_err = f"Unexpected {endpoint} format"
                continue
            return results, None
        except error.HTTPError as e:
            last_err = f"HTTP {e.code} on {endpoint}: {e.reason}"
        except error.URLError as e:
            last_err = f"URL error on {endpoint}: {e.reason}"
        except Exception as e:
            last_err = f"Exception on {endpoint}: {e}"
    return [], last_err


def fetch_job_detail(base_url, token, timeout, insecure, job_id):
    """
    Fetch a single job's details.
    """
    last_err = None
    for pattern in JOB_DETAIL_ENDPOINTS:
        endpoint = pattern.format(id=job_id)
        try:
            job = api_get(
                base_url,
                endpoint,
                token,
                timeout,
                insecure,
            )
            if not isinstance(job, dict):
                last_err = f"Unexpected job detail format from {endpoint}"
                continue
            return job, None
        except error.HTTPError as e:
            last_err = f"HTTP {e.code} on job {job_id} via {endpoint}: {e.reason}"
        except error.URLError as e:
            last_err = f"URL error on job {job_id} via {endpoint}: {e.reason}"
        except Exception as e:
            last_err = f"Exception on job {job_id} via {endpoint}: {e}"
    return None, last_err


def fetch_job_stdout(base_url, token, timeout, insecure, job_id):
    """
    Fetch job stdout as text.
    """
    last_err = None
    for pattern in JOB_STDOUT_ENDPOINTS:
        endpoint = pattern.format(id=job_id)
        try:
            text = api_get_text(
                base_url,
                endpoint,
                token,
                timeout,
                insecure,
                query={"format": "txt"},
            )
            return text, None
        except error.HTTPError as e:
            last_err = f"HTTP {e.code} on job {job_id} stdout via {endpoint}: {e.reason}"
        except error.URLError as e:
            last_err = f"URL error on job {job_id} stdout via {endpoint}: {e.reason}"
        except Exception as e:
            last_err = f"Exception on job {job_id} stdout via {endpoint}: {e}"
    return "", last_err


# ---------------------------------------------------------------------------
# Job ID prompt & job view
# ---------------------------------------------------------------------------

def prompt_for_job_id(stdscr):
    """
    Prompt the user for a job ID at the bottom of the screen.
    Returns an int job_id, or None if cancelled.
    """
    h, w = stdscr.getmaxyx()
    prompt = "Job ID to view (Enter to confirm, ESC to cancel): "
    job_str = ""

    stdscr.nodelay(False)  # blocking while typing
    stdscr.timeout(-1)

    while True:
        stdscr.move(h - 1, 0)
        stdscr.clrtoeol()
        line = prompt + job_str
        stdscr.addstr(h - 1, 0, line[: w - 1])
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (10, 13):  # Enter
            break
        if ch == 27:  # ESC
            job_str = ""
            break
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            job_str = job_str[:-1]
        elif 48 <= ch <= 57:  # digits 0-9
            job_str += chr(ch)

    stdscr.timeout(200)
    stdscr.nodelay(False)
    if not job_str:
        return None
    try:
        return int(job_str)
    except ValueError:
        return None


def job_view(stdscr, base_url, token, timeout, insecure, job_id):
    """
    Show a single job's details and stdout in a scrollable view.
    q or ESC returns to caller.
    Running jobs auto-refresh every 5 seconds.
    """
    stdscr.timeout(200)  # 200 ms
    stdscr.nodelay(False)

    scroll = 0
    last_fetch = 0
    job = None
    job_err = None
    stdout_text = ""
    stdout_err = None

    try:
        while True:
            now = time.time()
            running = False
            if job and isinstance(job, dict):
                status = str(job.get("status", "")).lower()
                running = (status == "running")

            refresh_interval = 5.0 if running else 60.0

            if now - last_fetch >= refresh_interval or job is None:
                job, job_err = fetch_job_detail(
                    base_url, token, timeout, insecure, job_id
                )
                stdout_text, stdout_err = fetch_job_stdout(
                    base_url, token, timeout, insecure, job_id
                )
                last_fetch = now
                scroll = min(scroll, max(0, len(stdout_text.splitlines()) - 1))

            h, w = stdscr.getmaxyx()
            stdscr.erase()

            # Header
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            title = f"AAP Job View (ID {job_id})"
            header = f"{title}  {now_str}  host:{MONITOR_HOST}"
            stdscr.addstr(0, 0, header[: w - 1], curses.color_pair(5))

            row = 2

            # Job metadata
            if job is None:
                msg = f"Unable to load job {job_id}: {job_err or 'unknown error'}"
                stdscr.addstr(row, 0, msg[: w - 1], curses.color_pair(3))
                row += 2
            else:
                row = render_job_metadata_block(
                    stdscr, row, w, job, curses.color_pair(5)
                )
                row += 1
                stdscr.addstr(
                    row,
                    0,
                    "Output (Up/Down/PgUp/PgDn to scroll, q/ESC to return):"[: w - 1],
                    curses.color_pair(5),
                )
                row += 1

            # Output area
            top_row = row
            max_lines = max(1, h - top_row - 1)

            if stdout_text:
                lines = stdout_text.splitlines()
            else:
                lines = ["<no output>"]

            max_scroll = max(0, len(lines) - max_lines)
            scroll = max(0, min(scroll, max_scroll))

            visible = lines[scroll: scroll + max_lines]
            for idx, line in enumerate(visible):
                if top_row + idx >= h:
                    break
                stdscr.addstr(
                    top_row + idx, 0,
                    line[: w - 1],
                    curses.color_pair(5),
                )

            # If there was an error fetching stdout, show it at the bottom
            if stdout_err and top_row + len(visible) < h:
                err_line = f"stdout error: {stdout_err}"
                stdscr.addstr(
                    h - 1, 0,
                    err_line[: w - 1],
                    curses.color_pair(4),
                )

            stdscr.refresh()

            # Handle keys
            ch = stdscr.getch()
            if ch == curses.KEY_RESIZE:
                continue
            if ch in (ord("q"), ord("Q"), 27):  # q or ESC
                break
            elif ch == curses.KEY_UP:
                scroll = max(0, scroll - 1)
            elif ch == curses.KEY_DOWN:
                scroll = min(max_scroll, scroll + 1)
            elif ch == curses.KEY_PPAGE:  # PgUp
                scroll = max(0, scroll - max_lines)
            elif ch == curses.KEY_NPAGE:  # PgDn
                scroll = min(max_scroll, scroll + max_lines)

    finally:
        stdscr.timeout(200)
        stdscr.nodelay(False)


# ---------------------------------------------------------------------------
# Shared job metadata renderer
# ---------------------------------------------------------------------------

def render_job_metadata_block(stdscr, row, w, job, base_style):
    """
    Render the job metadata (same as in job_view) starting at 'row'.
    Returns the next row index after the block.
    """
    status = job.get("status") or "?"
    status_lower = str(status).lower()
    name = str(job.get("name") or "")
    job_type = job.get("job_type") or ""
    template_name = ""
    sf = job.get("summary_fields") or {}
    jt = sf.get("job_template") or {}
    if isinstance(jt, dict):
        template_name = jt.get("name") or ""
    created_by = sf.get("created_by") or {}
    user = created_by.get("username") or created_by.get("first_name") or "?"
    started_raw = job.get("started")
    finished_raw = job.get("finished")
    started_dt = parse_iso8601(started_raw)
    finished_dt = parse_iso8601(finished_raw)
    elapsed = job.get("elapsed")

    try:
        elapsed_val = float(elapsed) if elapsed is not None else 0.0
    except Exception:
        elapsed_val = 0.0

    if elapsed is None or elapsed_val <= 0.0:
        if started_dt:
            elapsed = (datetime.now(timezone.utc) - started_dt).total_seconds()
        else:
            elapsed = None

    elapsed_str = format_elapsed(elapsed)
    age_str = format_age_from_start(started_dt) if started_dt else "--"

    cls = classify_status_text(status)
    if status_lower == "running":
        status_style = curses.color_pair(1) | curses.A_REVERSE
    elif status_lower in ("successful", "completed", "finished"):
        status_style = curses.color_pair(5) | curses.A_DIM
    elif cls == "bad":
        status_style = curses.color_pair(3)
    else:
        status_style = base_style

    stdscr.addstr(row, 0, f"Name:     {name}"[: w - 1], base_style)
    row += 1
    stdscr.addstr(row, 0, f"Template: {template_name}"[: w - 1], base_style)
    row += 1
    stdscr.addstr(row, 0, f"User:     {user}"[: w - 1], base_style)
    row += 1
    stdscr.addstr(row, 0, "Status:   ", base_style)
    stdscr.addstr(row, len("Status:   "), f"{status}", status_style)
    row += 1
    stdscr.addstr(
        row,
        0,
        f"Type:     {job_type}"[: w - 1],
        base_style,
    )
    row += 1
    started_line = f"Started:  {started_raw or '-'}"
    if started_dt:
        started_line += f"  ({age_str} ago)"
    stdscr.addstr(
        row,
        0,
        started_line[: w - 1],
        base_style,
    )
    row += 1
    stdscr.addstr(
        row,
        0,
        f"Finished: {finished_raw or '-'}"[: w - 1],
        base_style,
    )
    row += 1
    stdscr.addstr(
        row,
        0,
        f"Elapsed:  {elapsed_str}"[: w - 1],
        base_style,
    )
    row += 1
    return row


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------

def run_dashboard(
    stdscr,
    base_url,
    token,
    timeout,
    poll_interval,
    insecure=False,
    page_size=DEFAULT_PAGE_SIZE,
):
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)
    stdscr.timeout(200)  # 200 ms for getch
    curses.start_color()

    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)   # good
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # warn
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # bad
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)    # unknown/info
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)   # text / grey-ish

    color_for_class = {
        "good": curses.color_pair(1),
        "warn": curses.color_pair(2),
        "bad": curses.color_pair(3),
        "unknown": curses.color_pair(4),
    }

    instances = []
    inst_error = None
    jobs = []
    jobs_error = None

    executor = ThreadPoolExecutor(max_workers=2)

    # Job list navigation state (indexes into "display rows", not just jobs)
    job_scroll = 0               # index of first visible row in display_jobs
    job_selected = 0             # index of selected row (must be a job row)
    job_selection_active = False

    # Inline job info panel state
    info_job_id = None
    info_job_detail = None
    info_job_error = None

    last_fetch = 0.0

    try:
        while True:
            now = time.time()

            # ------------------------------------------------------------------
            # Fetch data if it's time
            # ------------------------------------------------------------------
            if now - last_fetch >= poll_interval:
                futures = {
                    executor.submit(fetch_instances, base_url, token, timeout, insecure): "instances",
                    executor.submit(fetch_recent_jobs, base_url, token, timeout, insecure, page_size): "jobs",
                }

                for fut in as_completed(futures):
                    what = futures[fut]
                    try:
                        result, err = fut.result()
                    except Exception as e:
                        result, err = [], f"Exception while fetching {what}: {e}"

                    if what == "instances":
                        instances, inst_error = result, err
                    else:
                        jobs, jobs_error = result, err

                last_fetch = time.time()

            # ------------------------------------------------------------------
            # Draw the screen
            # ------------------------------------------------------------------
            h, w = stdscr.getmaxyx()
            stdscr.erase()

            # Header
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            title = "AAP Environment Monitor (Controller)"
            header = f"{title}  {now_str}  host:{MONITOR_HOST}"
            stdscr.addstr(0, 0, header[:w - 1], curses.color_pair(5))

            # Summary line
            good_i = warn_i = bad_i = unknown_i = 0
            for inst in instances:
                cls = classify_instance(inst)
                if cls == "good":
                    good_i += 1
                elif cls == "warn":
                    warn_i += 1
                elif cls == "bad":
                    bad_i += 1
                else:
                    unknown_i += 1

            running_jobs_count = sum(
                1 for j in jobs
                if str(j.get("status", "")).lower() == "running"
            )
            failed_jobs = sum(
                1 for j in jobs
                if classify_status_text(j.get("status")) == "bad"
            )

            summary = (
                f"Instances: G={good_i} W={warn_i} B={bad_i} U={unknown_i}  "
                f"Recent jobs: {len(jobs)}  running={running_jobs_count}  failed={failed_jobs}  "
                f"(Up/Down/Home/End, 'v'=view, 'i'=info)"
            )
            stdscr.addstr(1, 0, summary[:w - 1], curses.color_pair(5))

            row = 3

            # ------------------------------------------------------------------
            # Topology section (instances)
            # ------------------------------------------------------------------
            if row < h:
                stdscr.addstr(row, 0, "Topology (instances):", curses.color_pair(5))
                row += 1

            inst_names = [
                str(i.get("hostname") or i.get("node") or i.get("id") or "?")
                for i in instances
            ]
            max_name_len = max((len(n) for n in inst_names), default=4)
            name_width = max(max_name_len, 8)

            for inst, name in zip(instances, inst_names):
                if row >= h:
                    break

                cls = classify_instance(inst)
                status_str = cls.upper()
                node_type = inst.get("node_type") or inst.get("type") or ""
                node_state = inst.get("node_state") or ""

                # details: memory / forks / last health
                memory = inst.get("memory") or inst.get("mem")
                forks = inst.get("forks")
                if forks is None:
                    forks = inst.get("capacity")
                last_health = (
                    inst.get("last_health_check")
                    or inst.get("heartbeat")
                    or inst.get("last_isolated_check")
                )

                details_parts = []
                if node_type:
                    details_parts.append(node_type)
                if node_state:
                    details_parts.append(node_state)

                memfork_parts = []
                if memory is not None:
                    memfork_parts.append(f"mem={memory}")
                if forks is not None:
                    memfork_parts.append(
                        forks if isinstance(forks, str) else f"forks={forks}"
                    )
                if memfork_parts:
                    details_parts.append(" ".join(memfork_parts))
                if last_health:
                    last_str = str(last_health)
                    if len(last_str) > 32:
                        last_str = last_str[:29] + "..."
                    details_parts.append(f"last={last_str}")

                errors_field = inst.get("errors")
                err_str = None
                if errors_field:
                    err_str = " ".join(str(errors_field).split())
                    max_err_width = max(10, w - 8)
                    if len(err_str) > max_err_width:
                        err_str = err_str[: max_err_width - 3] + "..."

                base = f"  {name:{name_width}} [{status_str:7}]"
                details_str = ""
                if details_parts:
                    details_str = "  (" + ", ".join(details_parts) + ")"
                err_piece = f"  error: {err_str}" if err_str else ""

                combined = base + details_str + err_piece

                color = color_for_class.get(cls, curses.color_pair(5))

                if len(combined) <= w - 1:
                    stdscr.addstr(row, 0, combined[: w - 1], color)
                    row += 1
                else:
                    stdscr.addstr(row, 0, base[: w - 1], color)
                    row += 1
                    if row >= h:
                        break
                    if details_str:
                        stdscr.addstr(row, 0, ("    " + details_str.strip())[0: w - 1], color)
                        row += 1
                    if row >= h:
                        break
                    if err_piece:
                        stdscr.addstr(row, 0, ("    " + err_piece.strip())[0: w - 1], color)
                        row += 1

            if inst_error and row < h:
                stdscr.addstr(
                    row, 2,
                    f"instances error: {inst_error}"[:w - 3],
                    curses.color_pair(4),
                )
                row += 1

            # ------------------------------------------------------------------
            # Recent jobs section (newest first by ID, running+pending first)
            # ------------------------------------------------------------------
            def job_sort_key(j):
                try:
                    return int(j.get("id", 0))
                except Exception:
                    return 0

            jobs_sorted = sorted(jobs, key=job_sort_key, reverse=True)

            running_or_pending_jobs = []
            other_jobs = []

            pending_like_statuses = {
                "pending",
                "waiting",
                "new",
                "scheduled",
                "pending approval",
                "pending_approval",
            }

            for j in jobs_sorted:
                st = str(j.get("status") or "").lower()
                if st == "running" or st in pending_like_statuses:
                    running_or_pending_jobs.append(j)
                else:
                    other_jobs.append(j)

            # Build display rows: ("job", job) or ("sep", None)
            display_jobs = []
            for j in running_or_pending_jobs:
                display_jobs.append(("job", j))
            if running_or_pending_jobs and other_jobs:
                display_jobs.append(("sep", None))
            for j in other_jobs:
                display_jobs.append(("job", j))

            len_display = len(display_jobs)
            job_indices = [i for i, (kind, _) in enumerate(display_jobs) if kind == "job"]
            job_count = len(job_indices)

            if row < h:
                stdscr.addstr(
                    row, 0,
                    "Recent jobs (running/pending first, newest by ID):",
                    curses.color_pair(5),
                )
                row += 1

            if row < h:
                header_line = " S   ID    Elapsed  Start  User           Status   Name"
                stdscr.addstr(row, 0, header_line[:w - 1], curses.color_pair(5))
                row += 1

            jobs_row_start = row

            # Reserve space for inline job info panel if present
            if (info_job_detail is not None or info_job_error is not None) and h > 12:
                reserved_info_lines = 10
            else:
                reserved_info_lines = 0

            max_visible_rows = max(0, h - jobs_row_start - 1 - reserved_info_lines)

            # Clamp selection/scroll
            if job_count == 0:
                job_scroll = 0
                job_selected = 0
                job_selection_active = False
                info_job_id = None
                info_job_detail = None
                info_job_error = None
            else:
                if not (0 <= job_selected < len_display) or display_jobs[job_selected][0] != "job":
                    job_selected = job_indices[0]

                if max_visible_rows > 0:
                    max_scroll = max(0, len_display - max_visible_rows)
                    if job_scroll > max_scroll:
                        job_scroll = max_scroll
                    if job_selected < job_scroll:
                        job_scroll = job_selected
                    if job_selected >= job_scroll + max_visible_rows:
                        job_scroll = max(0, job_selected - max_visible_rows + 1)
                else:
                    job_scroll = 0

            visible_rows = []
            if max_visible_rows > 0 and len_display > 0:
                visible_rows = display_jobs[job_scroll: job_scroll + max_visible_rows]

            row = jobs_row_start
            for idx, (kind, payload) in enumerate(visible_rows):
                if row >= h - reserved_info_lines:
                    break

                global_index = job_scroll + idx

                if kind == "sep":
                    sep_text = "---- other jobs ----"
                    stdscr.addstr(
                        row, 0,
                        sep_text[:w - 1],
                        curses.color_pair(5) | curses.A_DIM,
                    )
                    row += 1
                    continue

                job = payload
                jid = job.get("id")
                status = job.get("status") or "?"
                status_str = str(status)
                status_lower = status_str.lower()
                elapsed = job.get("elapsed")

                started_dt = parse_iso8601(job.get("started"))
                age_str = format_age_from_start(started_dt) if started_dt else "--"

                try:
                    elapsed_val = float(elapsed) if elapsed is not None else 0.0
                except Exception:
                    elapsed_val = 0.0

                if elapsed is None or elapsed_val <= 0.0:
                    if started_dt:
                        elapsed = (datetime.now(timezone.utc) - started_dt).total_seconds()
                    else:
                        elapsed = None

                elapsed_str = format_elapsed(elapsed)

                sf = job.get("summary_fields") or {}
                created_by = sf.get("created_by") or {}
                user = created_by.get("username") or created_by.get("first_name") or "?"

                name = str(job.get("name") or job.get("job_template", ""))

                cls = classify_status_text(status_str)
                base_style = color_for_class.get(cls, curses.color_pair(5))

                if status_lower == "running":
                    style = curses.color_pair(1) | curses.A_REVERSE
                elif status_lower in ("successful", "completed", "finished"):
                    style = curses.color_pair(5) | curses.A_DIM
                elif cls == "bad":
                    style = color_for_class["bad"]
                else:
                    style = base_style

                is_selected = job_selection_active and (global_index == job_selected)
                if is_selected:
                    style |= curses.A_REVERSE

                sel_char = ">" if is_selected else " "

                line = (
                    f" {sel_char}  {jid:4}  {elapsed_str:9}  {age_str:5}  "
                    f"{user:12.12}  {status_str:7}  {name}"
                )
                stdscr.addstr(
                    row, 0,
                    line[:w - 1],
                    style,
                )
                row += 1

            if jobs_error and row < h - reserved_info_lines:
                stdscr.addstr(
                    row, 2,
                    f"jobs error: {jobs_error}"[:w - 3],
                    curses.color_pair(4),
                )
                row += 1

            # ------------------------------------------------------------------
            # Inline job info panel (from 'i')
            # ------------------------------------------------------------------
            if reserved_info_lines and h > 10:
                info_start_row = h - reserved_info_lines
                if info_start_row > row:
                    # Title
                    title_line = f"Job info (ID {info_job_id})"
                    stdscr.addstr(
                        info_start_row,
                        0,
                        title_line[:w - 1],
                        curses.color_pair(5),
                    )
                    r = info_start_row + 1
                    if info_job_detail is None:
                        msg = f"Unable to load job {info_job_id}: {info_job_error or 'unknown error'}"
                        stdscr.addstr(r, 0, msg[: w - 1], curses.color_pair(3))
                    else:
                        r = render_job_metadata_block(
                            stdscr, r, w, info_job_detail, curses.color_pair(5)
                        )

            stdscr.refresh()

            # ------------------------------------------------------------------
            # Key handling (single getch per loop)
            # ------------------------------------------------------------------
            ch = stdscr.getch()
            if ch == -1:
                continue

            if ch == curses.KEY_RESIZE:
                continue

            # Quit
            if ch in (ord("q"), ord("Q"), 27):
                break

            # Helper to find first/last job row index
            def first_job_index():
                return job_indices[0] if job_indices else 0

            def last_job_index():
                return job_indices[-1] if job_indices else 0

            # Navigation only if there are job rows
            if job_count > 0:
                if ch == curses.KEY_UP:
                    job_selection_active = True
                    i = job_selected - 1
                    while i >= 0:
                        if display_jobs[i][0] == "job":
                            job_selected = i
                            break
                        i -= 1
                elif ch == curses.KEY_DOWN:
                    job_selection_active = True
                    i = job_selected + 1
                    while i < len_display:
                        if display_jobs[i][0] == "job":
                            job_selected = i
                            break
                        i += 1
                elif ch == curses.KEY_PPAGE:  # PgUp
                    job_selection_active = True
                    if max_visible_rows > 0:
                        job_scroll = max(0, job_scroll - max_visible_rows)
                        for i in range(job_scroll, len_display):
                            if display_jobs[i][0] == "job":
                                job_selected = i
                                break
                    else:
                        job_selected = first_job_index()
                        job_scroll = 0
                elif ch == curses.KEY_NPAGE:  # PgDn
                    job_selection_active = True
                    if max_visible_rows > 0:
                        max_scroll = max(0, len_display - max_visible_rows)
                        job_scroll = min(max_scroll, job_scroll + max_visible_rows)
                        selected = None
                        for i in range(job_scroll, min(len_display, job_scroll + max_visible_rows)):
                            if display_jobs[i][0] == "job":
                                selected = i
                                break
                        if selected is None:
                            job_selected = last_job_index()
                        else:
                            job_selected = selected
                    else:
                        job_selected = last_job_index()
                elif ch == curses.KEY_HOME:
                    job_selection_active = True
                    job_scroll = 0
                    job_selected = first_job_index()
                elif ch == curses.KEY_END:
                    job_selection_active = True
                    last_idx = last_job_index()
                    if max_visible_rows > 0:
                        job_scroll = max(0, last_idx - max_visible_rows + 1)
                    job_selected = last_idx

            # 'v' to view job (full-screen)
            if ch in (ord("v"), ord("V")):
                job_id = None
                if job_selection_active and job_count > 0 and \
                        0 <= job_selected < len_display and \
                        display_jobs[job_selected][0] == "job":
                    job_obj = display_jobs[job_selected][1]
                    job_id = job_obj.get("id")
                else:
                    job_id = prompt_for_job_id(stdscr)

                if job_id is not None:
                    job_view(stdscr, base_url, token, timeout, insecure, job_id)
                    # after returning, loop continues and redraws

            # 'i' to show inline info panel (metadata only)
            if ch in (ord("i"), ord("I")):
                job_id = None
                if job_selection_active and job_count > 0 and \
                        0 <= job_selected < len_display and \
                        display_jobs[job_selected][0] == "job":
                    job_obj = display_jobs[job_selected][1]
                    job_id = job_obj.get("id")
                else:
                    job_id = prompt_for_job_id(stdscr)

                if job_id is not None:
                    if info_job_id == job_id and info_job_detail is not None:
                        # toggle off
                        info_job_id = None
                        info_job_detail = None
                        info_job_error = None
                    else:
                        detail, err = fetch_job_detail(
                            base_url, token, timeout, insecure, job_id
                        )
                        info_job_id = job_id
                        info_job_detail = detail
                        info_job_error = err

    except KeyboardInterrupt:
        return
    finally:
        executor.shutdown(wait=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="AAP Controller environment monitor (topology + recent jobs)."
    )
    p.add_argument(
        "base_url",
        help="Base URL of the AAP Gateway/Controller (e.g. https://gateway.example.com)",
    )
    p.add_argument(
        "--token",
        "-t",
        help="Bearer token to use for Authorization header.",
    )
    p.add_argument(
        "--username",
        "-u",
        help="Controller username (a token will be requested).",
    )
    p.add_argument(
        "--password",
        "-p",
        help="Controller password. If omitted, you will be prompted securely when using --username.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    p.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Polling interval in seconds (default: {DEFAULT_POLL_INTERVAL}).",
    )
    p.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"How many recent jobs to fetch (default: {DEFAULT_PAGE_SIZE}).",
    )
    p.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Skip TLS certificate verification.",
    )
    return p.parse_args()


def resolve_token(args):
    """
    Work out which credential path to use and return a Bearer token string.
    Prefers an explicit token; falls back to username/password.
    """
    if args.token:
        return args.token

    if args.username:
        password = args.password
        if password is None:
            try:
                password = getpass.getpass("Controller password: ")
            except (EOFError, KeyboardInterrupt):
                raise SystemExit("Password prompt cancelled.")

        if not password:
            raise SystemExit("A password is required when using --username.")

        token, err = request_token_with_password(
            args.base_url,
            args.username,
            password,
            args.timeout,
            args.insecure,
        )
        if err:
            raise SystemExit(f"Unable to obtain token: {err}")
        return token

    raise SystemExit("Provide either --token or --username/--password.")


def main():
    args = parse_args()
    token = resolve_token(args)
    try:
        curses.wrapper(
            run_dashboard,
            args.base_url,
            token,
            args.timeout,
            args.poll_interval,
            args.insecure,
            args.page_size,
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
