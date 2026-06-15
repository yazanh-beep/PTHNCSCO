#!/usr/bin/env python3
"""
show_tech_collector.py
----------------------
Purpose:
    SSH into an aggregate switch, then hop from there into each access switch
    listed in devices.txt. On each access switch, pulls "show tech-support"
    and saves the bundle locally as:
        backups/YYYY-MM-DD_<ip>_<hostname>_show-tech.txt

    After each access switch the script exits back to the aggregate shell
    before moving on to the next device in the list.

Topology:
    Workstation ──SSH──► Aggregate switch ──SSH hop──► Access switch (per device)
                              ▲                               │
                              └───────── exit ────────────────┘

Credential cycling:
    Multiple username/password pairs may be supplied in CREDENTIALS. The
    script tries each pair in order:
      - connect_aggregate() : cycles through all credentials per attempt.
      - hop_to_access()     : cycles through all credentials per hop attempt.
    The first pair that authenticates successfully is used; the working
    enable password is taken from that pair (or its dedicated enable field).

Retry / reconnect behaviour:
    - connect_aggregate()  : retries up to AGG_CONNECT_RETRIES times with
                             AGG_RETRY_DELAY seconds between attempts.
    - is_agg_alive()       : probes the aggregate shell before every device.
                             If the socket is dead, reconnects automatically.
    - process_device()     : if the SSH hop to an access switch fails, retries
                             up to HOP_RETRIES times (with HOP_RETRY_DELAY
                             between attempts). On each retry the aggregate
                             session health is checked and reconnected if needed.

devices.txt format (one entry per line, lines starting with # are ignored):
    192.168.1.10
    192.168.1.11
    10.0.0.50

Requirements:
    Python 3.8+
    pip install paramiko
"""

import paramiko
import socket
import time
import re
import sys
from pathlib import Path

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
# Credential pairs are tried in order until one authenticates.
# Each entry: {"username": ..., "password": ..., "enable": ...}
#   - "enable" is optional; if omitted, the pair's password is used as enable.
CREDENTIALS = [
    {"username": "admin",    "password": "cisco",      "enable": None},
    {"username": "admin", "password": "AG37jjYpnyB4@", "enable": None},
]

AGGREGATE_IP        = "192.168.1.11"   # ← IP of the aggregate (jump) switch
DEVICES_FILE        = Path("devices.txt")
BACKUP_DIR          = Path("backups")
TIMEOUT             = 15            # general prompt wait (seconds)
SHOW_TECH_TIMEOUT   = 300           # show tech-support wait (seconds, 10 min)
MAX_READ            = 65535
DATE_STR            = time.strftime("%Y-%m-%d")

# ─── RETRY / DELAY CONFIG ────────────────────────────────────────────────────
AGG_CONNECT_RETRIES  = 5            # attempts to (re)connect to aggregate
AGG_RETRY_DELAY      = 10           # seconds between aggregate connect attempts
HOP_RETRIES          = 3            # attempts to SSH-hop to an access switch
HOP_RETRY_DELAY      = 8            # seconds between hop attempts
POST_TECH_DRAIN_TIME = 30           # seconds to keep draining buffer after show
                                    #   tech prompt arrives (device keeps sending)
POST_DEVICE_DELAY    = 0          # seconds to wait between devices (5 min)
                                    #   set to 0 to disable
# ─────────────────────────────────────────────────────────────────────────────

# Holds the credential pair confirmed working on the aggregate. Used as the
# starting point (tried first) when hopping to access switches.
ACTIVE_CRED = None


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def enable_pw(cred: dict) -> str:
    """Return the enable password for a credential pair (falls back to password)."""
    return cred["enable"] if cred.get("enable") else cred["password"]


def ordered_creds() -> list[dict]:
    """
    Credential list with the known-good ACTIVE_CRED first (if any),
    so successful auth on the aggregate is reused for hops before others.
    """
    if ACTIVE_CRED is None:
        return list(CREDENTIALS)
    rest = [c for c in CREDENTIALS if c is not ACTIVE_CRED]
    return [ACTIVE_CRED] + rest


def load_devices(path: Path) -> list[str]:
    """Read devices.txt; skip blank lines and comments (#)."""
    if not path.exists():
        print(f"[ERROR] {path} not found. Create it with one IP per line.")
        sys.exit(1)
    devices = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        devices.append(line)
    return devices


def expect_prompt(shell, patterns: tuple, timeout: int = TIMEOUT) -> str:
    """Read from shell until one of the pattern strings appears, or timeout."""
    buf = ""
    end = time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            for p in patterns:
                if p in buf:
                    return buf
        else:
            time.sleep(0.2)
    return buf


def send_cmd(shell, cmd: str, patterns: tuple = ("#",),
             timeout: int = TIMEOUT, sensitive: bool = False) -> str:
    """Send a command and wait for a prompt pattern."""
    if not sensitive:
        print(f"    [CMD] {cmd}")
    shell.send(cmd + "\n")
    out = expect_prompt(shell, patterns, timeout)
    if not sensitive:
        last = out.splitlines()[-1].strip() if out else "<no output>"
        print(f"    [PROMPT] {last}")
    return out


def elevate_and_init(shell, cred: dict):
    """Enable + disable paging on whatever device the shell is currently on."""
    out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=10)
    if "assword:" in out:
        send_cmd(shell, enable_pw(cred), patterns=("#",), timeout=10, sensitive=True)
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)


def flush_buffer(shell, pause: float = 30.0):
    """
    Drain any stale data sitting in the receive buffer.
    Called after exit_to_aggregate() to discard leftover show-tech output.

    Uses a continuous-drain loop: keeps reading as long as data keeps
    arriving, only stopping once the buffer has been empty for a full
    `pause` seconds. This handles devices that trickle output slowly
    after the prompt has appeared.
    """
    deadline = time.time() + pause
    while time.time() < deadline:
        if shell.recv_ready():
            shell.recv(MAX_READ)
            # Reset the deadline each time new data arrives
            deadline = time.time() + pause
        else:
            time.sleep(0.2)


def get_hostname(shell) -> str:
    """
    Extract hostname from the current CLI prompt (e.g. SW-ACCESS-01#).
    Requires a proper Cisco-style hostname: letters/digits/dash/dot/underscore,
    at least 2 chars, immediately followed by # or > with nothing after.
    """
    shell.send("\n")
    buf = expect_prompt(shell, ("#", ">"), timeout=8)
    for line in reversed(buf.splitlines()):
        stripped = line.strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]{1,63})[#>]\s*$", stripped)
        if m:
            return m.group(1)
    return "unknown"


def sanitize(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")


# ─── AGGREGATE CONNECTION & HEALTH ───────────────────────────────────────────

def _open_aggregate(ip: str, cred: dict):
    """
    Raw connect to aggregate with a single credential pair:
    TCP + SSH + enable + paging.
    Returns (SSHClient, shell). Raises on any failure.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ip,
        username=cred["username"],
        password=cred["password"],
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )
    shell = client.invoke_shell()
    expect_prompt(shell, ("#", ">"), timeout=15)
    elevate_and_init(shell, cred)
    return client, shell


def connect_aggregate(ip: str):
    """
    Connect to the aggregate switch with retry logic and credential cycling.
    Each attempt tries every credential pair in order; the first that
    authenticates wins and is recorded as ACTIVE_CRED. Tries up to
    AGG_CONNECT_RETRIES times, waiting AGG_RETRY_DELAY seconds between attempts.
    Exits the script if all attempts fail.
    """
    global ACTIVE_CRED
    for attempt in range(1, AGG_CONNECT_RETRIES + 1):
        print(f"[AGGREGATE] Connecting to {ip} (attempt {attempt}/{AGG_CONNECT_RETRIES}) …")
        last_exc = None
        for cred in ordered_creds():
            try:
                print(f"[AGGREGATE]   trying user '{cred['username']}' …")
                client, shell = _open_aggregate(ip, cred)
                ACTIVE_CRED = cred
                agg_host = get_hostname(shell)
                print(f"[AGGREGATE] Connected as '{cred['username']}' — prompt: {agg_host}#\n")
                return client, shell
            except Exception as exc:
                last_exc = exc
                print(f"[AGGREGATE]   user '{cred['username']}' failed: {exc}")

        print(f"[AGGREGATE] All credentials failed this attempt. Last error: {last_exc}")
        if attempt < AGG_CONNECT_RETRIES:
            print(f"[AGGREGATE] Retrying in {AGG_RETRY_DELAY}s …")
            time.sleep(AGG_RETRY_DELAY)
        else:
            print(f"[AGGREGATE] All {AGG_CONNECT_RETRIES} attempts failed. Aborting.")
            sys.exit(1)


def is_agg_alive(client, shell) -> bool:
    """
    Check whether the aggregate SSH session is still usable by sending a
    no-op newline and checking for a prompt within a short timeout.
    Also checks the underlying transport layer.
    """
    try:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            return False
        shell.send("\n")
        buf = expect_prompt(shell, ("#", ">"), timeout=5)
        return "#" in buf or ">" in buf
    except (socket.error, EOFError, paramiko.SSHException):
        return False


def ensure_aggregate(client, shell):
    """
    Verify the aggregate session is alive; reconnect if it is not.
    Returns the (possibly new) (client, shell) tuple.
    """
    if is_agg_alive(client, shell):
        return client, shell

    print(f"[AGGREGATE] ⚠  Socket closed or unresponsive — reconnecting …")
    try:
        client.close()
    except Exception:
        pass

    new_client, new_shell = connect_aggregate(AGGREGATE_IP)
    return new_client, new_shell


# ─── HOP LOGIC ───────────────────────────────────────────────────────────────

def _attempt_hop(agg_shell, access_ip: str, cred: dict):
    """
    Single attempt to SSH-hop from aggregate to access_ip using one
    credential pair. Raises RuntimeError on any detectable failure so the
    caller can retry / try the next credential.
    """
    print(f"    [HOP] aggregate → {access_ip}  (user '{cred['username']}')")
    out = send_cmd(
        agg_shell,
        f"ssh -l {cred['username']} {access_ip}",
        patterns=("Destination", "(yes/no)?", "yes/no", "assword:", "%", "#", ">"),
        timeout=20,
    )

    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(agg_shell, "yes",
                       patterns=("assword:", "%", "#", ">"), timeout=15)

    if "assword:" in out:
        out = send_cmd(agg_shell, cred["password"],
                       patterns=("assword:", "%", "#", ">"), timeout=15, sensitive=True)

    # A re-prompt for password means the credential was rejected.
    if "assword:" in out:
        # Send a newline to clear the re-prompt so the shell returns to the
        # aggregate prompt for the next credential attempt.
        send_cmd(agg_shell, "", patterns=("%", "#", ">"), timeout=10)
        raise RuntimeError(f"SSH hop auth rejected for user '{cred['username']}'")

    if "%" in out and "#" not in out and ">" not in out:
        raise RuntimeError(f"SSH hop failed: {out.strip().splitlines()[-1]}")

    elevate_and_init(agg_shell, cred)
    print(f"    [HOP] now at {access_ip}#  (user '{cred['username']}')")


def hop_to_access(client, shell, access_ip: str):
    """
    Hop from aggregate to access_ip with retry logic and credential cycling.

    On each attempt, every credential pair is tried in order (ACTIVE_CRED
    first). On a failed attempt:
      - Checks whether the aggregate session is still alive and reconnects
        if needed (socket-closed scenario).
      - Waits HOP_RETRY_DELAY seconds before the next attempt.

    Returns (client, shell, used_cred) where used_cred is the credential
    pair that successfully authenticated to the access switch.
    Raises RuntimeError if all HOP_RETRIES attempts are exhausted.
    """
    last_exc = None
    for attempt in range(1, HOP_RETRIES + 1):
        # Ensure aggregate is alive before each hop attempt
        client, shell = ensure_aggregate(client, shell)

        for cred in ordered_creds():
            try:
                _attempt_hop(shell, access_ip, cred)
                return client, shell, cred          # hop succeeded
            except Exception as exc:
                last_exc = exc
                print(f"    [HOP] user '{cred['username']}' failed: {exc}")
                # Make sure we're back at an aggregate prompt before trying
                # the next credential (in case the failed ssh left us mid-prompt).
                client, shell = ensure_aggregate(client, shell)

        print(f"    [HOP] Attempt {attempt}/{HOP_RETRIES} — all credentials failed.")
        if attempt < HOP_RETRIES:
            print(f"    [HOP] Retrying in {HOP_RETRY_DELAY}s …")
            time.sleep(HOP_RETRY_DELAY)

    raise RuntimeError(
        f"All {HOP_RETRIES} hop attempts to {access_ip} failed. Last error: {last_exc}"
    )


def exit_to_aggregate(agg_shell):
    """
    Send 'exit' on the access switch shell to return to the aggregate.
    Flushes residual show-tech bytes from the buffer afterwards.
    """
    print(f"    [EXIT] returning to aggregate …")
    send_cmd(agg_shell, "exit", patterns=("#", ">"), timeout=10)
    flush_buffer(agg_shell, pause=1.5)
    send_cmd(agg_shell, "terminal length 0", patterns=("#",), timeout=5)


# ─── SHOW TECH ────────────────────────────────────────────────────────────────

def pull_show_tech(shell, ip: str, hostname: str) -> Path:
    """
    Run 'show tech-support' on the currently active shell and save output.

    After the prompt (#) is detected, continues draining the buffer for
    POST_TECH_DRAIN_TIME seconds — many Cisco platforms keep sending
    output after the prompt appears, and cutting off early leaves garbage
    in the buffer for the next command.

    Returns the Path of the saved file.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    safe_host = sanitize(hostname) or "unknown"
    fn = BACKUP_DIR / f"{DATE_STR}_{ip}_{safe_host}_show-tech.txt"

    print(f"    [PULL] show tech-support  (timeout={SHOW_TECH_TIMEOUT}s — please wait…)")
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)

    raw = send_cmd(
        shell,
        "show tech-support",
        patterns=("#",),
        timeout=SHOW_TECH_TIMEOUT,
    )

    # Continue draining — device may still be sending after the prompt
    print(f"    [DRAIN] settling for {POST_TECH_DRAIN_TIME}s after prompt …")
    deadline = time.time() + POST_TECH_DRAIN_TIME
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(MAX_READ).decode("utf-8", "ignore")
            raw += chunk
            deadline = time.time() + POST_TECH_DRAIN_TIME  # reset on new data
        else:
            time.sleep(0.2)

    with open(fn, "w", encoding="utf-8", errors="ignore") as f:
        f.write(raw)

    size_kb = fn.stat().st_size // 1024
    print(f"    [SAVED] {fn}  ({size_kb} KB)")
    return fn


# ─── PER-DEVICE WORKFLOW ──────────────────────────────────────────────────────

def process_device(client, shell, access_ip: str) -> tuple[dict, object, object]:
    """
    Using the persistent aggregate session:
      1. Ensure aggregate is alive (reconnect if not)
      2. Hop to the access switch (with retry + credential cycling)
      3. Pull show tech-support
      4. Exit back to aggregate

    Returns (result_dict, client, shell) so the caller always has the
    current (possibly reconnected) aggregate session.
    """
    result = {
        "ip":       access_ip,
        "hostname": "?",
        "status":   "OK",
        "file":     None,
        "error":    None,
        "user":     None,
    }

    print(f"\n{'='*60}")
    print(f"[DEVICE] {access_ip}")
    print(f"{'='*60}")

    hopped = False
    try:
        # Proactive health check before we start
        client, shell = ensure_aggregate(client, shell)

        # Hop with retry + credential cycling
        client, shell, used_cred = hop_to_access(client, shell, access_ip)
        hopped = True
        result["user"] = used_cred["username"]

        hostname = get_hostname(shell)
        result["hostname"] = hostname
        print(f"    [HOST] {hostname}")

        out_file = pull_show_tech(shell, access_ip, hostname)
        result["file"] = str(out_file)

    except Exception as exc:
        result["status"] = "FAILED"
        result["error"]  = str(exc)
        print(f"    [ERROR] {exc}")

    finally:
        if hopped:
            try:
                exit_to_aggregate(shell)
            except Exception as exit_exc:
                print(f"    [WARN] exit back to aggregate failed: {exit_exc}")
                # If exit failed the session may be dead; reconnect so the
                # next device starts from a clean aggregate shell
                print(f"    [WARN] Attempting aggregate reconnect after failed exit …")
                try:
                    client.close()
                except Exception:
                    pass
                client, shell = connect_aggregate(AGGREGATE_IP)

    return result, client, shell


# ─── SUMMARY ─────────────────────────────────────────────────────────────────

def print_summary(results: list[dict]):
    ok     = [r for r in results if r["status"] == "OK"]
    failed = [r for r in results if r["status"] != "OK"]

    print(f"\n{'='*60}")
    print(f"  SUMMARY  —  {DATE_STR}")
    print(f"{'='*60}")
    print(f"  Aggregate     : {AGGREGATE_IP}")
    print(f"  Total devices : {len(results)}")
    print(f"  Succeeded     : {len(ok)}")
    print(f"  Failed        : {len(failed)}")

    if ok:
        print(f"\n  ✅ Successful:")
        for r in ok:
            user = r.get("user") or "?"
            print(f"     {r['ip']:<20}  {r['hostname']:<20}  [{user}]  {r['file']}")

    if failed:
        print(f"\n  ❌ Failed:")
        for r in failed:
            print(f"     {r['ip']:<20}  {r['error']}")

    print(f"\n  Output directory: ./{BACKUP_DIR}/")
    print(f"{'='*60}\n")


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    devices = load_devices(DEVICES_FILE)
    print(f"[INFO] Loaded {len(devices)} device(s) from {DEVICES_FILE}")
    print(f"[INFO] Aggregate jump host : {AGGREGATE_IP}")
    print(f"[INFO] Credential pairs    : {len(CREDENTIALS)} "
          f"({', '.join(c['username'] for c in CREDENTIALS)})")
    print(f"[INFO] Output directory    : {BACKUP_DIR}/\n")

    agg_client, agg_shell = connect_aggregate(AGGREGATE_IP)

    results = []
    try:
        for idx, ip in enumerate(devices, start=1):
            res, agg_client, agg_shell = process_device(agg_client, agg_shell, ip)
            results.append(res)

            # Inter-device delay — gives slow devices time to fully settle
            # before the next hop, and avoids hammering the aggregate.
            if POST_DEVICE_DELAY > 0 and idx < len(devices):
                print(f"\n[DELAY] Waiting {POST_DEVICE_DELAY}s before next device …")
                remaining = POST_DEVICE_DELAY
                while remaining > 0:
                    step = min(30, remaining)
                    time.sleep(step)
                    remaining -= step
                    if remaining > 0:
                        print(f"[DELAY] {remaining}s remaining …")
                print("[DELAY] Done — moving to next device.\n")
    finally:
        try:
            agg_client.close()
        except Exception:
            pass
        print("[AGGREGATE] Session closed.")

    print_summary(results)
