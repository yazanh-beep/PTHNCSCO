#!/usr/bin/env python3
"""
stp_audit.py — STP Diagnostic Script
Connects via a jump/aggregate switch and runs STP health checks
on all switches listed in devices.txt

Usage:
    python3 stp_audit.py
    python3 stp_audit.py --devices devices.txt --output stp_results --soak 60
"""

import argparse
import datetime
import getpass
import os
import re
import sys
import time
import traceback

import paramiko

# ─────────────────────────────────────────────
#  CUSTOM EXCEPTIONS
# ─────────────────────────────────────────────

class JumpSessionLost(Exception):
    """Raised when the jump switch socket dies mid-run."""
    pass


# ─────────────────────────────────────────────
#  CONFIGURATION — edit before running
# ─────────────────────────────────────────────
JUMP_HOST_IP     = "192.168.1.11"    # Aggregate/jump switch IP (reachable from server)
JUMP_SSH_PORT    = 22
DEVICE_SSH_PORT  = 22

USERNAME         = "admin"        # Set to None to prompt
PASSWORD         = "cisco"           # Set to None to prompt

CONN_TIMEOUT     = 15             # seconds per SSH connection attempt
CMD_TIMEOUT      = 30             # seconds to wait for command output
INTER_CMD_DELAY  = 0.5            # seconds between commands
INTER_DEVICE_DELAY = 2            # seconds between devices
SOAK_PERIOD      = 30             # seconds to wait after clearing counters

# ── Retry settings ───────────────────────────
MAX_JUMP_RETRIES   = 3            # retries for initial jump switch connection
MAX_HOP_RETRIES    = 3            # retries for hop from jump -> device
MAX_CMD_RETRIES    = 2            # retries per command if output looks bad
RETRY_BACKOFF      = 3            # seconds to wait between retries (doubles each time)

OUTPUT_DIR   = "stp_results"
DEVICES_FILE = "devices.txt"

# ─────────────────────────────────────────────
#  COMMANDS
# ─────────────────────────────────────────────

# Best-effort clear — non-fatal if unsupported on older IOS
CLEAR_COMMANDS = [
    "terminal length 0",
    "clear spanning-tree counters",
    "clear spanning-tree detected-protocols",
]

# Phase 1 — always run these to discover active VLANs
STP_BASE_COMMANDS = [
    "terminal length 0",
    "show spanning-tree summary",          # lists active VLANs + mode
    "show spanning-tree summary totals",   # aggregate port state counts
    "show interfaces status err-disabled", # BPDU Guard victims
    # "show logging last 100 | include ..." omitted — 'last' not on all IOS
    # Use plain show logging with include filter instead:
    "show logging | include SPANTREE|BPDUGUARD|MACFLAP|err-disable",
]

# Phase 2 — run per discovered VLAN (see discover_vlans() + run_stp_audit())
# These are templates; {vlan} gets substituted at runtime
STP_PER_VLAN_COMMANDS = [
    "show spanning-tree vlan {vlan}",                     # full per-VLAN STP state
    "show spanning-tree vlan {vlan} detail",              # TCN counters + port details
    "show spanning-tree vlan {vlan} | include BLK|LIS|LRN|Altn|Desg|Root",
]

# Patterns that indicate a command produced bad/incomplete output
CMD_ERROR_PATTERNS = [
    r"Invalid input detected",
    r"Incomplete command",
    r"Ambiguous command",
    r"% Unknown command",
    r"% Bad IP address",
    r"Connection timed out",
    r"ssh: connect to host",
    r"% Error",
]

# Patterns that mean the SSH session dropped mid-hop
SESSION_LOST_PATTERNS = [
    r"Connection closed by",
    r"ssh_exchange_identification",
    r"Connection reset by peer",
    r"Broken pipe",
    r"closed\.",
    r"kex_exchange_identification",
]


# ─────────────────────────────────────────────
#  STATS TRACKER
# ─────────────────────────────────────────────
class AuditStats:
    """Collects per-device and aggregate counters for the final summary."""

    def __init__(self):
        self.devices_attempted  = 0
        self.devices_success    = 0
        self.devices_failed     = 0
        self.hop_retries_total  = 0
        self.cmd_retries_total  = 0
        self.cmd_errors_total   = 0
        self.per_device: dict[str, dict] = {}

    def start_device(self, ip: str):
        self.devices_attempted += 1
        self.per_device[ip] = {
            "status":       "pending",
            "hop_retries":  0,
            "cmd_retries":  0,
            "cmd_errors":   0,
            "failed_cmds":  [],
            "error_detail": "",
        }

    def record_hop_retry(self, ip: str, attempt: int, reason: str):
        self.hop_retries_total += 1
        self.per_device[ip]["hop_retries"] += 1
        print(f"  [RETRY] Hop retry {attempt} for {ip} — {reason}")

    def record_cmd_retry(self, ip: str, cmd: str, attempt: int, reason: str):
        self.cmd_retries_total += 1
        self.per_device[ip]["cmd_retries"] += 1
        print(f"  [RETRY] Command retry {attempt}: '{cmd[:50]}' — {reason}")

    def record_cmd_error(self, ip: str, cmd: str, detail: str):
        self.cmd_errors_total += 1
        self.per_device[ip]["cmd_errors"] += 1
        self.per_device[ip]["failed_cmds"].append(cmd)
        print(f"  [CMD ERR] '{cmd[:50]}' — {detail}")

    def device_ok(self, ip: str):
        self.devices_success += 1
        self.per_device[ip]["status"] = "success"

    def device_failed(self, ip: str, reason: str):
        self.devices_failed += 1
        self.per_device[ip]["status"] = "failed"
        self.per_device[ip]["error_detail"] = reason


STATS = AuditStats()


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def load_devices(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        print(f"[ERROR] Devices file not found: {filepath}")
        sys.exit(1)
    devices = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                devices.append(line)
    if not devices:
        print(f"[ERROR] No devices found in {filepath}")
        sys.exit(1)
    print(f"[INFO] Loaded {len(devices)} device(s) from {filepath}")
    return devices


def prompt_credentials(username, password):
    if not username:
        username = input("SSH Username: ").strip()
    if not password:
        password = getpass.getpass("SSH Password: ")
    return username, password


def drain_buffer(shell, wait: float = 0.3) -> str:
    time.sleep(wait)
    output = ""
    while shell.recv_ready():
        chunk = shell.recv(65535).decode("utf-8", errors="replace")
        output += chunk
        time.sleep(0.05)
    return output


def wait_for_prompt(shell, timeout: int = 30) -> str:
    """Block until a Cisco CLI prompt appears (# or >)."""
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk
            if re.search(r"[#>]\s*$", chunk):
                break
        time.sleep(0.1)
    return output


def is_session_lost(output: str) -> bool:
    """Return True if the SSH session to a device has dropped."""
    return any(re.search(p, output, re.IGNORECASE) for p in SESSION_LOST_PATTERNS)


def has_cmd_error(output: str) -> tuple[bool, str]:
    """Return (True, matched_pattern) if the output contains a CLI error."""
    for pattern in CMD_ERROR_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            return True, pattern
    return False, ""


def send_command(shell, command: str, timeout: int = CMD_TIMEOUT) -> str:
    """Send a command and return raw output."""
    shell.send(command + "\n")
    output = wait_for_prompt(shell, timeout=timeout)
    time.sleep(INTER_CMD_DELAY)
    return output


def send_command_with_retry(
    shell, command: str, device_ip: str, timeout: int = CMD_TIMEOUT
) -> tuple[str, bool]:
    """
    Send a command with up to MAX_CMD_RETRIES retries on error.
    Returns (output, success).
    """
    backoff = RETRY_BACKOFF
    for attempt in range(1, MAX_CMD_RETRIES + 2):   # +2 = initial + retries
        output = send_command(shell, command, timeout=timeout)

        if is_session_lost(output):
            STATS.record_cmd_error(device_ip, command, "session lost mid-command")
            return output, False

        error, pattern = has_cmd_error(output)
        if not error:
            return output, True

        if attempt <= MAX_CMD_RETRIES:
            STATS.record_cmd_retry(device_ip, command, attempt, f"CLI error: {pattern}")
            time.sleep(backoff)
            backoff *= 2
        else:
            STATS.record_cmd_error(device_ip, command, f"failed after {MAX_CMD_RETRIES} retries — {pattern}")
            return output, False

    return "", False   # unreachable but satisfies linter


# ─────────────────────────────────────────────
#  JUMP CONNECTION
# ─────────────────────────────────────────────

def connect_to_jump(jump_ip: str, username: str, password: str) -> paramiko.SSHClient:
    """
    Connect to the jump switch with retries.
    Exits the script if all attempts fail (nothing works without the jump).
    """
    backoff = RETRY_BACKOFF
    for attempt in range(1, MAX_JUMP_RETRIES + 1):
        print(f"  [JUMP] Connection attempt {attempt}/{MAX_JUMP_RETRIES} to {jump_ip} ...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                jump_ip,
                port=JUMP_SSH_PORT,
                username=username,
                password=password,
                timeout=CONN_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            print(f"  [JUMP] Connected on attempt {attempt}")
            return client
        except paramiko.AuthenticationException:
            print(f"[FATAL] Authentication failed for {jump_ip} — check credentials")
            sys.exit(1)
        except Exception as e:
            reason = str(e)
            if attempt < MAX_JUMP_RETRIES:
                print(f"  [WARN] Jump connection failed: {reason} — retrying in {backoff}s ...")
                time.sleep(backoff)
                backoff *= 2
            else:
                print(f"[FATAL] Jump switch {jump_ip} unreachable after {MAX_JUMP_RETRIES} attempts: {reason}")
                sys.exit(1)


def open_jump_shell(jump_client: paramiko.SSHClient, password: str) -> paramiko.Channel:
    shell = jump_client.invoke_shell(width=250, height=50)
    wait_for_prompt(shell, timeout=CONN_TIMEOUT)
    print(f"  [JUMP] Shell open — prompt detected")
    enable_privilege_mode(shell, JUMP_HOST_IP, password)
    send_command(shell, "terminal length 0")
    return shell


# ─────────────────────────────────────────────
#  DEVICE HOP
# ─────────────────────────────────────────────

def hop_to_device(
    shell, device_ip: str, username: str, password: str
) -> bool:
    """
    SSH hop from jump shell to target device with retries.
    Returns True on success.
    """
    backoff = RETRY_BACKOFF

    for attempt in range(1, MAX_HOP_RETRIES + 1):
        if attempt > 1:
            STATS.record_hop_retry(device_ip, attempt, f"previous attempt failed, waiting {backoff}s")
            time.sleep(backoff)
            backoff *= 2

        print(f"  [HOP]  Attempt {attempt}/{MAX_HOP_RETRIES} -> {device_ip}")
        try:
            shell.send(f"ssh -l {username} {device_ip}\n")
        except OSError as e:
            raise JumpSessionLost(f"Jump socket dead before hop: {e}") from e

        deadline     = time.time() + CONN_TIMEOUT
        output       = ""
        result       = None   # "ok" | "refused" | "auth_fail" | "timeout"

        while time.time() < deadline:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", errors="replace")
                output += chunk

                if re.search(r"yes/no", chunk, re.IGNORECASE):
                    shell.send("yes\n")

                elif re.search(r"[Pp]assword:", chunk):
                    shell.send(password + "\n")

                elif re.search(r"[#>]\s*$", chunk):
                    result = "ok"
                    break

                elif re.search(r"Connection refused", chunk, re.IGNORECASE):
                    result = "refused"
                    break

                elif re.search(r"Permission denied|Authentication failed", chunk, re.IGNORECASE):
                    result = "auth_fail"
                    break

                elif re.search(r"No route to host|Network unreachable", chunk, re.IGNORECASE):
                    result = "unreachable"
                    break

                elif is_session_lost(output):
                    result = "session_lost"
                    break

            time.sleep(0.1)

        if result is None:
            result = "timeout"

        if result == "ok":
            print(f"  [OK]   Logged into {device_ip} (attempt {attempt})")
            enable_privilege_mode(shell, device_ip, password)
            send_command(shell, "terminal length 0")
            return True

        elif result == "auth_fail":
            # No point retrying — credentials won't change
            STATS.device_failed(device_ip, "authentication failed")
            print(f"  [FAIL] Authentication rejected by {device_ip} — skipping (wrong credentials)")
            _return_to_jump_prompt(shell)
            return False

        elif result == "unreachable":
            STATS.device_failed(device_ip, "no route to host")
            print(f"  [FAIL] {device_ip} is unreachable from jump switch")
            _return_to_jump_prompt(shell)
            return False

        else:
            # refused / timeout / session_lost — worth retrying
            reason_map = {
                "refused":      "SSH port refused",
                "timeout":      f"timed out after {CONN_TIMEOUT}s",
                "session_lost": "session dropped",
            }
            print(f"  [WARN] {device_ip}: {reason_map.get(result, result)}")
            _return_to_jump_prompt(shell)

    # All retries exhausted
    STATS.device_failed(device_ip, f"hop failed after {MAX_HOP_RETRIES} attempts")
    print(f"  [FAIL] {device_ip}: all {MAX_HOP_RETRIES} hop attempts exhausted")
    return False



def enable_privilege_mode(shell, device_ip: str, password: str) -> bool:
    """
    Ensure the shell is in privileged exec mode (#).
    Sends 'enable' if currently in user mode (>), handles enable password prompt.
    Returns True if # mode confirmed, False if it could not be reached.
    """
    current = drain_buffer(shell, wait=0.3)

    if re.search(r"#\s*$", current):
        print(f"  [PRIV] Already in # mode")
        return True

    print(f"  [PRIV] User mode (>) detected on {device_ip} — sending enable ...")
    shell.send("enable\n")

    deadline = time.time() + CONN_TIMEOUT
    output   = ""

    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", errors="replace")
            output += chunk

            if re.search(r"[Pp]assword:", chunk):
                shell.send(password + "\n")

            elif re.search(r"#\s*$", chunk):
                print(f"  [PRIV] # mode confirmed on {device_ip}")
                return True

            elif re.search(r"% Access denied|% Bad secrets|% Error in authentication", chunk, re.IGNORECASE):
                print(f"  [WARN] {device_ip}: enable password rejected — staying in user mode")
                return False

        time.sleep(0.1)

    print(f"  [WARN] {device_ip}: enable mode timed out — commands may be limited")
    return False


def _return_to_jump_prompt(shell):
    """
    Best-effort return to jump switch prompt after a failed hop.
    Raises JumpSessionLost if the socket is already dead so the
    caller can trigger a full jump reconnect.
    """
    try:
        shell.send("\x03")   # Ctrl-C
        time.sleep(0.5)
        shell.send("exit\n")
        time.sleep(1)
        drain_buffer(shell)
    except OSError as e:
        raise JumpSessionLost(f"Jump socket dead during cleanup: {e}") from e


def exit_device(shell):
    """
    Clean exit back to jump switch after a successful hop.
    Raises JumpSessionLost if the socket has gone away.
    """
    try:
        shell.send("exit\n")
        time.sleep(1)
        drain_buffer(shell)
    except OSError as e:
        raise JumpSessionLost(f"Jump socket dead on exit: {e}") from e


# ─────────────────────────────────────────────
#  CLEAR + AUDIT
# ─────────────────────────────────────────────

def clear_stp_counters(shell, device_ip: str):
    """
    Clear STP counters. Clear commands are best-effort — some older IOS
    versions don't support them. Failures are logged but do NOT count
    as cmd_errors (they don't affect data collection).
    """
    print(f"  [CLR]  Clearing STP counters on {device_ip} ...")
    for cmd in CLEAR_COMMANDS:
        if cmd.startswith("terminal"):
            send_command(shell, cmd)
            print(f"         + {cmd}")
            continue
        # Send once — no retry, no error counting for clear commands
        output = send_command(shell, cmd)
        error, _ = has_cmd_error(output)
        if error:
            print(f"         ~ {cmd}  (not supported on this platform — skipping)")
        else:
            print(f"         + {cmd}")

    print(f"  [WAIT] Soaking {SOAK_PERIOD}s for fresh counters ...")
    for remaining in range(SOAK_PERIOD, 0, -5):
        time.sleep(min(5, remaining))
        left = remaining - min(5, remaining)
        if left > 0:
            print(f"         ... {left}s remaining")
    print(f"         ... done")



def discover_vlans(shell, device_ip: str) -> list[str]:
    """
    Parse active VLAN IDs from 'show spanning-tree summary'.
    Returns a sorted list of VLAN ID strings e.g. ['1', '10', '100'].
    Falls back to ['1'] if parsing fails.
    """
    print(f"  [VLAN] Discovering active STP VLANs ...")
    output = send_command(shell, "show spanning-tree summary", timeout=CMD_TIMEOUT)
    cleaned = strip_echo(output, "show spanning-tree summary")

    # Match lines like: VLAN0001, VLAN0010, VLAN0100 or vlan1, vlan10
    vlans = re.findall(r"[Vv][Ll][Aa][Nn]0*(\d+)", cleaned)
    vlans = sorted(set(vlans), key=lambda x: int(x))

    if not vlans:
        print(f"  [VLAN] Could not parse VLANs — defaulting to VLAN 1")
        return ["1"]

    print(f"  [VLAN] Found {len(vlans)} active VLAN(s): {', '.join(vlans)}")
    return vlans

def run_stp_audit(shell, device_ip: str) -> dict:
    """
    Phase 1: run base commands (summary, err-disabled, logging).
    Phase 2: discover active VLANs, then run per-VLAN detail commands.
    Returns dict of {command_label: output}.
    """
    results = {}
    errors  = 0

    # ── Phase 1: base commands ───────────────────
    total_base = len([c for c in STP_BASE_COMMANDS if not c.startswith("terminal") and not c.startswith("#")])
    print(f"  [RUN]  Phase 1 — {total_base} base commands ...")

    for cmd in STP_BASE_COMMANDS:
        if cmd.startswith("terminal") or cmd.startswith("#"):
            if cmd.startswith("terminal"):
                send_command(shell, cmd)
            continue

        output, ok = send_command_with_retry(shell, cmd, device_ip)

        if not ok:
            errors += 1
            results[cmd] = f"[ERROR] Command failed or session lost\n{output}"
            print(f"         ✗ {cmd[:65]}")
        else:
            results[cmd] = strip_echo(output, cmd)
            print(f"         ✓ {cmd[:65]}")

        if is_session_lost(output):
            print(f"  [WARN] Session lost — stopping")
            return results

    # ── Phase 2: per-VLAN commands ───────────────
    vlans = discover_vlans(shell, device_ip)
    total_vlan_cmds = len(STP_PER_VLAN_COMMANDS) * len(vlans)
    print(f"  [RUN]  Phase 2 — {len(STP_PER_VLAN_COMMANDS)} commands x {len(vlans)} VLANs = {total_vlan_cmds} total ...")

    for vlan in vlans:
        for template in STP_PER_VLAN_COMMANDS:
            cmd = template.replace("{vlan}", vlan)
            output, ok = send_command_with_retry(shell, cmd, device_ip)

            label = cmd   # use full command as key
            if not ok:
                errors += 1
                results[label] = f"[ERROR] Command failed\n{output}"
                print(f"         ✗ VLAN {vlan}: {cmd[:55]}")
            else:
                results[label] = strip_echo(output, cmd)
                print(f"         ✓ VLAN {vlan}: {cmd[:55]}")

            if is_session_lost(output):
                print(f"  [WARN] Session lost during VLAN {vlan} commands — stopping")
                return results

    if errors:
        print(f"  [WARN] {errors} command(s) had errors on {device_ip}")

    return results


def strip_echo(output: str, command: str) -> str:
    lines    = output.splitlines()
    filtered = []
    for line in lines:
        if line.strip() == command.strip():
            continue
        if re.match(r"^[\w\-\.]+[#>]\s*$", line):
            continue
        filtered.append(line)
    return "\n".join(filtered).strip()


# ─────────────────────────────────────────────
#  ANALYSIS
# ─────────────────────────────────────────────

def analyze_results(device_ip: str, results: dict) -> list[str]:
    findings = []
    d        = STATS.per_device.get(device_ip, {})

    # Surface retry/error stats as findings
    if d.get("hop_retries", 0) > 0:
        findings.append(f"ℹ️  CONNECTION: required {d['hop_retries']} hop retries to reach device")
    if d.get("cmd_errors", 0) > 0:
        findings.append(f"⚠️  COLLECTION: {d['cmd_errors']} command(s) failed — data may be incomplete")
        for fc in d.get("failed_cmds", []):
            findings.append(f"    └─ failed: {fc}")

    for cmd, output in results.items():

        if "[ERROR]" in output:
            continue   # already flagged above

        # ── TCN check ──────────────────────────────
        if "topology" in cmd:
            m = re.search(r"(\d+)\s+topology change", output, re.IGNORECASE)
            if m:
                count = int(m.group(1))
                if count == 0:
                    findings.append("✅ TCN COUNT: 0 topology changes since counter clear")
                elif count <= 5:
                    findings.append(f"ℹ️  TCN COUNT: {count} topology changes (low — monitor)")
                elif count <= 20:
                    findings.append(f"⚠️  TCN COUNT: {count} topology changes (moderate — investigate)")
                else:
                    findings.append(f"🚨 TCN COUNT: {count} topology changes (HIGH — active instability)")

            m = re.search(r"last change occurred\s+([\d:]+)\s+ago", output, re.IGNORECASE)
            if m:
                age   = m.group(1)
                parts = age.split(":")
                if len(parts) >= 2:
                    total_sec = int(parts[0]) * 3600 + int(parts[1]) * 60
                    if total_sec < 60:
                        findings.append(f"🚨 RECENT TCN: last change {age} ago (< 1 min — actively flapping)")
                    elif total_sec < 300:
                        findings.append(f"⚠️  RECENT TCN: last change {age} ago (< 5 min)")

        # ── Port state check ────────────────────────
        if re.search(r"\bLIS\b", output):
            findings.append("🚨 PORTS IN LISTENING STATE — STP convergence in progress right now")
        if re.search(r"\bLRN\b", output):
            findings.append("⚠️  PORTS IN LEARNING STATE — STP recently transitioned")

        # ── Root bridge sanity ─────────────────────
        if "root" in cmd.lower() and re.search(r"This bridge is the root", output, re.IGNORECASE):
            findings.append("ℹ️  ROOT BRIDGE: this switch is root — verify this is intentional")

        # ── err-disabled ───────────────────────────
        if "err-disabled" in cmd:
            if re.search(r"\S+\s+err-disabled", output, re.IGNORECASE):
                ports = re.findall(r"(\S+)\s+err-disabled", output, re.IGNORECASE)
                findings.append(f"🚨 ERR-DISABLED: {len(ports)} port(s) down — {', '.join(ports[:5])}")
            else:
                findings.append("✅ ERR-DISABLED: no err-disabled ports found")

        # ── Log events ─────────────────────────────
        if "logging" in cmd:
            if "BPDUGUARD" in output:
                count = output.upper().count("BPDUGUARD")
                findings.append(f"🚨 BPDUGUARD: {count} event(s) in logs — rogue device or loop?")
            if "MACFLAP" in output or "MACMOVE" in output:
                findings.append("⚠️  MAC FLAPPING: events found — possible physical loop or dual-homed device")
            if "SPANTREE" in output:
                findings.append("ℹ️  SPANTREE: STP syslog events found — review command output below")
            if not any(k in output for k in ["BPDUGUARD", "MACFLAP", "MACMOVE", "SPANTREE"]):
                findings.append("✅ LOGS: no STP/MAC-flap events in last 100 log entries")

    if not findings:
        findings.append("✅ No STP anomalies detected")

    return findings


# ─────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────

def save_report(device_ip: str, results: dict, findings: list[str], output_dir: str) -> str:
    safe_ip   = device_ip.replace(".", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(output_dir, f"stp_{safe_ip}_{timestamp}.txt")
    d         = STATS.per_device.get(device_ip, {})

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  STP AUDIT REPORT\n")
        f.write(f"  Device      : {device_ip}\n")
        f.write(f"  Date        : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Method      : clear counters -> {SOAK_PERIOD}s soak -> collect\n")
        f.write(f"  Hop retries : {d.get('hop_retries', 0)}\n")
        f.write(f"  Cmd retries : {d.get('cmd_retries', 0)}\n")
        f.write(f"  Cmd errors  : {d.get('cmd_errors', 0)}\n")
        f.write("=" * 70 + "\n\n")

        f.write("── AUTOMATED FINDINGS ─────────────────────────────────────────────\n")
        for finding in findings:
            f.write(f"  {finding}\n")
        f.write("\n")

        f.write("── COMMAND OUTPUTS ────────────────────────────────────────────────\n\n")
        for cmd, output in results.items():
            f.write(f">>> {cmd}\n")
            f.write(output + "\n")
            f.write("-" * 60 + "\n\n")

    return filename


def write_summary(summary_rows: list[dict], output_dir: str) -> str:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(output_dir, f"stp_summary_{timestamp}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  STP AUDIT — NETWORK SUMMARY\n")
        f.write(f"  Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Devices   : {STATS.devices_attempted} attempted / "
                f"{STATS.devices_success} success / {STATS.devices_failed} failed\n")
        f.write(f"  Retries   : {STATS.hop_retries_total} hop / "
                f"{STATS.cmd_retries_total} cmd / {STATS.cmd_errors_total} cmd errors\n")
        f.write("=" * 70 + "\n\n")

        # Failed devices first
        failed = [r for r in summary_rows if r["status"] == "failed"]
        if failed:
            f.write("── FAILED DEVICES ─────────────────────────────────────────────────\n")
            for row in failed:
                f.write(f"  🚨 {row['ip']} — {row.get('error_detail', 'unknown error')}\n")
            f.write("\n")

        # Per-device findings
        f.write("── DEVICE FINDINGS ────────────────────────────────────────────────\n\n")
        for row in summary_rows:
            if row["status"] == "failed":
                tag = "🚨 FAILED "
            elif row["clean"]:
                tag = "✅ CLEAN  "
            else:
                tag = "⚠️  ISSUES "
            f.write(f"[{tag}] {row['ip']}\n")
            for finding in row["findings"]:
                f.write(f"             {finding}\n")
            f.write(f"             Report : {row['report_file']}\n\n")

    return filename



def reconnect_jump(
    jump_ip: str, username: str, password: str, old_client
) -> tuple:
    """
    Close the dead jump connection and establish a fresh one.
    Returns (new_jump_client, new_shell).
    """
    print(f"\n  [JUMP] Socket lost — reconnecting to {jump_ip} ...")
    try:
        old_client.close()
    except Exception:
        pass   # already dead

    new_client = connect_to_jump(jump_ip, username, password)
    new_shell  = open_jump_shell(new_client, password)
    print(f"  [JUMP] Reconnected successfully")
    return new_client, new_shell


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    global SOAK_PERIOD   # must be declared before any reference to the variable

    parser = argparse.ArgumentParser(description="STP Audit via Jump Switch")
    parser.add_argument("--devices", default=DEVICES_FILE,  help="Path to devices.txt")
    parser.add_argument("--output",  default=OUTPUT_DIR,    help="Output directory")
    parser.add_argument("--jump",    default=JUMP_HOST_IP,  help="Jump switch IP")
    parser.add_argument("--user",    default=USERNAME,      help="SSH username")
    parser.add_argument("--soak",    default=SOAK_PERIOD,   type=int, help="Soak seconds after clear")
    args = parser.parse_args()

    SOAK_PERIOD = args.soak

    os.makedirs(args.output, exist_ok=True)
    devices              = load_devices(args.devices)
    username, password   = prompt_credentials(args.user, PASSWORD)

    print(f"\n{'='*60}")
    print(f"  STP Audit")
    print(f"  Devices     : {len(devices)}")
    print(f"  Jump switch : {args.jump}")
    print(f"  Soak period : {SOAK_PERIOD}s")
    print(f"  Max retries : {MAX_HOP_RETRIES} hop / {MAX_CMD_RETRIES} cmd")
    print(f"  Output      : {args.output}")
    print(f"{'='*60}\n")

    # ── Connect to jump ───────────────────────
    print(f"[STEP 1] Connecting to jump switch {args.jump} ...")
    jump_client = connect_to_jump(args.jump, username, password)
    shell       = open_jump_shell(jump_client, password)

    summary_rows = []

    # ── Iterate devices ───────────────────────
    MAX_JUMP_RECONNECTS = 3   # max jump reconnects per device before giving up

    for idx, device_ip in enumerate(devices, 1):
        print(f"\n[{idx}/{len(devices)}] ── {device_ip} {'─'*35}")
        STATS.start_device(device_ip)

        # Attempt the device with jump-reconnect recovery
        jump_reconnects = 0
        device_done     = False

        while not device_done:
            try:
                is_jump = device_ip.strip() == args.jump.strip()

                if is_jump:
                    print("  [INFO] Jump switch — running commands directly on this session")
                    clear_stp_counters(shell, device_ip)
                    results = run_stp_audit(shell, device_ip)

                else:
                    connected = hop_to_device(shell, device_ip, username, password)
                    if not connected:
                        summary_rows.append({
                            "ip":           device_ip,
                            "status":       "failed",
                            "clean":        False,
                            "findings":     [f"🚨 UNREACHABLE — {STATS.per_device[device_ip]['error_detail']}"],
                            "error_detail": STATS.per_device[device_ip]["error_detail"],
                            "report_file":  "N/A",
                        })
                        device_done = True
                        continue

                    clear_stp_counters(shell, device_ip)
                    results = run_stp_audit(shell, device_ip)
                    exit_device(shell)
                    print(f"  [EXIT] Returned to jump switch")

                STATS.device_ok(device_ip)
                device_done = True

            except JumpSessionLost as e:
                jump_reconnects += 1
                print(f"\n  [JUMP] Session lost: {e}")

                if jump_reconnects > MAX_JUMP_RECONNECTS:
                    reason = f"jump reconnect limit ({MAX_JUMP_RECONNECTS}) exceeded"
                    STATS.device_failed(device_ip, reason)
                    print(f"  [FAIL] {device_ip}: {reason} — skipping device")
                    summary_rows.append({
                        "ip":           device_ip,
                        "status":       "failed",
                        "clean":        False,
                        "findings":     [f"🚨 JUMP LOST: {reason}"],
                        "error_detail": reason,
                        "report_file":  "N/A",
                    })
                    device_done = True
                    continue

                print(f"  [JUMP] Reconnect attempt {jump_reconnects}/{MAX_JUMP_RECONNECTS} — retrying {device_ip} after reconnect ...")
                # Reset the device stats so retry starts clean
                STATS.start_device(device_ip)
                try:
                    jump_client, shell = reconnect_jump(args.jump, username, password, jump_client)
                except SystemExit:
                    print(f"[FATAL] Cannot reconnect to jump switch — aborting run")
                    raise

                # Loop back and retry the device with fresh shell

            except Exception as e:
                reason = f"unexpected exception: {e}"
                STATS.device_failed(device_ip, reason)
                print(f"  [ERROR] {device_ip}: {reason}")
                traceback.print_exc()
                # Try to clean up — if shell is dead this raises JumpSessionLost
                # which we handle on the next outer iteration
                try:
                    _return_to_jump_prompt(shell)
                except JumpSessionLost:
                    pass   # will be caught if we loop again; device is done here
                summary_rows.append({
                    "ip":           device_ip,
                    "status":       "failed",
                    "clean":        False,
                    "findings":     [f"🚨 EXCEPTION: {reason}"],
                    "error_detail": reason,
                    "report_file":  "N/A",
                })
                device_done = True

        findings    = analyze_results(device_ip, results)
        report_file = save_report(device_ip, results, findings, args.output)
        is_clean    = all(f.startswith("✅") for f in findings)

        summary_rows.append({
            "ip":           device_ip,
            "status":       "success",
            "clean":        is_clean,
            "findings":     findings,
            "error_detail": "",
            "report_file":  report_file,
        })

        print(f"  [DONE] Saved -> {report_file}")
        for finding in findings:
            print(f"         {finding}")

        if idx < len(devices):
            time.sleep(INTER_DEVICE_DELAY)

    # ── Final summary ─────────────────────────
    summary_file = write_summary(summary_rows, args.output)

    print(f"\n{'='*60}")
    print(f"  AUDIT COMPLETE")
    print(f"  {'─'*40}")
    print(f"  Devices   : {STATS.devices_success}/{STATS.devices_attempted} succeeded")
    print(f"  Hop retries  : {STATS.hop_retries_total}")
    print(f"  Cmd retries  : {STATS.cmd_retries_total}")
    print(f"  Cmd errors   : {STATS.cmd_errors_total}")
    print(f"  Summary   : {summary_file}")
    print(f"{'='*60}\n")

    jump_client.close()


if __name__ == "__main__":
    main()
