#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import ipaddress
import re
from typing import Tuple, List, Optional

# ========================= USER CONFIG =========================
AGG_IP = ""
USERNAME = ""
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535

# VLAN settings (script arguments will supply the per-device IP/mask)
VLAN_ID = 100

# Retry configuration
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

# Per-device retry attempts (your request)
TARGET_MAX_RETRIES = 3           # <— now used to retry each device multiple times
TARGET_RETRY_DELAY = 8
TARGET_SSH_TIMEOUT = 60
TARGET_TCP_TIMEOUT = 30
# ===============================================================


# ========================= LOGGING SETUP =======================
class LiveFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'

    def format(self, record):
        try:
            if sys.stdout.isatty():
                color = self.COLORS.get(record.levelname, self.RESET)
                record.levelname = f"{color}{record.levelname}{self.RESET}"
        except Exception:
            pass
        return super().format(record)

file_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_formatter = LiveFormatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

file_handler = logging.FileHandler('vlan_100_config.log', mode='a')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(file_formatter)
try:
    file_handler.stream.reconfigure(line_buffering=True)
except Exception:
    pass

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass
# ===============================================================


# ========================= EXCEPTIONS ==========================
class NetworkConnectionError(Exception):
    def __init__(self, message, retry_allowed=False, reconnect_needed=False):
        super().__init__(message)
        self.retry_allowed = retry_allowed
        self.reconnect_needed = reconnect_needed

class ConfigurationError(Exception):
    pass
# ===============================================================


# ========================= SSH HELPERS =========================
def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, show_progress=False):
    buf, end = "", time.time() + timeout
    last_log = time.time()
    started = time.time()
    last_prog = time.time()

    while time.time() < end:
        if getattr(shell, "recv_ready", lambda: False)():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            if (time.time() - last_log > 2) or any(p in buf for p in patterns):
                if data.strip():
                    logger.debug(f"[RECV] {data.strip()[-120:]}")
                last_log = time.time()
            for p in patterns:
                if p in buf:
                    return buf
        else:
            if show_progress and time.time() - last_prog >= 5:
                elapsed = int(time.time() - started)
                remaining = max(0, int(end - time.time()))
                logger.info(f"[WAIT] Elapsed: {elapsed}s, Remaining: {remaining}s ...")
                sys.stdout.flush()
                last_prog = time.time()
            time.sleep(0.1)

    logger.warning(f"Timeout waiting for prompt. Buffer tail: {buf[-200:]}")
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, log_cmd=True, show_progress=False):
    if log_cmd:
        logger.debug(f"Sending: {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout, show_progress=show_progress)
# ===============================================================


# ========================= CORE CONNECT ========================
def connect_to_agg(retry=0):
    try:
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                       look_for_keys=False, allow_agent=False, timeout=10)
        shell = client.invoke_shell()
        logger.info("[CONNECT] Waiting for prompt...")
        out = expect_prompt(shell, ("#", ">"), timeout=15)
        if not out:
            raise NetworkConnectionError("No prompt from aggregation switch")
        # enable
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=8, log_cmd=False)
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("#",), timeout=8, log_cmd=False)
        # disable paging
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=6, log_cmd=False)
        # learn hostname
        agg_name = safe_get_hostname(shell) or "AGGREGATION"
        logger.info(f"[CONNECT] Connected to aggregation switch '{agg_name}'")
        return client, shell, agg_name
    except Exception as e:
        logger.error(f"[CONNECT] Failed: {e}")
        if retry < AGG_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {AGG_RETRY_DELAY}s before retry...")
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry+1)
        raise
# ===============================================================


# ========================= UTILS ===============================
HOSTNAME_RE = re.compile(r'^\s*hostname\s+(.+)$', re.MULTILINE)
PROMPT_HOST_RE = re.compile(r'\r?\n([A-Za-z0-9._\-\/]+)[#>]')

IFACE_RE = re.compile(r'^(Po\d+|Gi\d+(?:/\d+){1,2}|Te\d+(?:/\d+){1,2}|Fo\d+(?:/\d+){1,2})\b')

def safe_get_hostname(shell) -> Optional[str]:
    try:
        out = send_cmd(shell, "show run | i ^hostname", patterns=("#", ">", "--More--"), timeout=6, log_cmd=False)
        m = HOSTNAME_RE.search(out)
        if m:
            return m.group(1).strip()
        # Try prompt scrape
        out2 = send_cmd(shell, "", patterns=("#", ">"), timeout=3, log_cmd=False)
        m2 = PROMPT_HOST_RE.search(out2)
        if m2:
            return m2.group(1).strip()
    except Exception:
        pass
    return None

def backup_config(shell, label: str) -> str:
    logger.info("[BACKUP] Capturing running config...")
    out = send_cmd(shell, "show running-config", patterns=("#",), timeout=30, show_progress=True)
    fname = f"backup_{label}_{int(time.time())}.cfg"
    with open(fname, "w", encoding="utf-8", errors="ignore") as f:
        f.write(out)
    logger.info(f"[BACKUP] Saved to {fname}")
    return fname

def apply_vlan_config(shell, ip_addr: str, netmask: str):
    logger.info("[CONFIG] Applying VLAN 100 SVI")
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
    send_cmd(shell, f"vlan {VLAN_ID}", patterns=("(config-vlan)#", "(config)#"), timeout=8)
    send_cmd(shell, "exit", patterns=("(config)#",), timeout=6)
    send_cmd(shell, f"interface vlan {VLAN_ID}", patterns=("(config-if)#",), timeout=10)
    send_cmd(shell, f"ip address {ip_addr} {netmask}", patterns=("(config-if)#",), timeout=8)
    send_cmd(shell, "no shutdown", patterns=("(config-if)#",), timeout=6)
    send_cmd(shell, "exit", patterns=("(config)#",), timeout=6)
    send_cmd(shell, "end", patterns=("#",), timeout=6)

def find_trunk_interfaces(shell) -> List[str]:
    logger.info("[TRUNK] Identifying trunk interfaces...")
    out = send_cmd(shell, "show interfaces trunk", patterns=("#", ">"), timeout=12)

    trunks = set()
    for line in out.splitlines():
        s = line.strip()
        # ignore prompts/garbage
        if not s or s.endswith("#") or s.endswith(">") or "hostname" in s:
            continue
        m = IFACE_RE.match(s)
        if m:
            trunks.add(m.group(1))

    # Fallback to running-config scan
    if not trunks:
        out2 = send_cmd(shell, "show run | i ^interface (Po|Gi|Te|Fo)", patterns=("#",), timeout=10)
        for line in out2.splitlines():
            s = line.strip()
            if s.startswith("interface "):
                cand = s.split()[1]
                if IFACE_RE.match(cand):
                    trunks.add(cand)

    trunks = sorted(trunks)
    logger.info(f"[TRUNK] Found {len(trunks)} trunk interface(s): {', '.join(trunks) if trunks else 'None'}")
    return trunks

def add_vlan_to_trunks(shell, trunks: List[str], vlan: int):
    if not trunks:
        logger.info("[TRUNK] No trunks found — skipping trunk updates.")
        return
    logger.info("[TRUNK] Adding VLAN 100 to trunk allowed lists")
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=8)
    done = 0
    for iface in trunks:
        logger.info(f"[TRUNK] Updating {iface}")
        send_cmd(shell, f"interface {iface}", patterns=("(config-if)#",), timeout=8)
        send_cmd(shell, f"switchport trunk allowed vlan add {vlan}", patterns=("(config-if)#",), timeout=8)
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=6)
        done += 1
    send_cmd(shell, "end", patterns=("#",), timeout=6)
    logger.info(f"[TRUNK] Successfully updated {done}/{len(trunks)} trunk interface(s)")
# ===============================================================


# ========================= HOP & EXIT ==========================
def establish_device_session(shell, target_ip: str):
    logger.info(f"[HOP] SSH to {target_ip}")
    if shell.closed:
        raise NetworkConnectionError("SSH shell to aggregation switch is closed", reconnect_needed=True)

    out = send_cmd(
        shell,
        f"ssh -l {USERNAME} {target_ip}",
        patterns=("Destination", "(yes/no)?", "yes/no", "assword:", "%", "#", ">", "Connection refused", "Connection timed out"),
        timeout=TARGET_SSH_TIMEOUT,
        show_progress=True
    )

    if "Connection refused" in out:
        raise NetworkConnectionError(f"SSH refused by {target_ip}")
    if "Connection timed out" in out or "Destination" in out:
        raise NetworkConnectionError(f"SSH timed out to {target_ip}")
    if "No route to host" in out or "Host is unreachable" in out:
        raise NetworkConnectionError(f"Network unreachable to {target_ip}")

    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "#", ">", "%"), timeout=15)

    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("#", ">", "%", "assword:"), timeout=15)
        if "assword:" in out:
            raise NetworkConnectionError(f"Authentication failed for {target_ip}", retry_allowed=True)

    if not ("#" in out or ">" in out):
        raise NetworkConnectionError(f"No prompt from {target_ip}", retry_allowed=True)

    # If user-mode, enter enable
    last = out.strip().splitlines()[-1] if out.strip().splitlines() else ""
    if last.endswith(">") or (out.count(">") > out.count("#")):
        out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=8)
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=8)
        if "#" not in out:
            raise NetworkConnectionError(f"Failed to enter enable on {target_ip}", retry_allowed=True)

    # Disable paging on target
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5, log_cmd=False)

    # settle
    send_cmd(shell, "", patterns=("#",), timeout=3, log_cmd=False)
    return True

def exit_to_agg(shell):
    """Return one level (target -> agg) safely. Never raise."""
    try:
        if getattr(shell, "closed", False):
            logger.warning("[EXIT] Channel already closed; skipping exit")
            return
        # try a gentle exit sequence
        try:
            shell.send("\n")
            expect_prompt(shell, ("#", ">"), timeout=3)
        except Exception:
            pass
        try:
            shell.send("exit\n")
            expect_prompt(shell, ("#", ">"), timeout=5)
        except Exception:
            pass
        # clear any buffer
        try:
            shell.send("\n")
            time.sleep(0.2)
            if shell.recv_ready():
                _ = shell.recv(MAX_READ)
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"[EXIT] Error: {e}")
# ===============================================================


# ========================= DEVICE CONFIG WRAPPER ===============
def configure_over_hop(shell, target_ip: str, vlan_ip: str, netmask: str) -> Tuple[bool, bool]:
    """
    Try to hop to target and configure VLAN SVI + trunk allow-list.
    Returns (success, reconnect_needed).
    If SSH hop fails -> skip attempt, no 'exit' is sent.
    """
    # Try to establish session
    try:
        establish_device_session(shell, target_ip)
    except NetworkConnectionError as e:
        logger.warning(f"[SKIP] {target_ip} SSH hop failed — {e}. No changes on this attempt.")
        # If channel died, ask caller to reconnect
        if getattr(shell, "closed", False) or getattr(e, "reconnect_needed", False):
            return (False, True)
        # Probe liveness
        try:
            shell.send("\n")
            time.sleep(0.2)
            if shell.recv_ready():
                _ = shell.recv(MAX_READ)
        except Exception:
            return (False, True)
        return (False, False)

    # Now on target (enable mode)
    target_name = safe_get_hostname(shell) or "DEVICE"
    logger.info(f"[CONNECTED] On device '{target_name}'")

    label = (target_name or target_ip).replace(" ", "_").replace(".", "_")
    try:
        backup_config(shell, label)
        apply_vlan_config(shell, vlan_ip, netmask)
        trunks = find_trunk_interfaces(shell)
        add_vlan_to_trunks(shell, trunks, VLAN_ID)
    except Exception as e:
        logger.error(f"[CONFIG] Failed on {target_ip}: {e}")
        try:
            exit_to_agg(shell)
        except Exception:
            pass
        return (False, False)

    # exit back to agg
    exit_to_agg(shell)
    return (True, False)
# ===============================================================


# ========================= MAIN ================================
def main():
    if len(sys.argv) != 4:
        print("Usage: python vlan_100.py <devices_file> <vlan100_start_ip> <netmask>")
        sys.exit(1)

    devices_file = sys.argv[1]
    start_ip_str = sys.argv[2]
    netmask = sys.argv[3]

    logger.info("=" * 68)
    logger.info("VLAN 100 CONFIGURATION SCRIPT")
    logger.info("=" * 68)
    logger.info(f"Aggregation Switch: {AGG_IP}")
    logger.info(f"Devices file: {devices_file}")
    logger.info(f"Starting VLAN 100 IP: {start_ip_str}")
    logger.info(f"Netmask: {netmask}")
    logger.info("")

    # Load devices
    try:
        with open(devices_file, "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError as e:
        logger.error(f"Devices file not found: {e}")
        sys.exit(1)

    # Compute per-device IPs
    try:
        base_ip = ipaddress.IPv4Address(start_ip_str)
    except Exception as e:
        logger.error(f"Invalid start IP: {e}")
        sys.exit(1)

    plan = []
    for i, ip in enumerate(targets):
        vlan_ip = str(base_ip + i)
        plan.append((ip, vlan_ip))

    logger.info(f"Target devices: {len(plan)}")
    for ip, vip in plan:
        logger.info(f"   - {ip} -> VLAN 100 IP: {vip}")
    logger.info("")

    # Connect to aggregation and get name
    try:
        client, shell, agg_name = connect_to_agg()
    except Exception as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)

    # 1) Configure aggregation switch itself first
    logger.info("=" * 68)
    logger.info("CONFIGURING AGGREGATION SWITCH (FIRST)")
    logger.info("=" * 68)
    try:
        agg_label = agg_name.replace(" ", "_").replace(".", "_")
        backup_config(shell, agg_label)
        # Apply VLAN 100 on aggregation with the start_ip (adjust if you prefer a fixed agg IP)
        apply_vlan_config(shell, start_ip_str, netmask)
        trunks = find_trunk_interfaces(shell)
        add_vlan_to_trunks(shell, trunks, VLAN_ID)
    except Exception as e:
        logger.error(f"[AGG] Failed to configure aggregation switch: {e}")
        # Continue to devices anyway

    successful = []
    failed = []

    # 2) Iterate devices with up-to TARGET_MAX_RETRIES attempts each
    for idx, (target, vlan_ip) in enumerate(plan, 1):
        logger.info("")
        logger.info("=" * 68)
        logger.info(f"DEVICE {idx}/{len(plan)}: {target}")
        logger.info("=" * 68)

        # Skip agg if present in list
        if target == AGG_IP:
            logger.warning(f"[SKIP] {target} is the aggregation switch IP — already configured first. Skipping.")
            continue

        device_ok = False

        for attempt in range(1, TARGET_MAX_RETRIES + 1):
            # Ensure agg channel is alive
            if getattr(shell, "closed", False):
                logger.error("Aggregation channel closed; attempting reconnect...")
                try:
                    try:
                        client.close()
                    except Exception:
                        pass
                    client, shell, agg_name = connect_to_agg()
                    logger.info("Reconnected to aggregation switch")
                except Exception as e:
                    logger.error(f"Could not reconnect to aggregation switch: {e}")
                    # No point to continue; mark this device failed and break retry loop
                    break

            logger.info(f"[ATTEMPT] {attempt}/{TARGET_MAX_RETRIES} for {target}")
            start_t = time.time()
            ok, reconnect_needed = configure_over_hop(shell, target, vlan_ip, netmask)

            if reconnect_needed:
                logger.info("[RECOVER] Aggregation channel down — reconnecting...")
                try:
                    try:
                        client.close()
                    except Exception:
                        pass
                    client, shell, agg_name = connect_to_agg()
                    logger.info("[RECOVER] Reconnected to aggregation switch")
                except Exception as e:
                    logger.error(f"[RECOVER] Reconnect failed: {e}")
                    # will retry if attempts remain
            elif ok:
                elapsed = time.time() - start_t
                logger.info(f"[SUCCESS] VLAN 100 configured on {target} with IP {vlan_ip}")
                device_ok = True
                break  # done with this device
            else:
                logger.warning(f"[RETRY] Will retry {target} after {TARGET_RETRY_DELAY}s...")
                time.sleep(TARGET_RETRY_DELAY)

        if device_ok:
            successful.append((target, vlan_ip))
        else:
            logger.error(f"[FAILED] Could not configure {target} after {TARGET_MAX_RETRIES} attempt(s)")
            failed.append(target)

        time.sleep(1.5)

    # Close agg session
    try:
        client.close()
        logger.info("")
        logger.info("[DISCONNECT] Closed aggregation switch session")
    except Exception:
        pass

    # Summary
    logger.info("")
    logger.info("=" * 68)
    logger.info("VLAN 100 CONFIGURATION SUMMARY")
    logger.info("=" * 68)
    logger.info(f"Total devices: {len(plan)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed: {len(failed)}")
    if successful:
        logger.info("\nSuccessful configurations:")
        for d, vip in successful:
            logger.info(f"   - {d}: VLAN 100 IP {vip} {netmask}")
    if failed:
        logger.error("\nFailed devices:")
        for d in failed:
            logger.error(f"   - {d}")

    sys.exit(0 if not failed else 1)

# ===============================================================

if __name__ == "__main__":
    main()
