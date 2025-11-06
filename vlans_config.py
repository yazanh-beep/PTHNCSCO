#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import re
from typing import Tuple, List, Optional

# ========================= USER CONFIG =========================
AGG_IP = "192.168.100.11"  # Aggregation switch IP - configure this!
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535

# VLANs to configure with their names
TARGET_VLANS = [401, 402, 403, 404]
VLAN_NAMES = ["servers", "cameras", "pids", "intercoms"]

# Retry configuration
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

# Per-device retry attempts
TARGET_MAX_RETRIES = 10
TARGET_RETRY_DELAY = 60
TARGET_SSH_TIMEOUT = 60
TARGET_TCP_TIMEOUT = 60  # informational (hop uses device SSH client)
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

file_handler = logging.FileHandler('vlan_multi_config.log', mode='a')
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
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to aggregation {AGG_IP}")
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

# Expanded: support Port-channel/Po + Hu/Te/Fo/Gi/Eth with 1–3 slashes
IFACE_RE = re.compile(
    r'^(?:Port-channel\d+|Po\d+|(?:Hu|Te|Fo|Gi|Eth)\d+(?:/\d+){1,3})\b',
    re.IGNORECASE
)

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

def create_vlans(shell, vlans: List[int], vlan_names: List[str]):
    """Create VLANs with names without deleting any existing VLANs"""
    logger.info(f"[VLAN] Creating VLANs: {', '.join(map(str, vlans))}")
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)

    for i, vlan in enumerate(vlans):
        vlan_name = vlan_names[i] if i < len(vlan_names) else f"VLAN{vlan}"
        logger.info(f"[VLAN] Creating VLAN {vlan} - {vlan_name}")
        out = send_cmd(shell, f"vlan {vlan}", patterns=("(config-vlan)#", "(config)#"), timeout=8)
        # If device is in global (no vlan-database mode), both patterns above are safe
        send_cmd(shell, f"name {vlan_name}", patterns=("(config-vlan)#", "(config)#"), timeout=6)
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=6)

    send_cmd(shell, "end", patterns=("#",), timeout=6)
    logger.info(f"[VLAN] Successfully created {len(vlans)} VLAN(s) with names")

def find_trunk_interfaces(shell) -> List[str]:
    logger.info("[TRUNK] Identifying trunk interfaces...")
    out = send_cmd(shell, "show interfaces trunk", patterns=("#", ">"), timeout=12)

    trunks = set()
    for line in out.splitlines():
        s = line.strip()
        if not s or s.endswith("#") or s.endswith(">") or "hostname" in s:
            continue
        m = IFACE_RE.match(s)
        if m:
            iface = m.group(0)
            # normalize PoX to Port-channelX for consistency
            iface = re.sub(r'^Po', 'Port-channel', iface, flags=re.IGNORECASE)
            trunks.add(iface)

    # Fallback to running-config scan
    if not trunks:
        out2 = send_cmd(shell, r"show run | i ^interface (Port-channel|Po|Gi|Te|Fo|Hu|Eth)", patterns=("#",), timeout=10)
        for line in out2.splitlines():
            s = line.strip()
            if s.startswith("interface "):
                cand = s.split()[1]
                if IFACE_RE.match(cand):
                    cand = re.sub(r'^Po', 'Port-channel', cand, flags=re.IGNORECASE)
                    trunks.add(cand)

    trunks = sorted(trunks, key=lambda x: (x.split('/')[0], x))
    logger.info(f"[TRUNK] Found {len(trunks)} trunk interface(s): {', '.join(trunks) if trunks else 'None'}")
    return trunks

def add_vlans_to_trunks(shell, trunks: List[str], vlans: List[int]):
    """Add VLANs to trunk allowed list without removing existing VLANs"""
    if not trunks:
        logger.info("[TRUNK] No trunks found — skipping trunk updates.")
        return

    vlan_list = ",".join(map(str, vlans))
    logger.info(f"[TRUNK] Adding VLANs {vlan_list} to trunk allowed lists")
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=8)
    done = 0
    for iface in trunks:
        logger.info(f"[TRUNK] Updating {iface}")
        send_cmd(shell, f"interface {iface}", patterns=("(config-if)#",), timeout=8)
        # Use "add" to append to existing allowed list, not replace
        send_cmd(shell, f"switchport trunk allowed vlan add {vlan_list}", patterns=("(config-if)#",), timeout=8)
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=6)
        done += 1
    send_cmd(shell, "end", patterns=("#",), timeout=6)
    logger.info(f"[TRUNK] Successfully updated {done}/{len(trunks)} trunk interface(s)")
# ===============================================================


# ========================= HOP & EXIT ==========================
def establish_device_session(shell, target_ip: str, agg_hostname: str):
    logger.info(f"[HOP] SSH to {target_ip}")
    if shell.closed:
        raise NetworkConnectionError("SSH shell to aggregation switch is closed", reconnect_needed=True)

    out = send_cmd(
        shell,
        f"ssh -l {USERNAME} {target_ip}",
        patterns=(
            "Destination", "(yes/no)?", "yes/no", "assword:", "%", "#", ">", 
            "Permission denied", "Authentication failed", "Connection closed",
            "No route to host", "Host is unreachable", "Connection refused",
            "Connection timed out"
        ),
        timeout=TARGET_SSH_TIMEOUT,
        show_progress=True
    )

    negatives = (
        "Connection refused", "Connection timed out", "Destination",
        "No route to host", "Host is unreachable", "Permission denied",
        "Authentication failed", "Connection closed"
    )
    if any(n in out for n in negatives):
        raise NetworkConnectionError(f"SSH hop error to {target_ip}: {', '.join([n for n in negatives if n in out])}")

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

    # Verify we actually hopped (same as your logic)
    current_hostname = safe_get_hostname(shell)
    if current_hostname and current_hostname != "DEVICE" and current_hostname == agg_hostname:
        logger.error(f"[FAILED HOP] SSH to {target_ip} did not leave aggregation switch - still on '{agg_hostname}'")
        raise NetworkConnectionError(
            f"SSH hop to {target_ip} failed - still on aggregation switch",
            retry_allowed=True
        )

    if not current_hostname or current_hostname == "DEVICE":
        logger.warning(f"[HOP WARNING] Could not verify hop to {target_ip} - hostname unavailable. Proceeding anyway...")
    else:
        logger.info(f"[HOP VERIFIED] Successfully hopped to device '{current_hostname}'")

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
def configure_over_hop(shell, target_ip: str, agg_name: str) -> Tuple[bool, bool, bool]:
    """
    Try to hop to target and configure VLANs + trunk allow-list.
    Returns (success, reconnect_needed, is_agg_switch).
    If SSH hop fails -> skip attempt, no 'exit' is sent.
    """
    # Try to establish session
    try:
        establish_device_session(shell, target_ip, agg_name)
    except NetworkConnectionError as e:
        logger.warning(f"[SKIP] {target_ip} SSH hop failed — {e}. No changes on this attempt.")
        is_agg = "still on aggregation switch" in str(e)
        # If channel died, ask caller to reconnect
        if getattr(shell, "closed", False) or getattr(e, "reconnect_needed", False):
            return (False, True, is_agg)
        # Probe liveness
        try:
            shell.send("\n")
            time.sleep(0.2)
            if shell.recv_ready():
                _ = shell.recv(MAX_READ)
        except Exception:
            return (False, True, is_agg)
        return (False, False, is_agg)

    # Now on target (enable mode)
    target_name = safe_get_hostname(shell) or "DEVICE"
    logger.info(f"[CONNECTED] On device '{target_name}'")

    # Use IP for backup filename if hostname not available
    label = (target_name if target_name != "DEVICE" else target_ip).replace(" ", "_").replace(".", "_")

    try:
        backup_config(shell, label)
        create_vlans(shell, TARGET_VLANS, VLAN_NAMES)
        trunks = find_trunk_interfaces(shell)
        add_vlans_to_trunks(shell, trunks, TARGET_VLANS)
    except Exception as e:
        logger.error(f"[CONFIG] Failed on {target_ip}: {e}")
        try:
            exit_to_agg(shell)
        except Exception:
            pass
        return (False, False, False)

    # exit back to agg
    exit_to_agg(shell)
    return (True, False, False)
# ===============================================================


# ========================= MAIN ================================
def main():
    if len(sys.argv) != 2:
        print("Usage: python vlan_multi_config.py <devices_file>")
        print("Example: python vlan_multi_config.py devices.txt")
        sys.exit(1)

    devices_file = sys.argv[1]

    logger.info("=" * 68)
    logger.info("VLAN CONFIGURATION SCRIPT")
    logger.info("=" * 68)
    logger.info(f"Aggregation Switch: {AGG_IP}")
    logger.info(f"Target VLANs: {', '.join(map(str, TARGET_VLANS))}")
    logger.info(f"Devices file: {devices_file}")
    logger.info("")

    # Load device IPs from file
    try:
        with open(devices_file, "r") as f:
            target_ips = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        logger.info(f"Loaded {len(target_ips)} device(s) from {devices_file}")
    except FileNotFoundError as e:
        logger.error(f"Devices file not found: {e}")
        sys.exit(1)

    if not target_ips:
        logger.error("No device IPs found in file!")
        sys.exit(1)

    logger.info(f"Target devices: {len(target_ips)}")
    for ip in target_ips:
        logger.info(f"   - {ip}")
    logger.info("")

    # Connect to aggregation switch
    try:
        client, shell, agg_name = connect_to_agg()
    except Exception as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)

    # 1) Configure aggregation switch itself FIRST
    logger.info("")
    logger.info("=" * 68)
    logger.info("CONFIGURING AGGREGATION SWITCH (FIRST)")
    logger.info("=" * 68)
    agg_configured = False
    try:
        agg_label = agg_name.replace(" ", "_").replace(".", "_")
        backup_config(shell, agg_label)
        create_vlans(shell, TARGET_VLANS, VLAN_NAMES)
        trunks = find_trunk_interfaces(shell)
        add_vlans_to_trunks(shell, trunks, TARGET_VLANS)
        logger.info(f"[SUCCESS] Aggregation switch '{agg_name}' configured successfully")
        agg_configured = True
    except Exception as e:
        logger.error(f"[AGG] Failed to configure aggregation switch: {e}")
        # Continue to devices anyway

    skip_ips = {AGG_IP}
    successful = []
    failed = []

    # Iterate devices with up-to TARGET_MAX_RETRIES attempts each
    for idx, target_ip in enumerate(target_ips, 1):
        logger.info("")
        logger.info("=" * 68)
        logger.info(f"DEVICE {idx}/{len(target_ips)}: {target_ip}")
        logger.info("=" * 68)

        # Skip aggregation switch if present in list
        if target_ip in skip_ips:
            logger.warning(f"[SKIP] {target_ip} is the aggregation switch (already configured) — skipping.")
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
                    break  # mark failed for this device

            logger.info(f"[ATTEMPT] {attempt}/{TARGET_MAX_RETRIES} for {target_ip}")
            start_t = time.time()
            ok, reconnect_needed, is_agg = configure_over_hop(shell, target_ip, agg_name)

            if is_agg:
                logger.warning(f"[FAILED HOP] SSH to {target_ip} did not leave aggregation switch - reconnecting and will retry")
                try:
                    try:
                        client.close()
                    except Exception:
                        pass
                    client, shell, agg_name = connect_to_agg()
                    logger.info("[RECOVER] Reconnected to aggregation switch")
                except Exception as e:
                    logger.error(f"[RECOVER] Reconnect failed: {e}")
                if attempt < TARGET_MAX_RETRIES:
                    logger.warning(f"[RETRY] Will retry {target_ip} after {TARGET_RETRY_DELAY}s...")
                    time.sleep(TARGET_RETRY_DELAY)
                continue

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
                continue
            elif ok:
                elapsed = time.time() - start_t
                logger.info(f"[SUCCESS] VLANs {', '.join(map(str, TARGET_VLANS))} configured on {target_ip}")
                device_ok = True
                break
            else:
                if attempt < TARGET_MAX_RETRIES:
                    logger.warning(f"[RETRY] Will retry {target_ip} after {TARGET_RETRY_DELAY}s...")
                    time.sleep(TARGET_RETRY_DELAY)

        if device_ok:
            if target_ip not in skip_ips:
                successful.append(target_ip)
        else:
            logger.error(f"[FAILED] Could not configure {target_ip} after {TARGET_MAX_RETRIES} attempt(s)")
            failed.append(target_ip)

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
    logger.info("VLAN CONFIGURATION SUMMARY")
    logger.info("=" * 68)
    logger.info(f"Aggregation switch: {'SUCCESS' if agg_configured else 'FAILED'}")
    logger.info(f"Total target devices: {len(target_ips)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed: {len(failed)}")

    if agg_configured:
        logger.info(f"\nAggregation switch configured:")
        logger.info(f"   - {AGG_IP} ({agg_name}): VLANs {', '.join(map(str, TARGET_VLANS))}")

    if successful:
        logger.info("\nSuccessfully configured:")
        for d in successful:
            logger.info(f"   - {d}: VLANs {', '.join(map(str, TARGET_VLANS))}")

    if failed:
        logger.error("\nFailed devices:")
        for d in failed:
            logger.error(f"   - {d}")

    logger.info("")
    logger.info(f"VLANs configured: {', '.join(map(str, TARGET_VLANS))}")
    logger.info("Note: Existing VLANs were preserved, new VLANs were added to trunks")

    # Exit with error if agg failed or any devices failed
    sys.exit(0 if (agg_configured and not failed) else 1)

# ===============================================================

if __name__ == "__main__":
    main()
