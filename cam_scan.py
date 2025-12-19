#!/usr/bin/env python3
import paramiko
import time
import re
import json
import csv
import logging
import sys
import io
from datetime import datetime
from collections import deque

# ============================================================================
# IDLE-SAFE LOGGING CONFIGURATION
# ============================================================================

class IDLESafeHandler(logging.StreamHandler):
    """Custom handler that's safe for IDLE and handles Unicode properly"""
    def __init__(self):
        super().__init__(sys.stdout)
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    def emit(self, record):
        try:
            msg = self.format(record)
            # Replace problematic Unicode characters with ASCII equivalents
            msg = msg.replace('✓', 'OK')
            msg = msg.replace('⏳', 'WAIT')
            msg = msg.replace('○', 'SKIP')
            msg = msg.replace('✗', 'ERROR')
            msg = msg.replace('⊗', 'X')
            # Print with flush to ensure immediate output
            print(msg, flush=True)
        except Exception:
            self.handleError(record)

# Detect if running in IDLE
running_in_idle = 'idlelib.run' in sys.modules

log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

if running_in_idle:
    # IDLE: Use custom safe handler + file
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            IDLESafeHandler()  # Custom IDLE-safe handler
        ]
    )
    print("="*80)
    print("RUNNING IN IDLE MODE - LIVE LOGGING ENABLED")
    print(f"Logs saved to: {log_filename}")
    print("="*80)
else:
    # Normal: Standard logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

logger = logging.getLogger(__name__)

# ============================================================================
# USER CONFIG
# ============================================================================

SEED_SWITCH_IP = "192.168.100.13"
TIMEOUT = 150
MAX_READ = 65535
CREDENTIAL_SETS = [
    {"username": "admin",  "password": "cisco",  "enable": ""} ,
    {"username": "cisco",  "password": "cisco",  "enable": ""}
]
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
CDP_LLDP_TIMEOUT = 35

# --- RETRY CONFIGURATION ---
SSH_HOP_RETRY_ATTEMPTS = 5
SSH_HOP_RETRY_BASE_DELAY = 2
SSH_HOP_USE_EXPONENTIAL_BACKOFF = True
SSH_HOP_VERIFY_ROUTE = True

# --- MAC TABLE POLLING CONFIGURATION ---
MAC_POLL_INTERVAL = 5            # Check every 5 seconds
MAC_POLL_MAX_ATTEMPTS = 999999   # Effectively infinite (relies on hard timeout)
MAC_POLL_INITIAL_WAIT = 15       # Initial wait after clearing table
MAC_POLL_BATCH_SIZE = 100        # Ports per batch
MAC_POLL_BATCH_PAUSE = 2         # Pause between batches
MAC_POLL_HARD_TIMEOUT = 180      # 10 minutes absolute maximum per port (safety net)

# --- INDIRECT DISCOVERY CONFIGURATION (NEW) ---
ENABLE_INDIRECT_DISCOVERY = True    # Scan parent uplink if SSH fails
INDIRECT_DISCOVERY_MIN_MACS = 2     # Minimum MACs to confirm it's not just the switch itself
INDIRECT_DISCOVERY_MAX_MACS = 100   # Limit output to prevent flooding logs

#--- SWITCH TYPE DETECTION BY HARDWARE MODEL ---
HARDWARE_MODEL_MAPPING = {
    # Catalyst 3850 = Always Aggregate
    "3850": "AGGREGATE",
    "WS-C3850": "AGGREGATE",
    
    # Catalyst 3650 = Always Access/Edge
    "3650": "EDGE",
    "WS-C3650": "EDGE",
    
    # Catalyst 9300 = Access or Server (we'll check hostname for "SRV")
    "9300": "EDGE",  # Default to EDGE, but override if hostname has "SRV"
    "C9300": "EDGE",
    
    # Industrial Ethernet = Always Field/Edge
    "IE-": "EDGE",            # IE-3300, IE-3400, etc.
    "IE-3": "EDGE",
    "IE-4": "EDGE",
    "IE-5": "EDGE",
    "ESS-": "EDGE",
    "CGS-": "EDGE",
}

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

PROMPT_RE = re.compile(r"(?m)^[^\r\n>\s][^\r\n>]*[>#]\s?$")

visited_switches = set()
discovered_aggregates = set()
aggregate_hostnames = {}
camera_data = []
failed_switches = []

discovery_stats = {
    "switches_attempted": 0,
    "switches_successfully_scanned": 0,
    "switches_failed_auth": 0,
    "switches_failed_unreachable": 0,
    "switches_failed_timeout": 0,
    "switches_failed_other": 0,
    "aggregates_reconnections": 0,
    "total_cameras_found": 0,
    "switches_retried_from_seed": 0,
    "switches_recovered_on_retry": 0,
    "total_ports_no_mac": 0,
    # --- NEW STATS ---
    "indirect_discoveries": 0,
    "switches_with_indirect_discovery": 0,
    "indirect_upgraded_to_direct": 0,
    "duplicates_removed": 0,
    # -----------------
    "switches_by_type": {
        "EDGE": {"attempted": 0, "successful": 0, "failed": 0},
        "SERVER": {"attempted": 0, "successful": 0, "failed": 0},
        "OTHER": {"attempted": 0, "successful": 0, "failed": 0},
        "AGGREGATE": {"attempted": 0, "successful": 0, "failed": 0}
    },
    "failure_details": []
}

agg_client = None
agg_shell = None
agg_creds = None
agg_hostname = None
session_depth = 0
device_creds = {}
hostname_to_ip = {}

# ============================================================================
# HELPER CLASSES AND FUNCTIONS
# ============================================================================

class NetworkConnectionError(Exception):
    def __init__(self, message, retry_allowed=False, reconnect_needed=False):
        super().__init__(message)
        self.retry_allowed = retry_allowed
        self.reconnect_needed = reconnect_needed

def _drain(shell):
    time.sleep(0.05)
    buf = ""
    while shell and not shell.closed and shell.recv_ready():
        try:
            buf += shell.recv(MAX_READ).decode("utf-8", "ignore")
        except Exception:
            break
        time.sleep(0.02)
    return buf

def expect_prompt(shell, timeout=TIMEOUT):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell and not shell.closed and shell.recv_ready():
            try:
                buf += shell.recv(MAX_READ).decode("utf-8", "ignore")
            except Exception:
                break
            if PROMPT_RE.search(buf):
                return buf
        else:
            time.sleep(0.05)
    return buf

def send_cmd(shell, cmd, timeout=TIMEOUT, silent=False):
    if not silent:
        logger.debug(f"CMD: {cmd}")
    if not shell or shell.closed:
        raise NetworkConnectionError("SSH shell is closed", reconnect_needed=True)
    try:
        _ = _drain(shell)
        shell.send(cmd + "\n")
        return expect_prompt(shell, timeout=timeout)
    except Exception as e:
        logger.error(f"Exception in send_cmd('{cmd}'): {e}")
        raise NetworkConnectionError(f"Send command failed: {e}", reconnect_needed=True)

def _ensure_enable(shell, enable_candidates, timeout=10):
    out = send_cmd(shell, "", timeout=3, silent=True)
    if out.strip().endswith("#"):
        return True
    en = send_cmd(shell, "enable", timeout=5, silent=True)
    if en.strip().endswith("#"):
        return True
    if re.search(r"[Pp]assword:", en):
        for pw in enable_candidates:
            if pw is None or pw == "":
                continue
            test = send_cmd(shell, pw, timeout=timeout, silent=True)
            if test.strip().endswith("#"):
                return True
        test = send_cmd(shell, "", timeout=timeout, silent=True)
        if test.strip().endswith("#"):
            return True
        logger.error("Enable failed with all provided enable passwords")
        return False
    out2 = send_cmd(shell, "", timeout=3, silent=True)
    return out2.strip().endswith("#")

def verify_aggregate_connection():
    global agg_shell
    try:
        if not agg_shell or agg_shell.closed:
            return False
        agg_shell.send("\n")
        time.sleep(0.3)
        if agg_shell.recv_ready():
            data = agg_shell.recv(MAX_READ).decode("utf-8", "ignore")
            return bool(PROMPT_RE.search(data))
        return False
    except Exception:
        return False

def cleanup_failed_session():
    global agg_shell, session_depth
    sh = agg_shell
    try:
        if not sh or sh.closed:
            logger.debug("[CLEANUP] Shell closed")
            return False
        logger.debug("[CLEANUP] Cleaning up")
        try:
            sh.send("\x03")
            time.sleep(0.2)
        except Exception:
            pass
        _ = _drain(sh)
        if session_depth > 0:
            try:
                sh.send("exit\n")
                time.sleep(0.6)
                _ = _drain(sh)
                session_depth = max(0, session_depth - 1)
            except Exception:
                pass
        try:
            sh.send("\n")
            time.sleep(0.2)
            data = _drain(sh)
            ok = bool(PROMPT_RE.search(data))
        except Exception:
            ok = False
        if not ok:
            logger.warning("[CLEANUP] Could not verify prompt")
        return ok
    except Exception as e:
        logger.debug(f"[CLEANUP] Exception: {e}")
        return False

def get_hostname(shell):
    shell.send("\n")
    time.sleep(0.2)
    buff = expect_prompt(shell, timeout=4)
    for line in reversed(buff.splitlines()):
        line = line.strip()
        # Cisco prompts always end with # or >
        if line.endswith('#') or line.endswith('>'):
            hostname = line[:-1]  # Remove last character
            return hostname
    return "Unknown"

def _connect_to_aggregate_internal():
    global agg_client, agg_shell, agg_creds, agg_hostname
    last_err = None
    for cred in CREDENTIAL_SETS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                SEED_SWITCH_IP,
                username=cred["username"],
                password=cred["password"],
                look_for_keys=False,
                allow_agent=False,
                timeout=15
            )
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(30)
            shell = client.invoke_shell()
            expect_prompt(shell, timeout=TIMEOUT)
            en_list = [cred.get("enable") or cred.get("password"), cred.get("password")]
            if not _ensure_enable(shell, en_list, timeout=8):
                logger.warning("Enable escalation failed on seed")
                client.close()
                continue
            send_cmd(shell, "terminal length 0", silent=True)
            logger.info("[CONNECT] Configuring SSH timeout...")
            send_cmd(shell, "configure terminal")
            send_cmd(shell, "ip ssh time-out 10")
            send_cmd(shell, "end")
            logger.info("[CONNECT] SSH timeout set to 10 minutes")
            agg_client = client
            agg_shell = shell
            agg_creds = cred
            agg_hostname = get_hostname(agg_shell) or "UNKNOWN"
            logger.info(f"Seed hostname: {agg_hostname}")
            logger.info("Successfully connected to aggregate switch")
            return SEED_SWITCH_IP
        except Exception as e:
            last_err = e
            logger.warning(f"Seed connection failed: {e}")
    raise last_err or Exception("Unable to connect")

def connect_to_seed(retry_count=0):
    try:
        logger.info(f"[CONNECT] Attempt {retry_count + 1}/{AGG_MAX_RETRIES} - SSH to seed: {SEED_SWITCH_IP}")
        return _connect_to_aggregate_internal()
    except Exception as e:
        logger.error(f"[CONNECT] Connection failed: {e}")
        if retry_count < AGG_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {AGG_RETRY_DELAY}s...")
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_seed(retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed after {AGG_MAX_RETRIES} attempts: {e}")

def reconnect_to_aggregate(reason=""):
    global agg_client, agg_shell
    last_err = None
    if reason:
        logger.warning(f"[RECONNECT] Reconnecting: {reason}")
    try:
        if agg_client:
            agg_client.close()
    except Exception:
        pass
    for attempt in range(AGG_MAX_RETRIES):
        logger.info(f"[RECONNECT] Attempt {attempt+1}/{AGG_MAX_RETRIES}")
        try:
            mgmt_ip = _connect_to_aggregate_internal()
            logger.info("[RECONNECT] Reconnected to seed")
            return mgmt_ip
        except Exception as e:
            last_err = e
            time.sleep(AGG_RETRY_DELAY)
    raise NetworkConnectionError(f"Failed to reconnect: {last_err}", reconnect_needed=True)

def verify_ip_reachable_quick(target_ip, shell, timeout=3):
    try:
        logger.debug(f"[PING] Testing {target_ip}...")
        ping_out = send_cmd(shell, f"ping {target_ip} timeout 1 repeat 2", timeout=timeout, silent=True)
        if re.search(r"Success rate is [1-9]|!+|\d+ packets received", ping_out):
            logger.debug(f"[PING] {target_ip} is reachable")
            return True
        logger.debug(f"[PING] {target_ip} not reachable")
        return False
    except Exception as e:
        logger.debug(f"[PING] Error testing reachability: {e}")
        return True

def cleanup_and_return_to_parent(expected_parent_hostname, max_attempts=3):
    global agg_shell, session_depth
    for attempt in range(1, max_attempts + 1):
        try:
            current_hostname = get_hostname(agg_shell)
            if current_hostname == expected_parent_hostname:
                logger.debug(f"[CLEANUP] Already at parent: {expected_parent_hostname}")
                return True
            logger.warning(f"[CLEANUP] At {current_hostname}, need to return to {expected_parent_hostname}")
            logger.info(f"[CLEANUP] Sending exit command (attempt {attempt}/{max_attempts})")
            agg_shell.send("exit\n")
            time.sleep(1)
            output = _drain(agg_shell)
            if agg_shell.closed or "closed by" in output.lower():
                logger.error(f"[CLEANUP] Connection closed - exited too far!")
                return False
            time.sleep(0.5)
            new_hostname = get_hostname(agg_shell)
            if new_hostname == expected_parent_hostname:
                logger.info(f"[CLEANUP] Successfully returned to {expected_parent_hostname}")
                session_depth = max(0, session_depth - 1)
                return True
        except Exception as e:
            logger.error(f"[CLEANUP] Exception: {e}")
    logger.error(f"[CLEANUP] Failed to return to parent after {max_attempts} attempts")
    return False

def attempt_ssh_hop(target_ip, parent_hostname, expected_hostname=None, attempt_number=1):
    global agg_shell, session_depth, device_creds, hostname_to_ip
    for cred_idx, cred_set in enumerate(CREDENTIAL_SETS, 1):
        username = cred_set["username"]
        password = cred_set["password"]
        enable_pw = cred_set.get("enable", "")
        logger.debug(f"[HOP] Trying credentials {cred_idx}/{len(CREDENTIAL_SETS)}")
        try:
            agg_shell.send(f"ssh -l {username} {target_ip}\n")
            time.sleep(2)
            output = ""
            timeout_time = time.time() + 45
            password_sent = False
            while time.time() < timeout_time:
                if not agg_shell or agg_shell.closed:
                    return {"success": False, "reason": "shell_closed", "fatal": True}
                if agg_shell.recv_ready():
                    chunk = agg_shell.recv(MAX_READ).decode("utf-8", "ignore")
                    output += chunk
                    if re.search(r"[Pp]assword:", output) and not password_sent:
                        logger.debug(f"[HOP] Sending password")
                        agg_shell.send(password + "\n")
                        password_sent = True
                        time.sleep(1)
                        output = ""
                        continue
                    if re.search(r"\(yes/no\)", output):
                        logger.debug(f"[HOP] Accepting SSH key")
                        agg_shell.send("yes\n")
                        time.sleep(0.5)
                        continue
                    if re.search(r"Connection refused|Connection timed out|No route to host", output, re.IGNORECASE):
                        logger.debug(f"[HOP] Connection error in output")
                        cleanup_failed_session()
                        return {"success": False, "reason": "connection_refused"}
                    if re.search(r"Authentication failed|Permission denied|Access denied|Login invalid", output, re.IGNORECASE):
                        logger.debug(f"[HOP] Authentication failed with credential {cred_idx}")
                        cleanup_failed_session()
                        continue
                    if PROMPT_RE.search(output):
                        logger.debug(f"[HOP] Prompt detected")
                        time.sleep(0.5)
                        reached_hostname = get_hostname(agg_shell)
                        logger.debug(f"[HOP] Parent: {parent_hostname}, Reached: {reached_hostname}")
                        if reached_hostname == parent_hostname:
                            logger.warning(f"[HOP] HOSTNAME UNCHANGED with credential {cred_idx} - still on {parent_hostname}")
                            cleanup_failed_session()
                            continue
                        if expected_hostname and reached_hostname != expected_hostname:
                            logger.warning(f"[HOP] Hostname mismatch: expected '{expected_hostname}', got '{reached_hostname}'")
                        logger.info(f"[HOP] Successfully reached {reached_hostname} at {target_ip} using credential {cred_idx}")
                        enable_candidates = [enable_pw, password, ""]
                        if not _ensure_enable(agg_shell, enable_candidates, timeout=10):
                            logger.warning(f"[HOP] Could not enter enable mode")
                        send_cmd(agg_shell, "terminal length 0", timeout=5, silent=True)
                        session_depth += 1
                        device_creds[target_ip] = cred_set
                        hostname_to_ip[reached_hostname] = target_ip
                        return {"success": True, "hostname": reached_hostname}
                time.sleep(0.1)
            logger.debug(f"[HOP] Timeout with credential {cred_idx}")
            cleanup_failed_session()
        except Exception as e:
            logger.error(f"[HOP] Exception during SSH with credential {cred_idx}: {e}")
            cleanup_failed_session()
            continue
    logger.warning(f"[HOP] All {len(CREDENTIAL_SETS)} credential sets failed for {target_ip}")
    return {"success": False, "reason": "auth_failed_all_credentials"}

def ssh_to_device(target_ip, expected_hostname=None, parent_hostname=None):
    global agg_shell, session_depth, device_creds, hostname_to_ip
    if parent_hostname is None:
        try:
            parent_hostname = get_hostname(agg_shell) or agg_hostname or "UNKNOWN"
        except Exception:
            parent_hostname = agg_hostname or "UNKNOWN"
    logger.debug(f"[RETRY] Attempting SSH to {target_ip} from {parent_hostname}")
    
    # Check if we are trying to SSH to ourselves
    try:
        ip_brief_out = send_cmd(agg_shell, "show ip interface brief", timeout=10, silent=True)
        for line in ip_brief_out.splitlines():
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 2:
                line_ip = parts[1]
                if line_ip == target_ip and ("up" in line.lower() or "administratively" in line.lower()):
                    logger.info(f"Target IP {target_ip} belongs to current switch {parent_hostname} - already connected")
                    return None
    except Exception as e:
        logger.debug(f"Could not check local IPs: {e}")
    
    for attempt in range(1, SSH_HOP_RETRY_ATTEMPTS + 1):
        if attempt > 1:
            if SSH_HOP_USE_EXPONENTIAL_BACKOFF:
                delay = SSH_HOP_RETRY_BASE_DELAY * (2 ** (attempt - 2))
            else:
                delay = SSH_HOP_RETRY_BASE_DELAY
            logger.info(f"[RETRY] Waiting {delay}s before attempt {attempt}/{SSH_HOP_RETRY_ATTEMPTS}...")
            time.sleep(delay)
        logger.info(f"[RETRY] SSH hop attempt {attempt}/{SSH_HOP_RETRY_ATTEMPTS} to {target_ip}")
        if SSH_HOP_VERIFY_ROUTE and attempt == 1:
            if not verify_ip_reachable_quick(target_ip, agg_shell):
                logger.warning(f"[RETRY] {target_ip} not reachable via ping")
        if attempt > 1:
            if not verify_aggregate_connection():
                logger.error(f"[RETRY] Lost connection to parent switch before attempt {attempt}")
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
            current_host = get_hostname(agg_shell)
            if current_host != parent_hostname:
                logger.warning(f"[RETRY] Not at parent hostname ({current_host} != {parent_hostname})")
                logger.warning(f"[RETRY] Attempting to return to parent...")
                if not cleanup_and_return_to_parent(parent_hostname):
                    logger.error(f"[RETRY] Could not return to parent switch")
                    raise NetworkConnectionError("Cannot return to parent", reconnect_needed=True)
        result = attempt_ssh_hop(
            target_ip=target_ip,
            parent_hostname=parent_hostname,
            expected_hostname=expected_hostname,
            attempt_number=attempt
        )
        if result["success"]:
            logger.info(f"[RETRY] SUCCESS on attempt {attempt}/{SSH_HOP_RETRY_ATTEMPTS}")
            return True
        failure_reason = result.get("reason", "Unknown")
        logger.warning(f"[RETRY] Attempt {attempt} failed: {failure_reason}")
        if result.get("fatal", False):
            logger.error(f"[RETRY] Fatal error - no retry possible")
            return False
        if "hostname_unchanged" in failure_reason:
            logger.warning(f"[RETRY] Hostname didn't change - target may be unreachable or misconfigured")
    logger.error(f"[RETRY] Failed to connect to {target_ip} after {SSH_HOP_RETRY_ATTEMPTS} attempts")
    return False

def exit_device():
    global agg_shell, session_depth
    sh = agg_shell
    if not sh or sh.closed:
        return False
    try:
        if session_depth > 0:
            logger.debug("[EXIT] Leaving nested session")
            sh.send("exit\n")
            time.sleep(0.6)
            _ = _drain(sh)
            session_depth = max(0, session_depth - 1)
        sh.send("\n")
        time.sleep(0.2)
        data = _drain(sh)
        return bool(PROMPT_RE.search(data))
    except Exception as e:
        logger.warning(f"[EXIT] Exception: {e}")
        return False

def convert_mac_format(mac_cisco):
    mac_clean = mac_cisco.replace(".", "").upper()
    return ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])

def normalize_interface_name(intf):
    if not intf:
        return ""
    intf = intf.strip()
    replacements = [
        ('TenGigabitEthernet', 'tengigabitethernet'),
        ('TenGigE', 'tengigabitethernet'),
        ('TenGig', 'tengigabitethernet'),
        ('Ten', 'tengigabitethernet'),
        ('Te', 'tengigabitethernet'),
        ('GigabitEthernet', 'gigabitethernet'),
        ('GigE', 'gigabitethernet'),
        ('Gig', 'gigabitethernet'),
        ('Gi', 'gigabitethernet'),
        ('FastEthernet', 'fastethernet'),
        ('Fas', 'fastethernet'),
        ('Fa', 'fastethernet'),
        ('FortyGigabitEthernet', 'fortygigabitethernet'),
        ('FortyGigE', 'fortygigabitethernet'),
        ('FortyGig', 'fortygigabitethernet'),
        ('For', 'fortygigabitethernet'),
        ('Fo', 'fortygigabitethernet'),
        ('TwentyFiveGigE', 'twentyfivegigabitethernet'),
        ('TwentyFiveGig', 'twentyfivegigabitethernet'),
        ('Twe', 'twentyfivegigabitethernet'),
        ('Tw', 'twentyfivegigabitethernet'),
        ('Ethernet', 'ethernet'),
        ('Eth', 'ethernet'),
        ('Et', 'ethernet'),
        ('Port-channel', 'port-channel'),
        ('Po', 'port-channel'),
        ('Vlan', 'vlan'),
        ('Vl', 'vlan'),
    ]
    for short, full in replacements:
        if intf.startswith(short):
            if len(intf) > len(short):
                next_char = intf[len(short)]
                if next_char.isdigit() or next_char in ['/', ' ']:
                    normalized = full + intf[len(short):]
                    normalized = normalized.replace(' ', '')
                    return normalized.lower()
    return intf.lower()

def get_switch_hardware_model(shell):
    try:
        version_out = send_cmd(shell, "show version", timeout=10, silent=True)
        patterns = [
            r"Model [Nn]umber\s*:\s*(\S+)",
            r"cisco\s+(\S+)\s+\(",
            r"Cisco IOS Software,\s*([A-Z0-9\-]+)\s+Software",
        ]
        for pattern in patterns:
            match = re.search(pattern, version_out, re.IGNORECASE)
            if match:
                model = match.group(1)
                logger.debug(f"Detected hardware model: {model}")
                return model
        inv_out = send_cmd(shell, "show inventory", timeout=10, silent=True)
        pid_match = re.search(r"PID:\s*(\S+)", inv_out)
        if pid_match:
            model = pid_match.group(1)
            logger.debug(f"Detected hardware model from inventory: {model}")
            return model
        return None
    except Exception as e:
        logger.warning(f"Error getting hardware model: {e}")
        return None

def determine_switch_type(hostname, hardware_model=None):
    if not hostname:
        return "OTHER"
    if hardware_model:
        hardware_upper = hardware_model.upper()
        for pattern, switch_type in HARDWARE_MODEL_MAPPING.items():
            if pattern.upper() in hardware_upper:
                if "9300" in pattern:
                    if "SMSSRV" in hostname.upper() or "SRV" in hostname.upper():
                        return "SERVER"
                    else:
                        return "EDGE"
                return switch_type
    upper = hostname.upper()
    if "SMSAGG" in upper:
        return "AGGREGATE"
    if "SMSSRV" in upper:
        return "SERVER"
    if any(x in upper for x in ["SMSACC", "SMSIE", "SMS"]):
        return "EDGE"
    return "OTHER"

def is_aggregate_switch(hostname, hardware_model=None):
    switch_type = determine_switch_type(hostname, hardware_model)
    return switch_type == "AGGREGATE"

def parse_cdp_neighbors(output):
    neighbors = []
    blocks = re.split(r"(?=^Device ID:\s*)", output, flags=re.M)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        neighbor = {"hostname": None, "mgmt_ip": None, "local_intf": None, "remote_intf": None, "platform": None, "source": "CDP"}
        if m := re.search(r"Device ID:\s*(\S+(?:\.\S+)*)", block):
            neighbor["hostname"] = m.group(1)
        cdp_ip_patterns = (
            r"IPv4 [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
            r"IP [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
            r"Management [Aa]ddress(?:es)?:.*?IP(?:v4)?:\s*(\d+\.\d+\.\d+\.\d+)",
        )
        for pat in cdp_ip_patterns:
            m = re.search(pat, block, flags=re.I | re.S)
            if m:
                neighbor["mgmt_ip"] = m.group(1)
                break
        if m := re.search(r"Interface:\s*(\S+)", block):
            neighbor["local_intf"] = m.group(1).rstrip(',')
        if m := re.search(r"Port ID.*?:\s*(\S+)", block):
            neighbor["remote_intf"] = m.group(1)
        if m := re.search(r"Platform:\s*([^,\n]+)", block):
            neighbor["platform"] = m.group(1).strip()
        if neighbor["hostname"] and neighbor["mgmt_ip"]:
            if neighbor["platform"] and "cisco" in neighbor["platform"].lower():
                neighbors.append(neighbor)
    return neighbors

def parse_lldp_neighbors(output):
    neighbors = []
    blocks = re.split(r'[-]{40,}', output)
    for block in blocks:
        if not block.strip():
            continue
        if "Local Intf:" not in block:
            continue
        if "Capability codes:" in block and "Local Intf:" not in block:
            continue
        neighbor = {"hostname": None, "mgmt_ip": None, "local_intf": None, "remote_intf": None, "sys_descr": "", "source": "LLDP"}
        if m := re.search(r'^Local Intf:\s*(\S+)', block, re.M):
            neighbor["local_intf"] = m.group(1)
        if m := re.search(r'^Port id:\s*(\S+)', block, re.M | re.I):
            neighbor["remote_intf"] = m.group(1)
        if m := re.search(r'^System Name:\s*(.+?)$', block, re.M):
            hostname = m.group(1).strip().strip('"').strip("'")
            neighbor["hostname"] = hostname
        if m := re.search(r'^System Description:\s*\n([\s\S]+?)(?=^Time remaining:|^System Capabilities:|^Management Addresses:|$)', block, re.M):
            neighbor["sys_descr"] = m.group(1).strip()
        if neighbor["sys_descr"]:
            sys_desc_lower = neighbor["sys_descr"].lower()
            if "cisco ios" not in sys_desc_lower and "cisco nx-os" not in sys_desc_lower:
                continue
        else:
            continue
        if not neighbor["hostname"] and neighbor["sys_descr"]:
            m = re.search(r'(\S+)\s+Software', neighbor["sys_descr"], re.I)
            if m:
                neighbor["hostname"] = m.group(1)
        if m := re.search(r'^Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)', block, re.M):
            neighbor["mgmt_ip"] = m.group(1)
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'Management Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'IPv4:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        if neighbor["mgmt_ip"]:
            if not neighbor["hostname"]:
                neighbor["hostname"] = f"LLDP-Device-{neighbor['mgmt_ip']}"
            neighbors.append(neighbor)
    return neighbors

def parse_cdp_neighbors_for_port_exclusion(output):
    neighbors = []
    blocks = re.split(r"(?=^Device ID:\s*)", output, flags=re.M)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        neighbor = {"hostname": None, "local_intf": None, "platform": None}
        if m := re.search(r"Device ID:\s*(\S+(?:\.\S+)*)", block):
            neighbor["hostname"] = m.group(1)
        if m := re.search(r"Interface:\s*(\S+)", block):
            neighbor["local_intf"] = m.group(1).rstrip(',')
        if m := re.search(r"Platform:\s*([^,\n]+)", block):
            neighbor["platform"] = m.group(1).strip()
        if neighbor["platform"] and "cisco" in neighbor["platform"].lower():
            if neighbor["local_intf"]:
                neighbors.append(neighbor)
    return neighbors

def parse_lldp_neighbors_for_port_exclusion(output):
    neighbors = []
    blocks = re.split(r'[-]{40,}', output)
    for block in blocks:
        if not block.strip():
            continue
        if "Local Intf:" not in block:
            continue
        if "Capability codes:" in block and "Local Intf:" not in block:
            continue
        neighbor = {"hostname": None, "local_intf": None, "sys_descr": "", "mgmt_ip": None, "source": "LLDP"}
        if m := re.search(r'^Local Intf:\s*(\S+)', block, re.M):
            neighbor["local_intf"] = m.group(1)
        if m := re.search(r'^System Name:\s*(.+?)$', block, re.M):
            neighbor["hostname"] = m.group(1).strip().strip('"').strip("'")
        if m := re.search(r'^System Description:\s*\n([\s\S]+?)(?=^Time remaining:|^System Capabilities:|^Management Addresses:|$)', block, re.M):
            neighbor["sys_descr"] = m.group(1).strip()
        if m := re.search(r'^Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)', block, re.M):
            neighbor["mgmt_ip"] = m.group(1)
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'Management Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'IPv4:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        if neighbor["sys_descr"]:
            sys_desc_lower = neighbor["sys_descr"].lower()
            if "cisco ios" in sys_desc_lower or "cisco nx-os" in sys_desc_lower:
                if neighbor["local_intf"]:
                    neighbors.append(neighbor)
    return neighbors

def get_uplink_ports_from_neighbors(shell, current_switch_type="UNKNOWN"):
    logger.info("Discovering ports with CDP/LLDP neighbors...")
    excluded_ports = []
    excluded_ports_normalized = set()
    
    # CDP
    logger.info("Checking CDP neighbors...")
    cdp_detail = send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "CDP is not enabled" not in cdp_detail and "Invalid input" not in cdp_detail:
        cdp_neighbors = parse_cdp_neighbors_for_port_exclusion(cdp_detail)
        if cdp_neighbors:
            logger.info(f"Found {len(cdp_neighbors)} CDP neighbors")
            for nbr in cdp_neighbors:
                if nbr.get("local_intf"):
                    local_port = nbr["local_intf"]
                    port_norm = normalize_interface_name(local_port)
                    if port_norm not in excluded_ports_normalized:
                        excluded_ports.append(local_port)
                        excluded_ports_normalized.add(port_norm)
                        logger.info(f"NEIGHBOR DETECTED: {local_port} -> {nbr.get('hostname', 'Unknown')} (Cisco via CDP) - EXCLUDED")
    else:
        logger.info("CDP not enabled")
    
    # LLDP
    logger.info("Checking LLDP neighbors...")
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors_for_port_exclusion(lldp_output)
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
            for nbr in lldp_neighbors:
                if nbr.get("local_intf"):
                    lldp_intf_norm = normalize_interface_name(nbr["local_intf"])
                    if lldp_intf_norm in excluded_ports_normalized:
                        continue
                    excluded_ports.append(nbr["local_intf"])
                    excluded_ports_normalized.add(lldp_intf_norm)
                    ip_info = f"({nbr['mgmt_ip']})" if nbr.get('mgmt_ip') else "(no IP)"
                    logger.info(f"NEIGHBOR DETECTED: {nbr['local_intf']} -> {nbr.get('hostname', 'Unknown')} {ip_info} (Cisco via LLDP) - EXCLUDED")
    else:
        logger.info("LLDP not enabled")
    
    logger.info(f"Total ports with Cisco switch neighbors: {len(excluded_ports)}")
    return excluded_ports

def get_interface_status(shell):
    out = send_cmd(shell, "show ip interface brief", timeout=10)
    up_interfaces = []
    excluded_prefixes = ("Vlan", "Loopback", "Tunnel", "Null", "Port-channel", "Po", "Ap", "AP", "Management", "Mgmt")
    for line in out.splitlines():
        line = line.strip()
        if not line or "Interface" in line:
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 6:
            intf = parts[0]
            if intf.startswith(excluded_prefixes):
                continue
            if parts[4] == "administratively" and len(parts) >= 7:
                status = "down"
                protocol = parts[6]
            else:
                status = parts[4]
                protocol = parts[5]
            if status.lower() == "up" and protocol.lower() == "up":
                if re.match(r"(Gi|Te|Fa|Eth|Fo|Tw|GigabitEthernet|TenGigabitEthernet|FastEthernet|FourtyGig|FortyGig|TwentyFiveGig)", intf, re.IGNORECASE):
                    up_interfaces.append(intf)
    return up_interfaces

def parse_mac_table_interface(raw):
    entries = []
    lines = raw.splitlines()
    in_table = False
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        lower_line = line_clean.lower()
        if 'show mac' in lower_line or 'address-table' in lower_line:
            continue
        if "Mac Address Table" in line_clean or "MAC Address Table" in line_clean or "MaAddresTabl" in line_clean:
            in_table = False
            continue
        if ("vla" in lower_line and ("mac" in lower_line or "addr" in lower_line) and "typ" in lower_line and "port" in lower_line):
            in_table = True
            continue
        if re.match(r'^[-=]+$', line_clean) or "----" in line_clean:
            continue
        if "Total" in line_clean or "Tota" in line_clean:
            continue
        if not in_table:
            continue
        parts = re.split(r"\s+", line_clean)
        if len(parts) < 4:
            continue
        vlan = parts[0]
        mac = parts[1]
        if not vlan[0].isdigit():
            continue
        mac_clean = mac.replace('.', '')
        if len(mac_clean) >= 10 and all(c in '0123456789abcdefABCDEF' for c in mac_clean):
            if '.' not in mac and len(mac_clean) == 12:
                mac = f"{mac_clean[0:4]}.{mac_clean[4:8]}.{mac_clean[8:12]}"
        else:
            continue
        port = None
        mac_type_parts = []
        for i in range(2, len(parts)):
            if re.match(r'^(Gi|Te|Fa|Et|Po|Vl|Tw|Fo)', parts[i], re.IGNORECASE):
                port = parts[i]
                break
            else:
                mac_type_parts.append(parts[i])
        if port:
            mac_type = " ".join(mac_type_parts)
            entries.append({"vlan": vlan, "mac_address": mac, "type": mac_type, "port": port})
    return entries

def select_camera_mac(entries, interface):
    count = len(entries)
    if count == 0:
        return None
    unique_macs = []
    seen_macs = set()
    for entry in entries:
        mac = entry["mac_address"]
        if mac not in seen_macs:
            unique_macs.append(entry)
            seen_macs.add(mac)
    unique_count = len(unique_macs)
    total_count = len(entries)
    dup_count = total_count - unique_count
    if unique_count == 1:
        logger.debug(f"  {interface}: Single MAC found")
    elif unique_count == 2:
        logger.info(f"  {interface}: 2 unique MACs found (Private VLAN detected)")
    elif dup_count > 0:
        logger.info(f"  {interface}: {unique_count} unique MACs found ({dup_count} duplicates removed)")
    else:
        logger.info(f"  {interface}: {unique_count} unique MACs found")
    return unique_macs

def poll_port_for_mac(shell, interface, max_attempts=MAC_POLL_MAX_ATTEMPTS, interval=MAC_POLL_INTERVAL):
    logger.info(f"  [POLL] {interface} - waiting for MAC address...")
    start_time = time.time()
    attempt = 0
    last_log_time = start_time
    while True:
        attempt += 1
        elapsed = time.time() - start_time
        if elapsed > MAC_POLL_HARD_TIMEOUT:
            logger.error(f"  [CRITICAL] {interface}: Hard timeout at {MAC_POLL_HARD_TIMEOUT}s")
            discovery_stats["total_ports_no_mac"] += 1
            return [{"vlan": "UNKNOWN", "mac_address": "UNKNOWN", "type": "TIMEOUT", "port": interface}]
        try:
            cmd = f"show mac address-table interface {interface}"
            mac_out = send_cmd(shell, cmd, timeout=10, silent=True)
            entries = parse_mac_table_interface(mac_out)
            if entries:
                logger.info(f"  [OK] {interface}: MAC found (attempt {attempt}, {elapsed:.1f}s)")
                return select_camera_mac(entries, interface)
            time_since_last_log = elapsed - (last_log_time - start_time)
            if attempt <= 3:
                logger.info(f"  [WAIT] {interface}: No MAC yet (attempt {attempt})")
                last_log_time = time.time()
            elif time_since_last_log >= 30:
                logger.info(f"  [WAIT] {interface}: Still waiting... (attempt {attempt}, {elapsed:.1f}s elapsed)")
                last_log_time = time.time()
            time.sleep(interval)
        except Exception as e:
            logger.error(f"  [ERROR] {interface}: Exception during polling: {e}")
            time.sleep(interval)
            continue

def discover_cameras_from_switch(shell, switch_hostname, switch_type="UNKNOWN"):
    logger.info("="*80)
    logger.info(f"Scanning {switch_type} switch: {switch_hostname}")
    logger.info("="*80)
    hardware_model = get_switch_hardware_model(shell)
    if hardware_model:
        logger.info(f"Hardware model: {hardware_model}")
        detected_type = determine_switch_type(switch_hostname, hardware_model)
        if detected_type != switch_type:
            logger.info(f"Switch type updated: {switch_type} -> {detected_type}")
            switch_type = detected_type
    overall_start = time.time()
    downstream_switches = []
    logger.info("Clearing dynamic MAC address table...")
    send_cmd(shell, "clear mac address-table dynamic", timeout=10)
    logger.info(f"Waiting {MAC_POLL_INITIAL_WAIT}s for initial MAC table repopulation...")
    time.sleep(MAC_POLL_INITIAL_WAIT)
    logger.info("Starting per-port MAC polling...")
    neighbor_ports = get_uplink_ports_from_neighbors(shell, switch_type)
    neighbor_ports_normalized = set()
    for port in neighbor_ports:
        normalized = normalize_interface_name(port)
        neighbor_ports_normalized.add(normalized)
    up_interfaces = get_interface_status(shell)
    logger.info(f"Found {len(up_interfaces)} UP interfaces total")
    camera_count = 0
    scanned_count = 0
    no_mac_count = 0
    neighbor_skip_count = 0
    ports_to_scan = []
    for intf in up_interfaces:
        intf_normalized = normalize_interface_name(intf)
        if intf_normalized in neighbor_ports_normalized:
            logger.debug(f"SKIP: {intf} - HAS CDP/LLDP NEIGHBOR")
            neighbor_skip_count += 1
            continue
        ports_to_scan.append(intf)
    logger.info(f"Ports to scan for cameras: {len(ports_to_scan)}")
    if neighbor_skip_count > 0:
        logger.info(f"Ports with neighbors excluded: {neighbor_skip_count}")
    logger.info("")
    for batch_start in range(0, len(ports_to_scan), MAC_POLL_BATCH_SIZE):
        batch = ports_to_scan[batch_start:batch_start + MAC_POLL_BATCH_SIZE]
        batch_num = (batch_start // MAC_POLL_BATCH_SIZE) + 1
        total_batches = (len(ports_to_scan) + MAC_POLL_BATCH_SIZE - 1) // MAC_POLL_BATCH_SIZE
        batch_start_time = time.time()
        logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} ports)...")
        for idx, intf in enumerate(batch, 1):
            scanned_count += 1
            logger.info(f"  Port {batch_start + idx}/{len(ports_to_scan)}: {intf}")
            mac_entries = poll_port_for_mac(shell, intf)
            if mac_entries:
                for mac_entry in mac_entries:
                    if mac_entry["mac_address"] == "UNKNOWN":
                        camera_info = {
                            "switch_name": switch_hostname, "switch_type": switch_type,
                            "port": mac_entry["port"], "mac_address": "UNKNOWN",
                            "vlan": "UNKNOWN", "mac_count": 1,
                            "status": "TIMEOUT - No MAC learned after 10 minutes"
                        }
                        camera_data.append(camera_info)
                        no_mac_count += 1
                        logger.warning(f"  [!] UNKNOWN MAC on {mac_entry['port']}")
                    else:
                        mac_formatted = convert_mac_format(mac_entry["mac_address"])
                        camera_info = {
                            "switch_name": switch_hostname, "switch_type": switch_type,
                            "port": mac_entry["port"], "mac_address": mac_formatted,
                            "vlan": mac_entry["vlan"], "mac_count": len(mac_entries),
                            "status": "OK"
                        }
                        camera_data.append(camera_info)
                        camera_count += 1
                        discovery_stats["total_cameras_found"] += 1
                        if len(mac_entries) > 1:
                            logger.info(f"  [+] MAC {mac_entries.index(mac_entry)+1}/{len(mac_entries)}: {mac_formatted} on {mac_entry['port']}")
                        else:
                            logger.info(f"  [+] Camera: {mac_formatted} on {mac_entry['port']}")
        batch_elapsed = time.time() - batch_start_time
        logger.info(f"  Batch {batch_num} complete in {batch_elapsed:.1f}s")
        if batch_start + MAC_POLL_BATCH_SIZE < len(ports_to_scan):
            logger.info(f"  Pausing {MAC_POLL_BATCH_PAUSE}s before next batch...")
            time.sleep(MAC_POLL_BATCH_PAUSE)
    overall_elapsed = time.time() - overall_start
    logger.info("")
    logger.info(f"Summary for {switch_hostname}:")
    logger.info(f"  - Total UP interfaces: {len(up_interfaces)}")
    logger.info(f"  - Ports with neighbors excluded: {neighbor_skip_count}")
    logger.info(f"  - Ports scanned: {scanned_count}")
    logger.info(f"  - Cameras found: {camera_count}")
    logger.info(f"  - Ports with UNKNOWN MAC (timeouts): {no_mac_count}")
    logger.info(f"  - Total time: {overall_elapsed:.1f}s")
    logger.info("="*80)
    return downstream_switches

def discover_aggregate_neighbors(shell, current_agg_hostname):
    logger.info("Discovering neighboring aggregate switches...")
    aggregate_neighbors = []
    all_neighbors_by_hostname = {}
    cdp_output = send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        if cdp_neighbors:
            logger.info(f"Found {len(cdp_neighbors)} CDP neighbors")
            for nbr in cdp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    hostname_to_ip.setdefault(nbr["hostname"], nbr["mgmt_ip"])
                    all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
            for nbr in lldp_neighbors:
                if nbr["hostname"]:
                    if not nbr["mgmt_ip"] and nbr["hostname"] in hostname_to_ip:
                        nbr["mgmt_ip"] = hostname_to_ip[nbr["hostname"]]
                    if nbr["mgmt_ip"]:
                        if nbr["hostname"] in hostname_to_ip:
                            authoritative_ip = hostname_to_ip[nbr["hostname"]]
                            if authoritative_ip != nbr["mgmt_ip"]:
                                nbr["mgmt_ip"] = authoritative_ip
                        else:
                            hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                        is_dup = False
                        if nbr["hostname"] in all_neighbors_by_hostname:
                            lldp_intf_norm = normalize_interface_name(nbr["local_intf"])
                            for existing in all_neighbors_by_hostname[nbr["hostname"]]:
                                if (normalize_interface_name(existing.get("local_intf")) == lldp_intf_norm and existing.get("source") == "CDP"):
                                    is_dup = True
                                    break
                        if not is_dup:
                            all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    for hostname, links in all_neighbors_by_hostname.items():
        if is_aggregate_switch(hostname):
            logger.info(f"Evaluating aggregate: {hostname}")
            if hostname != current_agg_hostname:
                mgmt_ip = hostname_to_ip.get(hostname)
                if mgmt_ip:
                    aggregate_neighbors.append({"hostname": hostname, "mgmt_ip": mgmt_ip})
    logger.info(f"Total aggregate neighbors found: {len(aggregate_neighbors)}")
    return aggregate_neighbors

# ============================================================================
# INDIRECT DISCOVERY & PROCESSING LOGIC
# ============================================================================

def discover_devices_via_mac_table(shell, uplink_port, downstream_switch_name, downstream_switch_ip, downstream_switch_type="EDGE"):
    """Fallback: Discover devices behind an unreachable switch by scanning the MAC table on parent."""
    if not ENABLE_INDIRECT_DISCOVERY:
        return 0
    logger.info("="*80)
    logger.info(f"INDIRECT DISCOVERY: Scanning parent port {uplink_port}")
    logger.info(f"  Target (Unreachable): {downstream_switch_name} ({downstream_switch_ip})")
    logger.info(f"  Target Type: {downstream_switch_type}")
    logger.info("="*80)
    try:
        current_hostname = get_hostname(shell)
        cmd = f"show mac address-table interface {uplink_port}"
        mac_output = send_cmd(shell, cmd, timeout=15, silent=True)
        mac_entries = parse_mac_table_interface(mac_output)
        if not mac_entries:
            logger.warning(f"No MAC addresses found on {uplink_port}")
            return 0
        total_macs = len(mac_entries)
        if total_macs < INDIRECT_DISCOVERY_MIN_MACS:
            logger.warning(f"Found {total_macs} MACs (Below threshold {INDIRECT_DISCOVERY_MIN_MACS}) - likely just switch management MAC.")
            return 0
        if total_macs > INDIRECT_DISCOVERY_MAX_MACS:
            logger.warning(f"Found {total_macs} MACs - limiting to {INDIRECT_DISCOVERY_MAX_MACS}")
            mac_entries = mac_entries[:INDIRECT_DISCOVERY_MAX_MACS]
        logger.info(f"Found {len(mac_entries)} indirect device(s).")
        devices_added = 0
        for entry in mac_entries:
            mac_formatted = convert_mac_format(entry["mac_address"])
            
            # CRITICAL FIX: Attribute to the DOWNSTREAM switch, not the parent
            camera_info = {
                "switch_name": downstream_switch_name,      # Where the device physically is
                "switch_type": downstream_switch_type,      # Type of that switch
                "switch_ip": downstream_switch_ip,          # IP of that switch
                "port": "UNKNOWN (Indirect)", 
                "mac_address": mac_formatted, 
                "vlan": entry.get("vlan", "UNKNOWN"),
                "mac_count": 1, 
                "status": "INDIRECT", 
                "discovery_method": "MAC_TABLE_SCAN",
                "parent_switch": current_hostname,          # Where we scanned FROM
                "parent_port": uplink_port,
                "notes": f"Discovered via MAC table on {current_hostname} port {uplink_port} (Switch {downstream_switch_name} Unreachable)"
            }
            camera_data.append(camera_info)
            devices_added += 1
            logger.info(f"  [+] Indirect: {mac_formatted} (VLAN {entry.get('vlan')}) on {downstream_switch_name}")
            
        discovery_stats["total_cameras_found"] += devices_added
        discovery_stats["indirect_discoveries"] += devices_added
        discovery_stats["switches_with_indirect_discovery"] += 1
        return devices_added
    except Exception as e:
        logger.error(f"Error during indirect discovery: {e}")
        return 0

def upgrade_indirect_to_direct_discovery(switch_name, switch_ip):
    """When a switch recovers, upgrade indirect discoveries to direct ones and remove duplicates."""
    logger.info("="*80)
    logger.info(f"DEDUPLICATION: Checking for indirect discoveries on {switch_name}")
    logger.info("="*80)
    
    # Find indirect entries attributed to THIS switch
    indirect_entries = [entry for entry in camera_data if entry.get("switch_name") == switch_name and entry.get("status") == "INDIRECT"]
    
    if not indirect_entries:
        logger.info(f"No indirect discoveries found for {switch_name}")
        return (0, 0, 0)
    
    logger.info(f"Found {len(indirect_entries)} indirect discoveries to check")
    
    # Find new direct entries for THIS switch
    direct_entries = [entry for entry in camera_data if entry.get("switch_name") == switch_name and entry.get("status") != "INDIRECT" and entry.get("mac_address") != "UNKNOWN"]
    
    upgraded = []
    duplicates = []
    
    for indirect_entry in indirect_entries:
        indirect_mac = indirect_entry["mac_address"]
        matching_direct = next((e for e in direct_entries if e["mac_address"] == indirect_mac), None)
        
        if matching_direct:
            logger.info(f"  OK: {indirect_mac} confirmed via direct discovery")
            matching_direct["was_indirect"] = True
            matching_direct["indirect_parent"] = indirect_entry.get("parent_switch")
            matching_direct["notes"] = f"Initially discovered indirectly, confirmed via SSH"
            duplicates.append(indirect_entry)
            upgraded.append(indirect_mac)
        else:
            logger.info(f"  KEEP: {indirect_mac} not found in direct scan")

    for dup in duplicates:
        if dup in camera_data:
            camera_data.remove(dup)
    
    discovery_stats["indirect_discoveries"] -= len(duplicates)
    discovery_stats["indirect_upgraded_to_direct"] += len(duplicates)
    
    return (len(indirect_entries), len(upgraded), len(duplicates))

def check_for_duplicate_macs():
    """Final check for any remaining duplicate MAC addresses."""
    logger.info("="*80)
    logger.info("FINAL DUPLICATE CHECK")
    logger.info("="*80)
    mac_map = {}
    for entry in camera_data:
        mac = entry.get("mac_address")
        if mac and mac != "UNKNOWN":
            mac_map.setdefault(mac, []).append(entry)
    
    duplicates_removed = 0
    for mac, entries in mac_map.items():
        if len(entries) > 1:
            # Prioritize direct discovery over indirect
            direct = [e for e in entries if e.get("status") != "INDIRECT"]
            indirect = [e for e in entries if e.get("status") == "INDIRECT"]
            keeper = direct[0] if direct else entries[0]
            to_remove = [e for e in entries if e != keeper]
            
            for item in to_remove:
                if item in camera_data:
                    camera_data.remove(item)
                    duplicates_removed += 1
            logger.warning(f"Removed {len(to_remove)} duplicates for MAC {mac}")
            
    discovery_stats["duplicates_removed"] = duplicates_removed
    return duplicates_removed

def process_switch(parent_ip, neighbor_info, switch_type="UNKNOWN", is_retry=False):
    """Process a switch: Attempt SSH. If SSH fails, attempt Indirect MAC Discovery."""
    global failed_switches
    switch_ip = neighbor_info["mgmt_ip"]
    switch_name = neighbor_info["remote_name"]
    local_intf = neighbor_info["local_intf"]
    if switch_type == "AGGREGATE":
        return True
    if not switch_ip or (switch_ip in visited_switches and not is_retry):
        return True
    logger.info("*"*80)
    logger.info(f"Processing {switch_type}: {switch_name} ({switch_ip})")
    logger.info("*"*80)
    if not is_retry:
        visited_switches.add(switch_ip)
        discovery_stats["switches_attempted"] += 1
        discovery_stats["switches_by_type"][switch_type]["attempted"] += 1
    else:
        discovery_stats["switches_retried_from_seed"] += 1
    try:
        parent_hostname = get_hostname(agg_shell) or agg_hostname or "UNKNOWN"
        if not verify_aggregate_connection():
            raise NetworkConnectionError("Parent connection lost", reconnect_needed=True)
        
        # 1. ATTEMPT SSH HOP
        ssh_success = ssh_to_device(switch_ip, switch_name, parent_hostname)
        if ssh_success is None: 
            return True # IP belongs to current switch
        
        # 2. IF SSH FAILS -> INDIRECT DISCOVERY
        if not ssh_success:
            logger.error(f"SSH failed to {switch_name}. Attempting Indirect Discovery...")
            devices_found = 0
            if ENABLE_INDIRECT_DISCOVERY and local_intf:
                devices_found = discover_devices_via_mac_table(agg_shell, local_intf, switch_name, switch_ip, switch_type)
            failure_info = {
                "switch_name": switch_name, "switch_ip": switch_ip, "switch_type": switch_type,
                "parent_ip": parent_ip, "parent_hostname": parent_hostname,
                "reason": "SSH Failed - Indirect Discovery Run",
                "local_intf": local_intf, "is_retry": is_retry,
                "indirect_devices_found": devices_found
            }
            if not is_retry:
                failed_switches.append(failure_info)
                logger.warning(f"Added {switch_name} to retry queue")
            discovery_stats["switches_by_type"][switch_type]["failed"] += 1
            discovery_stats["switches_failed_unreachable"] += 1
            discovery_stats["failure_details"].append(failure_info)
            return devices_found > 0

        # 3. IF SSH SUCCESS -> NORMAL DISCOVERY
        actual_hostname = get_hostname(agg_shell)
        if actual_hostname == parent_hostname:
            logger.error(f"FATAL: Hostname verification failed (Still on {parent_hostname})")
            return False
        try:
            downstream_switches = discover_cameras_from_switch(agg_shell, actual_hostname, switch_type)
            discovery_stats["switches_successfully_scanned"] += 1
            discovery_stats["switches_by_type"][switch_type]["successful"] += 1
            if is_retry:
                discovery_stats["switches_recovered_on_retry"] += 1
                logger.info(f"[RECOVERED] RETRY SUCCESS: {switch_name} recovered on retry from seed")
                
                # CRITICAL: DEDUPLICATION ON RETRY (Using correct switch hostname)
                upgrade_indirect_to_direct_discovery(actual_hostname, switch_ip)
            
            if downstream_switches:
                for ds in downstream_switches:
                    ds_info = {"remote_name": ds["hostname"], "mgmt_ip": ds["ip"], "local_intf": ds["local_port"]}
                    try:
                        process_switch(switch_ip, ds_info, ds["type"], is_retry=False)
                    except Exception as e:
                        logger.error(f"Downstream error: {e}")
        except Exception as e:
            logger.error(f"Error scanning switch: {e}")
        exit_device()
        return True
    except NetworkConnectionError as e:
        if getattr(e, 'reconnect_needed', False):
            raise
        logger.error(f"Connection error: {e}")
        return False

def scan_aggregate_switch(shell, agg_ip, aggregates_to_process=None, seed_ips=None, resume_mode=False):
    """Scan an aggregate switch - discover neighbors AND scan for cameras."""
    if not resume_mode and agg_ip in visited_switches:
        logger.info(f"Aggregate {agg_ip} already visited")
        return []
    if not resume_mode:
        visited_switches.add(agg_ip)
        discovered_aggregates.add(agg_ip)
    hostname = get_hostname(shell)
    aggregate_hostnames[agg_ip] = hostname
    hardware_model = get_switch_hardware_model(shell)
    if hardware_model:
        logger.info(f"Hardware model: {hardware_model}")
        detected_type = determine_switch_type(hostname, hardware_model)
        if detected_type != "AGGREGATE":
            logger.warning(f"WARNING: Expected AGGREGATE but hardware indicates {detected_type}")
    if not resume_mode:
        discovery_stats["switches_attempted"] += 1
        discovery_stats["switches_by_type"]["AGGREGATE"]["attempted"] += 1
    logger.info("#"*80)
    if resume_mode:
        logger.info(f"RESUMING AGGREGATE SCAN: {hostname} ({agg_ip})")
    else:
        logger.info(f"Scanning AGGREGATE: {hostname} ({agg_ip})")
    logger.info("#"*80)
    new_aggregates = []
    if not resume_mode:
        new_aggregates = discover_aggregate_neighbors(shell, hostname)
        if aggregates_to_process is not None and seed_ips is not None:
            for agg in new_aggregates:
                if agg["mgmt_ip"] in seed_ips:
                    continue
                if agg["mgmt_ip"] not in aggregates_to_process:
                    aggregates_to_process.append(agg["mgmt_ip"])
                    logger.info(f">>> ADDED NEW AGGREGATE TO QUEUE: {agg['hostname']} ({agg['mgmt_ip']})")
    else:
        logger.info(">>> Resume mode: skipping aggregate discovery")
    
    logger.info(">>> Scanning for cameras (excluding ports with neighbors)...")
    try:
        # Note: We capture output but discover_cameras_from_switch doesn't return downstream nodes anymore
        # because the logic is now handled by process_switch iteration
        _ = discover_cameras_from_switch(shell, hostname, "AGGREGATE")
    except Exception as e:
        logger.error(f"Error scanning aggregate for cameras: {e}")

    logger.info(">>> Discovering downstream switches for topology...")
    all_neighbors_by_hostname = {}
    cdp_output = send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "CDP is not enabled" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        for nbr in cdp_neighbors:
            if nbr["hostname"] and nbr["mgmt_ip"]:
                hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        for nbr in lldp_neighbors:
            if nbr["hostname"] and nbr["mgmt_ip"]:
                if nbr["hostname"] not in hostname_to_ip:
                    hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)

    logger.info(f"Found {len(all_neighbors_by_hostname)} total neighbors")
    switch_counts = {"EDGE": 0, "AGGREGATE": 0, "SERVER": 0, "OTHER": 0}
    for nhost, links in all_neighbors_by_hostname.items():
        switch_type = determine_switch_type(nhost)
        mgmt_ip = hostname_to_ip.get(nhost)
        if switch_type == "AGGREGATE":
            continue
        if mgmt_ip in visited_switches:
            continue
        switch_counts[switch_type] += 1
        logger.info(f"{switch_type} switch detected: {nhost} - {mgmt_ip}")
        for link in links:
            neighbor_info = {"remote_name": nhost, "mgmt_ip": mgmt_ip, "local_intf": link.get("local_intf")}
            try:
                process_switch(agg_ip, neighbor_info, switch_type, is_retry=False)
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False):
                    raise
            break
    if not resume_mode:
        discovery_stats["switches_successfully_scanned"] += 1
        discovery_stats["switches_by_type"]["AGGREGATE"]["successful"] += 1
    logger.info(f"Summary for {hostname}: Edge: {switch_counts['EDGE']}, Server: {switch_counts['SERVER']}")
    return new_aggregates

def retry_failed_switches_from_seed():
    global failed_switches, agg_shell
    if not failed_switches:
        logger.info("PHASE 3: No failed switches to retry")
        return
    logger.info("="*80)
    logger.info(f"PHASE 3: RETRYING {len(failed_switches)} FAILED SWITCHES FROM SEED")
    logger.info("="*80)
    try:
        if not verify_aggregate_connection():
            reconnect_to_aggregate("Phase 3 Retry")
    except Exception as e:
        logger.error(f"Cannot reconnect to seed for retries: {e}")
        return
    
    current_hostname = get_hostname(agg_shell)
    seed_hostname = agg_hostname or "UNKNOWN"
    if current_hostname != seed_hostname:
        logger.warning(f"Attempting to return to seed...")
        try:
            for _ in range(5):
                exit_device()
                time.sleep(0.5)
                if get_hostname(agg_shell) == seed_hostname:
                    break
            else:
                reconnect_to_aggregate("Return to seed for retry")
        except Exception:
            return

    switches_to_retry = failed_switches.copy()
    retry_successes = 0
    retry_failures = 0
    for idx, switch_info in enumerate(switches_to_retry, 1):
        switch_name = switch_info["switch_name"]
        switch_ip = switch_info["switch_ip"]
        switch_type = switch_info["switch_type"]
        neighbor_info = {"remote_name": switch_name, "mgmt_ip": switch_ip, "local_intf": switch_info.get("local_intf", "Unknown")}
        logger.info(f"[RETRY {idx}/{len(switches_to_retry)}] {switch_name} ({switch_ip})")
        try:
            success = process_switch(SEED_SWITCH_IP, neighbor_info, switch_type, is_retry=True)
            if success:
                retry_successes += 1
                logger.info(f"[SUCCESS] Retry {idx}: RECOVERED")
            else:
                retry_failures += 1
                logger.warning(f"[FAILED] Retry {idx}: STILL FAILED")
        except Exception as e:
            logger.error(f"Error retrying: {e}")
            retry_failures += 1
            if isinstance(e, NetworkConnectionError) and getattr(e, 'reconnect_needed', False):
                try:
                    reconnect_to_aggregate("Phase 3 recovery")
                except:
                    break
    logger.info(f"PHASE 3 COMPLETE. Recovered: {retry_successes}, Failed: {retry_failures}")

def print_enhanced_statistics():
    logger.info("")
    logger.info("="*80)
    logger.info("DETAILED DISCOVERY STATISTICS")
    logger.info("="*80)
    logger.info(f"Total switches attempted: {discovery_stats['switches_attempted']}")
    logger.info(f"Successfully scanned (direct): {discovery_stats['switches_successfully_scanned']}")
    
    initial_failures = discovery_stats['switches_attempted'] - (
        discovery_stats['switches_successfully_scanned'] - 
        discovery_stats['switches_recovered_on_retry']
    )
    final_failures = discovery_stats['switches_attempted'] - discovery_stats['switches_successfully_scanned']
    logger.info(f"Initial failures: {initial_failures}")
    logger.info(f"Recovered in Phase 3: {discovery_stats['switches_recovered_on_retry']}")
    logger.info(f"Final failures: {final_failures}")
    
    if ENABLE_INDIRECT_DISCOVERY:
        logger.info("")
        logger.info("INDIRECT DISCOVERY STATISTICS")
        logger.info("-"*80)
        indirect_devices = discovery_stats.get("indirect_discoveries", 0)
        switches_with_indirect = discovery_stats.get("switches_with_indirect_discovery", 0)
        logger.info(f"Switches with indirect discovery: {switches_with_indirect}")
        logger.info(f"Devices found via MAC table: {indirect_devices}")
        logger.info(f"Upgraded to Direct: {discovery_stats.get('indirect_upgraded_to_direct', 0)}")
        logger.info(f"Duplicates Removed: {discovery_stats.get('duplicates_removed', 0)}")
        if indirect_devices > 0:
            logger.info("")
            logger.info("Indirect discoveries by switch:")
            for failure in discovery_stats.get("failure_details", []):
                if failure.get("indirect_devices_found", 0) > 0:
                    logger.info(f"  - {failure['switch_name']} ({failure['switch_ip']}): {failure['indirect_devices_found']} device(s)")

    logger.info("")
    logger.info("DEVICE DISCOVERY BREAKDOWN")
    logger.info("-"*80)
    direct_cameras = sum(1 for cam in camera_data if cam.get("status") != "INDIRECT" and cam.get("mac_address") != "UNKNOWN")
    indirect_cameras = sum(1 for cam in camera_data if cam.get("status") == "INDIRECT")
    unknown_mac = sum(1 for cam in camera_data if cam.get("mac_address") == "UNKNOWN")
    logger.info(f"Total devices found: {len(camera_data)}")
    logger.info(f"  - Direct discovery (via SSH): {direct_cameras}")
    logger.info(f"  - Indirect discovery (via MAC table): {indirect_cameras}")
    logger.info(f"  - Unknown MAC (timeouts): {unknown_mac}")

def main():
    logger.info("="*80)
    logger.info("CAMERA DISCOVERY SCRIPT STARTED")
    logger.info(f"Seed switch: {SEED_SWITCH_IP}")
    logger.info("="*80)
    
    try:
        connect_to_seed()
    except NetworkConnectionError as e:
        logger.error(f"Failed to connect to seed: {e}")
        return
    
    seed_ips = set([SEED_SWITCH_IP])
    try:
        ip_brief_out = send_cmd(agg_shell, "show ip interface brief", timeout=10, silent=True)
        for line in ip_brief_out.splitlines():
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 2:
                ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", parts[1])
                if ip_match:
                    seed_ips.add(ip_match.group(1))
    except Exception:
        pass
    
    try:
        aggregates_to_process = deque()
        logger.info("PHASE 1: DISCOVERING AGGREGATE SWITCHES")
        reconnect_attempts = 0
        max_reconnects = AGG_MAX_RETRIES
        seed_scan_complete = False
        while reconnect_attempts < max_reconnects and not seed_scan_complete:
            try:
                if SEED_SWITCH_IP in discovered_aggregates:
                    new_aggregates = scan_aggregate_switch(agg_shell, SEED_SWITCH_IP, aggregates_to_process, seed_ips, resume_mode=True)
                    seed_scan_complete = True
                else:
                    new_aggregates = scan_aggregate_switch(agg_shell, SEED_SWITCH_IP, aggregates_to_process, seed_ips, resume_mode=False)
                    seed_scan_complete = True
                    break
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False) or not verify_aggregate_connection():
                    reconnect_attempts += 1
                    logger.error("Connection to seed lost during Phase 1")
                    if reconnect_attempts < max_reconnects:
                        try:
                            reconnect_to_aggregate("Phase 1")
                        except NetworkConnectionError:
                            return
                    else:
                        return

        logger.info(f"PHASE 2: PROCESSING {len(aggregates_to_process)} ADDITIONAL AGGREGATES")
        while aggregates_to_process:
            agg_ip = aggregates_to_process.popleft()
            if agg_ip in seed_ips or agg_ip in discovered_aggregates:
                continue
            logger.info(f"PROCESSING AGGREGATE: {agg_ip}")
            aggregate_reconnect_attempts = 0
            aggregate_processed = False
            while aggregate_reconnect_attempts < max_reconnects and not aggregate_processed:
                try:
                    if not verify_aggregate_connection():
                        raise NetworkConnectionError("Seed lost", reconnect_needed=True)
                    parent_hostname = get_hostname(agg_shell)
                    hop_success = ssh_to_device(target_ip=agg_ip, parent_hostname=parent_hostname)
                    if not hop_success:
                        break
                    scan_aggregate_switch(agg_shell, agg_ip, aggregates_to_process, seed_ips)
                    logger.info("Returning to seed...")
                    exit_device()
                    time.sleep(1)
                    if not verify_aggregate_connection():
                        raise NetworkConnectionError("Lost seed connection", reconnect_needed=True)
                    aggregate_processed = True
                except NetworkConnectionError as e:
                    if getattr(e, 'reconnect_needed', False) or not verify_aggregate_connection():
                        aggregate_reconnect_attempts += 1
                        if aggregate_reconnect_attempts < max_reconnects:
                            try:
                                reconnect_to_aggregate(f"Aggregate {agg_ip}")
                                aggregate_processed = True
                            except NetworkConnectionError:
                                aggregate_processed = True
                        else:
                            aggregate_processed = True
                    else:
                        aggregate_processed = True
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        try:
            retry_failed_switches_from_seed()
        except Exception as e:
            logger.error(f"Error in Phase 3: {e}", exc_info=True)
        
        # FINAL PHASE: DEDUPLICATION
        try:
            check_for_duplicate_macs()
        except Exception as e:
            logger.error(f"Error in duplicate cleanup: {e}")

        try:
            if agg_client:
                agg_client.close()
        except:
            pass
    
    print_enhanced_statistics()
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"camera_inventory_{len(camera_data)}devices_{timestamp}.json"
    output_data = {
        "discovery_metadata": {
            "timestamp": timestamp, "seed_switch": SEED_SWITCH_IP,
            "total_devices": len(camera_data), "total_aggregates": len(discovered_aggregates)
        },
        "discovery_statistics": discovery_stats, "cameras": camera_data
    }
    with open(json_file, "w", encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved: {json_file}")
    
    if camera_data:
        csv_file = f"camera_inventory_{len(camera_data)}devices_{timestamp}.csv"
        with open(csv_file, "w", newline="", encoding='utf-8') as f:
            fieldnames = ["switch_name", "switch_type", "switch_ip", "port", "mac_address", "vlan", "mac_count", "status", "discovery_method", "parent_switch", "parent_port", "was_indirect", "notes"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in camera_data:
                csv_row = {k: v for k, v in row.items() if k in fieldnames}
                writer.writerow(csv_row)
        logger.info(f"Saved: {csv_file}")
    logger.info(f"Log file: {log_filename}")

if __name__ == "__main__":
    main()
