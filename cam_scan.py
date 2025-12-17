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

SEED_SWITCH_IP = "192.168.1.1"
TIMEOUT = 150
MAX_READ = 65535
CREDENTIAL_SETS = [
    {"username": "admin",  "password": "cisco",  "enable": ""} ,
    {"username": "",  "password": "",  "enable": ""}
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
    "IE-": "EDGE",           # IE-3300, IE-3400, etc.
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

def determine_switch_type(hostname):
    if not hostname:
        return "UNKNOWN"
    upper = hostname.upper()
    if "SMSAGG" in upper:
        return "AGGREGATE"
    elif "SMSSRV" in upper:
        return "SERVER"
    elif "SMSACC" in upper:
        return "EDGE"
    elif "SMSIE" in upper:
        return "EDGE"
    elif "SMS" in upper:
        return "EDGE"
    return "OTHER"

def is_aggregate_switch(hostname, hardware_model=None):
    """
    Check if a switch is an aggregate switch.
    Now supports hardware model detection.
    
    Args:
        hostname: Switch hostname
        hardware_model: Hardware model string (optional)
    
    Returns:
        bool: True if aggregate switch
    """
    switch_type = determine_switch_type(hostname, hardware_model)
    return switch_type == "AGGREGATE"


def is_server_switch(hostname):
    return determine_switch_type(hostname) == "SERVER"

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
    
    # ========================================================================
    # FIX: EXACT IP MATCHING (NOT SUBSTRING)
    # ========================================================================
    try:
        ip_brief_out = send_cmd(agg_shell, "show ip interface brief", timeout=10, silent=True)
        for line in ip_brief_out.splitlines():
            # Parse the IP address from the line (exact match, not substring)
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 2:
                line_ip = parts[1]
                # Exact IP match (not substring)
                if line_ip == target_ip and ("up" in line.lower() or "administratively" in line.lower()):
                    logger.info(f"Target IP {target_ip} belongs to current switch {parent_hostname} - already connected")
                    logger.info(f"This is not a separate device to SSH to - it's an interface on current switch")
                    return None
    except Exception as e:
        logger.debug(f"Could not check local IPs: {e}")
    # ========================================================================
    
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
    """
    Parse LLDP neighbor details with improved block handling.
    
    FIXED: Now correctly handles blocks that contain both neighbor data
    AND "Total entries displayed" footer text.
    """
    neighbors = []
    blocks = re.split(r'[-]{40,}', output)
    
    for block in blocks:
        if not block.strip():
            continue
        
        # FIXED: Only skip blocks that don't contain neighbor data
        # If "Local Intf:" is present, this is real neighbor data even if it has "Total entries"
        if "Local Intf:" not in block:
            continue
        
        # Skip capability code headers (they won't have Local Intf anyway)
        if "Capability codes:" in block and "Local Intf:" not in block:
            continue
        
        neighbor = {
            "hostname": None,
            "mgmt_ip": None,
            "local_intf": None,
            "remote_intf": None,
            "sys_descr": "",
            "source": "LLDP"
        }
        
        if m := re.search(r'^Local Intf:\s*(\S+)', block, re.M):
            neighbor["local_intf"] = m.group(1)
        
        if m := re.search(r'^Port id:\s*(\S+)', block, re.M | re.I):
            neighbor["remote_intf"] = m.group(1)
        
        if m := re.search(r'^System Name:\s*(.+?)$', block, re.M):
            hostname = m.group(1).strip().strip('"').strip("'")
            neighbor["hostname"] = hostname
        
        if m := re.search(r'^System Description:\s*\n([\s\S]+?)(?=^Time remaining:|^System Capabilities:|^Management Addresses:|$)', block, re.M):
            neighbor["sys_descr"] = m.group(1).strip()
        
        # Validate it's a Cisco device
        if neighbor["sys_descr"]:
            sys_desc_lower = neighbor["sys_descr"].lower()
            if "cisco ios" not in sys_desc_lower and "cisco nx-os" not in sys_desc_lower:
                logger.debug(f"  X Skipping non-Cisco LLDP device: {neighbor.get('hostname', 'Unknown')} "
                           f"(Desc: {neighbor['sys_descr'][:50]}...)")
                continue
        else:
            logger.debug(f"  X Skipping LLDP device without System Description: {neighbor.get('hostname', 'Unknown')}")
            continue
        
        # Try to extract hostname from system description if not found
        if not neighbor["hostname"] and neighbor["sys_descr"]:
            m = re.search(r'(\S+)\s+Software', neighbor["sys_descr"], re.I)
            if m:
                neighbor["hostname"] = m.group(1)
        
        # Parse management IP
        if m := re.search(r'^Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)', block, re.M):
            neighbor["mgmt_ip"] = m.group(1)
        
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'Management Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'IPv4:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        
        # Only add if we have management IP
        if neighbor["mgmt_ip"]:
            if not neighbor["hostname"]:
                neighbor["hostname"] = f"LLDP-Device-{neighbor['mgmt_ip']}"
                logger.warning(f"No hostname in LLDP for {neighbor['mgmt_ip']}")
            neighbors.append(neighbor)
            logger.debug(f"  OK Cisco LLDP neighbor: {neighbor['hostname']} ({neighbor['mgmt_ip']}) "
                        f"via {neighbor['local_intf']} <-> {neighbor['remote_intf']}")
        else:
            logger.debug(f"  X Skipping LLDP neighbor without mgmt IP: {neighbor.get('hostname', 'Unknown')}")
    
    return neighbors

def get_interface_status(shell):
    """
    Get all UP physical interfaces from the switch.
    Excludes: VLANs, Access Points (AppGigabitEthernet), and other logical interfaces
    """
    out = send_cmd(shell, "show ip interface brief", timeout=10)
    up_interfaces = []
    
    # Interfaces to exclude (virtual/logical/management)
    excluded_prefixes = (
        "Vlan", "Loopback", "Tunnel", "Null", 
        "Port-channel", "Po",
        "Ap", "AP",  # AppGigabitEthernet (IOx application hosting)
        "Management", "Mgmt"
    )
    
    for line in out.splitlines():
        line = line.strip()
        if not line or "Interface" in line:
            continue
        
        parts = re.split(r"\s+", line)
        if len(parts) >= 6:
            intf = parts[0]
            
            # Skip excluded interface types
            if intf.startswith(excluded_prefixes):
                logger.debug(f"Skipping virtual/logical interface: {intf}")
                continue
            
            # Handle "administratively down" case
            if parts[4] == "administratively" and len(parts) >= 7:
                status = "down"
                protocol = parts[6]
            else:
                status = parts[4]
                protocol = parts[5]
            
            # Only include physical interfaces that are up/up
            if status.lower() == "up" and protocol.lower() == "up":
                if re.match(r"(Gi|Te|Fa|Eth|Fo|Tw|"
                           r"GigabitEthernet|TenGigabitEthernet|FastEthernet|"
                           r"FourtyGig|FortyGig|TwentyFiveGig)", intf, re.IGNORECASE):
                    up_interfaces.append(intf)
    
    return up_interfaces

def discover_cameras_from_switch(shell, switch_hostname, switch_type="UNKNOWN"):
    """
    Enhanced camera discovery with infinite MAC polling for UP ports.
    Tracks ALL unique MACs per port (not just one).
    Excludes ANY port with a CDP/LLDP neighbor.
    
    FIXED: Uses normalized interface name sets for reliable port exclusion
    """
    logger.info("="*80)
    logger.info(f"Scanning {switch_type} switch: {switch_hostname}")
    logger.info("="*80)

    hardware_model = get_switch_hardware_model(shell)
    if hardware_model:
        logger.info(f"Hardware model: {hardware_model}")
        # Re-determine switch type with hardware info
        detected_type = determine_switch_type(switch_hostname, hardware_model)
        if detected_type != switch_type:
            logger.info(f"Switch type updated: {switch_type} -> {detected_type} (based on hardware)")
            switch_type = detected_type
    
    overall_start = time.time()
    
    # No more downstream switch discovery - handled by neighbor port exclusion
    downstream_switches = []
    
    logger.info("Clearing dynamic MAC address table...")
    send_cmd(shell, "clear mac address-table dynamic", timeout=10)
    
    logger.info(f"Waiting {MAC_POLL_INITIAL_WAIT}s for initial MAC table repopulation...")
    time.sleep(MAC_POLL_INITIAL_WAIT)
    logger.info("Starting per-port MAC polling (will wait indefinitely for UP ports)...")
    
    # Get ALL ports with CDP/LLDP neighbors (these will be excluded)
    neighbor_ports = get_uplink_ports_from_neighbors(shell, switch_type)
    if not neighbor_ports:
        logger.warning(f"No CDP/LLDP neighbors detected on {switch_hostname}")
    else:
        logger.info(f"Ports with neighbors to exclude: {len(neighbor_ports)}")
    
    # FIXED: Pre-normalize all neighbor ports for faster/reliable comparison
    neighbor_ports_normalized = set()
    for port in neighbor_ports:
        normalized = normalize_interface_name(port)
        neighbor_ports_normalized.add(normalized)
        logger.debug(f"Neighbor port normalized: {port} -> {normalized}")
    
    up_interfaces = get_interface_status(shell)
    logger.info(f"Found {len(up_interfaces)} UP interfaces total")
    
    camera_count = 0
    scanned_count = 0
    no_mac_count = 0
    neighbor_skip_count = 0
    
    # Build list of ports to scan (exclude any with neighbors)
    ports_to_scan = []
    for intf in up_interfaces:
        # FIXED: Normalize interface before checking
        intf_normalized = normalize_interface_name(intf)
        
        # Check if this port has a CDP/LLDP neighbor
        if intf_normalized in neighbor_ports_normalized:
            logger.debug(f"SKIP: {intf} (normalized: {intf_normalized}) - HAS CDP/LLDP NEIGHBOR")
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
            
            mac_entries = poll_port_for_mac(shell, intf)  # Returns LIST of MAC entries
            
            if mac_entries:
                for mac_entry in mac_entries:  # Loop through ALL MACs found on port
                    # Check if this is an UNKNOWN MAC (timeout case)
                    if mac_entry["mac_address"] == "UNKNOWN":
                        camera_info = {
                            "switch_name": switch_hostname,
                            "switch_type": switch_type,
                            "port": mac_entry["port"],
                            "mac_address": "UNKNOWN",
                            "vlan": "UNKNOWN",
                            "mac_count": 1,
                            "status": "TIMEOUT - No MAC learned after 10 minutes"
                        }
                        camera_data.append(camera_info)
                        no_mac_count += 1
                        logger.warning(f"  [!] UNKNOWN MAC on {mac_entry['port']} - Port UP but no MAC learned (TIMEOUT)")
                    else:
                        # Normal camera with valid MAC
                        mac_formatted = convert_mac_format(mac_entry["mac_address"])
                        camera_info = {
                            "switch_name": switch_hostname,
                            "switch_type": switch_type,
                            "port": mac_entry["port"],
                            "mac_address": mac_formatted,
                            "vlan": mac_entry["vlan"],
                            "mac_count": len(mac_entries),  # Track how many total MACs on this port
                            "status": "OK"
                        }
                        camera_data.append(camera_info)
                        camera_count += 1
                        discovery_stats["total_cameras_found"] += 1
                        
                        # Enhanced logging for multiple MACs
                        if len(mac_entries) > 1:
                            logger.info(f"  [+] MAC {mac_entries.index(mac_entry)+1}/{len(mac_entries)}: {mac_formatted} on {mac_entry['port']} (VLAN {mac_entry['vlan']})")
                        else:
                            logger.info(f"  [+] Camera: {mac_formatted} on {mac_entry['port']} (VLAN {mac_entry['vlan']})")
        
        batch_elapsed = time.time() - batch_start_time
        logger.info(f"  Batch {batch_num} complete: {len(batch)} ports in {batch_elapsed:.1f}s")
        
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
    
    # Return empty list (no downstream switch processing)
    return downstream_switches


def parse_mac_table_interface(raw):
    """
    Parse MAC address table output - handles backspaces and corruption.
    """
    entries = []
    lines = raw.splitlines()
    in_table = False
    
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        
        # Skip command echoes
        lower_line = line_clean.lower()
        if 'show mac' in lower_line or 'address-table' in lower_line:
            continue
        
        # Detect table header
        if "Mac Address Table" in line_clean or "MAC Address Table" in line_clean or "MaAddresTabl" in line_clean:
            in_table = False
            continue
        
        # Detect column headers (flexible matching for corrupted text)
        if ("vla" in lower_line and ("mac" in lower_line or "addr" in lower_line) and 
            "typ" in lower_line and "port" in lower_line):
            in_table = True
            continue
        
        # Skip separators
        if re.match(r'^[-=]+$', line_clean) or "----" in line_clean:
            continue
        
        # Skip summaries
        if "Total" in line_clean or "Tota" in line_clean:
            continue
        
        # Must be in table
        if not in_table:
            continue
        
        # Parse entry
        parts = re.split(r"\s+", line_clean)
        if len(parts) < 4:
            continue
        
        vlan = parts[0]
        mac = parts[1]
        
        # VLAN must start with digit
        if not vlan[0].isdigit():
            continue
        
        # Look for something that looks like a MAC
        # Valid: xxxx.xxxx.xxxx or xxxxxxxxxxxx (dots optional due to corruption)
        mac_clean = mac.replace('.', '')
        if len(mac_clean) >= 10 and all(c in '0123456789abcdefABCDEF' for c in mac_clean):
            # Looks like hex - accept it
            if '.' not in mac and len(mac_clean) == 12:
                # Reconstruct dots: b8a44f55a2ef -> b8a4.4f55.a2ef
                mac = f"{mac_clean[0:4]}.{mac_clean[4:8]}.{mac_clean[8:12]}"
        else:
            continue
        
        # Find port
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
            entries.append({
                "vlan": vlan,
                "mac_address": mac,
                "type": mac_type,
                "port": port
            })
    
    return entries



def determine_switch_type(hostname, hardware_model=None):
    """
    Determine switch type based on hardware model and hostname.
    
    Priority:
    1. Hardware model (most reliable)
    2. Hostname pattern (fallback)
    
    Args:
        hostname: Switch hostname
        hardware_model: Hardware model string (optional)
    
    Returns:
        str: "AGGREGATE", "EDGE", "SERVER", or "OTHER"
    """
    if not hostname:
        return "OTHER"
    
    # METHOD 1: Check hardware model first (most reliable)
    if hardware_model:
        hardware_upper = hardware_model.upper()
        
        for pattern, switch_type in HARDWARE_MODEL_MAPPING.items():
            if pattern.upper() in hardware_upper:
                # Special case: 9300 can be either EDGE or SERVER
                if "9300" in pattern:
                    if "SMSSRV" in hostname.upper() or "SRV" in hostname.upper():
                        logger.debug(f"Hardware {hardware_model} + hostname {hostname} -> SERVER")
                        return "SERVER"
                    else:
                        logger.debug(f"Hardware {hardware_model} -> EDGE")
                        return "EDGE"
                
                logger.debug(f"Hardware {hardware_model} matches '{pattern}' -> {switch_type}")
                return switch_type
    
    # METHOD 2: Fallback to hostname-based detection
    upper = hostname.upper()
    
    # Aggregate switches
    if "SMSAGG" in upper:
        return "AGGREGATE"
    
    # Server switches
    if "SMSSRV" in upper:
        return "SERVER"
    
    # Edge/Access switches
    if any(x in upper for x in ["SMSACC", "SMSIE", "SMS"]):
        return "EDGE"
    
    return "OTHER"


def get_switch_hardware_model(shell):
    """
    Get the hardware model of the current switch.
    
    Returns:
        str: Hardware model (e.g., "WS-C3850-24P", "C9300-48U", "IE-3300-8T2S")
             or None if unable to determine
    """
    try:
        # Try "show version"
        version_out = send_cmd(shell, "show version", timeout=10, silent=True)
        
        # Look for Model number line
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
        
        # Try "show inventory"
        inv_out = send_cmd(shell, "show inventory", timeout=10, silent=True)
        pid_match = re.search(r"PID:\s*(\S+)", inv_out)
        if pid_match:
            model = pid_match.group(1)
            logger.debug(f"Detected hardware model from inventory: {model}")
            return model
        
        logger.debug("Could not determine hardware model")
        return None
        
    except Exception as e:
        logger.warning(f"Error getting hardware model: {e}")
        return None


def normalize_interface_name(intf):
    """
    Normalize interface names to a standard format.
    
    CRITICAL FIX: Now handles *GigE patterns (TwentyFiveGigE, TenGigE, GigE, FortyGigE)
    These are abbreviated forms that Cisco uses in "show ip interface brief"
    """
    if not intf:
        return ""
    
    intf = intf.strip()
    
    # Comprehensive replacement mappings
    # Order matters - check longer patterns first!
    replacements = [
        # TenGigabit variants
        ('TenGigabitEthernet', 'tengigabitethernet'),
        ('TenGigE', 'tengigabitethernet'),           # CRITICAL: Handle show ip int brief format
        ('TenGig', 'tengigabitethernet'),
        ('Ten', 'tengigabitethernet'),
        ('Te', 'tengigabitethernet'),
        
        # GigabitEthernet variants
        ('GigabitEthernet', 'gigabitethernet'),
        ('GigE', 'gigabitethernet'),                 # CRITICAL: Handle show ip int brief format
        ('Gig', 'gigabitethernet'),
        ('Gi', 'gigabitethernet'),
        
        # FastEthernet variants
        ('FastEthernet', 'fastethernet'),
        ('Fas', 'fastethernet'),
        ('Fa', 'fastethernet'),
        
        # FortyGigabit variants
        ('FortyGigabitEthernet', 'fortygigabitethernet'),
        ('FortyGigE', 'fortygigabitethernet'),       # CRITICAL: Handle show ip int brief format
        ('FortyGig', 'fortygigabitethernet'),
        ('For', 'fortygigabitethernet'),
        ('Fo', 'fortygigabitethernet'),
        
        # TwentyFiveGig variants
        ('TwentyFiveGigE', 'twentyfivegigabitethernet'),  # CRITICAL: Handle show ip int brief format
        ('TwentyFiveGig', 'twentyfivegigabitethernet'),
        ('Twe', 'twentyfivegigabitethernet'),
        ('Tw', 'twentyfivegigabitethernet'),
        
        # Basic Ethernet
        ('Ethernet', 'ethernet'),
        ('Eth', 'ethernet'),
        ('Et', 'ethernet'),
        
        # Port-channel
        ('Port-channel', 'port-channel'),
        ('Po', 'port-channel'),
        
        # VLAN
        ('Vlan', 'vlan'),
        ('Vl', 'vlan'),
    ]
    
    # Check each pattern
    for short, full in replacements:
        if intf.startswith(short):
            # Make sure it's followed by a digit or slash (not part of a longer word)
            if len(intf) > len(short):
                next_char = intf[len(short)]
                if next_char.isdigit() or next_char in ['/', ' ']:
                    # Replace and lowercase everything
                    normalized = full + intf[len(short):]
                    # Remove any spaces
                    normalized = normalized.replace(' ', '')
                    return normalized.lower()
    
    # If no match, just lowercase it
    return intf.lower()

def is_same_interface(intf1, intf2):
    if not intf1 or not intf2:
        return False
    norm1 = normalize_interface_name(intf1).lower()
    norm2 = normalize_interface_name(intf2).lower()
    if norm1 == norm2:
        return True
    pattern = r'(gigabitethernet|tengigabitethernet|fastethernet|ethernet|port-channel|vlan)[\s/]*(\d+[/\d]*)'
    match1 = re.search(pattern, norm1)
    match2 = re.search(pattern, norm2)
    if match1 and match2:
        type1, num1 = match1.groups()
        type2, num2 = match2.groups()
        type_map = {'gigabitethernet': 'gi', 'tengigabitethernet': 'te', 'fastethernet': 'fa', 'ethernet': 'eth', 'port-channel': 'po', 'vlan': 'vl'}
        short_type1 = type_map.get(type1, type1)
        short_type2 = type_map.get(type2, type2)
        num1_clean = num1.strip().replace(' ', '')
        num2_clean = num2.strip().replace(' ', '')
        return short_type1 == short_type2 and num1_clean == num2_clean
    return False


def select_camera_mac(entries, interface):
    """
    Return ALL unique MAC addresses found on the port.
    Now returns a list of unique MACs instead of just one.
    """
    count = len(entries)
    if count == 0:
        return None
    
    # Extract all unique MACs
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
        logger.info(f"  {interface}: {unique_count} unique MACs found ({dup_count} duplicates removed from {total_count} total)")
    else:
        logger.info(f"  {interface}: {unique_count} unique MACs found")
    
    return unique_macs  # Return list of all unique MAC entries


def poll_port_for_mac(shell, interface, max_attempts=MAC_POLL_MAX_ATTEMPTS, interval=MAC_POLL_INTERVAL):
    """
    Poll a specific port until MAC addresses appear.
    
    Returns:
        list: List of MAC entries when found, or list with UNKNOWN MAC on timeout
    """
    logger.info(f"  [POLL] {interface} - waiting for MAC address...")
    
    start_time = time.time()
    attempt = 0
    last_log_time = start_time
    
    while True:
        attempt += 1
        elapsed = time.time() - start_time
        
        # Hard timeout check (safety net - should rarely trigger)
        if elapsed > MAC_POLL_HARD_TIMEOUT:
            logger.error(f"  [CRITICAL] {interface}: Hard timeout at {MAC_POLL_HARD_TIMEOUT}s ({attempt} attempts)")
            logger.error(f"  [CRITICAL] {interface}: UP/UP port with no MAC - port may be misconfigured!")
            discovery_stats["total_ports_no_mac"] += 1
            
            # Return a special entry for UNKNOWN MAC
            return [{
                "vlan": "UNKNOWN",
                "mac_address": "UNKNOWN",
                "type": "TIMEOUT",
                "port": interface
            }]
        
        try:
            cmd = f"show mac address-table interface {interface}"
            mac_out = send_cmd(shell, cmd, timeout=10, silent=True)
            
            entries = parse_mac_table_interface(mac_out)
            
            if entries:
                # SUCCESS - Found MAC addresses
                logger.info(f"  [OK] {interface}: MAC found (attempt {attempt}, {elapsed:.1f}s)")
                return select_camera_mac(entries, interface)  # Returns list of unique MACs
            
            # Log progress periodically
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

def get_uplink_ports_from_neighbors(shell, current_switch_type="UNKNOWN"):
    """
    Discover ports with Cisco switch neighbors.
    
    NEW LOGIC (Option B):
    - Only exclude Cisco neighbors that HAVE a management IP
    - Scan ports with Cisco neighbors that have NO management IP
      (might be misconfigured or might have cameras connected)
    
    Returns:
        List of port names to exclude from scanning
    """
    logger.info("Discovering ports with CDP/LLDP neighbors...")
    excluded_ports = []
    excluded_ports_normalized = set()
    
    # ========================================================================
    # CDP NEIGHBORS
    # ========================================================================
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
                    
                    # CHANGED: Only exclude if neighbor has a management IP
                    if nbr.get("mgmt_ip"):
                        if port_norm not in excluded_ports_normalized:
                            excluded_ports.append(local_port)
                            excluded_ports_normalized.add(port_norm)
                            logger.info(f"NEIGHBOR DETECTED: {local_port} -> {nbr.get('hostname', 'Unknown')} ({nbr['mgmt_ip']}) (Cisco via CDP) - EXCLUDED")
                    else:
                        logger.info(f"NEIGHBOR NO IP: {local_port} -> {nbr.get('hostname', 'Unknown')} (Cisco via CDP, no mgmt IP) - WILL SCAN")
    else:
        logger.info("CDP not enabled")
    
    # ========================================================================
    # LLDP NEIGHBORS
    # ========================================================================
    logger.info("Checking LLDP neighbors...")
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors_for_port_exclusion(lldp_output)
        
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
            for nbr in lldp_neighbors:
                if nbr.get("local_intf"):
                    lldp_intf_norm = normalize_interface_name(nbr["local_intf"])
                    
                    # Don't duplicate if already found via CDP
                    if lldp_intf_norm in excluded_ports_normalized:
                        logger.debug(f"Port {nbr['local_intf']} already excluded via CDP")
                        continue
                    
                    # CHANGED: Only exclude if neighbor has a management IP
                    if nbr.get("mgmt_ip"):
                        excluded_ports.append(nbr["local_intf"])
                        excluded_ports_normalized.add(lldp_intf_norm)
                        logger.info(f"NEIGHBOR DETECTED: {nbr['local_intf']} -> {nbr.get('hostname', 'Unknown')} ({nbr['mgmt_ip']}) (Cisco via LLDP) - EXCLUDED")
                    else:
                        logger.info(f"NEIGHBOR NO IP: {nbr['local_intf']} -> {nbr.get('hostname', 'Unknown')} (Cisco via LLDP, no mgmt IP) - WILL SCAN")
    else:
        logger.info("LLDP not enabled")
    
    logger.info(f"Total ports with Cisco switch neighbors (with IPs): {len(excluded_ports)}")
    return excluded_ports

def parse_lldp_neighbors_for_port_exclusion(output):
    """
    Simplified LLDP parser specifically for port exclusion.
    
    CHANGED BEHAVIOR:
    - Only excludes Cisco devices that HAVE a management IP
    - If no IP is found, the port will be scanned (might have cameras)
    
    Returns:
        List of neighbors with: hostname, local_intf, sys_descr, mgmt_ip
    """
    neighbors = []
    blocks = re.split(r'[-]{40,}', output)
    
    for block in blocks:
        if not block.strip():
            continue
        
        # Only process blocks that contain neighbor data
        if "Local Intf:" not in block:
            continue
        
        # Skip capability code headers
        if "Capability codes:" in block and "Local Intf:" not in block:
            continue
        
        neighbor = {
            "hostname": None,
            "local_intf": None,
            "sys_descr": "",
            "mgmt_ip": None,
            "source": "LLDP"
        }
        
        # Extract local interface
        if m := re.search(r'^Local Intf:\s*(\S+)', block, re.M):
            neighbor["local_intf"] = m.group(1)
        
        # Extract hostname
        if m := re.search(r'^System Name:\s*(.+?)$', block, re.M):
            hostname = m.group(1).strip().strip('"').strip("'")
            neighbor["hostname"] = hostname
        
        # Extract System Description (CRITICAL for Cisco detection)
        if m := re.search(r'^System Description:\s*\n([\s\S]+?)(?=^Time remaining:|^System Capabilities:|^Management Addresses:|$)', block, re.M):
            neighbor["sys_descr"] = m.group(1).strip()
        
        # Extract management IP (CRITICAL for exclusion decision)
        if m := re.search(r'^Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)', block, re.M):
            neighbor["mgmt_ip"] = m.group(1)
        
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'Management Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'IPv4:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        
        # Validate it's a Cisco device
        if neighbor["sys_descr"]:
            sys_desc_lower = neighbor["sys_descr"].lower()
            if "cisco ios" in sys_desc_lower or "cisco nx-os" in sys_desc_lower:
                # It's a Cisco device!
                if neighbor["local_intf"]:
                    neighbors.append(neighbor)
                    logger.debug(f"  OK Cisco LLDP neighbor: {neighbor.get('hostname', 'Unknown')} via {neighbor['local_intf']}")
                else:
                    logger.warning(f"LLDP Cisco neighbor {neighbor.get('hostname', 'Unknown')} has no local interface")
            else:
                logger.debug(f"  X Skipping non-Cisco LLDP device: {neighbor.get('hostname', 'Unknown')}")
        else:
            logger.debug(f"  X Skipping LLDP device without System Description: {neighbor.get('hostname', 'Unknown')}")
    
    return neighbors


def parse_cdp_neighbors_for_port_exclusion(output):
    """
    Simplified CDP parser specifically for port exclusion.
    
    CHANGED BEHAVIOR:
    - Only excludes Cisco devices that HAVE a management IP
    - If no IP is found, the port will be scanned (might have cameras)
    
    Returns:
        List of neighbors with: hostname, local_intf, platform, mgmt_ip
    """
    neighbors = []
    blocks = re.split(r"(?=^Device ID:\s*)", output, flags=re.M)
    
    for block in blocks:
        if "Device ID:" not in block:
            continue
        
        neighbor = {
            "hostname": None,
            "local_intf": None,
            "platform": None,
            "mgmt_ip": None
        }
        
        # Extract Device ID (hostname)
        if m := re.search(r"Device ID:\s*(\S+(?:\.\S+)*)", block):
            neighbor["hostname"] = m.group(1)
        
        # Extract local interface
        if m := re.search(r"Interface:\s*(\S+)", block):
            neighbor["local_intf"] = m.group(1).rstrip(',')
        
        # Extract platform
        if m := re.search(r"Platform:\s*([^,\n]+)", block):
            neighbor["platform"] = m.group(1).strip()
        
        # Extract management IP (CRITICAL for exclusion decision)
        cdp_ip_patterns = (
            r"IPv4 [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
            r"IP [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
            r"Management [Aa]ddress(?:es)?:.*?IP(?:v4)?:\s*(\d+\.\d+\.\d+\.\d+)",
            r"Entry address\(es\):[\s\S]*?IP address:\s*(\d+\.\d+\.\d+\.\d+)",
        )
        for pat in cdp_ip_patterns:
            m = re.search(pat, block, flags=re.I | re.S)
            if m:
                neighbor["mgmt_ip"] = m.group(1)
                break
        
        # Check if it's a Cisco device with a valid local interface
        if neighbor["platform"] and "cisco" in neighbor["platform"].lower():
            if neighbor["local_intf"]:
                neighbors.append(neighbor)
            else:
                logger.warning(f"CDP neighbor {neighbor.get('hostname', 'Unknown')} has no local interface - skipping")
    
    return neighbors

def parse_cdp_neighbors_for_port_exclusion(output):
    """
    Simplified CDP parser specifically for port exclusion.
    
    ONLY cares about:
    1. Is it a Cisco device? (check platform)
    2. What's the local interface? (for exclusion)
    
    Does NOT require IP address.
    """
    neighbors = []
    blocks = re.split(r"(?=^Device ID:\s*)", output, flags=re.M)
    
    for block in blocks:
        if "Device ID:" not in block:
            continue
        
        neighbor = {
            "hostname": None,
            "local_intf": None,
            "platform": None
        }
        
        # Extract Device ID (hostname)
        if m := re.search(r"Device ID:\s*(\S+(?:\.\S+)*)", block):
            neighbor["hostname"] = m.group(1)
        
        # Extract local interface
        if m := re.search(r"Interface:\s*(\S+)", block):
            neighbor["local_intf"] = m.group(1).rstrip(',')
        
        # Extract platform
        if m := re.search(r"Platform:\s*([^,\n]+)", block):
            neighbor["platform"] = m.group(1).strip()
        
        # Check if it's a Cisco device with a valid local interface
        if neighbor["platform"] and "cisco" in neighbor["platform"].lower():
            if neighbor["local_intf"]:
                neighbors.append(neighbor)
            else:
                logger.warning(f"CDP neighbor {neighbor.get('hostname', 'Unknown')} has no local interface - skipping")
    
    return neighbors

def process_switch(parent_ip, neighbor_info, switch_type="UNKNOWN", is_retry=False):
    """
    Process a switch with enhanced retry logic, hostname verification, and failure tracking.
    """
    global failed_switches
    
    switch_ip = neighbor_info["mgmt_ip"]
    switch_name = neighbor_info["remote_name"]
    local_intf = neighbor_info["local_intf"]
    
    # Skip aggregate switches - they never have cameras directly connected
    if switch_type == "AGGREGATE":
        logger.debug(f"Skipping {switch_name} - aggregate switches don't have cameras")
        return True
    
    if not switch_ip or (switch_ip in visited_switches and not is_retry):
        return True
    
    logger.info("")
    logger.info("*"*80)
    if is_retry:
        logger.info(f"RETRYING {switch_type} SWITCH: {switch_name} ({switch_ip}) FROM SEED")
    else:
        logger.info(f"Processing {switch_type} SWITCH: {switch_name} ({switch_ip})")
    logger.info("*"*80)
    
    if not is_retry:
        visited_switches.add(switch_ip)
        discovery_stats["switches_attempted"] += 1
        discovery_stats["switches_by_type"][switch_type]["attempted"] += 1
    else:
        discovery_stats["switches_retried_from_seed"] += 1
    
    try:
        parent_hostname = get_hostname(agg_shell)
    except Exception:
        parent_hostname = agg_hostname or "UNKNOWN"
    
    try:
        if not verify_aggregate_connection():
            raise NetworkConnectionError("Parent connection lost", reconnect_needed=True)
        
        ssh_success = ssh_to_device(
            target_ip=switch_ip,
            expected_hostname=switch_name,
            parent_hostname=parent_hostname
        )
        
        if ssh_success is None:
            logger.info(f"Skipping {switch_name} ({switch_ip}) - IP belongs to current switch")
            return True
        
        if not ssh_success:
            logger.error(f"Cannot SSH to {switch_name} after {SSH_HOP_RETRY_ATTEMPTS} attempts - SKIPPING")
            
            failure_info = {
                "switch_name": switch_name,
                "switch_ip": switch_ip,
                "switch_type": switch_type,
                "parent_ip": parent_ip,
                "parent_hostname": parent_hostname,
                "reason": f"SSH connection failed after {SSH_HOP_RETRY_ATTEMPTS} retry attempts",
                "local_intf": local_intf,
                "is_retry": is_retry
            }
            
            if not is_retry:
                failed_switches.append(failure_info)
                logger.warning(f"Added {switch_name} to retry queue for Phase 3")
            
            discovery_stats["switches_by_type"][switch_type]["failed"] += 1
            discovery_stats["switches_failed_unreachable"] += 1
            discovery_stats["failure_details"].append(failure_info)
            return False
        
        actual_hostname = get_hostname(agg_shell)
        if actual_hostname == parent_hostname:
            logger.error(f"FATAL: Still on parent {parent_hostname} after supposedly successful hop!")
            discovery_stats["switches_by_type"][switch_type]["failed"] += 1
            discovery_stats["switches_failed_other"] += 1
            
            if not is_retry:
                failed_switches.append({
                    "switch_name": switch_name,
                    "switch_ip": switch_ip,
                    "switch_type": switch_type,
                    "parent_ip": parent_ip,
                    "parent_hostname": parent_hostname,
                    "reason": "Hostname verification failed - still on parent switch",
                    "local_intf": local_intf,
                    "is_retry": is_retry
                })
            return False
        
        try:
            downstream_switches = discover_cameras_from_switch(agg_shell, actual_hostname, switch_type)
            discovery_stats["switches_successfully_scanned"] += 1
            discovery_stats["switches_by_type"][switch_type]["successful"] += 1
            
            if is_retry:
                discovery_stats["switches_recovered_on_retry"] += 1
                logger.info(f"[RECOVERED] RETRY SUCCESS: {switch_name} recovered on retry from seed")
            
            # Process any downstream switches discovered
            if downstream_switches:
                logger.info(f"Processing {len(downstream_switches)} downstream switches from {actual_hostname}...")
                for ds in downstream_switches:
                    ds_neighbor_info = {
                        "remote_name": ds["hostname"],
                        "mgmt_ip": ds["ip"],
                        "local_intf": ds["local_port"]
                    }
                    try:
                        process_switch(switch_ip, ds_neighbor_info, ds["type"], is_retry=False)
                    except NetworkConnectionError as ds_e:
                        if getattr(ds_e, 'reconnect_needed', False):
                            logger.error(f"Lost connection while processing downstream switch {ds['hostname']}")
                            raise
                        else:
                            logger.error(f"Failed to process downstream switch {ds['hostname']}: {ds_e}")
            
        except NetworkConnectionError as e:
            if getattr(e, 'reconnect_needed', False):
                logger.error(f"Lost parent connection: {e}")
                raise
            else:
                logger.error(f"Error during camera discovery: {e}")
        except Exception as e:
            logger.error(f"Error during camera discovery: {e}", exc_info=True)
        
        try:
            logger.debug(f"[EXIT] Exiting from {switch_type} switch")
            exit_success = exit_device()
            if not exit_success:
                logger.warning(f"[EXIT] Exit may have failed")
            time.sleep(1)
            
            final_hostname = get_hostname(agg_shell)
            if final_hostname != parent_hostname:
                logger.error(f"After exit: at {final_hostname}, expected {parent_hostname}")
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
            
            logger.info("Returned to parent switch")
            
            if not verify_aggregate_connection():
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
                
            return True
            
        except Exception as e:
            logger.error(f"Error exiting: {e}")
            if not verify_aggregate_connection():
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
    
    except NetworkConnectionError as e:
        reconnect_needed = getattr(e, 'reconnect_needed', False)
        if reconnect_needed:
            logger.error(f"Parent connection lost while processing {switch_name}")
            if not is_retry:
                failed_switches.append({
                    "switch_name": switch_name,
                    "switch_ip": switch_ip,
                    "switch_type": switch_type,
                    "parent_ip": parent_ip,
                    "parent_hostname": parent_hostname,
                    "reason": "Parent connection lost during SSH attempts",
                    "local_intf": local_intf,
                    "is_retry": is_retry
                })
                logger.warning(f"Added {switch_name} to retry queue for Phase 3 (connection lost)")
            raise
        logger.error(f"Cannot connect - SKIPPING: {e}")
        discovery_stats["switches_by_type"][switch_type]["failed"] += 1
        
        if not is_retry:
            failed_switches.append({
                "switch_name": switch_name,
                "switch_ip": switch_ip,
                "switch_type": switch_type,
                "parent_ip": parent_ip,
                "parent_hostname": parent_hostname,
                "reason": str(e),
                "local_intf": local_intf,
                "is_retry": is_retry
            })
        
        discovery_stats["failure_details"].append({
            "switch_name": switch_name,
            "switch_ip": switch_ip,
            "switch_type": switch_type,
            "reason": str(e)
        })
        return False

def discover_aggregate_neighbors(shell, current_agg_hostname):
    logger.info("Discovering neighboring aggregate switches...")
    logger.info(f"Current aggregate hostname: {current_agg_hostname}")
    aggregate_neighbors = []
    all_neighbors_by_hostname = {}
    logger.info("Checking CDP neighbors...")
    cdp_output = send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        if cdp_neighbors:
            logger.info(f"Found {len(cdp_neighbors)} CDP neighbors")
            for nbr in cdp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    hostname_to_ip.setdefault(nbr["hostname"], nbr["mgmt_ip"])
                    all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
                    if is_aggregate_switch(nbr["hostname"]):
                        logger.info(f"CDP: Found aggregate {nbr['hostname']} ({nbr['mgmt_ip']})")
    logger.info("Checking LLDP neighbors...")
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
            for nbr in lldp_neighbors:
                if nbr["hostname"]:
                    if is_aggregate_switch(nbr["hostname"]):
                        logger.info(f"LLDP: Found potential aggregate {nbr['hostname']}")
                    if not nbr["mgmt_ip"] and nbr["hostname"] in hostname_to_ip:
                        nbr["mgmt_ip"] = hostname_to_ip[nbr["hostname"]]
                        logger.info(f"Resolved IP for {nbr['hostname']} from CDP")
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
                    logger.info(f"  OK Added: {hostname} ({mgmt_ip})")
                else:
                    logger.warning(f"  X No management IP for {hostname}")
            else:
                logger.info(f"  X Skipping (same as current)")
    logger.info(f"Total aggregate neighbors found: {len(aggregate_neighbors)}")
    return aggregate_neighbors

#!/usr/bin/env python3
"""
FIXED scan_aggregate_switch FUNCTION
Replace the entire function in your camera_discovery.py (starting around line 1751)
"""

def scan_aggregate_switch(shell, agg_ip, aggregates_to_process=None, seed_ips=None, resume_mode=False):
    """
    Scan an aggregate switch - discover neighbors AND scan for cameras.
    
    CHANGED: Now scans for cameras on aggregates (excluding neighbor ports).
    """
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
    
    logger.info("")
    logger.info("#"*80)
    if resume_mode:
        logger.info(f"RESUMING AGGREGATE SCAN: {hostname} ({agg_ip})")
    else:
        logger.info(f"Scanning AGGREGATE: {hostname} ({agg_ip})")
    logger.info("#"*80)
    
    new_aggregates = []
    if not resume_mode:
        new_aggregates = discover_aggregate_neighbors(shell, hostname)
        
        # ADD TO QUEUE IMMEDIATELY (before downstream scanning starts)
        if aggregates_to_process is not None and seed_ips is not None:
            for agg in new_aggregates:
                if agg["mgmt_ip"] in seed_ips:
                    logger.info(f"Skipping {agg['hostname']} ({agg['mgmt_ip']}) - same as seed switch")
                    continue
                
                if agg["mgmt_ip"] not in aggregates_to_process:
                    aggregates_to_process.append(agg["mgmt_ip"])
                    logger.info(f">>> ADDED NEW AGGREGATE TO QUEUE: {agg['hostname']} ({agg['mgmt_ip']})")
                else:
                    logger.debug(f"Aggregate {agg['hostname']} already in queue")
    else:
        logger.info(">>> Resume mode: skipping aggregate discovery")
    
    # CHANGED: Now scan for cameras on aggregate (excluding neighbor ports)
    logger.info(">>> Scanning for cameras (excluding ports with neighbors)...")
    try:
        downstream_switches = discover_cameras_from_switch(shell, hostname, "AGGREGATE")
        # downstream_switches will be empty now since discover_cameras_from_switch 
        # no longer discovers them
    except Exception as e:
        logger.error(f"Error scanning aggregate for cameras: {e}")
        downstream_switches = []
    
    # Still discover downstream switches via CDP/LLDP for topology mapping
    logger.info(">>> Discovering downstream switches for topology...")
    all_neighbors_by_hostname = {}
    
    cdp_output = send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        if cdp_neighbors:
            for nbr in cdp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                    all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            for nbr in lldp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
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
    
    logger.info(f"Found {len(all_neighbors_by_hostname)} total neighbors")
    
    # Process downstream switches
    switch_counts = {"EDGE": 0, "AGGREGATE": 0, "SERVER": 0, "OTHER": 0}
    for nhost, links in all_neighbors_by_hostname.items():
        switch_type = determine_switch_type(nhost)
        mgmt_ip = hostname_to_ip.get(nhost)
        
        if switch_type == "AGGREGATE":
            logger.debug(f"Skipping aggregate: {nhost}")
            continue
        
        if mgmt_ip in visited_switches:
            logger.info(f"Skipping {switch_type} {nhost} - already processed")
            continue
        
        switch_counts[switch_type] += 1
        logger.info(f"{switch_type} switch detected: {nhost} - {mgmt_ip}")
        
        for link in links:
            neighbor_info = {
                "remote_name": nhost,
                "mgmt_ip": mgmt_ip,
                "local_intf": link.get("local_intf")
            }
            try:
                process_switch(agg_ip, neighbor_info, switch_type, is_retry=False)
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False):
                    logger.error(f"Lost aggregate connection")
                    raise
            break
    
    if not resume_mode:
        discovery_stats["switches_successfully_scanned"] += 1
        discovery_stats["switches_by_type"]["AGGREGATE"]["successful"] += 1
    
    logger.info(f"Summary for {hostname}:")
    logger.info(f"  - Edge: {switch_counts['EDGE']}, Server: {switch_counts['SERVER']}, Other: {switch_counts['OTHER']}")
    
    return new_aggregates


def retry_failed_switches_from_seed():
    """
    PHASE 3: Retry all failed switches from the seed switch.
    """
    global failed_switches, agg_shell
    
    if not failed_switches:
        logger.info("="*80)
        logger.info("PHASE 3: No failed switches to retry")
        logger.info("="*80)
        return
    
    logger.info("="*80)
    logger.info(f"PHASE 3: RETRYING {len(failed_switches)} FAILED SWITCHES FROM SEED")
    logger.info("="*80)
    logger.info("Since this is Layer 2, all edge switches should be reachable from seed")
    
    try:
        if not verify_aggregate_connection():
            logger.info("Reconnecting to seed for retry phase...")
            reconnect_to_aggregate("Phase 3 Retry")
    except Exception as e:
        logger.error(f"Cannot reconnect to seed for retries: {e}")
        return
    
    current_hostname = get_hostname(agg_shell)
    seed_hostname = agg_hostname or "UNKNOWN"
    
    if current_hostname != seed_hostname:
        logger.warning(f"Not on seed switch (on {current_hostname}, expected {seed_hostname})")
        logger.warning(f"Attempting to return to seed...")
        try:
            for _ in range(5):
                exit_device()
                time.sleep(0.5)
                current_hostname = get_hostname(agg_shell)
                if current_hostname == seed_hostname:
                    logger.info(f"Successfully returned to seed: {seed_hostname}")
                    break
            else:
                logger.error("Could not return to seed - reconnecting...")
                reconnect_to_aggregate("Return to seed for retry")
                current_hostname = get_hostname(agg_shell)
                if current_hostname != seed_hostname:
                    logger.error(f"Still not on seed after reconnect: {current_hostname}")
                    return
        except Exception as e:
            logger.error(f"Error returning to seed: {e}")
            return
    
    logger.info(f"Ready to retry from seed switch: {seed_hostname}")
    
    switches_to_retry = failed_switches.copy()
    retry_successes = 0
    retry_failures = 0
    
    for idx, switch_info in enumerate(switches_to_retry, 1):
        switch_name = switch_info["switch_name"]
        switch_ip = switch_info["switch_ip"]
        switch_type = switch_info["switch_type"]
        original_parent = switch_info.get("parent_hostname", "Unknown")
        
        logger.info("")
        logger.info(f"[RETRY {idx}/{len(switches_to_retry)}] {switch_name} ({switch_ip})")
        logger.info(f"  Originally failed from: {original_parent}")
        logger.info(f"  Retrying from: {seed_hostname} (seed)")
        
        neighbor_info = {
            "remote_name": switch_name,
            "mgmt_ip": switch_ip,
            "local_intf": switch_info.get("local_intf", "Unknown")
        }
        
        try:
            success = process_switch(
                parent_ip=SEED_SWITCH_IP,
                neighbor_info=neighbor_info,
                switch_type=switch_type,
                is_retry=True
            )
            
            if success:
                retry_successes += 1
                logger.info(f"[SUCCESS] Retry {idx}/{len(switches_to_retry)}: RECOVERED")
            else:
                retry_failures += 1
                logger.warning(f"[FAILED] Retry {idx}/{len(switches_to_retry)}: STILL FAILED")
            
        except NetworkConnectionError as e:
            logger.error(f"Network error during retry: {e}")
            retry_failures += 1
            
            if getattr(e, 'reconnect_needed', False):
                logger.warning("Lost seed connection during retry - reconnecting...")
                try:
                    reconnect_to_aggregate("Phase 3 recovery")
                    logger.info("Reconnected to seed")
                except Exception as reconnect_err:
                    logger.error(f"Could not reconnect: {reconnect_err}")
                    logger.error("Aborting retry phase")
                    break
        
        except Exception as e:
            logger.error(f"Error retrying {switch_name}: {e}", exc_info=True)
            retry_failures += 1
    
    logger.info("")
    logger.info("="*80)
    logger.info("PHASE 3 COMPLETE - RETRY FROM SEED")
    logger.info("="*80)
    logger.info(f"Switches retried: {len(switches_to_retry)}")
    logger.info(f"Recovered: {retry_successes}")
    logger.info(f"Still failed: {retry_failures}")
    logger.info("="*80)

def main():
    logger.info("="*80)
    logger.info("CAMERA DISCOVERY SCRIPT STARTED")
    logger.info(f"Seed switch: {SEED_SWITCH_IP}")
    logger.info(f"MAC polling: Infinite (up to {MAC_POLL_HARD_TIMEOUT}s hard timeout per port)")
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
        logger.info(f"Seed switch IPs: {seed_ips}")
    except Exception as e:
        logger.warning(f"Could not get all seed IPs: {e}")
    
    try:
        aggregates_to_process = deque()
        
        logger.info("="*80)
        logger.info("PHASE 1: DISCOVERING AGGREGATE SWITCHES")
        logger.info("="*80)
        
        reconnect_attempts = 0
        max_reconnects = AGG_MAX_RETRIES
        seed_scan_complete = False
        
        while reconnect_attempts < max_reconnects and not seed_scan_complete:
            try:
                if SEED_SWITCH_IP in discovered_aggregates:
                    logger.info("Seed scan interrupted - resuming...")
                    new_aggregates = scan_aggregate_switch(agg_shell, SEED_SWITCH_IP, aggregates_to_process, seed_ips, resume_mode=True)
                    seed_scan_complete = True
                else:
                    new_aggregates = scan_aggregate_switch(agg_shell, SEED_SWITCH_IP, aggregates_to_process, seed_ips, resume_mode=False)
                
                # NOTE: Aggregates are already added to queue inside scan_aggregate_switch()
                # This code is kept for backwards compatibility
                for agg in new_aggregates:
                    if agg["mgmt_ip"] in seed_ips:
                        logger.info(f"Skipping {agg['hostname']} ({agg['mgmt_ip']}) - same as seed switch")
                        continue
                    
                    if agg["mgmt_ip"] not in aggregates_to_process:
                        aggregates_to_process.append(agg["mgmt_ip"])
                        logger.info(f">>> ADDED NEW AGGREGATE TO QUEUE: {agg['hostname']} ({agg['mgmt_ip']})")
                    else:
                        logger.debug(f"Aggregate {agg['hostname']} already in queue")
                
                seed_scan_complete = True
                break
                
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False) or not verify_aggregate_connection():
                    reconnect_attempts += 1
                    logger.error("Connection to seed lost during Phase 1")
                    discovery_stats["aggregates_reconnections"] += 1
                    if reconnect_attempts < max_reconnects:
                        logger.info(f"Reconnecting (attempt {reconnect_attempts + 1}/{max_reconnects})...")
                        try:
                            reconnect_to_aggregate("Phase 1")
                            logger.info("Reconnected successfully")
                        except NetworkConnectionError:
                            if reconnect_attempts >= max_reconnects - 1:
                                logger.error("Max reconnects reached. Exiting.")
                                return
                    else:
                        logger.error("Max reconnects reached. Exiting.")
                        return

        logger.info("="*80)
        logger.info(f"PHASE 2: PROCESSING {len(aggregates_to_process)} ADDITIONAL AGGREGATES")
        logger.info("="*80)
        
        while aggregates_to_process:
            agg_ip = aggregates_to_process.popleft()
            
            if agg_ip in seed_ips:
                logger.info(f"Skipping aggregate {agg_ip} - same as seed switch")
                continue
                
            if agg_ip in discovered_aggregates:
                logger.info(f"Aggregate {agg_ip} already processed - skipping")
                continue
                
            logger.info("*"*80)
            logger.info(f"PROCESSING AGGREGATE: {agg_ip}")
            logger.info("*"*80)
            
            aggregate_reconnect_attempts = 0
            aggregate_processed = False
            
            while aggregate_reconnect_attempts < max_reconnects and not aggregate_processed:
                try:
                    if not verify_aggregate_connection():
                        raise NetworkConnectionError("Seed lost", reconnect_needed=True)
                    
                    logger.info("Hopping to aggregate...")
                    parent_hostname = get_hostname(agg_shell)
                    
                    hop_success = ssh_to_device(
                        target_ip=agg_ip,
                        expected_hostname=None,
                        parent_hostname=parent_hostname
                    )
                    
                    if not hop_success:
                        logger.error(f"Failed to connect to {agg_ip} after {SSH_HOP_RETRY_ATTEMPTS} attempts")
                        break
                    
                    new_aggregates = scan_aggregate_switch(agg_shell, agg_ip, aggregates_to_process, seed_ips)
                    
                    # NOTE: Aggregates are already added to queue inside scan_aggregate_switch()
                    # This code is kept for backwards compatibility
                    for agg in new_aggregates:
                        if agg["mgmt_ip"] in seed_ips:
                            logger.info(f"Skipping {agg['hostname']} ({agg['mgmt_ip']}) - same as seed switch")
                            continue
                        
                        if agg["mgmt_ip"] not in aggregates_to_process:
                            aggregates_to_process.append(agg["mgmt_ip"])
                            logger.info(f">>> ADDED NEW AGGREGATE TO QUEUE: {agg['hostname']} ({agg['mgmt_ip']})")
                        else:
                            logger.debug(f"Aggregate {agg['hostname']} already in queue")
                    
                    logger.info("Returning to seed...")
                    exit_device()
                    time.sleep(1)
                    
                    if not verify_aggregate_connection():
                        raise NetworkConnectionError("Lost seed connection", reconnect_needed=True)
                    
                    logger.info("Returned to seed")
                    aggregate_processed = True
                    
                except NetworkConnectionError as e:
                    if getattr(e, 'reconnect_needed', False) or not verify_aggregate_connection():
                        aggregate_reconnect_attempts += 1
                        logger.error(f"Connection lost processing {agg_ip}")
                        discovery_stats["aggregates_reconnections"] += 1
                        
                        if aggregate_reconnect_attempts < max_reconnects:
                            logger.info(f"Reconnecting (attempt {aggregate_reconnect_attempts + 1}/{max_reconnects})...")
                            try:
                                reconnect_to_aggregate(f"Aggregate {agg_ip}")
                                logger.info("Reconnected - will continue with remaining aggregates")
                                aggregate_processed = True
                            except NetworkConnectionError:
                                if aggregate_reconnect_attempts >= max_reconnects - 1:
                                    logger.error("Max reconnects reached. Moving to next aggregate.")
                                    aggregate_processed = True
                        else:
                            logger.error("Max reconnects reached. Moving to next aggregate.")
                            aggregate_processed = True
                    else:
                        logger.error(f"Error processing {agg_ip}: {e}")
                        aggregate_processed = True
            
            if aggregates_to_process:
                logger.info(f">>> {len(aggregates_to_process)} aggregate(s) remaining in queue")
        
        logger.info("="*80)
        logger.info("PHASE 2 COMPLETE - ALL AGGREGATES PROCESSED")
        logger.info("="*80)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        try:
            retry_failed_switches_from_seed()
        except Exception as e:
            logger.error(f"Error in Phase 3 (retry from seed): {e}", exc_info=True)
        
        try:
            if agg_client:
                agg_client.close()
            logger.info("Closed connection to seed")
        except:
            pass
    
    logger.info("="*80)
    logger.info("DISCOVERY COMPLETE")
    logger.info("="*80)
    logger.info(f"Aggregates discovered: {len(discovered_aggregates)}")
    for agg_ip in sorted(discovered_aggregates):
        agg_name = aggregate_hostnames.get(agg_ip, "Unknown")
        logger.info(f"  - {agg_name} ({agg_ip})")
    logger.info(f"Total devices found: {len(camera_data)}")
    logger.info("")
    logger.info("DISCOVERY STATISTICS")
    logger.info("="*80)
    logger.info(f"Switches attempted: {discovery_stats['switches_attempted']}")
    logger.info(f"Successfully scanned: {discovery_stats['switches_successfully_scanned']}")
    
    initial_failures = discovery_stats['switches_attempted'] - (discovery_stats['switches_successfully_scanned'] - discovery_stats['switches_recovered_on_retry'])
    final_failures = discovery_stats['switches_attempted'] - discovery_stats['switches_successfully_scanned']
    
    logger.info(f"Initial failures (Phase 1-2): {initial_failures}")
    logger.info(f"Recovered in Phase 3: {discovery_stats['switches_recovered_on_retry']}")
    logger.info(f"Final failures: {final_failures}")
    logger.info(f"Aggregate reconnections: {discovery_stats['aggregates_reconnections']}")
    logger.info(f"Switches retried from seed: {discovery_stats['switches_retried_from_seed']}")
    
    cameras_with_mac = sum(1 for cam in camera_data if cam.get("mac_address") != "UNKNOWN")
    cameras_without_mac = sum(1 for cam in camera_data if cam.get("mac_address") == "UNKNOWN")
    
    logger.info(f"Total devices found: {len(camera_data)}")
    logger.info(f"  - Cameras with MAC: {cameras_with_mac}")
    logger.info(f"  - Ports with UNKNOWN MAC (timeouts): {cameras_without_mac}")
    logger.info(f"Ports with no MAC (critical timeouts): {discovery_stats['total_ports_no_mac']}")
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"camera_inventory_{len(camera_data)}devices_{timestamp}.json"
    output_data = {
        "discovery_metadata": {
            "timestamp": timestamp,
            "seed_switch": SEED_SWITCH_IP,
            "total_devices": len(camera_data),
            "cameras_with_mac": cameras_with_mac,
            "ports_with_unknown_mac": cameras_without_mac,
            "total_aggregates": len(discovered_aggregates),
            "mac_poll_hard_timeout": MAC_POLL_HARD_TIMEOUT,
            "mac_poll_interval": MAC_POLL_INTERVAL
        },
        "discovery_statistics": discovery_stats,
        "cameras": camera_data
    }
    with open(json_file, "w", encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved: {json_file}")
    
    if camera_data:
        csv_file = f"camera_inventory_{len(camera_data)}devices_{timestamp}.csv"
        with open(csv_file, "w", newline="", encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["switch_name", "switch_type", "port", "mac_address", "vlan", "mac_count", "status"])
            writer.writeheader()
            
            for row in camera_data:
                if "status" not in row:
                    row["status"] = "OK"
                if "mac_count" not in row:
                    row["mac_count"] = 1
                csv_row = {k: v for k, v in row.items() if k != "timeout_seconds"}
                writer.writerow(csv_row)
        logger.info(f"Saved: {csv_file}")
    logger.info(f"Log file: {log_filename}")


if __name__ == "__main__":
    main()
