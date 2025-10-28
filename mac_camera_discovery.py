#!/usr/bin/env python3
import paramiko
import time
import re
import json
import csv
import logging
from datetime import datetime
from collections import deque

# --- USER CONFIG -------------------------------------------------------------
SEED_SWITCH_IP = "192.168.1.18"
TIMEOUT = 150
MAX_READ = 65535
SSH_RETRY_ATTEMPTS = 10
SSH_RETRY_DELAY = 30
CREDENTIAL_SETS = [
    {"username": "admin", "password": "/2/_HKX6YvCGMwzAdJp", "enable": ""},
]
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
CDP_LLDP_TIMEOUT = 35

# --- RETRY CONFIGURATION (NEW) ---
SSH_HOP_RETRY_ATTEMPTS = 5  # Number of retry attempts for SSH hops
SSH_HOP_RETRY_BASE_DELAY = 2  # Base delay between retries (seconds)
SSH_HOP_USE_EXPONENTIAL_BACKOFF = True  # Use exponential backoff (2s, 4s, 8s, 16s...)
SSH_HOP_VERIFY_ROUTE = True  # Test ping before SSH attempt
# -----------------------------------------------------------------------------

PROMPT_RE = re.compile(r"(?m)^[^\r\n#>\s][^\r\n#>]*[>#]\s?$")

visited_switches = set()
discovered_aggregates = set()
aggregate_hostnames = {}
camera_data = []
failed_switches = []  # Track switches that failed for retry from seed

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
    "switches_by_type": {
        "EDGE": {"attempted": 0, "successful": 0, "failed": 0},
        "SERVER": {"attempted": 0, "successful": 0, "failed": 0},
        "OTHER": {"attempted": 0, "successful": 0, "failed": 0},
        "AGGREGATE": {"attempted": 0, "successful": 0, "failed": 0}
    },
    "failure_details": []
}

log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

agg_client = None
agg_shell = None
agg_creds = None
agg_hostname = None
session_depth = 0
device_creds = {}
hostname_to_ip = {}

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
        m = re.match(r"^([^#>\s]+(?:\.[^#>\s]+)*)[#>]", line)
        if m:
            return m.group(1)
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

def is_aggregate_switch(hostname):
    return determine_switch_type(hostname) == "AGGREGATE"

def is_server_switch(hostname):
    return determine_switch_type(hostname) == "SERVER"

def _interactive_hop(shell, ip, username, password, overall_timeout=90):
    start = time.time()
    buf = ""
    def feed(s):
        try:
            shell.send(s)
        except Exception:
            pass
    while time.time() - start < overall_timeout:
        time.sleep(0.15)
        if shell.recv_ready():
            try:
                chunk = shell.recv(MAX_READ).decode("utf-8", "ignore")
            except Exception:
                chunk = ""
            if chunk:
                buf += chunk
        if PROMPT_RE.search(buf):
            return True, buf
        low = buf.lower()
        if "(yes/no)" in low or "yes/no" in low:
            feed("yes\n")
            continue
        if "username:" in low:
            feed(username + "\n")
            continue
        if "password:" in low:
            feed(password + "\n")
            time.sleep(0.5)
            continue
        fail_keys = (
            "connection refused", "unable to connect", "timed out",
            "no route to host", "host is unreachable",
            "closed by foreign host", "connection closed by",
            "authentication failed", "permission denied",
            "% bad passwords", "% login invalid"
        )
        if any(k in low for k in fail_keys):
            return False, buf
        if (time.time() - start) % 5 < 0.2:
            feed("\n")
    return False, buf

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

# ============================================================================
# NEW RETRY LOGIC FUNCTIONS
# ============================================================================

def verify_ip_reachable_quick(target_ip, shell, timeout=3):
    """
    Quick ping test to verify IP is reachable.
    Returns True if reachable, False otherwise.
    """
    try:
        logger.debug(f"[PING] Testing {target_ip}...")
        ping_out = send_cmd(shell, f"ping {target_ip} timeout 1 repeat 2", timeout=timeout, silent=True)
        
        # Check for any successful replies
        if re.search(r"Success rate is [1-9]|!+|\d+ packets received", ping_out):
            logger.debug(f"[PING] {target_ip} is reachable")
            return True
        
        logger.debug(f"[PING] {target_ip} not reachable")
        return False
        
    except Exception as e:
        logger.debug(f"[PING] Error testing reachability: {e}")
        return True  # Assume reachable if test fails


def cleanup_and_return_to_parent(expected_parent_hostname, max_attempts=3):
    """
    Ensure we're back at the parent switch.
    Handles cases where session depth is confused.
    
    Returns:
        True if successfully at parent, False otherwise
    """
    global agg_shell, session_depth
    
    for attempt in range(1, max_attempts + 1):
        try:
            current_hostname = get_hostname(agg_shell)
            
            if current_hostname == expected_parent_hostname:
                logger.debug(f"[CLEANUP] Already at parent: {expected_parent_hostname}")
                return True
            
            logger.warning(f"[CLEANUP] At {current_hostname}, need to return to {expected_parent_hostname}")
            logger.info(f"[CLEANUP] Sending exit command (attempt {attempt}/{max_attempts})")
            
            # Try to exit
            agg_shell.send("exit\n")
            time.sleep(1)
            output = _drain(agg_shell)
            
            # Check if connection closed (we exited too far)
            if agg_shell.closed or "closed by" in output.lower():
                logger.error(f"[CLEANUP] Connection closed - exited too far!")
                return False
            
            # Verify hostname
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
    """
    Single SSH hop attempt with detailed result reporting.
    
    Returns:
        dict with keys:
            - success (bool): True if hop succeeded
            - reason (str): Failure reason if unsuccessful
            - hostname (str): Hostname reached (if any)
            - fatal (bool): True if error is unrecoverable
    """
    global agg_shell, session_depth, device_creds, hostname_to_ip
    
    # Try each credential set
    for cred_idx, cred_set in enumerate(CREDENTIAL_SETS, 1):
        username = cred_set["username"]
        password = cred_set["password"]
        enable_pw = cred_set.get("enable", "")
        
        logger.debug(f"[HOP] Trying credentials {cred_idx}/{len(CREDENTIAL_SETS)}")
        
        try:
            # Send SSH command
            agg_shell.send(f"ssh -l {username} {target_ip}\n")
            time.sleep(2)
            
            output = ""
            timeout_time = time.time() + 45  # Increased timeout
            password_sent = False
            
            while time.time() < timeout_time:
                if not agg_shell or agg_shell.closed:
                    return {
                        "success": False,
                        "reason": "shell_closed",
                        "fatal": True
                    }
                
                if agg_shell.recv_ready():
                    chunk = agg_shell.recv(MAX_READ).decode("utf-8", "ignore")
                    output += chunk
                    
                    # Handle password prompt
                    if re.search(r"[Pp]assword:", output) and not password_sent:
                        logger.debug(f"[HOP] Sending password")
                        agg_shell.send(password + "\n")
                        password_sent = True
                        time.sleep(1)
                        output = ""
                        continue
                    
                    # Handle SSH key confirmation
                    if re.search(r"\(yes/no\)", output):
                        logger.debug(f"[HOP] Accepting SSH key")
                        agg_shell.send("yes\n")
                        time.sleep(0.5)
                        continue
                    
                    # Handle connection errors
                    if re.search(r"Connection refused|Connection timed out|No route to host", output, re.IGNORECASE):
                        logger.debug(f"[HOP] Connection error in output")
                        cleanup_failed_session()
                        return {
                            "success": False,
                            "reason": "connection_refused"
                        }
                    
                    # Check for authentication failure
                    if re.search(r"Authentication failed|Permission denied|Access denied|Login invalid", output, re.IGNORECASE):
                        logger.debug(f"[HOP] Authentication failed")
                        cleanup_failed_session()
                        break  # Try next credential set
                    
                    # Check for prompt (potential success)
                    if PROMPT_RE.search(output):
                        logger.debug(f"[HOP] Prompt detected")
                        time.sleep(0.5)  # Let buffer settle
                        
                        # CRITICAL: Verify hostname changed
                        reached_hostname = get_hostname(agg_shell)
                        logger.debug(f"[HOP] Parent: {parent_hostname}, Reached: {reached_hostname}")
                        
                        if reached_hostname == parent_hostname:
                            # FAILURE: We're still on the same switch!
                            logger.error(f"[HOP] HOSTNAME UNCHANGED - still on {parent_hostname}")
                            cleanup_failed_session()
                            return {
                                "success": False,
                                "reason": "hostname_unchanged",
                                "hostname": reached_hostname
                            }
                        
                        # Verify expected hostname if provided
                        if expected_hostname and reached_hostname != expected_hostname:
                            logger.warning(f"[HOP] Hostname mismatch: expected '{expected_hostname}', got '{reached_hostname}'")
                        
                        # SUCCESS!
                        logger.info(f"[HOP] Successfully reached {reached_hostname} at {target_ip}")
                        
                        # Enter enable mode
                        enable_candidates = [enable_pw, password, ""]
                        if not _ensure_enable(agg_shell, enable_candidates, timeout=10):
                            logger.warning(f"[HOP] Could not enter enable mode")
                        
                        # Set terminal length
                        send_cmd(agg_shell, "terminal length 0", timeout=5, silent=True)
                        
                        # Update tracking
                        session_depth += 1
                        device_creds[target_ip] = cred_set
                        hostname_to_ip[reached_hostname] = target_ip
                        
                        return {
                            "success": True,
                            "hostname": reached_hostname
                        }
                
                time.sleep(0.1)
            
            # Timeout reached for this credential
            logger.debug(f"[HOP] Timeout with credential {cred_idx}")
            cleanup_failed_session()
            
        except Exception as e:
            logger.error(f"[HOP] Exception during SSH: {e}")
            cleanup_failed_session()
            return {
                "success": False,
                "reason": f"exception: {str(e)}",
                "fatal": False
            }
    
    # All credentials failed
    return {
        "success": False,
        "reason": "auth_failed_all_credentials"
    }


def ssh_to_device(target_ip, expected_hostname=None, parent_hostname=None):
    """
    SSH from current switch to target IP with retry logic and hostname verification.
    
    Args:
        target_ip: IP address to connect to
        expected_hostname: Expected hostname of target device (optional)
        parent_hostname: Hostname of current device (for verification)
    
    Returns:
        True on success, False on failure after all retries
    """
    global agg_shell, session_depth, device_creds, hostname_to_ip
    
    # Get current hostname if not provided
    if parent_hostname is None:
        try:
            parent_hostname = get_hostname(agg_shell) or agg_hostname or "UNKNOWN"
        except Exception:
            parent_hostname = agg_hostname or "UNKNOWN"
    
    logger.debug(f"[RETRY] Attempting SSH to {target_ip} from {parent_hostname}")
    
    # Check if we're already on the target switch
    try:
        ip_brief_out = send_cmd(agg_shell, "show ip interface brief", timeout=10, silent=True)
        for line in ip_brief_out.splitlines():
            if target_ip in line and ("up" in line.lower() or "administratively" in line.lower()):
                logger.info(f"Target IP {target_ip} belongs to current switch {parent_hostname} - already connected")
                logger.info(f"This is not a separate device to SSH to - it's an interface on current switch")
                return None  # Return None to indicate "already here, skip this"
    except Exception as e:
        logger.debug(f"Could not check local IPs: {e}")
    
    for attempt in range(1, SSH_HOP_RETRY_ATTEMPTS + 1):
        # Calculate delay for this attempt (exponential backoff)
        if attempt > 1:
            if SSH_HOP_USE_EXPONENTIAL_BACKOFF:
                delay = SSH_HOP_RETRY_BASE_DELAY * (2 ** (attempt - 2))
            else:
                delay = SSH_HOP_RETRY_BASE_DELAY
            
            logger.info(f"[RETRY] Waiting {delay}s before attempt {attempt}/{SSH_HOP_RETRY_ATTEMPTS}...")
            time.sleep(delay)
        
        logger.info(f"[RETRY] SSH hop attempt {attempt}/{SSH_HOP_RETRY_ATTEMPTS} to {target_ip}")
        
        # Optional: Verify routing/reachability before attempting SSH
        if SSH_HOP_VERIFY_ROUTE and attempt == 1:
            if not verify_ip_reachable_quick(target_ip, agg_shell):
                logger.warning(f"[RETRY] {target_ip} not reachable via ping")
        
        # Ensure we're in a clean state before retry
        if attempt > 1:
            if not verify_aggregate_connection():
                logger.error(f"[RETRY] Lost connection to parent switch before attempt {attempt}")
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
            
            # Make sure we're back at parent hostname
            current_host = get_hostname(agg_shell)
            if current_host != parent_hostname:
                logger.warning(f"[RETRY] Not at parent hostname ({current_host} != {parent_hostname})")
                logger.warning(f"[RETRY] Attempting to return to parent...")
                if not cleanup_and_return_to_parent(parent_hostname):
                    logger.error(f"[RETRY] Could not return to parent switch")
                    raise NetworkConnectionError("Cannot return to parent", reconnect_needed=True)
        
        # Attempt the SSH hop
        result = attempt_ssh_hop(
            target_ip=target_ip,
            parent_hostname=parent_hostname,
            expected_hostname=expected_hostname,
            attempt_number=attempt
        )
        
        if result["success"]:
            logger.info(f"[RETRY] SUCCESS on attempt {attempt}/{SSH_HOP_RETRY_ATTEMPTS}")
            return True
        
        # Log why this attempt failed
        failure_reason = result.get("reason", "Unknown")
        logger.warning(f"[RETRY] Attempt {attempt} failed: {failure_reason}")
        
        # Determine if we should retry based on failure type
        if result.get("fatal", False):
            logger.error(f"[RETRY] Fatal error - no retry possible")
            return False
        
        # Special handling for specific failure types
        if "hostname_unchanged" in failure_reason:
            logger.warning(f"[RETRY] Hostname didn't change - target may be unreachable or misconfigured")
    
    # All retries exhausted
    logger.error(f"[RETRY] Failed to connect to {target_ip} after {SSH_HOP_RETRY_ATTEMPTS} attempts")
    return False

# ============================================================================
# END NEW RETRY LOGIC FUNCTIONS
# ============================================================================

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
    Parse LLDP neighbors - returns ONLY Cisco network devices (filters out cameras, phones, etc.)
    """
    neighbors = []
    
    # Split on dashes separator (40 or more dashes)
    blocks = re.split(r'[-]{40,}', output)
    
    for block in blocks:
        if not block.strip():
            continue
        
        # Skip header/footer blocks
        if "Capability codes:" in block or "Total entries" in block or "Device ID" in block:
            continue
        
        # Must have Local Intf to be a valid neighbor entry
        if "Local Intf:" not in block:
            continue
        
        neighbor = {
            "hostname": None, 
            "mgmt_ip": None, 
            "local_intf": None, 
            "remote_intf": None, 
            "sys_descr": "", 
            "source": "LLDP"
        }
        
        # Extract local interface
        if m := re.search(r'^Local Intf:\s*(\S+)', block, re.M):
            neighbor["local_intf"] = m.group(1)
        
        # Extract remote port ID
        if m := re.search(r'^Port id:\s*(\S+)', block, re.M | re.I):
            neighbor["remote_intf"] = m.group(1)
        
        # Extract system name (hostname)
        if m := re.search(r'^System Name:\s*(.+?)$', block, re.M):
            hostname = m.group(1).strip().strip('"').strip("'")
            neighbor["hostname"] = hostname
        
        # Extract system description - CRITICAL for filtering
        if m := re.search(r'^System Description:\s*\n([\s\S]+?)(?=^Time remaining:|^System Capabilities:|^Management Addresses:|$)', block, re.M):
            neighbor["sys_descr"] = m.group(1).strip()
        
        # FILTER: Skip non-Cisco devices (Axis cameras, IP phones, etc.)
        if neighbor["sys_descr"]:
            sys_desc_lower = neighbor["sys_descr"].lower()
            # Only accept Cisco devices
            if "cisco ios" not in sys_desc_lower and "cisco nx-os" not in sys_desc_lower:
                logger.debug(f"  ⊗ Skipping non-Cisco LLDP device: {neighbor.get('hostname', 'Unknown')} "
                           f"(Desc: {neighbor['sys_descr'][:50]}...)")
                continue
        else:
            # No system description - cannot verify it's Cisco, skip it
            logger.debug(f"  ⊗ Skipping LLDP device without System Description: {neighbor.get('hostname', 'Unknown')}")
            continue
        
        # If no hostname found in System Name, try extracting from System Description
        if not neighbor["hostname"] and neighbor["sys_descr"]:
            m = re.search(r'(\S+)\s+Software', neighbor["sys_descr"], re.I)
            if m:
                neighbor["hostname"] = m.group(1)
        
        # Extract management IP address - try multiple patterns
        # Pattern 1: Standard format
        if m := re.search(r'^Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)', block, re.M):
            neighbor["mgmt_ip"] = m.group(1)
        
        # Pattern 2: Single-line format
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'Management Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        
        # Pattern 3: IPv4 explicit
        if not neighbor["mgmt_ip"]:
            if m := re.search(r'IPv4:\s*(\d+\.\d+\.\d+\.\d+)', block, re.I):
                neighbor["mgmt_ip"] = m.group(1)
        
        # Only add if we have minimum required fields
        if neighbor["mgmt_ip"]:
            if not neighbor["hostname"]:
                neighbor["hostname"] = f"LLDP-Device-{neighbor['mgmt_ip']}"
                logger.warning(f"No hostname in LLDP for {neighbor['mgmt_ip']}")
            
            neighbors.append(neighbor)
            logger.debug(f"  ✓ Cisco LLDP neighbor: {neighbor['hostname']} ({neighbor['mgmt_ip']}) "
                        f"via {neighbor['local_intf']} ↔ {neighbor['remote_intf']}")
        else:
            logger.debug(f"  ⊗ Skipping LLDP neighbor without mgmt IP: {neighbor.get('hostname', 'Unknown')}")
    
    return neighbors

def get_interface_status(shell):
    out = send_cmd(shell, "show ip interface brief", timeout=10)
    up_interfaces = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "Interface" in line or line.startswith("Vlan"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 5:
            intf, status = parts[0], parts[4]
            if status.lower() == "up":
                if re.match(r"(Gig|Ten|FastEthernet|Ethernet)", intf, re.IGNORECASE):
                    up_interfaces.append(intf)
    return up_interfaces

def parse_mac_table_interface(raw):
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if (not line or "Mac Address Table" in line or line.startswith("---") or
            line.lower().startswith("vlan") or line.startswith("Total") or
            "Mac Address" in line or "----" in line):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 4:
            vlan = parts[0]
            mac = parts[1]
            port = None
            mac_type_parts = []
            for i in range(2, len(parts)):
                if re.match(r'^(Gi|Te|Fa|Et|Po|Vl)', parts[i], re.IGNORECASE):
                    port = parts[i]
                    break
                else:
                    mac_type_parts.append(parts[i])
            mac_type = " ".join(mac_type_parts)
            if port and "DYNAMIC" in mac_type.upper():
                entries.append({"vlan": vlan, "mac_address": mac, "type": mac_type, "port": port})
    return entries

def normalize_interface_name(intf):
    if not intf:
        return ""
    replacements = {'Te': 'TenGigabitEthernet', 'Gi': 'GigabitEthernet', 'Fa': 'FastEthernet', 'Et': 'Ethernet', 'Po': 'Port-channel', 'Vl': 'Vlan'}
    intf = intf.strip()
    for short, full in replacements.items():
        if intf.startswith(short) and len(intf) > len(short):
            next_char = intf[len(short)]
            if next_char.isdigit() or next_char == '/':
                return intf.replace(short, full, 1)
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

def get_uplink_ports_from_neighbors(shell):
    logger.info("Discovering uplink ports using CDP and LLDP...")
    uplink_ports = []
    uplink_ports_normalized = set()
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
    else:
        logger.info("CDP not enabled")
    logger.info("Checking LLDP neighbors...")
    lldp_output = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
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
    else:
        logger.info("LLDP not enabled")
    for hostname, links in all_neighbors_by_hostname.items():
        if is_aggregate_switch(hostname) or is_server_switch(hostname):
            for nbr in links:
                uplink_port = nbr.get("local_intf")
                if uplink_port:
                    uplink_norm = normalize_interface_name(uplink_port)
                    if uplink_norm not in uplink_ports_normalized:
                        uplink_ports.append(uplink_port)
                        uplink_ports_normalized.add(uplink_norm)
                        logger.info(f"UPLINK DETECTED: {uplink_port} → {hostname} (via {nbr.get('source','?')})")
                    else:
                        logger.debug(f"UPLINK DUPLICATE: {uplink_port}")
                else:
                    logger.warning(f"Could not determine uplink port for {hostname}")
        else:
            logger.debug(f"Skipping {hostname} (not AGG/SRV)")
    logger.info(f"Total uplinks identified: {len(uplink_ports)}")
    return uplink_ports

def select_camera_mac(entries, interface):
    count = len(entries)
    if count == 0:
        return None
    elif count == 1:
        logger.debug(f"  {interface}: Single MAC found")
        return entries[0]
    elif count == 2:
        logger.info(f"  {interface}: 2 MACs found - Private VLAN detected")
        return entries[0]
    else:
        logger.warning(f"  {interface}: {count} MACs found - Taking first")
        return entries[0]

def discover_cameras_from_switch(shell, switch_hostname, switch_type="UNKNOWN"):
    logger.info("="*80)
    logger.info(f"Scanning {switch_type} switch: {switch_hostname}")
    logger.info("="*80)
    logger.info("Clearing dynamic MAC address table...")
    send_cmd(shell, "clear mac address-table dynamic", timeout=10)
    logger.info("Waiting 60 seconds for MAC table to repopulate...")
    time.sleep(60)
    logger.info("MAC table refresh complete")
    uplink_ports = get_uplink_ports_from_neighbors(shell)
    if not uplink_ports:
        logger.warning(f"No uplink ports detected on {switch_hostname}")
    else:
        logger.info(f"Uplink ports to exclude: {uplink_ports}")
    up_interfaces = get_interface_status(shell)
    logger.info(f"Found {len(up_interfaces)} UP interfaces total")
    camera_count = 0
    scanned_count = 0
    for intf in up_interfaces:
        is_uplink = False
        for upl in uplink_ports:
            if is_same_interface(intf, upl):
                is_uplink = True
                logger.info(f"SKIP: {intf} - UPLINK PORT")
                break
        if is_uplink:
            continue
        scanned_count += 1
        cmd = f"show mac address-table interface {intf}"
        mac_out = send_cmd(shell, cmd, timeout=10)
        entries = parse_mac_table_interface(mac_out)
        if entries:
            selected_entry = select_camera_mac(entries, intf)
            if selected_entry:
                mac_formatted = convert_mac_format(selected_entry["mac_address"])
                camera_info = {
                    "switch_name": switch_hostname,
                    "switch_type": switch_type,
                    "port": selected_entry["port"],
                    "mac_address": mac_formatted,
                    "vlan": selected_entry["vlan"]
                }
                camera_data.append(camera_info)
                camera_count += 1
                discovery_stats["total_cameras_found"] += 1
                logger.info(f"  [+] Camera: {mac_formatted} on {selected_entry['port']} (VLAN {selected_entry['vlan']})")
        else:
            logger.debug(f"No dynamic MAC entries on {intf}")
    logger.info("")
    logger.info(f"Summary for {switch_hostname}:")
    logger.info(f"  - Total UP interfaces: {len(up_interfaces)}")
    logger.info(f"  - Uplink ports excluded: {len(uplink_ports)}")
    logger.info(f"  - Ports scanned: {scanned_count}")
    logger.info(f"  - Cameras found: {camera_count}")
    logger.info("="*80)

def process_switch(parent_ip, neighbor_info, switch_type="UNKNOWN", is_retry=False):
    """
    Process a switch with enhanced retry logic, hostname verification, and failure tracking.
    
    Args:
        parent_ip: IP of the parent aggregate
        neighbor_info: Dict with switch details
        switch_type: Type of switch (EDGE, SERVER, etc.)
        is_retry: True if this is a retry attempt from seed
        
    Returns:
        True on success, False on failure
    """
    global failed_switches
    
    switch_ip = neighbor_info["mgmt_ip"]
    switch_name = neighbor_info["remote_name"]
    local_intf = neighbor_info["local_intf"]
    
    # CRITICAL: Skip aggregate switches - they never have cameras directly connected
    if switch_type == "AGGREGATE":
        logger.debug(f"Skipping {switch_name} - aggregate switches don't have cameras")
        return True
    
    if not switch_ip or (switch_ip in visited_switches and not is_retry):
        return True  # Skip already processed
    
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
        # Don't increment attempted for retries - already counted in Phase 2
        discovery_stats["switches_retried_from_seed"] += 1
    
    # Get parent hostname for verification
    try:
        parent_hostname = get_hostname(agg_shell)
    except Exception:
        parent_hostname = agg_hostname or "UNKNOWN"
    
    try:
        if not verify_aggregate_connection():
            raise NetworkConnectionError("Parent connection lost", reconnect_needed=True)
        
        # Use new ssh_to_device with retry logic and hostname verification
        ssh_success = ssh_to_device(
            target_ip=switch_ip,
            expected_hostname=switch_name,
            parent_hostname=parent_hostname
        )
        
        # Handle case where target IP belongs to current switch
        if ssh_success is None:
            logger.info(f"Skipping {switch_name} ({switch_ip}) - IP belongs to current switch, not a separate device")
            # Don't count as failure, just skip it
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
                # Only add to failed list if this wasn't already a retry
                failed_switches.append(failure_info)
                logger.warning(f"Added {switch_name} to retry queue for Phase 3")
            
            discovery_stats["switches_by_type"][switch_type]["failed"] += 1
            discovery_stats["switches_failed_unreachable"] += 1
            discovery_stats["failure_details"].append(failure_info)
            return False  # Indicate failure
        
        # Verify we actually changed switches
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
            discover_cameras_from_switch(agg_shell, actual_hostname, switch_type)
            discovery_stats["switches_successfully_scanned"] += 1
            discovery_stats["switches_by_type"][switch_type]["successful"] += 1
            
            if is_retry:
                discovery_stats["switches_recovered_on_retry"] += 1
                logger.info(f"[RECOVERED] RETRY SUCCESS: {switch_name} recovered on retry from seed")
            
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
            
            # Verify we returned to parent
            final_hostname = get_hostname(agg_shell)
            if final_hostname != parent_hostname:
                logger.error(f"After exit: at {final_hostname}, expected {parent_hostname}")
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
            
            logger.info("Returned to parent switch")
            
            if not verify_aggregate_connection():
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
                
            return True  # Success!
            
        except Exception as e:
            logger.error(f"Error exiting: {e}")
            if not verify_aggregate_connection():
                raise NetworkConnectionError("Lost parent connection", reconnect_needed=True)
    
    except NetworkConnectionError as e:
        reconnect_needed = getattr(e, 'reconnect_needed', False)
        if reconnect_needed:
            logger.error(f"Parent connection lost while processing {switch_name}")
            # IMPORTANT: Still add to failed list even if parent connection lost
            # This switch should be retried in Phase 3 from seed
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
            raise  # Propagate to trigger reconnection
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
                    logger.info(f"  ✓ Added: {hostname} ({mgmt_ip})")
                else:
                    logger.warning(f"  ✗ No management IP for {hostname}")
            else:
                logger.info(f"  ✗ Skipping (same as current)")
    logger.info(f"Total aggregate neighbors found: {len(aggregate_neighbors)}")
    return aggregate_neighbors

def scan_aggregate_switch(shell, agg_ip, resume_mode=False):
    if not resume_mode and agg_ip in visited_switches:
        logger.info(f"Aggregate {agg_ip} already visited")
        return []
    if not resume_mode:
        visited_switches.add(agg_ip)
        discovered_aggregates.add(agg_ip)
    hostname = get_hostname(shell)
    aggregate_hostnames[agg_ip] = hostname
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
    logger.info(">>> Skipping camera scan on aggregate switch")
    new_aggregates = []
    if not resume_mode:
        new_aggregates = discover_aggregate_neighbors(shell, hostname)
    else:
        logger.info(">>> Resume mode: skipping aggregate discovery")
    logger.info(">>> Discovering downstream switches...")
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
    
    Since this is Layer 2, all edge switches should be reachable from the seed
    via CDP/LLDP regardless of which aggregate they're connected to.
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
    
    # Ensure we're connected to seed
    try:
        if not verify_aggregate_connection():
            logger.info("Reconnecting to seed for retry phase...")
            reconnect_to_aggregate("Phase 3 Retry")
    except Exception as e:
        logger.error(f"Cannot reconnect to seed for retries: {e}")
        return
    
    # Verify we're on seed
    current_hostname = get_hostname(agg_shell)
    seed_hostname = agg_hostname or "UNKNOWN"
    
    if current_hostname != seed_hostname:
        logger.warning(f"Not on seed switch (on {current_hostname}, expected {seed_hostname})")
        logger.warning(f"Attempting to return to seed...")
        try:
            # Try to exit back to seed
            for _ in range(5):  # Max 5 exits
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
    
    # Create a copy of failed switches to retry
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
        
        # Create neighbor_info for retry
        neighbor_info = {
            "remote_name": switch_name,
            "mgmt_ip": switch_ip,
            "local_intf": switch_info.get("local_intf", "Unknown")
        }
        
        try:
            # Retry the switch from seed
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
            
            # Try to reconnect to seed if connection lost
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
    logger.info("="*80)
    try:
        connect_to_seed()
    except NetworkConnectionError as e:
        logger.error(f"Failed to connect to seed: {e}")
        return
    
    # Get all IPs of the seed switch to avoid trying to SSH to it later
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
                    new_aggregates = scan_aggregate_switch(agg_shell, SEED_SWITCH_IP, resume_mode=True)
                    seed_scan_complete = True
                else:
                    new_aggregates = scan_aggregate_switch(agg_shell, SEED_SWITCH_IP, resume_mode=False)
                    for agg in new_aggregates:
                        # Skip if this IP belongs to the seed switch
                        if agg["mgmt_ip"] in seed_ips:
                            logger.info(f"Skipping {agg['hostname']} ({agg['mgmt_ip']}) - same as seed switch")
                            continue
                        if agg["mgmt_ip"] not in discovered_aggregates and agg["mgmt_ip"] not in aggregates_to_process:
                            aggregates_to_process.append(agg["mgmt_ip"])
                            logger.info(f"Added aggregate to queue: {agg['hostname']} ({agg['mgmt_ip']})")
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
            
            # Skip if this IP belongs to the seed switch
            if agg_ip in seed_ips:
                logger.info(f"Skipping aggregate {agg_ip} - same as seed switch")
                continue
                
            if agg_ip in discovered_aggregates:
                logger.info(f"Aggregate {agg_ip} already processed")
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
                    
                    # Get parent hostname before hop
                    parent_hostname = get_hostname(agg_shell)
                    
                    hop_success = ssh_to_device(
                        target_ip=agg_ip,
                        expected_hostname=None,
                        parent_hostname=parent_hostname
                    )
                    
                    if not hop_success:
                        logger.error(f"Failed to connect to {agg_ip} after {SSH_HOP_RETRY_ATTEMPTS} attempts")
                        break
                    
                    new_aggregates = scan_aggregate_switch(agg_shell, agg_ip)
                    for agg in new_aggregates:
                        # Skip if this IP belongs to the seed switch
                        if agg["mgmt_ip"] in seed_ips:
                            logger.info(f"Skipping {agg['hostname']} ({agg['mgmt_ip']}) - same as seed switch")
                            continue
                        if agg["mgmt_ip"] not in discovered_aggregates and agg["mgmt_ip"] not in aggregates_to_process:
                            aggregates_to_process.append(agg["mgmt_ip"])
                            logger.info(f"Added new aggregate: {agg['hostname']} ({agg['mgmt_ip']})")
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
                            logger.info(f"Reconnecting (attempt {aggregate_reconnect_attempts + 1})...")
                            try:
                                reconnect_to_aggregate(f"Aggregate {agg_ip}")
                                logger.info("Reconnected - will retry")
                            except NetworkConnectionError:
                                if aggregate_reconnect_attempts >= max_reconnects - 1:
                                    logger.error("Max reconnects reached. Moving to next.")
                                    break
                        else:
                            logger.error("Max reconnects reached. Moving to next.")
                            break
                    else:
                        logger.error(f"Error processing {agg_ip}: {e}")
                        break
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        # ====================================================================
        # PHASE 3: RETRY FAILED SWITCHES FROM SEED
        # ====================================================================
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
    logger.info(f"Total cameras found: {len(camera_data)}")
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
    logger.info(f"Total cameras: {discovery_stats['total_cameras_found']}")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"camera_inventory_{len(camera_data)}cameras_{timestamp}.json"
    output_data = {
        "discovery_metadata": {
            "timestamp": timestamp,
            "seed_switch": SEED_SWITCH_IP,
            "total_cameras": len(camera_data),
            "total_aggregates": len(discovered_aggregates)
        },
        "discovery_statistics": discovery_stats,
        "cameras": camera_data
    }
    with open(json_file, "w", encoding='utf-8' ) as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved: {json_file}")
    if camera_data:
        csv_file = f"camera_inventory_{len(camera_data)}cameras_{timestamp}.csv"
        with open(csv_file, "w", newline="", encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["switch_name", "switch_type", "port", "mac_address", "vlan"])
            writer.writeheader()
            writer.writerows(camera_data)
        logger.info(f"Saved: {csv_file}")
    logger.info(f"Log file: {log_filename}")

if __name__ == "__main__":
    main()
