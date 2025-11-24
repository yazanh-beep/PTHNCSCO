#!/usr/bin/env python3
"""
TDR Cable Diagnostics - Unified Tool
Runs cable diagnostics on network switches and analyzes results.

Usage:
    # Run diagnostics
    python3 tdr_cable_diagnostics.py scan <devices_file>
    
    # Analyze results
    python3 tdr_cable_diagnostics.py analyze <results.json> [--summary|--issues|--devices|--csv|--all]
    
    # Quick queries
    python3 tdr_cable_diagnostics.py query <results.json> <issues|longest|shortest|open|short|stats|all>
"""
import paramiko
import time
import sys
import logging
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict

# ========================= USER CONFIG =========================
AGG_IP = ""
USERNAME = ""
PASSWORD = ""
TIMEOUT = 10
MAX_READ = 65535

# TDR Test Configuration
TDR_TEST_TIMEOUT = 90
TDR_RESULT_WAIT = 10
TDR_BATCH_SIZE = 5
TDR_BATCH_DELAY = 2

# Retry configuration
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
TARGET_MAX_RETRIES = 3
TARGET_RETRY_DELAY = 8
TARGET_SSH_TIMEOUT = 60
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

file_handler = logging.FileHandler('tdr_diagnostics.log', mode='a')
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

class DiagnosticsError(Exception):
    pass
# ===============================================================


# ========================= SSH HELPERS =========================
def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, show_progress=False):
    """Wait for expected prompt patterns with timeout"""
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
    """Send command and wait for prompt"""
    if log_cmd:
        logger.debug(f"Sending: {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout, show_progress=show_progress)
# ===============================================================


# ========================= REGEX PATTERNS ======================
HOSTNAME_RE = re.compile(r'^\s*hostname\s+([\w.-]+)$', re.MULTILINE)
PROMPT_HOST_RE = re.compile(r'\r?\n([A-Za-z0-9._\-]+)[#>]')

IFACE_RE = re.compile(
    r'^(Po(?:rt-channel)?\d+|'
    r'(?:Gi|Te|Fo|Eth|Fa|TwoGi|FiveGi|TenGi|FortyGi|HundredGi)'
    r'(?:gabitEthernet)?(?:\d+/)*\d+)\b',
    re.IGNORECASE
)

IFACE_STATUS_RE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+(\S+)',
    re.MULTILINE
)

TDR_PAIR_RE = re.compile(
    r'Pair\s+([A-D])\s+length\s+(\d+|\+\-)\s+meters',
    re.IGNORECASE
)
TDR_STATUS_RE = re.compile(
    r'TDR\s+test\s+last\s+run:.*?result:\s+(\w+)',
    re.IGNORECASE | re.DOTALL
)
# ===============================================================


# ========================= CORE CONNECT ========================
def connect_to_agg(retry=0):
    """Connect to aggregation switch with retry logic"""
    try:
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            AGG_IP, 
            username=USERNAME, 
            password=PASSWORD,
            look_for_keys=False, 
            allow_agent=False, 
            timeout=10
        )
        shell = client.invoke_shell()
        
        logger.info("[CONNECT] Waiting for prompt...")
        out = expect_prompt(shell, ("#", ">"), timeout=15)
        if not out:
            raise NetworkConnectionError("No prompt from aggregation switch")
        
        # Enable mode
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=8, log_cmd=False)
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("#",), timeout=8, log_cmd=False)
        
        # Disable paging
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=6, log_cmd=False)
        
        # Get hostname
        agg_name = safe_get_hostname(shell) or "AGGREGATION"
        logger.info(f"[CONNECT] Connected to aggregation switch '{agg_name}'")
        return client, shell, agg_name
        
    except Exception as e:
        logger.error(f"[CONNECT] Failed: {e}")
        if retry < AGG_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {AGG_RETRY_DELAY}s before retry...")
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry+1)
        raise NetworkConnectionError(f"Failed to connect after {AGG_MAX_RETRIES} attempts: {e}")
# ===============================================================


# ========================= UTILS ===============================
def safe_get_hostname(shell) -> Optional[str]:
    """Safely get device hostname"""
    try:
        out = send_cmd(shell, "show run | i ^hostname", patterns=("#", ">"), timeout=6, log_cmd=False)
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

def find_trunk_interfaces(shell) -> List[str]:
    """Find all trunk/uplink interfaces that should be skipped"""
    logger.info("[TRUNK] Identifying trunk/uplink interfaces...")
    trunks = set()
    
    # Method 1: Check show interfaces trunk
    try:
        out = send_cmd(shell, "show interfaces trunk", patterns=("#", ">"), timeout=15)
        for line in out.splitlines():
            s = line.strip()
            if not s or s.endswith("#") or s.endswith(">"):
                continue
            m = IFACE_RE.match(s)
            if m:
                # Normalize interface name before adding
                iface_normalized = normalize_interface_name(m.group(1))
                trunks.add(iface_normalized)
    except Exception as e:
        logger.debug(f"[TRUNK] Method 1 failed: {e}")
    
    # Method 2: Check running config for trunk mode
    try:
        out = send_cmd(shell, "show run | section interface", patterns=("#",), timeout=20)
        current_iface = None
        
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('interface '):
                parts = line.split()
                if len(parts) >= 2:
                    current_iface = parts[1]
            elif current_iface and 'switchport mode trunk' in line:
                # Normalize interface name before adding
                iface_normalized = normalize_interface_name(current_iface)
                trunks.add(iface_normalized)
    except Exception as e:
        logger.debug(f"[TRUNK] Method 2 failed: {e}")
    
    # Method 3: Check for port-channels
    try:
        out = send_cmd(shell, "show etherchannel summary", patterns=("#", ">"), timeout=12)
        for line in out.splitlines():
            if line.strip().startswith('Po'):
                m = re.match(r'^(Po\d+)', line.strip())
                if m:
                    # Normalize interface name before adding
                    iface_normalized = normalize_interface_name(m.group(1))
                    trunks.add(iface_normalized)
    except Exception as e:
        logger.debug(f"[TRUNK] Method 3 failed: {e}")
    
    trunks_list = sorted(trunks)
    logger.info(f"[TRUNK] Found {len(trunks_list)} trunk interface(s): {', '.join(trunks_list) if trunks_list else 'None'}")
    return trunks_list

def normalize_interface_name(iface: str) -> str:
    """Normalize interface names for comparison"""
    iface = iface.strip()
    replacements = {
        'GigabitEthernet': 'Gi',
        'TenGigabitEthernet': 'Te',
        'FortyGigabitEthernet': 'Fo',
        'FastEthernet': 'Fa',
        'Ethernet': 'Eth',
        'Port-channel': 'Po'
    }
    for long, short in replacements.items():
        if iface.startswith(long):
            iface = short + iface[len(long):]
            break
    return iface

def get_testable_interfaces(shell, trunk_list: List[str]) -> List[str]:
    """Get list of interfaces that should be tested"""
    logger.info("[INTERFACES] Getting list of testable interfaces...")
    
    trunks_normalized = {normalize_interface_name(t) for t in trunk_list}
    testable = []
    
    try:
        out = send_cmd(shell, "show interface status", patterns=("#", ">"), timeout=15)
        
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith('Port') or line.startswith('---'):
                continue
            
            parts = line.split()
            if len(parts) < 3:
                continue
            
            iface_name = parts[0]
            status = parts[2] if len(parts) > 2 else ""
            
            if not IFACE_RE.match(iface_name):
                continue
            
            if status.lower() not in ['connected', 'up']:
                logger.debug(f"[INTERFACES] Skipping {iface_name}: status={status}")
                continue
            
            iface_normalized = normalize_interface_name(iface_name)
            if iface_normalized in trunks_normalized:
                logger.debug(f"[INTERFACES] Skipping {iface_name}: is trunk/uplink")
                continue
            
            testable.append(iface_name)
    
    except Exception as e:
        logger.error(f"[INTERFACES] Failed to get interface list: {e}")
        try:
            out = send_cmd(shell, "show ip interface brief", patterns=("#", ">"), timeout=15)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    iface_name = parts[0]
                    if IFACE_RE.match(iface_name):
                        iface_normalized = normalize_interface_name(iface_name)
                        if iface_normalized not in trunks_normalized:
                            testable.append(iface_name)
        except Exception as e2:
            logger.error(f"[INTERFACES] Fallback method also failed: {e2}")
    
    logger.info(f"[INTERFACES] Found {len(testable)} testable interface(s)")
    return testable
# ===============================================================


# ========================= TDR FUNCTIONS =======================
def run_tdr_test(shell, interface: str) -> bool:
    """Initiate TDR test on an interface"""
    try:
        logger.debug(f"[TDR] Initiating test on {interface}")
        out = send_cmd(
            shell, 
            f"test cable-diagnostics tdr interface {interface}",
            patterns=("#", "%"),
            timeout=10
        )
        
        if "Invalid" in out or "incomplete" in out or "% " in out:
            logger.warning(f"[TDR] Failed to initiate test on {interface}: {out[-100:]}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"[TDR] Exception initiating test on {interface}: {e}")
        return False

def parse_tdr_results(output: str, interface: str) -> Dict[str, Any]:
    """Parse TDR test results from show cable-diagnostics output"""
    result = {
        "interface": interface,
        "test_status": "unknown",
        "pairs": {},
        "raw_output": output
    }
    
    try:
        status_match = re.search(
            r'TDR\s+test\s+last\s+run.*?(\w+)',
            output,
            re.IGNORECASE | re.DOTALL
        )
        if status_match:
            result["test_status"] = status_match.group(1).lower()
        
        for line in output.splitlines():
            line = line.strip()
            
            pair_match = re.search(
                r'Pair\s+([A-D])\s+(\S+)\s+(\S+)(?:\s+(\S+))?',
                line,
                re.IGNORECASE
            )
            
            if pair_match:
                pair_name = pair_match.group(1).upper()
                
                pair_data = {
                    "status": "unknown",
                    "length": None,
                    "length_unit": "meters"
                }
                
                if "length" in line.lower():
                    length_match = re.search(r'(\d+|\+\-)\s+meters', line, re.IGNORECASE)
                    if length_match:
                        length_str = length_match.group(1)
                        if length_str != '+-':
                            try:
                                pair_data["length"] = int(length_str)
                            except ValueError:
                                pair_data["length"] = length_str
                    
                    status_match = re.search(
                        r'(Normal|Open|Short|Impedance\s+Mismatch|Not\s+Completed)',
                        line,
                        re.IGNORECASE
                    )
                    if status_match:
                        pair_data["status"] = status_match.group(1).lower().replace(' ', '_')
                    elif pair_data["length"] is not None:
                        pair_data["status"] = "normal"
                else:
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            pair_data["length"] = int(parts[2])
                            pair_data["status"] = parts[3].lower() if len(parts) > 3 else "normal"
                        except (ValueError, IndexError):
                            pass
                
                result["pairs"][f"pair_{pair_name}"] = pair_data
        
        if not result["pairs"]:
            if "Not yet run" in output or "not yet run" in output:
                result["test_status"] = "not_run"
            elif "In progress" in output or "in progress" in output:
                result["test_status"] = "in_progress"
    
    except Exception as e:
        logger.error(f"[PARSE] Error parsing TDR results for {interface}: {e}")
        result["parse_error"] = str(e)
    
    return result

def get_tdr_results(shell, interface: str) -> Dict[str, Any]:
    """Get TDR test results for an interface"""
    try:
        logger.debug(f"[TDR] Getting results for {interface}")
        out = send_cmd(
            shell,
            f"show cable-diagnostics tdr interface {interface}",
            patterns=("#", ">"),
            timeout=10
        )
        
        return parse_tdr_results(out, interface)
        
    except Exception as e:
        logger.error(f"[TDR] Exception getting results for {interface}: {e}")
        return {
            "interface": interface,
            "test_status": "error",
            "error": str(e)
        }

def run_tdr_diagnostics(shell, interfaces: List[str]) -> Dict[str, Dict[str, Any]]:
    """Run TDR diagnostics on all specified interfaces"""
    results = {}
    total = len(interfaces)
    
    logger.info(f"[TDR] Starting diagnostics on {total} interface(s)")
    
    if not interfaces:
        logger.warning("[TDR] No interfaces to test")
        return results
    
    for batch_num in range(0, total, TDR_BATCH_SIZE):
        batch = interfaces[batch_num:batch_num + TDR_BATCH_SIZE]
        batch_end = min(batch_num + TDR_BATCH_SIZE, total)
        
        logger.info(f"[TDR] Processing batch {batch_num//TDR_BATCH_SIZE + 1} "
                   f"(interfaces {batch_num+1}-{batch_end} of {total})")
        
        initiated = []
        for iface in batch:
            if run_tdr_test(shell, iface):
                initiated.append(iface)
                time.sleep(0.5)
            else:
                results[iface] = {
                    "interface": iface,
                    "test_status": "failed_to_initiate",
                    "error": "Could not start TDR test"
                }
        
        if not initiated:
            logger.warning(f"[TDR] No tests initiated in this batch")
            continue
        
        logger.info(f"[TDR] Waiting {TDR_RESULT_WAIT}s for tests to complete...")
        time.sleep(TDR_RESULT_WAIT)
        
        for iface in initiated:
            logger.info(f"[TDR] Collecting results for {iface}")
            results[iface] = get_tdr_results(shell, iface)
            time.sleep(0.3)
        
        if batch_end < total:
            logger.info(f"[TDR] Batch delay {TDR_BATCH_DELAY}s before next batch...")
            time.sleep(TDR_BATCH_DELAY)
    
    completed = sum(1 for r in results.values() if r.get("test_status") not in ["error", "failed_to_initiate"])
    logger.info(f"[TDR] Completed {completed}/{total} tests successfully")
    
    return results
# ===============================================================


# ========================= HOP & EXIT ==========================
def establish_device_session(shell, target_ip: str):
    """Establish SSH session to target device"""
    logger.info(f"[HOP] SSH to {target_ip}")
    
    if shell.closed:
        raise NetworkConnectionError("SSH shell to aggregation switch is closed", reconnect_needed=True)

    out = send_cmd(
        shell,
        f"ssh -l {USERNAME} {target_ip}",
        patterns=("Destination", "(yes/no)?", "yes/no", "assword:", "%", "#", ">", 
                 "Connection refused", "Connection timed out"),
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

    last = out.strip().splitlines()[-1] if out.strip().splitlines() else ""
    if last.endswith(">") or (out.count(">") > out.count("#")):
        out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=8)
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=8)
        if "#" not in out:
            raise NetworkConnectionError(f"Failed to enter enable on {target_ip}", retry_allowed=True)

    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5, log_cmd=False)
    send_cmd(shell, "", patterns=("#",), timeout=3, log_cmd=False)
    
    logger.info(f"[CONNECTED] Successfully connected to {target_ip}")
    return True

def exit_to_agg(shell):
    """Return one level (target -> agg) safely"""
    try:
        if getattr(shell, "closed", False):
            logger.warning("[EXIT] Channel already closed; skipping exit")
            return
        
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
        
        try:
            shell.send("\n")
            time.sleep(0.2)
            if shell.recv_ready():
                _ = shell.recv(MAX_READ)
        except Exception:
            pass
        
        logger.info("[EXIT] Returned to aggregation switch")
        
    except Exception as e:
        logger.warning(f"[EXIT] Error: {e}")
# ===============================================================


# ========================= DEVICE DIAGNOSTICS ==================
def run_device_diagnostics(shell, target_ip: str) -> Tuple[Optional[Dict], bool]:
    """Connect to device and run TDR diagnostics"""
    
    try:
        establish_device_session(shell, target_ip)
    except NetworkConnectionError as e:
        logger.warning(f"[SKIP] {target_ip} SSH hop failed — {e}")
        
        if getattr(e, "retry_allowed", False):
            if getattr(shell, "closed", False) or getattr(e, "reconnect_needed", False):
                return (None, True)
            return (None, False)
        else:
            logger.info(f"[SKIP] {target_ip} is unreachable - will not retry")
            return (None, False)
    
    device_name = safe_get_hostname(shell) or target_ip
    logger.info(f"[DEVICE] Running diagnostics on '{device_name}'")
    
    device_data = {
        "device_ip": target_ip,
        "device_hostname": device_name,
        "timestamp": datetime.now().isoformat(),
        "interfaces": {}
    }
    
    try:
        trunk_list = find_trunk_interfaces(shell)
        device_data["trunk_interfaces"] = trunk_list
        
        testable = get_testable_interfaces(shell, trunk_list)
        device_data["testable_interfaces"] = testable
        
        if not testable:
            logger.warning(f"[DEVICE] No testable interfaces found on {device_name}")
            device_data["status"] = "no_testable_interfaces"
        else:
            tdr_results = run_tdr_diagnostics(shell, testable)
            device_data["interfaces"] = tdr_results
            device_data["status"] = "completed"
        
    except Exception as e:
        logger.error(f"[DEVICE] Error during diagnostics on {target_ip}: {e}")
        device_data["status"] = "error"
        device_data["error"] = str(e)
    
    exit_to_agg(shell)
    
    return (device_data, False)
# ===============================================================


# ========================= SCAN COMMAND ========================
def cmd_scan(devices_file: str, auto_mode: bool = False):
    """Main scan command - run TDR diagnostics on devices"""
    logger.info("=" * 70)
    logger.info("TDR CABLE DIAGNOSTICS SCAN")
    logger.info("=" * 70)
    logger.info(f"Aggregation Switch: {AGG_IP}")
    logger.info(f"Devices file: {devices_file}")
    logger.info(f"Log file: tdr_diagnostics.log")
    logger.info("")

    try:
        with open(devices_file, "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError as e:
        logger.error(f"Devices file not found: {e}")
        sys.exit(1)

    logger.info(f"Target devices: {len(targets)}")
    for ip in targets:
        logger.info(f"   - {ip}")
    logger.info("")

    try:
        client, shell, agg_name = connect_to_agg()
    except Exception as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)

    all_results = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "aggregation_switch": AGG_IP,
            "aggregation_hostname": agg_name,
            "total_devices": len(targets),
            "tdr_test_timeout": TDR_TEST_TIMEOUT,
            "tdr_result_wait": TDR_RESULT_WAIT
        },
        "devices": {}
    }

    successful = []
    failed = []
    start_time = time.time()

    for idx, target_ip in enumerate(targets, 1):
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"DEVICE {idx}/{len(targets)}: {target_ip}")
        logger.info("=" * 70)

        device_ok = False

        for attempt in range(1, TARGET_MAX_RETRIES + 1):
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
                    logger.error(f"Could not reconnect: {e}")
                    break

            logger.info(f"[ATTEMPT] {attempt}/{TARGET_MAX_RETRIES} for {target_ip}")
            device_start = time.time()
            
            result_data, reconnect_needed = run_device_diagnostics(shell, target_ip)

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
            elif result_data:
                elapsed = time.time() - device_start
                logger.info(f"[SUCCESS] Diagnostics completed for {target_ip} in {elapsed:.1f}s")
                all_results["devices"][target_ip] = result_data
                device_ok = True
                break
            else:
                logger.warning(f"[RETRY] Will retry {target_ip} after {TARGET_RETRY_DELAY}s...")
                time.sleep(TARGET_RETRY_DELAY)

        if device_ok:
            successful.append(target_ip)
        else:
            logger.error(f"[FAILED] Could not run diagnostics on {target_ip} after {TARGET_MAX_RETRIES} attempts")
            failed.append(target_ip)
            all_results["devices"][target_ip] = {
                "device_ip": target_ip,
                "status": "failed",
                "error": f"Could not connect after {TARGET_MAX_RETRIES} attempts"
            }

        time.sleep(1)

    try:
        client.close()
        logger.info("")
        logger.info("[DISCONNECT] Closed aggregation switch session")
    except Exception:
        pass

    total_elapsed = time.time() - start_time
    all_results["scan_info"]["duration_seconds"] = round(total_elapsed, 1)
    all_results["scan_info"]["successful_devices"] = len(successful)
    all_results["scan_info"]["failed_devices"] = len(failed)

    output_filename = f"tdr_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(output_filename, 'w') as f:
            json.dump(all_results, f, indent=2)
        logger.info("")
        logger.info(f"[OUTPUT] Results saved to: {output_filename}")
    except Exception as e:
        logger.error(f"[OUTPUT] Failed to save JSON results: {e}")

    logger.info("")
    logger.info("=" * 70)
    logger.info("DIAGNOSTICS SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total time: {total_elapsed:.1f}s")
    logger.info(f"Total devices: {len(targets)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed: {len(failed)}")
    logger.info(f"Success rate: {(len(successful)/len(targets)*100):.1f}%")
    
    if successful:
        logger.info(f"\nSuccessful devices:")
        for device in successful:
            logger.info(f"   - {device}")
    
    if failed:
        logger.error(f"\nFailed devices:")
        for device in failed:
            logger.error(f"   - {device}")
    
    total_interfaces = sum(
        len(data.get("interfaces", {})) 
        for data in all_results["devices"].values()
        if data.get("status") == "completed"
    )
    logger.info(f"\nTotal interfaces tested: {total_interfaces}")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info(f"Results available in: {output_filename}")
    logger.info("=" * 70)
    
    # If in auto-mode, return instead of exiting
    if auto_mode:
        return output_filename
    
    sys.exit(0 if not failed else 1)
# ===============================================================


# ========================= ANALYZE COMMAND =====================
def load_results(filename: str) -> Dict:
    """Load TDR results from JSON file"""
    with open(filename, 'r') as f:
        return json.load(f)

def analyze_cable_issues(results: Dict) -> Dict[str, List[Dict]]:
    """Analyze results and categorize cable issues"""
    issues = {
        'open': [],
        'short': [],
        'impedance_mismatch': [],
        'no_cable': [],
        'other': []
    }
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            pairs = iface_data.get('pairs', {})
            
            for pair_name, pair_data in pairs.items():
                status = pair_data.get('status', 'unknown')
                
                if status != 'normal':
                    issue_info = {
                        'device_ip': device_ip,
                        'device_name': device_name,
                        'interface': iface_name,
                        'pair': pair_name,
                        'status': status,
                        'length': pair_data.get('length', 'N/A')
                    }
                    
                    if status == 'open':
                        issues['open'].append(issue_info)
                    elif status == 'short':
                        issues['short'].append(issue_info)
                    elif 'impedance' in status:
                        issues['impedance_mismatch'].append(issue_info)
                    else:
                        issues['other'].append(issue_info)
    
    return issues

def generate_summary_report(results: Dict) -> str:
    """Generate summary report"""
    lines = []
    lines.append("=" * 80)
    lines.append("TDR CABLE DIAGNOSTICS SUMMARY REPORT")
    lines.append("=" * 80)
    lines.append("")
    
    scan_info = results.get('scan_info', {})
    lines.append(f"Scan Timestamp:    {scan_info.get('timestamp', 'N/A')}")
    lines.append(f"Aggregation SW:    {scan_info.get('aggregation_hostname', 'N/A')} ({scan_info.get('aggregation_switch', 'N/A')})")
    lines.append(f"Duration:          {scan_info.get('duration_seconds', 0):.1f} seconds")
    lines.append(f"Total Devices:     {scan_info.get('total_devices', 0)}")
    lines.append(f"Successful:        {scan_info.get('successful_devices', 0)}")
    lines.append(f"Failed:            {scan_info.get('failed_devices', 0)}")
    lines.append("")
    
    total_interfaces = 0
    total_issues = 0
    devices_with_issues = set()
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') == 'completed':
            interfaces = device_data.get('interfaces', {})
            total_interfaces += len(interfaces)
            
            for iface_name, iface_data in interfaces.items():
                pairs = iface_data.get('pairs', {})
                for pair_data in pairs.values():
                    if pair_data.get('status') != 'normal':
                        total_issues += 1
                        devices_with_issues.add(device_ip)
    
    lines.append(f"Total Interfaces Tested:  {total_interfaces}")
    lines.append(f"Total Cable Issues:       {total_issues}")
    lines.append(f"Devices with Issues:      {len(devices_with_issues)}")
    lines.append("")
    
    return "\n".join(lines)

def generate_issue_report(results: Dict) -> str:
    """Generate detailed issue report"""
    lines = []
    lines.append("=" * 80)
    lines.append("CABLE ISSUES DETAIL REPORT")
    lines.append("=" * 80)
    lines.append("")
    
    issues = analyze_cable_issues(results)
    
    if issues['open']:
        lines.append(f"OPEN CIRCUITS ({len(issues['open'])} issues)")
        lines.append("-" * 80)
        for issue in issues['open']:
            lines.append(f"  Device: {issue['device_name']} ({issue['device_ip']})")
            lines.append(f"    Interface: {issue['interface']}, {issue['pair']}")
            lines.append(f"    Distance to fault: {issue['length']} meters")
            lines.append("")
    
    if issues['short']:
        lines.append(f"SHORT CIRCUITS ({len(issues['short'])} issues)")
        lines.append("-" * 80)
        for issue in issues['short']:
            lines.append(f"  Device: {issue['device_name']} ({issue['device_ip']})")
            lines.append(f"    Interface: {issue['interface']}, {issue['pair']}")
            lines.append(f"    Distance to fault: {issue['length']} meters")
            lines.append("")
    
    if issues['impedance_mismatch']:
        lines.append(f"IMPEDANCE MISMATCHES ({len(issues['impedance_mismatch'])} issues)")
        lines.append("-" * 80)
        for issue in issues['impedance_mismatch']:
            lines.append(f"  Device: {issue['device_name']} ({issue['device_ip']})")
            lines.append(f"    Interface: {issue['interface']}, {issue['pair']}")
            lines.append(f"    Distance: {issue['length']} meters")
            lines.append("")
    
    if issues['other']:
        lines.append(f"OTHER ISSUES ({len(issues['other'])} issues)")
        lines.append("-" * 80)
        for issue in issues['other']:
            lines.append(f"  Device: {issue['device_name']} ({issue['device_ip']})")
            lines.append(f"    Interface: {issue['interface']}, {issue['pair']}")
            lines.append(f"    Status: {issue['status']}")
            lines.append(f"    Length: {issue['length']} meters")
            lines.append("")
    
    if not any(issues.values()):
        lines.append("✓ No cable issues detected!")
        lines.append("")
    
    return "\n".join(lines)

def generate_device_report(results: Dict) -> str:
    """Generate per-device report"""
    lines = []
    lines.append("=" * 80)
    lines.append("PER-DEVICE DETAILED REPORT")
    lines.append("=" * 80)
    lines.append("")
    
    for device_ip, device_data in results['devices'].items():
        device_name = device_data.get('device_hostname', device_ip)
        status = device_data.get('status', 'unknown')
        
        lines.append(f"DEVICE: {device_name} ({device_ip})")
        lines.append("-" * 80)
        lines.append(f"Status: {status}")
        
        if status == 'failed':
            lines.append(f"Error: {device_data.get('error', 'Unknown error')}")
            lines.append("")
            continue
        
        if status != 'completed':
            lines.append("")
            continue
        
        trunk_ifaces = device_data.get('trunk_interfaces', [])
        testable_ifaces = device_data.get('testable_interfaces', [])
        
        lines.append(f"Trunk/Uplink Ports: {', '.join(trunk_ifaces) if trunk_ifaces else 'None'}")
        lines.append(f"Tested Interfaces:  {len(testable_ifaces)}")
        lines.append("")
        
        interfaces = device_data.get('interfaces', {})
        
        if not interfaces:
            lines.append("  No interfaces tested")
            lines.append("")
            continue
        
        for iface_name in sorted(interfaces.keys()):
            iface_data = interfaces[iface_name]
            test_status = iface_data.get('test_status', 'unknown')
            
            lines.append(f"  Interface: {iface_name}")
            lines.append(f"    Test Status: {test_status}")
            
            pairs = iface_data.get('pairs', {})
            if pairs:
                has_issue = False
                for pair_name in sorted(pairs.keys()):
                    pair_data = pairs[pair_name]
                    status = pair_data.get('status', 'unknown')
                    length = pair_data.get('length', 'N/A')
                    
                    status_symbol = "✓" if status == "normal" else "✗"
                    
                    if status != "normal":
                        has_issue = True
                    
                    lines.append(f"      {status_symbol} {pair_name}: {status} - {length} meters")
                
                if has_issue:
                    lines.append("      ⚠ CABLE ISSUE DETECTED")
            else:
                lines.append("      No pair data available")
            
            lines.append("")
        
        lines.append("")
    
    return "\n".join(lines)

def generate_csv_export(results: Dict) -> str:
    """Generate CSV export of all test results"""
    lines = []
    lines.append("device_ip,device_hostname,interface,pair,status,length_meters")
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            pairs = iface_data.get('pairs', {})
            
            for pair_name, pair_data in pairs.items():
                status = pair_data.get('status', 'unknown')
                length = pair_data.get('length', '')
                
                lines.append(f"{device_ip},{device_name},{iface_name},{pair_name},{status},{length}")
    
    return "\n".join(lines)

def cmd_analyze(filename: str, options: List[str]):
    """Analyze command - generate reports from TDR results"""
    try:
        results = load_results(filename)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}")
        sys.exit(1)
    
    if not options or '--all' in options:
        options = ['--summary', '--issues', '--devices', '--csv']
    
    if '--summary' in options:
        print(generate_summary_report(results))
    
    if '--issues' in options:
        print(generate_issue_report(results))
    
    if '--devices' in options:
        print(generate_device_report(results))
    
    if '--csv' in options:
        csv_output = generate_csv_export(results)
        csv_filename = filename.replace('.json', '.csv')
        with open(csv_filename, 'w') as f:
            f.write(csv_output)
        print(f"\n✓ CSV export saved to: {csv_filename}\n")
# ===============================================================


# ========================= QUERY COMMAND =======================
def query_devices_with_issues(results: Dict):
    """List all devices that have cable issues"""
    print("\n" + "=" * 70)
    print("DEVICES WITH CABLE ISSUES")
    print("=" * 70 + "\n")
    
    devices_with_issues = {}
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        issue_count = 0
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            for pair_data in iface_data.get('pairs', {}).values():
                if pair_data.get('status') != 'normal':
                    issue_count += 1
        
        if issue_count > 0:
            devices_with_issues[device_name] = {
                'ip': device_ip,
                'issues': issue_count
            }
    
    if not devices_with_issues:
        print("✓ No devices with cable issues detected!\n")
        return
    
    for device_name in sorted(devices_with_issues.keys()):
        info = devices_with_issues[device_name]
        print(f"  {device_name} ({info['ip']})")
        print(f"    → {info['issues']} cable issue(s)\n")
    
    print(f"Total: {len(devices_with_issues)} device(s) with issues\n")

def query_longest_cables(results: Dict, top_n: int = 10):
    """Find the longest cable runs"""
    print("\n" + "=" * 70)
    print(f"TOP {top_n} LONGEST CABLE RUNS")
    print("=" * 70 + "\n")
    
    cables = []
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            lengths = []
            for pair_data in iface_data.get('pairs', {}).values():
                length = pair_data.get('length')
                if length and isinstance(length, (int, float)):
                    lengths.append(length)
            
            if lengths:
                avg_length = sum(lengths) / len(lengths)
                cables.append({
                    'device': device_name,
                    'ip': device_ip,
                    'interface': iface_name,
                    'length': avg_length
                })
    
    cables.sort(key=lambda x: x['length'], reverse=True)
    
    for i, cable in enumerate(cables[:top_n], 1):
        print(f"{i:2d}. {cable['device']} ({cable['ip']})")
        print(f"     Interface: {cable['interface']}")
        print(f"     Length: {cable['length']:.1f} meters\n")

def query_shortest_cables(results: Dict, top_n: int = 10):
    """Find the shortest cable runs"""
    print("\n" + "=" * 70)
    print(f"TOP {top_n} SHORTEST CABLE RUNS")
    print("=" * 70 + "\n")
    
    cables = []
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            lengths = []
            for pair_data in iface_data.get('pairs', {}).values():
                length = pair_data.get('length')
                if length and isinstance(length, (int, float)):
                    lengths.append(length)
            
            if lengths:
                avg_length = sum(lengths) / len(lengths)
                cables.append({
                    'device': device_name,
                    'ip': device_ip,
                    'interface': iface_name,
                    'length': avg_length
                })
    
    cables.sort(key=lambda x: x['length'])
    
    for i, cable in enumerate(cables[:top_n], 1):
        print(f"{i:2d}. {cable['device']} ({cable['ip']})")
        print(f"     Interface: {cable['interface']}")
        print(f"     Length: {cable['length']:.1f} meters\n")

def query_open_circuits(results: Dict):
    """List all open circuits"""
    print("\n" + "=" * 70)
    print("OPEN CIRCUITS (Disconnected/Damaged Cables)")
    print("=" * 70 + "\n")
    
    found = False
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        device_printed = False
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            interface_printed = False
            
            for pair_name, pair_data in iface_data.get('pairs', {}).items():
                if pair_data.get('status') == 'open':
                    if not device_printed:
                        print(f"Device: {device_name} ({device_ip})")
                        device_printed = True
                        found = True
                    
                    if not interface_printed:
                        print(f"  Interface: {iface_name}")
                        interface_printed = True
                    
                    length = pair_data.get('length', 'N/A')
                    print(f"    {pair_name}: OPEN at {length} meters")
            
            if interface_printed:
                print()
        
        if device_printed:
            print()
    
    if not found:
        print("✓ No open circuits detected!\n")

def query_short_circuits(results: Dict):
    """List all short circuits"""
    print("\n" + "=" * 70)
    print("SHORT CIRCUITS")
    print("=" * 70 + "\n")
    
    found = False
    
    for device_ip, device_data in results['devices'].items():
        if device_data.get('status') != 'completed':
            continue
        
        device_name = device_data.get('device_hostname', device_ip)
        device_printed = False
        
        for iface_name, iface_data in device_data.get('interfaces', {}).items():
            interface_printed = False
            
            for pair_name, pair_data in iface_data.get('pairs', {}).items():
                if pair_data.get('status') == 'short':
                    if not device_printed:
                        print(f"Device: {device_name} ({device_ip})")
                        device_printed = True
                        found = True
                    
                    if not interface_printed:
                        print(f"  Interface: {iface_name}")
                        interface_printed = True
                    
                    length = pair_data.get('length', 'N/A')
                    print(f"    {pair_name}: SHORT at {length} meters")
            
            if interface_printed:
                print()
        
        if device_printed:
            print()
    
    if not found:
        print("✓ No short circuits detected!\n")

def query_statistics(results: Dict):
    """Show overall statistics"""
    print("\n" + "=" * 70)
    print("TDR DIAGNOSTICS STATISTICS")
    print("=" * 70 + "\n")
    
    scan_info = results.get('scan_info', {})
    
    print(f"Scan Date:         {scan_info.get('timestamp', 'N/A')[:19]}")
    print(f"Duration:          {scan_info.get('duration_seconds', 0):.1f} seconds")
    print(f"Aggregation SW:    {scan_info.get('aggregation_hostname', 'N/A')}")
    print()
    
    total_devices = len(results.get('devices', {}))
    successful = 0
    failed = 0
    total_interfaces = 0
    total_pairs = 0
    
    status_counts = {'normal': 0, 'open': 0, 'short': 0, 'impedance_mismatch': 0, 'other': 0}
    cable_lengths = []
    
    for device_data in results['devices'].values():
        if device_data.get('status') == 'completed':
            successful += 1
            interfaces = device_data.get('interfaces', {})
            total_interfaces += len(interfaces)
            
            for iface_data in interfaces.values():
                pairs = iface_data.get('pairs', {})
                total_pairs += len(pairs)
                
                for pair_data in pairs.values():
                    status = pair_data.get('status', 'other')
                    
                    if status in status_counts:
                        status_counts[status] += 1
                    else:
                        status_counts['other'] += 1
                    
                    length = pair_data.get('length')
                    if length and isinstance(length, (int, float)):
                        cable_lengths.append(length)
        else:
            failed += 1
    
    print(f"Total Devices:     {total_devices}")
    print(f"  Successful:      {successful}")
    print(f"  Failed:          {failed}")
    print()
    
    print(f"Total Interfaces:  {total_interfaces}")
    print(f"Total Pairs:       {total_pairs}")
    print()
    
    print("Pair Status Breakdown:")
    print(f"  Normal:          {status_counts['normal']} ({status_counts['normal']/max(total_pairs,1)*100:.1f}%)")
    print(f"  Open:            {status_counts['open']}")
    print(f"  Short:           {status_counts['short']}")
    print(f"  Impedance:       {status_counts['impedance_mismatch']}")
    print(f"  Other:           {status_counts['other']}")
    print()
    
    if cable_lengths:
        avg_length = sum(cable_lengths) / len(cable_lengths)
        min_length = min(cable_lengths)
        max_length = max(cable_lengths)
        
        print("Cable Length Statistics:")
        print(f"  Average:         {avg_length:.1f} meters")
        print(f"  Minimum:         {min_length:.1f} meters")
        print(f"  Maximum:         {max_length:.1f} meters")
        print()

def cmd_query(filename: str, query: str, args: List[str]):
    """Query command - quick queries on TDR results"""
    try:
        results = load_results(filename)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}")
        sys.exit(1)
    
    if query == 'issues':
        query_devices_with_issues(results)
    
    elif query == 'longest':
        top_n = int(args[0]) if args else 10
        query_longest_cables(results, top_n)
    
    elif query == 'shortest':
        top_n = int(args[0]) if args else 10
        query_shortest_cables(results, top_n)
    
    elif query == 'open':
        query_open_circuits(results)
    
    elif query == 'short':
        query_short_circuits(results)
    
    elif query == 'stats':
        query_statistics(results)
    
    elif query == 'all':
        query_statistics(results)
        query_devices_with_issues(results)
        query_open_circuits(results)
        query_short_circuits(results)
        query_longest_cables(results, 10)
        query_shortest_cables(results, 10)
    
    else:
        print(f"Unknown query: {query}")
        print("Available queries: issues, longest, shortest, open, short, stats, all")
        sys.exit(1)
# ===============================================================


# ========================= MAIN ================================
def print_usage():
    """Print usage information"""
    print("""
TDR Cable Diagnostics - Unified Tool

QUICK MODE (Automatic - Recommended):
  Just provide the devices file - auto scans, analyzes, and queries!
    python3 tdr_cable_diagnostics.py <devices_file>
  
  Example:
    python3 tdr_cable_diagnostics.py devices.txt
    
  This will automatically:
    1. Scan all devices
    2. Generate summary and issues reports
    3. Show statistics and devices with issues

MANUAL MODE (Advanced):
  Scan devices and run TDR diagnostics:
    python3 tdr_cable_diagnostics.py scan <devices_file>
  
  Analyze results:
    python3 tdr_cable_diagnostics.py analyze <results.json> [options]
    
    Options:
      --summary    Generate summary report (default)
      --issues     Generate detailed issues report
      --devices    Generate per-device report
      --csv        Generate CSV export
      --all        Generate all reports
  
  Quick queries:
    python3 tdr_cable_diagnostics.py query <results.json> <query_type> [args]
    
    Query types:
      issues           List devices with cable issues
      longest [N]      Show N longest cables (default: 10)
      shortest [N]     Show N shortest cables (default: 10)
      open             List all open circuits
      short            List all short circuits
      stats            Show overall statistics
      all              Run all queries

EXAMPLES:
  # Quick mode (easiest!)
  python3 tdr_cable_diagnostics.py devices.txt
  
  # Manual scan only
  python3 tdr_cable_diagnostics.py scan devices.txt
  
  # View summary
  python3 tdr_cable_diagnostics.py analyze tdr_results_*.json --summary
  
  # Find issues
  python3 tdr_cable_diagnostics.py query tdr_results_*.json issues
  
  # Export to CSV
  python3 tdr_cable_diagnostics.py analyze tdr_results_*.json --csv
  
  # Top 20 longest cables
  python3 tdr_cable_diagnostics.py query tdr_results_*.json longest 20

CONFIGURATION:
  Edit lines 29-50 in this script to configure:
  - AGG_IP: Aggregation switch IP address
  - USERNAME/PASSWORD: SSH credentials
  - TDR_BATCH_SIZE: Number of interfaces to test per batch
  - TARGET_MAX_RETRIES: Retry attempts per device
  
  See full documentation in TDR_README.md
""")

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    # Check if first argument is a file that exists (auto-mode)
    first_arg = sys.argv[1]
    
    # Auto-mode: If first argument is a file, assume scan + analyze + query
    if first_arg not in ['scan', 'analyze', 'query', 'help', '--help', '-h']:
        # Check if it's a devices file
        import os
        if os.path.isfile(first_arg):
            logger.info("=" * 70)
            logger.info("AUTO MODE: SCAN → ANALYZE → QUERY")
            logger.info("=" * 70)
            logger.info("")
            
            # Step 1: Scan
            logger.info("STEP 1/3: Running scan...")
            logger.info("")
            latest_results = cmd_scan(first_arg, auto_mode=True)
            
            if not latest_results:
                logger.error("No results file generated after scan!")
                sys.exit(1)
            
            logger.info("")
            logger.info("=" * 70)
            logger.info(f"STEP 2/3: Analyzing results from {latest_results}")
            logger.info("=" * 70)
            logger.info("")
            
            # Step 2: Analyze (show summary and issues)
            cmd_analyze(latest_results, ['--summary', '--issues'])
            
            logger.info("")
            logger.info("=" * 70)
            logger.info("STEP 3/3: Quick queries")
            logger.info("=" * 70)
            
            # Step 3: Query (show common queries)
            cmd_query(latest_results, 'stats', [])
            cmd_query(latest_results, 'issues', [])
            
            logger.info("")
            logger.info("=" * 70)
            logger.info("AUTO MODE COMPLETE")
            logger.info("=" * 70)
            logger.info(f"Full results available in: {latest_results}")
            logger.info("")
            logger.info("Additional commands you can run:")
            logger.info(f"  python {sys.argv[0]} analyze {latest_results} --csv")
            logger.info(f"  python {sys.argv[0]} query {latest_results} open")
            logger.info(f"  python {sys.argv[0]} query {latest_results} longest 20")
            logger.info("")
            
            return
        else:
            print(f"Error: File '{first_arg}' not found")
            print_usage()
            sys.exit(1)
    
    # Manual mode: explicit command specified
    command = sys.argv[1].lower()
    
    if command == 'scan':
        if len(sys.argv) < 3:
            print("Error: Missing devices file")
            print("Usage: python tdr_cable_diagnostics.py scan <devices_file>")
            sys.exit(1)
        cmd_scan(sys.argv[2], auto_mode=False)
    
    elif command == 'analyze':
        if len(sys.argv) < 3:
            print("Error: Missing results file")
            print("Usage: python tdr_cable_diagnostics.py analyze <results.json> [options]")
            sys.exit(1)
        cmd_analyze(sys.argv[2], sys.argv[3:])
    
    elif command == 'query':
        if len(sys.argv) < 4:
            print("Error: Missing results file or query type")
            print("Usage: python tdr_cable_diagnostics.py query <results.json> <query_type>")
            sys.exit(1)
        cmd_query(sys.argv[2], sys.argv[3].lower(), sys.argv[4:])
    
    elif command in ['help', '--help', '-h']:
        print_usage()
    
    else:
        print(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()
# ===============================================================
