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
    def __init__(self):
        super().__init__(sys.stdout)
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    def emit(self, record):
        try:
            msg = self.format(record)
            msg = msg.replace('✓', 'OK').replace('⏳', 'WAIT').replace('○', 'SKIP').replace('✗', 'ERROR').replace('⊗', 'X')
            print(msg, flush=True)
        except Exception:
            self.handleError(record)

running_in_idle = 'idlelib.run' in sys.modules
log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

if running_in_idle:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_filename, encoding='utf-8'), IDLESafeHandler()])
    print("="*80)
    print(f"RUNNING IN IDLE MODE - Logs: {log_filename}")
    print("="*80)
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(log_filename, encoding='utf-8'), logging.StreamHandler()])

logger = logging.getLogger(__name__)

# ============================================================================
# USER CONFIG
# ============================================================================

SEED_SWITCH_IP = ""
TIMEOUT = 150
MAX_READ = 65535
CREDENTIAL_SETS = [
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
MAC_POLL_INTERVAL = 5            
MAC_POLL_MAX_ATTEMPTS = 999999   
MAC_POLL_INITIAL_WAIT = 15       
MAC_POLL_BATCH_SIZE = 100        
MAC_POLL_BATCH_PAUSE = 2         
MAC_POLL_HARD_TIMEOUT = 180      

# --- INDIRECT DISCOVERY CONFIGURATION ---
ENABLE_INDIRECT_DISCOVERY = True    
INDIRECT_DISCOVERY_MIN_MACS = 1     
INDIRECT_DISCOVERY_MAX_MACS = 100   

#--- SWITCH TYPE DETECTION BY HARDWARE MODEL ---
HARDWARE_MODEL_MAPPING = {
    "3850": "AGGREGATE", "WS-C3850": "AGGREGATE",
    "3650": "EDGE", "WS-C3650": "EDGE",
    "9300": "EDGE", "C9300": "EDGE",
    "IE-": "EDGE", "IE-3": "EDGE", "IE-4": "EDGE", "IE-5": "EDGE", "ESS-": "EDGE", "CGS-": "EDGE",
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
    "switches_attempted": 0, "switches_successfully_scanned": 0,
    "switches_failed_auth": 0, "switches_failed_unreachable": 0,
    "switches_failed_timeout": 0, "switches_failed_other": 0,
    "aggregates_reconnections": 0, "total_cameras_found": 0,
    "switches_retried_from_seed": 0, "switches_recovered_on_retry": 0,
    "total_ports_no_mac": 0,
    "indirect_discoveries": 0, "switches_with_indirect_discovery": 0,
    "indirect_upgraded_to_direct": 0, "duplicates_removed": 0,
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
    if out.strip().endswith("#"): return True
    en = send_cmd(shell, "enable", timeout=5, silent=True)
    if en.strip().endswith("#"): return True
    if re.search(r"[Pp]assword:", en):
        for pw in enable_candidates:
            if not pw: continue
            test = send_cmd(shell, pw, timeout=timeout, silent=True)
            if test.strip().endswith("#"): return True
        return False
    return send_cmd(shell, "", timeout=3, silent=True).strip().endswith("#")

def verify_aggregate_connection():
    global agg_shell
    try:
        if not agg_shell or agg_shell.closed: return False
        agg_shell.send("\n")
        time.sleep(0.3)
        return bool(PROMPT_RE.search(agg_shell.recv(MAX_READ).decode("utf-8", "ignore"))) if agg_shell.recv_ready() else False
    except Exception:
        return False

def get_hostname(shell):
    shell.send("\n")
    time.sleep(0.2)
    buff = expect_prompt(shell, timeout=4)
    for line in reversed(buff.splitlines()):
        line = line.strip()
        if line.endswith('#') or line.endswith('>'):
            return line[:-1]
    return "Unknown"

def _connect_to_aggregate_internal():
    global agg_client, agg_shell, agg_creds, agg_hostname
    last_err = None
    for cred in CREDENTIAL_SETS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(SEED_SWITCH_IP, username=cred["username"], password=cred["password"], look_for_keys=False, allow_agent=False, timeout=15)
            shell = client.invoke_shell()
            expect_prompt(shell, timeout=TIMEOUT)
            if not _ensure_enable(shell, [cred.get("enable"), cred.get("password")], timeout=8):
                client.close()
                continue
            send_cmd(shell, "terminal length 0", silent=True)
            agg_client = client
            agg_shell = shell
            agg_creds = cred
            agg_hostname = get_hostname(agg_shell) or "UNKNOWN"
            logger.info(f"Seed hostname: {agg_hostname}")
            return SEED_SWITCH_IP
        except Exception as e:
            last_err = e
    raise last_err or Exception("Unable to connect")

def connect_to_seed(retry_count=0):
    try:
        return _connect_to_aggregate_internal()
    except Exception as e:
        if retry_count < AGG_MAX_RETRIES - 1:
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_seed(retry_count + 1)
        raise NetworkConnectionError(f"Failed after {AGG_MAX_RETRIES} attempts: {e}")

def reconnect_to_aggregate(reason=""):
    global agg_client
    if reason: logger.warning(f"[RECONNECT] {reason}")
    try: agg_client.close() 
    except: pass
    return _connect_to_aggregate_internal()

def verify_ip_reachable_quick(target_ip, shell, timeout=3):
    try:
        ping_out = send_cmd(shell, f"ping {target_ip} timeout 1 repeat 2", timeout=timeout, silent=True)
        return bool(re.search(r"Success rate is [1-9]|!+|\d+ packets received", ping_out))
    except: return True

def cleanup_and_return_to_parent(expected_parent, max_attempts=3):
    global agg_shell, session_depth
    for _ in range(max_attempts):
        if get_hostname(agg_shell) == expected_parent: return True
        agg_shell.send("exit\n")
        time.sleep(1)
        _drain(agg_shell)
        session_depth = max(0, session_depth - 1)
    return False

def ssh_to_device(target_ip, expected_hostname=None, parent_hostname=None):
    global agg_shell, session_depth, device_creds, hostname_to_ip
    if not parent_hostname: parent_hostname = get_hostname(agg_shell)
    
    # --- BUG FIX: EXACT IP MATCHING ---
    try:
        brief = send_cmd(agg_shell, "show ip interface brief", timeout=10, silent=True)
        for line in brief.splitlines():
            # Typical line: Vlan1 192.168.1.100 YES manual up up
            parts = line.split()
            if len(parts) >= 2:
                current_ip = parts[1] # The IP is usually the second column
                # Exact string match check
                if current_ip == target_ip and ("up" in line.lower()):
                    logger.info(f"Target IP {target_ip} is current switch (Self-detection)")
                    return None
    except Exception as e: 
        logger.debug(f"Self-IP check failed: {e}")
    # ----------------------------------
    
    for attempt in range(1, SSH_HOP_RETRY_ATTEMPTS + 1):
        if attempt > 1: time.sleep(SSH_HOP_RETRY_BASE_DELAY)
        logger.info(f"[RETRY] SSH hop {attempt}/{SSH_HOP_RETRY_ATTEMPTS} to {target_ip}")
        
        if not verify_aggregate_connection(): raise NetworkConnectionError("Lost parent", reconnect_needed=True)
        if get_hostname(agg_shell) != parent_hostname: cleanup_and_return_to_parent(parent_hostname)
        
        # Attempt SSH
        for cred in CREDENTIAL_SETS:
            try:
                agg_shell.send(f"ssh -l {cred['username']} {target_ip}\n")
                time.sleep(2)
                end_time = time.time() + 45
                pw_sent = False
                while time.time() < end_time:
                    if agg_shell.recv_ready():
                        out = agg_shell.recv(MAX_READ).decode('utf-8', 'ignore')
                        if "assword:" in out and not pw_sent:
                            agg_shell.send(cred['password'] + "\n")
                            pw_sent = True
                        elif "(yes/no)" in out:
                            agg_shell.send("yes\n")
                        elif PROMPT_RE.search(out):
                            new_host = get_hostname(agg_shell)
                            if new_host != parent_hostname:
                                _ensure_enable(agg_shell, [cred.get('enable'), cred['password']])
                                send_cmd(agg_shell, "terminal length 0", silent=True)
                                session_depth += 1
                                return True
                    time.sleep(0.1)
            except: pass
            # Cleanup if failed
            agg_shell.send("\x03"); time.sleep(0.5); _drain(agg_shell)
            
    return False

def exit_device():
    global agg_shell, session_depth
    if not agg_shell or agg_shell.closed: return False
    try:
        agg_shell.send("exit\n"); time.sleep(0.6); _drain(agg_shell)
        session_depth = max(0, session_depth - 1)
        return True
    except: return False

def convert_mac_format(mac):
    clean = mac.replace(".", "").upper()
    return ":".join([clean[i:i+2] for i in range(0, 12, 2)])

def normalize_interface_name(intf):
    if not intf: return ""
    intf = intf.strip()
    replacements = [
        ('TenGigabitEthernet', 'tengigabitethernet'), ('TenGigE', 'tengigabitethernet'),
        ('GigabitEthernet', 'gigabitethernet'), ('GigE', 'gigabitethernet'), ('Gi', 'gigabitethernet'),
        ('FastEthernet', 'fastethernet'), ('Fa', 'fastethernet'),
        ('TwentyFiveGigE', 'twentyfivegigabitethernet'), ('Twe', 'twentyfivegigabitethernet'),
        ('Te', 'tengigabitethernet')
    ]
    for short, full in replacements:
        if intf.startswith(short) and len(intf) > len(short):
            if intf[len(short)].isdigit() or intf[len(short)] in ['/', ' ']:
                return (full + intf[len(short):]).replace(' ', '').lower()
    return intf.lower()

def get_switch_hardware_model(shell):
    try:
        ver = send_cmd(shell, "show version", timeout=10, silent=True)
        if m := re.search(r"Model [Nn]umber\s*:\s*(\S+)", ver): return m.group(1)
        if m := re.search(r"cisco\s+(\S+)\s+\(", ver): return m.group(1)
        return None
    except: return None

def determine_switch_type(hostname, hardware_model=None):
    if not hostname: return "OTHER"
    if hardware_model:
        if "3850" in hardware_model: return "AGGREGATE"
        if "9300" in hardware_model: return "SERVER" if "SRV" in hostname.upper() else "EDGE"
    if "SMSAGG" in hostname.upper(): return "AGGREGATE"
    return "EDGE"

def is_aggregate_switch(hostname, hardware_model=None):
    return determine_switch_type(hostname, hardware_model) == "AGGREGATE"

def parse_cdp_neighbors(output):
    neighbors = []
    blocks = re.split(r"(?=^Device ID:\s*)", output, flags=re.M)
    for block in blocks:
        if "Device ID:" not in block: continue
        nbr = {"hostname": None, "mgmt_ip": None, "local_intf": None}
        if m := re.search(r"Device ID:\s*(\S+)", block): nbr["hostname"] = m.group(1)
        if m := re.search(r"Interface:\s*(\S+)", block): nbr["local_intf"] = m.group(1).rstrip(',')
        if m := re.search(r"IP.*?ddress:\s*(\d+\.\d+\.\d+\.\d+)", block, re.I): nbr["mgmt_ip"] = m.group(1)
        if nbr["hostname"] and "cisco" in block.lower(): neighbors.append(nbr)
    return neighbors

def parse_lldp_neighbors(output):
    neighbors = []
    blocks = re.split(r'[-]{40,}', output)
    for block in blocks:
        if "Local Intf:" not in block: continue
        nbr = {"hostname": None, "mgmt_ip": None, "local_intf": None}
        if m := re.search(r'^Local Intf:\s*(\S+)', block, re.M): nbr["local_intf"] = m.group(1)
        if m := re.search(r'^System Name:\s*(.+?)$', block, re.M): nbr["hostname"] = m.group(1).strip().strip('"')
        if m := re.search(r'IP:\s*(\d+\.\d+\.\d+\.\d+)', block): nbr["mgmt_ip"] = m.group(1)
        if not nbr["mgmt_ip"] and (m := re.search(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', block)): nbr["mgmt_ip"] = m.group(1)
        
        sys_desc = ""
        if m := re.search(r'^System Description:\s*\n([\s\S]+?)(?=^Time|^System)', block, re.M):
            sys_desc = m.group(1).strip().lower()
        
        if "cisco" in sys_desc or "ios" in sys_desc:
            neighbors.append(nbr)
    return neighbors

def get_interface_status(shell):
    out = send_cmd(shell, "show ip interface brief", timeout=10)
    up_intfs = []
    # Added Gi0/0 to exclude list
    excludes = ("Vlan", "Loopback", "Tunnel", "Null", "Po", "Ap", "Mgmt", "Gi0/0", "GigabitEthernet0/0")
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 4 and parts[0].startswith(excludes): continue
        if len(parts) > 4 and "up" in parts[4].lower() and "up" in parts[5].lower():
            up_intfs.append(parts[0])
    return up_intfs

def parse_mac_table_interface(raw):
    entries = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit() and "." in parts[1]:
             entries.append({"vlan": parts[0], "mac_address": parts[1], "port": parts[-1]})
    return entries

def poll_port_for_mac(shell, interface):
    logger.info(f"  [POLL] {interface} - waiting for MAC address...")
    for attempt in range(1, 40): # Roughly 3 mins
        try:
            res = send_cmd(shell, f"show mac address-table interface {interface}", timeout=5, silent=True)
            entries = parse_mac_table_interface(res)
            if entries:
                logger.info(f"  [OK] {interface}: MAC found")
                return entries
            time.sleep(MAC_POLL_INTERVAL)
        except: pass
    logger.error(f"  [CRITICAL] {interface}: Hard timeout")
    discovery_stats["total_ports_no_mac"] += 1
    return [{"vlan": "UNKNOWN", "mac_address": "UNKNOWN", "port": interface}]

# ============================================================================
# NEW: RECURSIVE DISCOVERY LOGIC
# ============================================================================

def discover_cameras_from_switch(shell, switch_hostname, switch_type="UNKNOWN"):
    """
    Scans a switch for cameras AND returns downstream neighbors for recursion.
    """
    logger.info("="*80)
    logger.info(f"Scanning {switch_type} switch: {switch_hostname}")
    logger.info("="*80)

    hardware_model = get_switch_hardware_model(shell)
    if hardware_model:
        detected_type = determine_switch_type(switch_hostname, hardware_model)
        if detected_type != switch_type: switch_type = detected_type

    # 1. Clear MAC Table
    send_cmd(shell, "clear mac address-table dynamic", timeout=10)
    time.sleep(MAC_POLL_INITIAL_WAIT)

    # 2. Discover Neighbors (Exclusion + Daisy Chain Candidates)
    downstream_candidates = []
    neighbor_ports_normalized = set()
    
    # Check CDP
    cdp_out = send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "CDP is not enabled" not in cdp_out:
        for nbr in parse_cdp_neighbors(cdp_out):
            if nbr.get("local_intf"):
                neighbor_ports_normalized.add(normalize_interface_name(nbr["local_intf"]))
                if nbr.get("mgmt_ip"):
                    downstream_candidates.append(nbr)
                    logger.info(f"NEIGHBOR (CDP): {nbr['local_intf']} -> {nbr['hostname']} ({nbr['mgmt_ip']})")

    # Check LLDP
    lldp_out = send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
    if "LLDP is not enabled" not in lldp_out:
        for nbr in parse_lldp_neighbors(lldp_out):
            if nbr.get("local_intf"):
                norm = normalize_interface_name(nbr["local_intf"])
                if norm not in neighbor_ports_normalized:
                    neighbor_ports_normalized.add(norm)
                    if nbr.get("mgmt_ip"):
                        downstream_candidates.append(nbr)
                        logger.info(f"NEIGHBOR (LLDP): {nbr['local_intf']} -> {nbr['hostname']} ({nbr['mgmt_ip']})")

    # 3. Scan Ports
    up_interfaces = get_interface_status(shell)
    ports_to_scan = [p for p in up_interfaces if normalize_interface_name(p) not in neighbor_ports_normalized]
    
    logger.info(f"Scanning {len(ports_to_scan)} ports (excluding {len(neighbor_ports_normalized)} uplinks)...")

    for idx, intf in enumerate(ports_to_scan, 1):
        logger.info(f"  Port {idx}/{len(ports_to_scan)}: {intf}")
        entries = poll_port_for_mac(shell, intf)
        
        for entry in entries:
            mac = entry["mac_address"]
            if mac == "UNKNOWN":
                camera_data.append({
                    "switch_name": switch_hostname, "switch_type": switch_type,
                    "port": intf, "mac_address": "UNKNOWN", "status": "TIMEOUT",
                    "vlan": "UNKNOWN"
                })
            else:
                mac_fmt = convert_mac_format(mac)
                camera_data.append({
                    "switch_name": switch_hostname, "switch_type": switch_type,
                    "port": intf, "mac_address": mac_fmt, "status": "OK",
                    "vlan": entry.get("vlan", "0")
                })
                discovery_stats["total_cameras_found"] += 1
                logger.info(f"  [+] Device: {mac_fmt} on {intf}")

    return downstream_candidates

def discover_devices_via_mac_table(shell, uplink_port, downstream_switch_name, downstream_switch_ip, downstream_switch_type):
    """Indirect discovery fallback."""
    if not ENABLE_INDIRECT_DISCOVERY: return 0
    logger.info(f"INDIRECT DISCOVERY: Scanning parent port {uplink_port} for {downstream_switch_name}")
    
    try:
        current_host = get_hostname(shell)
        res = send_cmd(shell, f"show mac address-table interface {uplink_port}", timeout=15, silent=True)
        entries = parse_mac_table_interface(res)
        
        if len(entries) < INDIRECT_DISCOVERY_MIN_MACS:
            logger.warning(f"Only {len(entries)} MACs found (threshold {INDIRECT_DISCOVERY_MIN_MACS}). Skipping.")
            return 0
            
        added = 0
        for e in entries[:INDIRECT_DISCOVERY_MAX_MACS]:
            camera_data.append({
                "switch_name": downstream_switch_name,
                "switch_type": downstream_switch_type,
                "switch_ip": downstream_switch_ip,
                "port": "UNKNOWN (Indirect)",
                "mac_address": convert_mac_format(e["mac_address"]),
                "vlan": e.get("vlan", "0"),
                "status": "INDIRECT",
                "parent_switch": current_host,
                "parent_port": uplink_port,
                "notes": "Indirect discovery via parent MAC table"
            })
            added += 1
        discovery_stats["indirect_discoveries"] += added
        logger.info(f"Added {added} indirect devices.")
        return added
    except Exception as e:
        logger.error(f"Indirect discovery failed: {e}")
        return 0

def upgrade_indirect_to_direct_discovery(switch_name, switch_ip):
    """Deduplicate entries when a switch comes back online."""
    indirect_entries = [e for e in camera_data if e.get("switch_name") == switch_name and e.get("status") == "INDIRECT"]
    if not indirect_entries: return
    
    direct_entries = [e for e in camera_data if e.get("switch_name") == switch_name and e.get("status") != "INDIRECT"]
    
    duplicates = []
    for ind in indirect_entries:
        match = next((d for d in direct_entries if d["mac_address"] == ind["mac_address"]), None)
        if match:
            match["was_indirect"] = True
            duplicates.append(ind)
            
    for dup in duplicates:
        if dup in camera_data:
            camera_data.remove(dup)
    
    logger.info(f"Deduplicated {len(duplicates)} records for {switch_name}")

def process_switch(parent_ip, neighbor_info, switch_type="UNKNOWN", is_retry=False):
    """
    Main recursive processing function.
    """
    global failed_switches
    switch_ip = neighbor_info.get("mgmt_ip") or neighbor_info.get("ip")
    switch_name = neighbor_info.get("remote_name") or neighbor_info.get("hostname")
    local_intf = neighbor_info.get("local_intf") or neighbor_info.get("local_port")

    if not switch_ip: return True
    if switch_ip in visited_switches and not is_retry: return True
    
    logger.info("*"*80)
    logger.info(f"Processing: {switch_name} ({switch_ip})")
    
    if not is_retry: 
        visited_switches.add(switch_ip)
        discovery_stats["switches_attempted"] += 1

    try:
        parent_hostname = get_hostname(agg_shell)
        if not verify_aggregate_connection(): raise NetworkConnectionError("Lost parent")

        # 1. SSH HOP
        ssh_success = ssh_to_device(switch_ip, switch_name, parent_hostname)
        
        # 2. FAILURE -> INDIRECT
        if not ssh_success and ssh_success is not None:
            logger.error(f"SSH Failed to {switch_name}. Attempting Indirect.")
            found = 0
            if ENABLE_INDIRECT_DISCOVERY and local_intf:
                found = discover_devices_via_mac_table(agg_shell, local_intf, switch_name, switch_ip, switch_type)
            
            if not is_retry:
                failed_switches.append({
                    "switch_name": switch_name, "switch_ip": switch_ip, 
                    "switch_type": switch_type, "local_intf": local_intf,
                    "parent_hostname": parent_hostname, "indirect_found": found
                })
            return found > 0

        # 3. SUCCESS -> SCAN & RECURSE
        actual_hostname = get_hostname(agg_shell)
        try:
            # A. Scan cameras & get candidates
            downstream_candidates = discover_cameras_from_switch(agg_shell, actual_hostname, switch_type)
            discovery_stats["switches_successfully_scanned"] += 1
            
            # B. Recurse!
            if downstream_candidates:
                logger.info(f"Daisy-Chain: Found {len(downstream_candidates)} downstream neighbors.")
                for cand in downstream_candidates:
                    if cand.get("mgmt_ip") and cand["mgmt_ip"] not in visited_switches:
                        logger.info(f" >> Descending to {cand['hostname']} ({cand['mgmt_ip']})")
                        process_switch(switch_ip, cand, determine_switch_type(cand["hostname"]), is_retry)
        
        except Exception as e:
            logger.error(f"Error scanning {switch_name}: {e}")
        
        exit_device()
        return True

    except Exception as e:
        logger.error(f"Process error: {e}")
        return False

def check_for_duplicate_macs():
    logger.info("FINAL DUPLICATE CHECK")
    mac_map = {}
    for e in camera_data:
        if e["mac_address"] != "UNKNOWN": mac_map.setdefault(e["mac_address"], []).append(e)
    
    removed = 0
    for mac, entries in mac_map.items():
        if len(entries) > 1:
            # Prefer Direct over Indirect
            keep = next((e for e in entries if e.get("status") != "INDIRECT"), entries[0])
            for e in entries:
                if e != keep:
                    camera_data.remove(e)
                    removed += 1
    discovery_stats["duplicates_removed"] = removed
    logger.info(f"Removed {removed} duplicates.")

def scan_aggregate_switch(shell, agg_ip, aggregates_to_process, seed_ips):
    """Root level scan for aggregate switches."""
    if agg_ip in visited_switches: return
    visited_switches.add(agg_ip)
    hostname = get_hostname(shell)
    logger.info(f"Scanning ROOT AGGREGATE: {hostname}")
    
    # 1. Topology discovery (Aggregates only)
    cdp_out = send_cmd(shell, "show cdp neighbors detail", silent=True)
    for nbr in parse_cdp_neighbors(cdp_out):
        if is_aggregate_switch(nbr["hostname"]) and nbr["mgmt_ip"] not in seed_ips:
            if nbr["mgmt_ip"] not in aggregates_to_process:
                aggregates_to_process.append(nbr["mgmt_ip"])
    
    # 2. Camera Scan (Aggregate itself) & Daisy Chain Trigger
    candidates = discover_cameras_from_switch(shell, hostname, "AGGREGATE")
    
    # 3. Trigger recursion for connected edges
    for cand in candidates:
        if cand.get("mgmt_ip") and cand["mgmt_ip"] not in visited_switches:
            process_switch(agg_ip, cand, determine_switch_type(cand["hostname"]), is_retry=False)

def retry_failed_switches_from_seed():
    if not failed_switches: return
    logger.info(f"PHASE 3: RETRYING {len(failed_switches)} SWITCHES")
    for item in failed_switches:
        nbr = {"mgmt_ip": item["switch_ip"], "remote_name": item["switch_name"], "local_intf": item["local_intf"]}
        process_switch(SEED_SWITCH_IP, nbr, item["switch_type"], is_retry=True)

def main():
    logger.info("STARTING DISCOVERY V5")
    connect_to_seed()
    
    # Phase 1 & 2: Aggregates & Recursion
    aggs = deque([SEED_SWITCH_IP])
    seed_ips = {SEED_SWITCH_IP}
    
    while aggs:
        agg_ip = aggs.popleft()
        try:
            if get_hostname(agg_shell) != agg_hostname:
                if not cleanup_and_return_to_parent(agg_hostname): reconnect_to_aggregate()
            
            if agg_ip != SEED_SWITCH_IP:
                if not ssh_to_device(agg_ip): continue
            
            scan_aggregate_switch(agg_shell, agg_ip, aggs, seed_ips)
            
            if agg_ip != SEED_SWITCH_IP: exit_device()
            
        except Exception as e:
            logger.error(f"Aggregate error: {e}")
            reconnect_to_aggregate()

    # Phase 3: Retry
    retry_failed_switches_from_seed()
    
    # Phase 4: Dedupe
    check_for_duplicate_macs()
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 1. JSON REPORT (Restored)
    json_file = f"camera_inventory_{len(camera_data)}devices_{timestamp}.json"
    output_data = {
        "discovery_metadata": {
            "timestamp": timestamp,
            "seed_switch": SEED_SWITCH_IP,
            "total_devices": len(camera_data),
            "total_aggregates": len(discovered_aggregates)
        },
        "discovery_statistics": discovery_stats,
        "cameras": camera_data
    }
    with open(json_file, "w", encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved JSON: {json_file}")

    # 2. CSV REPORT
    csv_file = f"camera_inventory_{len(camera_data)}devices_{timestamp}.csv"
    with open(csv_file, "w", newline='', encoding='utf-8') as f:
        fieldnames = ["switch_name", "switch_type", "port", "mac_address", "vlan", "status", "parent_switch", "parent_port", "notes"]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(camera_data)
    logger.info(f"Saved CSV: {csv_file}")
    
    logger.info(f"Done. Found {len(camera_data)} devices.")

if __name__ == "__main__":
    main()
