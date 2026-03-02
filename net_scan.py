#!/usr/bin/env python3
import paramiko
import time
import re
import csv
import logging
import sys
import warnings
import socket
from datetime import datetime
from collections import deque

# Suppress Cryptography Deprecation Warnings
warnings.filterwarnings("ignore")

# ============================================================================
# CONFIGURATION
# ============================================================================
SEED_SWITCH_IP = "192.168.0.251" 

CREDENTIAL_SETS = [
    {"username": "admin", "password": "admin", "enable": "flounder"},
    {"username": "Admin",  "password": "/2/_HKX6YvCGMwzAdJp",  "enable": ""}
   
]

# Observation Logic
POLL_DURATION = 60      # Seconds to observe each switch
POLL_INTERVAL = 5       # Frequency of MAC table checks
# ============================================================================

class CleanConsoleFormatter(logging.Formatter):
    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        return f"[{timestamp}] {record.getMessage()}"

def setup_logging():
    log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(CleanConsoleFormatter())
    root_logger.addHandler(console_handler)
    
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger.addHandler(file_handler)
    
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    return logging.getLogger(__name__), log_filename

# GLOBAL STATE
logger = None 
visited_ips = set()
visited_hostnames = set()
camera_data = []
agg_client = None
agg_shell = None
seed_hostname = "Unknown"

# ============================================================================
# UTILITIES
# ============================================================================

def _drain(shell):
    try:
        time.sleep(0.5) 
        buf = ""
        while shell and not shell.closed and shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", "ignore")
            buf += chunk
        return buf
    except: return ""

def send_cmd(shell, cmd, timeout=30, silent=False):
    if not silent: logger.debug(f"CMD: {cmd}")
    try:
        _drain(shell)
        shell.send(cmd + "\n")
        time.sleep(0.5)
        buf = ""
        end = time.time() + timeout
        while time.time() < end:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", "ignore")
                buf += chunk
                if re.search(r"(?m)^[^\r\n>\s][^\r\n>]*[>#]\s?$", buf): return buf
            time.sleep(0.2)
        return buf
    except: return ""

def get_hostname(shell):
    try:
        shell.send("\n\n")
        time.sleep(1)
        buf = _drain(shell)
        lines = [l.strip() for l in buf.splitlines() if l.strip()]
        for line in reversed(lines):
            if line.endswith(('#', '>')):
                name = line[:-1].strip()
                name = re.sub(r'^[^\w]+', '', name)
                if name: return name
    except: pass
    return "Unknown"

def normalize_intf(name):
    if not name: return ""
    n = name.lower().strip()
    if n.startswith("gi") and not n.startswith("gigabit"): n = n.replace("gi", "gigabitethernet")
    elif n.startswith("te") and not n.startswith("tengigabit"): n = n.replace("te", "tengigabitethernet")
    elif n.startswith("fa") and not n.startswith("fast"): n = n.replace("fa", "fastethernet")
    elif n.startswith("po") and not n.startswith("port-channel"): n = n.replace("po", "port-channel")
    n = n.split('.')[0].replace(" ", "")
    return n

# ============================================================================
# CONNECTION & JUMP
# ============================================================================

def connect_to_seed():
    global agg_client, agg_shell, seed_hostname
    logger.info(f"➜ Connecting to Seed {SEED_SWITCH_IP}...")
    for cred in CREDENTIAL_SETS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(SEED_SWITCH_IP, username=cred["username"], password=cred["password"], timeout=20)
            client.get_transport().set_keepalive(20)
            shell = client.invoke_shell()
            time.sleep(1)
            
            banner = _drain(shell)
            if ">" in banner and "#" not in banner:
                shell.send("enable\n")
                time.sleep(0.5)
                shell.send(cred.get("enable", cred["password"]) + "\n")
                time.sleep(1)
            
            send_cmd(shell, "terminal length 0", silent=True)
            seed_hostname = get_hostname(shell)
            agg_client, agg_shell = client, shell
            logger.info(f"✓ Connected. Hostname: {seed_hostname}")
            return True
        except: continue
    return False

def explicit_jump_poll(target_ip):
    global agg_shell
    for cred in CREDENTIAL_SETS:
        try:
            agg_shell.send("\x03"); time.sleep(0.5); _drain(agg_shell)
            agg_shell.send(f"ssh -l {cred['username']} {target_ip}\n")
            start = time.time()
            buffer = ""
            while (time.time() - start) < 30:
                if agg_shell.recv_ready():
                    chunk = agg_shell.recv(65535).decode("utf-8", "ignore")
                    buffer += chunk
                    if "password:" in chunk.lower(): agg_shell.send(cred["password"] + "\n")
                    if "yes/no" in chunk.lower(): agg_shell.send("yes\n")
                    if re.search(r"(?m)^[^\r\n>\s][^\r\n>]*[>#]\s?$", buffer):
                        if ">" in buffer and "#" not in buffer:
                            agg_shell.send("enable\n"); time.sleep(0.5)
                            agg_shell.send(cred.get("enable", cred["password"]) + "\n")
                        host = get_hostname(agg_shell)
                        send_cmd(agg_shell, "terminal length 0", silent=True)
                        return host
                time.sleep(0.5)
        except: pass
    return False

def return_to_seed(context):
    global agg_shell
    agg_shell.send("\x03")
    for _ in range(3):
        agg_shell.send("exit\n")
        time.sleep(1)
        if seed_hostname.lower() in _drain(agg_shell).lower(): return True
    return connect_to_seed()

# ============================================================================
# PROTOCOL-STRICT SCANNER
# ============================================================================

def scan_current_switch(switch_ip, switch_name):
    global agg_shell
    neighbors_to_visit = []
    bridge_interfaces = set()

    # 1. CDP DISCOVERY
    logger.info("   ○ Parsing CDP Neighbors...")
    cdp_out = send_cmd(agg_shell, "show cdp neighbors detail")
    # Split by Device ID to isolate neighbor blocks
    cdp_blocks = re.split(r"-------------------------|Device ID: ", cdp_out)
    for block in cdp_blocks:
        ip_m = re.search(r"IP address: (\d+\.\d+\.\d+\.\d+)", block)
        intf_m = re.search(r"Interface: ([^,\s]+)", block)
        plat_m = re.search(r"Platform: (.*),", block)
        cap_m = re.search(r"Capabilities: (.*)", block)
        
        if intf_m:
            norm = normalize_intf(intf_m.group(1))
            # If it's a Cisco device OR has Bridge/Router capabilities, mark as trunk
            is_switch = False
            if plat_m and "Cisco" in plat_m.group(1): is_switch = True
            if cap_m and any(c in cap_m.group(1) for c in ['B', 'R']): is_switch = True
            
            if is_switch:
                bridge_interfaces.add(norm)
                if ip_m:
                    target_ip = ip_m.group(1)
                    if target_ip not in visited_ips: neighbors_to_visit.append(target_ip)

    # 2. LLDP DISCOVERY
    logger.info("   ○ Parsing LLDP Neighbors...")
    lldp_out = send_cmd(agg_shell, "show lldp neighbors detail")
    lldp_blocks = re.split(r"------------------------------------------------|Chassis id:", lldp_out)
    for block in lldp_blocks:
        ip_m = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", block)
        intf_m = re.search(r"Local Intf: (\S+)", block)
        cap_m = re.search(r"Enabled Capabilities: (.*)", block)
        sys_m = re.search(r"System Name: (.*)", block)

        if intf_m:
            norm = normalize_intf(intf_m.group(1))
            # If capabilities include Bridge (B) or Router (R)
            if cap_m and any(c in cap_m.group(1) for c in ['B', 'R']):
                bridge_interfaces.add(norm)
                if ip_m:
                    target_ip = ip_m.group(1)
                    if target_ip not in visited_ips: neighbors_to_visit.append(target_ip)

    # 3. FILTER PORTS
    int_out = send_cmd(agg_shell, "show ip interface brief")
    active_access_ports = {}
    for line in int_out.splitlines():
        parts = line.split()
        if len(parts) >= 6 and "up" in parts[4].lower() and "up" in parts[5].lower():
            raw = parts[0]
            norm = normalize_intf(raw)
            if any(x in raw for x in ["Vlan", "Loop", "Port-channel", "Po", "Nu", "Tun"]): continue
            
            # EXCLUDE IF IN BRIDGE INTERFACES
            if norm in bridge_interfaces:
                logger.debug(f"     [Skip] {raw} (Neighbor Protocol match)")
                continue
                
            active_access_ports[norm] = raw

    # 4. OBSERVATION
    logger.info(f"   ○ Observing {len(active_access_ports)} access ports for {POLL_DURATION}s...")
    found_macs = {}
    start_obs = time.time()
    while (time.time() - start_obs) < POLL_DURATION:
        snap = send_cmd(agg_shell, "show mac address-table dynamic", silent=True)
        for norm, raw in active_access_ports.items():
            matches = re.findall(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}).*" + re.escape(raw), snap, re.I)
            if matches:
                if raw not in found_macs: found_macs[raw] = set()
                for m in matches: found_macs[raw].add(m)
        time.sleep(POLL_INTERVAL)

    # 5. PROCESS
    for raw in active_access_ports.values():
        if raw in found_macs:
            for mac in found_macs[raw]:
                camera_data.append({"switch": switch_name, "ip": switch_ip, "port": raw, "mac": mac, "status": "Detected"})
                logger.info(f"     [+] {mac} on {raw}")
        else:
            camera_data.append({"switch": switch_name, "ip": switch_ip, "port": raw, "mac": "TIMEOUT", "status": "Silent Port"})
            logger.warning(f"     [!] {raw} silent.")

    return list(set(neighbors_to_visit))

# ============================================================================
# MAIN
# ============================================================================

def main():
    global logger
    logger, _ = setup_logging()
    if not connect_to_seed(): return
    
    queue = deque([SEED_SWITCH_IP])
    while queue:
        ip = queue.popleft()
        if ip in visited_ips: continue
        host = seed_hostname if ip == SEED_SWITCH_IP else explicit_jump_poll(ip)
        if host:
            visited_ips.add(ip)
            visited_hostnames.add(host)
            logger.info(f"➜ Scanning {host} ({ip})")
            new_neighbors = scan_current_switch(ip, host)
            for n in new_neighbors:
                if n not in visited_ips: queue.append(n)
            if ip != SEED_SWITCH_IP: return_to_seed(host)
        else:
            logger.error(f"   ✖ Failed {ip}")

    csv_name = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csv_name, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["switch", "ip", "port", "mac", "status"])
        writer.writeheader()
        writer.writerows(camera_data)
    logger.info(f"DONE. File: {csv_name}")

if __name__ == "__main__":
    main()
