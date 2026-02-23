#!/usr/bin/env python3
import paramiko
import time
import re
import csv
import logging
import sys
import warnings
from datetime import datetime
from collections import deque

# Suppress Cryptography Deprecation Warnings
warnings.filterwarnings("ignore")

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

class CleanConsoleFormatter(logging.Formatter):
    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        return f"[{timestamp}] {record.getMessage()}"

def setup_logging():
    log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(CleanConsoleFormatter())
    root_logger.addHandler(console_handler)

    logging.getLogger("paramiko").setLevel(logging.WARNING)
    
    return logging.getLogger(__name__), log_filename

logger = None 

# ============================================================================
# CONFIGURATION
# ============================================================================

SEED_SWITCH_IP = "192.168.20.20" 
CREDENTIAL_SETS = [
    {"username": "admin",  "password": "flounder",  "enable": ""}
]

TIMEOUT = 120               
SSH_CONNECT_TIMEOUT = 60    
COMMAND_TIMEOUT = 60        
JUMP_RETRIES = 20           

LINUX_DISABLED_ALGORITHMS = {
    'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']
}

PROMPT_RE = re.compile(r"(?m)^[^\r\n>\s][^\r\n>]*[>#]\s?$")

# GLOBAL STATE
visited_ips = set()
visited_hostnames = set()
camera_data = []
agg_client = None
agg_shell = None
seed_hostname = "Unknown"

# ============================================================================
# CORE UTILITIES
# ============================================================================

def _drain(shell):
    time.sleep(0.1) 
    buf = ""
    while shell and not shell.closed and shell.recv_ready():
        try:
            chunk = shell.recv(65535).decode("utf-8", "ignore")
            buf += chunk
        except: break
    return buf

def send_cmd(shell, cmd, timeout=COMMAND_TIMEOUT, silent=False):
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
                if chunk: logger.debug(f"[RX] {repr(chunk)}")
                buf += chunk
                if PROMPT_RE.search(buf): return buf
            time.sleep(0.2)
        return buf
    except Exception as e:
        logger.error(f"Command failed: {cmd} - {e}")
        return ""

def get_hostname(shell):
    try:
        _drain(shell)
        shell.send("\n")
        time.sleep(1)
        buf = ""
        for _ in range(20):
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", "ignore")
                buf += chunk
                if PROMPT_RE.search(buf): break
            time.sleep(0.1)
            
        for line in reversed(buf.splitlines()):
            line = line.strip()
            if line.endswith('#') or line.endswith('>'):
                hostname = line[:-1].strip()
                if hostname: return hostname
    except: pass
    return "Unknown"

def clean_hostname(raw_name):
    if not raw_name: return ""
    return raw_name.split('.')[0].upper()

def normalize_intf(interface_name):
    if not interface_name: return ""
    name = interface_name.lower().strip()
    
    if name.startswith("gi") and not name.startswith("gigabit"):
        return name.replace("gi", "gigabitethernet")
    if name.startswith("te") and not name.startswith("tengigabit"):
        return name.replace("te", "tengigabitethernet")
    if name.startswith("fa") and not name.startswith("fast"):
        return name.replace("fa", "fastethernet")
    if name.startswith("po") and not name.startswith("port-channel"):
        return name.replace("po", "port-channel")
        
    return name

# ============================================================================
# CONNECTION
# ============================================================================

def connect_to_seed():
    global agg_client, agg_shell, seed_hostname
    logger.info(f"➜ Connecting to Seed Switch {SEED_SWITCH_IP}...")
    for cred in CREDENTIAL_SETS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(SEED_SWITCH_IP, username=cred["username"], password=cred["password"], 
                           allow_agent=False, timeout=20, disabled_algorithms=LINUX_DISABLED_ALGORITHMS)
            client.get_transport().set_keepalive(15)
            shell = client.invoke_shell(width=1000, height=1000)
            
            time.sleep(1)
            while not shell.recv_ready(): time.sleep(1)
            
            send_cmd(shell, "terminal length 0", silent=True)
            if not send_cmd(shell, "", silent=True).strip().endswith("#"):
                _drain(shell)
                shell.send("enable\n")
                time.sleep(1)
                shell.send(cred["password"] + "\n")
                time.sleep(1)
            
            seed_hostname = get_hostname(shell)
            visited_hostnames.add(clean_hostname(seed_hostname))
            visited_ips.add(SEED_SWITCH_IP)
            agg_client, agg_shell = client, shell
            logger.info(f"✓ Connected to Seed: {seed_hostname}")
            return True
        except: pass
    return False

def explicit_jump_poll(target_ip):
    global agg_shell
    logger.info(f"➜ Jumping from Seed -> {target_ip}")
    
    for cred in CREDENTIAL_SETS:
        try:
            _drain(agg_shell)
            logger.debug(f"[TX] ssh -l {cred['username']} {target_ip}")
            agg_shell.send(f"ssh -l {cred['username']} {target_ip}\n")
            
            buffer = ""
            start_time = time.time()
            
            while (time.time() - start_time) < SSH_CONNECT_TIMEOUT:
                if agg_shell.recv_ready():
                    chunk = agg_shell.recv(65535).decode("utf-8", "ignore")
                    buffer += chunk
                    logger.debug(f"[POLL-RX] {repr(chunk)}") 
                
                if "assword:" in buffer:
                    logger.debug("Found 'Password:' prompt.")
                    agg_shell.send(cred["password"] + "\n")
                    buffer = "" 
                    time.sleep(1)
                    continue

                if "yes/no" in buffer:
                    logger.debug("Found 'yes/no'. Sending yes.")
                    agg_shell.send("yes\n")
                    buffer = ""
                    time.sleep(1)
                    continue
                
                if PROMPT_RE.search(buffer):
                    lines = buffer.splitlines()
                    if len(lines) > 1 or (len(lines) == 1 and "ssh" not in lines[0]):
                         current_host = get_hostname(agg_shell)
                         clean_host = clean_hostname(current_host)
                         clean_seed = clean_hostname(seed_hostname)
                         
                         if clean_host != clean_seed and current_host != "Unknown":
                             logger.info(f"  ✓ Logged into {current_host}")
                             
                             send_cmd(agg_shell, "terminal length 0", silent=True)
                             if not send_cmd(agg_shell, "", silent=True).strip().endswith("#"):
                                 agg_shell.send("enable\n"); time.sleep(1)
                                 agg_shell.send(cred["password"] + "\n"); time.sleep(1)
                             
                             visited_hostnames.add(clean_host)
                             visited_ips.add(target_ip)
                             return current_host
                         elif clean_host == clean_seed:
                             if "Connection refused" in buffer or "closed by" in buffer:
                                 logger.warning(f"  ✖ Connection failed to {target_ip}")
                                 return False

                time.sleep(1)

            logger.warning(f"  ✖ Timeout waiting for jump to {target_ip}")
            return_to_seed("Timeout")
            return False
            
        except Exception as e:
            logger.error(f"Jump exception: {e}")
            return_to_seed("Exception")
            
    return False

def return_to_seed(context):
    global agg_shell
    logger.debug(f"Returning to Seed ({context})...")
    
    # Send Ctrl+C first to clear any stuck command lines
    agg_shell.send("\x03") 
    time.sleep(0.5)

    for i in range(5):
        # Check if we see the seed hostname in a quick check
        _drain(agg_shell)
        agg_shell.send("\n")
        time.sleep(0.5)
        
        # Read whatever is there
        if agg_shell.recv_ready():
            buf = agg_shell.recv(65535).decode("utf-8", "ignore")
            # Loose match is safer here
            if seed_hostname in buf:
                logger.debug("Back at Seed (Confirmed).")
                return True

        logger.debug(f"Sending exit (attempt {i+1})...")
        agg_shell.send("exit\n")
        time.sleep(1.0)
    
    logger.critical("Stuck! Reconnecting...")
    try: agg_client.close()
    except: pass
    connect_to_seed()
    return False

# ============================================================================
# SCANNER
# ============================================================================

def scan_current_switch(switch_ip, switch_name):
    global agg_shell
    neighbors_to_visit = []
    bridge_interfaces = set()
    found_hostnames_this_scan = set()

    # 1. CDP
    logger.info(f"  ○ Scanning neighbors (CDP)...")
    try:
        cdp_out = send_cmd(agg_shell, "show cdp neighbors detail", timeout=60)
        blocks = re.split(r"-{10,}", cdp_out)
        for block in blocks:
            ip_m = re.search(r"IP address: (\d+\.\d+\.\d+\.\d+)", block)
            intf_m = re.search(r"Interface: (\S+),", block)
            name_m = re.search(r"Device ID:\s*(.+)", block)
            
            if ip_m and intf_m:
                ip = ip_m.group(1)
                raw_intf = intf_m.group(1).split(',')[0]
                norm_intf = normalize_intf(raw_intf)
                bridge_interfaces.add(norm_intf)
                
                hostname = clean_hostname(name_m.group(1).strip()) if name_m else "Unknown"
                if hostname != "Unknown": found_hostnames_this_scan.add(hostname)
                
                if ip not in visited_ips and ip != SEED_SWITCH_IP:
                    neighbors_to_visit.append(ip)
                    logger.info(f"    [CDP] Queueing {hostname} ({ip})")
    except: pass

    # 2. LLDP
    try:
        lldp_out = send_cmd(agg_shell, "show lldp neighbors detail", timeout=60)
        blocks = re.split(r"-{10,}", lldp_out)
        for block in blocks:
            ip_m = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", block)
            intf_m = re.search(r"Local Intf: (\S+)", block)
            name_m = re.search(r"System Name:\s*(.+)", block)
            cap_m = re.search(r"Enabled Capabilities: (.*)", block)
            
            if ip_m and intf_m and cap_m:
                ip = ip_m.group(1)
                raw_intf = intf_m.group(1)
                norm_intf = normalize_intf(raw_intf)
                hostname = clean_hostname(name_m.group(1).strip()) if name_m else "Unknown"
                
                if 'B' in cap_m.group(1):
                    bridge_interfaces.add(norm_intf)
                    if hostname in found_hostnames_this_scan: continue
                    if ip not in visited_ips and ip != SEED_SWITCH_IP and ip not in neighbors_to_visit:
                        neighbors_to_visit.append(ip)
                        found_hostnames_this_scan.add(hostname)
                        logger.info(f"    [LLDP] Queueing {hostname} ({ip})")
    except: pass
    
    # 3. MAC SCANNING
    logger.info(f"  ○ Harvesting MACs (skipping {len(bridge_interfaces)} uplinks)...")
    count = 0
    try:
        agg_shell.send("clear mac address-table dynamic\n")
        time.sleep(1); _drain(agg_shell)
        
        int_out = send_cmd(agg_shell, "show ip interface brief")
        interfaces = []
        for line in int_out.splitlines():
            parts = line.split()
            if len(parts) >= 6 and "up" in parts[4].lower() and "up" in parts[5].lower():
                raw_port = parts[0]
                if "Vlan" not in raw_port and "Loopback" not in raw_port:
                    norm_port = normalize_intf(raw_port)
                    if norm_port not in bridge_interfaces:
                        interfaces.append(raw_port)

        # Log what we are actually attempting to scan
        if not interfaces:
            logger.warning("    ! No up/up access ports found to scan.")
        else:
            logger.debug(f"    Scanning ports: {', '.join(interfaces)}")

        for intf in interfaces:
            mac_out = send_cmd(agg_shell, f"show mac address-table interface {intf}", timeout=10, silent=True)
            unique_macs = set(re.findall(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", mac_out, re.I))
            
            for mac in unique_macs:
                camera_data.append({
                    "switch": switch_name, "ip": switch_ip, "port": intf, "mac": mac
                })
                count += 1
                logger.info(f"    [+] Found {mac} on {intf}")
    except Exception as e:
        logger.error(f"MAC harvest failed: {e}")

    logger.info(f"    -> Harvested {count} MACs.")
    return list(set(neighbors_to_visit))

# ============================================================================
# MAIN
# ============================================================================

def main():
    global logger
    logger, logfile = setup_logging()
    
    logger.info("========================================")
    logger.info(f"STARTING DISCOVERY V38 (EXIT FIX)")
    logger.info(f"Log File: {logfile}")
    logger.info("========================================")
    
    if not connect_to_seed(): return

    queue = deque()
    initial_neighbors = scan_current_switch(SEED_SWITCH_IP, seed_hostname)
    for n in initial_neighbors: queue.append(n)

    while queue:
        target_ip = queue.popleft()
        if target_ip in visited_ips: continue
        
        target_host = None
        
        for attempt in range(1, JUMP_RETRIES + 1):
            target_host = explicit_jump_poll(target_ip)
            if target_host:
                break 
            else:
                logger.warning(f"  ⚠ Jump attempt {attempt}/{JUMP_RETRIES} failed. Retrying...")
                clean_seed = clean_hostname(seed_hostname)
                curr = clean_hostname(get_hostname(agg_shell))
                if curr != clean_seed: return_to_seed("Retry Reset")
        
        if target_host:
            new_hops = scan_current_switch(target_ip, target_host)
            for h in new_hops: queue.append(h)
            return_to_seed(target_host)
        else:
            logger.error(f"  ✖ Failed to jump to {target_ip}. Skipping.")
            clean_seed = clean_hostname(seed_hostname)
            if clean_hostname(get_hostname(agg_shell)) != clean_seed: return_to_seed("Give Up")

    # DEDUPLICATION
    logger.info("  ○ Post-Processing: Deduplicating MACs...")
    unique_devices = {}
    for device in camera_data:
        mac = device['mac']
        if mac not in unique_devices:
            unique_devices[mac] = device
    
    final_data = list(unique_devices.values())
    
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_filename = f"camera_inventory_{ts}.csv"
    with open(csv_filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["switch", "ip", "port", "mac"])
        writer.writeheader()
        writer.writerows(final_data)
        
    logger.info("========================================")
    logger.info(f"DONE. Scanned: {len(visited_hostnames)} Switches.")
    logger.info(f"Raw Devices: {len(camera_data)}")
    logger.info(f"Unique Devices: {len(final_data)}")
    logger.info(f"Saved to: {csv_filename}")
    logger.info("========================================")

if __name__ == "__main__":
    main()
