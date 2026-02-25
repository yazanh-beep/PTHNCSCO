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
    {"username": "Admin",  "password": "wrong_password",  "enable": ""}, # Fails
    {"username": "admin",  "password": "flounder",  "enable": ""}        # Succeeds
]

SSH_CONNECT_TIMEOUT = 45    
COMMAND_TIMEOUT = 60        

LINUX_DISABLED_ALGORITHMS = {'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']}
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
    time.sleep(0.5) 
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
        for _ in range(15):
            if shell.recv_ready():
                buf += shell.recv(65535).decode("utf-8", "ignore")
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

def normalize_intf(name):
    if not name: return ""
    n = name.lower().strip()
    if n.startswith("gi") and not n.startswith("gigabit"): return n.replace("gi", "gigabitethernet")
    if n.startswith("te") and not n.startswith("tengigabit"): return n.replace("te", "tengigabitethernet")
    if n.startswith("fa") and not n.startswith("fast"): return n.replace("fa", "fastethernet")
    if n.startswith("po") and not n.startswith("port-channel"): return n.replace("po", "port-channel")
    return n

# ============================================================================
# CONNECTION & JUMP LOGIC
# ============================================================================

def connect_to_seed():
    global agg_client, agg_shell, seed_hostname
    logger.info(f"➜ Connecting to Seed Switch {SEED_SWITCH_IP}...")
    for cred in CREDENTIAL_SETS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(SEED_SWITCH_IP, username=cred["username"], password=cred["password"], 
                           timeout=20, disabled_algorithms=LINUX_DISABLED_ALGORITHMS)
            shell = client.invoke_shell(width=1000, height=1000)
            time.sleep(2)
            send_cmd(shell, "terminal length 0", silent=True)
            seed_hostname = get_hostname(shell)
            visited_hostnames.add(clean_hostname(seed_hostname))
            visited_ips.add(SEED_SWITCH_IP)
            agg_client, agg_shell = client, shell
            logger.info(f"✓ Connected to Seed: {seed_hostname}")
            return True
        except: continue
    return False

def explicit_jump_poll(target_ip):
    global agg_shell
    logger.info(f"➜ Attempting Jump to {target_ip}...")
    
    for cred in CREDENTIAL_SETS:
        try:
            # Clear previous context
            agg_shell.send("\x03") 
            time.sleep(0.5)
            _drain(agg_shell)
            
            logger.debug(f"  Trying credential: {cred['username']}")
            agg_shell.send(f"ssh -l {cred['username']} {target_ip}\n")
            
            buffer = ""
            start_time = time.time()
            
            while (time.time() - start_time) < SSH_CONNECT_TIMEOUT:
                if agg_shell.recv_ready():
                    chunk = agg_shell.recv(65535).decode("utf-8", "ignore")
                    buffer += chunk
                    
                    if "password:" in buffer.lower():
                        agg_shell.send(cred["password"] + "\n")
                        buffer = ""
                        continue
                    
                    if "yes/no" in buffer.lower():
                        agg_shell.send("yes\n")
                        buffer = ""
                        continue

                    # If this credential fails, we break the while loop to try the next credential
                    if any(x in buffer.lower() for x in ["permission denied", "connection refused", "closed by"]):
                        logger.warning(f"   ✖ Credential {cred['username']} failed.")
                        # Reset shell for next attempt
                        agg_shell.send("\x03")
                        time.sleep(1)
                        break 

                    # If we see a prompt, we are IN
                    if PROMPT_RE.search(buffer):
                        current_host = get_hostname(agg_shell)
                        # Safety: make sure we aren't still on the seed
                        if clean_hostname(current_host) != clean_hostname(seed_hostname):
                            logger.info(f"     ✓ Logged into {current_host}")
                            # Prepare the remote shell
                            send_cmd(agg_shell, "terminal length 0", silent=True)
                            return current_host
                time.sleep(0.5)
        except Exception as e:
            logger.error(f"  Jump Exception on {cred['username']}: {e}")
            
    return False

def return_to_seed(context):
    global agg_shell
    logger.debug(f"Returning to Seed from {context}...")
    agg_shell.send("\x03") 
    time.sleep(0.5)
    for i in range(4):
        _drain(agg_shell)
        agg_shell.send("exit\n")
        time.sleep(1.0)
        # Check if we see the seed name in the buffer
        buf = _drain(agg_shell)
        if seed_hostname.lower() in buf.lower(): 
            return True
    return connect_to_seed()

# ============================================================================
# SCANNER
# ============================================================================

def scan_current_switch(switch_ip, switch_name):
    global agg_shell
    neighbors_to_visit = []
    bridge_interfaces = set()

    # 1. DISCOVERY (CDP/LLDP)
    for cmd in ["show cdp neighbors detail", "show lldp neighbors detail"]:
        out = send_cmd(agg_shell, cmd, timeout=30)
        blocks = re.split(r"-{10,}", out)
        for block in blocks:
            ip_m = re.search(r"(?:IP address|IP): (\d+\.\d+\.\d+\.\d+)", block)
            intf_m = re.search(r"(?:Interface|Local Intf): ([^,\n\r]+)", block)
            if ip_m and intf_m:
                ip = ip_m.group(1)
                norm_intf = normalize_intf(intf_m.group(1).split(',')[0])
                bridge_interfaces.add(norm_intf)
                if ip not in visited_ips and ip != SEED_SWITCH_IP:
                    neighbors_to_visit.append(ip)

    # 2. MAC HARVESTING
    logger.info(f"   ○ Harvesting MACs (Filtering Trunks/Port-channels)...")
    count = 0
    try:
        send_cmd(agg_shell, "clear mac address-table dynamic", timeout=5)
        time.sleep(1)
        
        int_out = send_cmd(agg_shell, "show ip interface brief")
        interfaces = []
        for line in int_out.splitlines():
            parts = line.split()
            if len(parts) >= 6 and "up" in parts[4].lower() and "up" in parts[5].lower():
                raw_port = parts[0]
                if any(x in raw_port for x in ["Vlan", "Loopback", "Port-channel", "Po"]):
                    continue
                if normalize_intf(raw_port) not in bridge_interfaces:
                    interfaces.append(raw_port)

        for intf in interfaces:
            mac_out = send_cmd(agg_shell, f"show mac address-table interface {intf}", timeout=10, silent=True)
            macs = set(re.findall(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", mac_out, re.I))
            for mac in macs:
                camera_data.append({"switch": switch_name, "ip": switch_ip, "port": intf, "mac": mac})
                count += 1
                logger.info(f"     [+] {mac} on {intf}")
    except Exception as e:
        logger.error(f"MAC harvest error: {e}")

    return list(set(neighbors_to_visit))

# ============================================================================
# MAIN
# ============================================================================

def main():
    global logger
    logger, logfile = setup_logging()
    
    logger.info("========================================")
    logger.info(f"STARTING DISCOVERY V41 (CREDENTIAL FIX)")
    logger.info("========================================")
    
    if not connect_to_seed(): 
        logger.error("Failed to connect to seed switch.")
        return

    # Start queue with seed neighbors
    queue = deque(scan_current_switch(SEED_SWITCH_IP, seed_hostname))

    while queue:
        target_ip = queue.popleft()
        if target_ip in visited_ips: 
            continue
        
        target_host = explicit_jump_poll(target_ip)
        
        if target_host:
            # Mark as visited only AFTER successful jump
            visited_ips.add(target_ip)
            visited_hostnames.add(clean_hostname(target_host))
            
            # Now Scan
            new_hops = scan_current_switch(target_ip, target_host)
            for h in new_hops:
                if h not in visited_ips:
                    queue.append(h)
            
            # Go back to seed for the next IP in the queue
            return_to_seed(target_host)
        else:
            logger.error(f"   ✖ Skipping {target_ip} (Credential/Connection Failure)")
            # Ensure we are back at seed even after failure
            return_to_seed("Failure Recovery")

    # FINAL EXPORT
    unique_devices = {d['mac']: d for d in camera_data}.values()
    csv_filename = f"camera_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csv_filename, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["switch", "ip", "port", "mac"])
        writer.writeheader()
        writer.writerows(unique_devices)
        
    logger.info("========================================")
    logger.info(f"DONE. Scanned {len(visited_hostnames)} Switches. Found {len(unique_devices)} unique devices.")
    logger.info(f"File: {csv_filename}")
    logger.info("========================================")

if __name__ == "__main__":
    main()
