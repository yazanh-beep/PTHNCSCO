"target IP | changed vlan 100 ip | netmask"


#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import re
import getpass
import pandas as pd
from typing import Tuple, List, Dict

# ========================= USER CONFIG =========================
# Leave these blank to be prompted at runtime
AGG_IP = ""  
USERNAME = ""
PASSWORD = ""

TIMEOUT = 10
MAX_READ = 65535
VLAN_ID = 100

# Retry configuration
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
TARGET_MAX_RETRIES = 3
TARGET_RETRY_DELAY = 5
TARGET_SSH_TIMEOUT = 30
# ===============================================================

# ========================= LOGGING SETUP =======================
class LiveFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[41m', # Red Background
    }
    RESET = '\033[0m'

    def format(self, record):
        try:
            if sys.stdout.isatty():
                color = self.COLORS.get(record.levelname, self.RESET)
                record.levelname = f"{color}{record.levelname}{self.RESET}"
        except Exception: pass
        return super().format(record)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Console Handler - DEBUG level enabled to see every command
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG) 
ch.setFormatter(LiveFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ch)

# File Handler
fh = logging.FileHandler('vlan_fix.log', mode='a')
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s'))
logger.addHandler(fh)

# ========================= SSH HELPERS =========================
def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, log_output=True):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            if log_output and data.strip():
                # Logs raw output to help debug "hanging"
                logger.debug(f"[RECV] {data.strip()[-100:]}") 
            for p in patterns:
                if p in buf: return buf
        time.sleep(0.05)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    logger.debug(f"[SEND] {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def get_hostname(shell) -> str:
    """Attempts to grab the hostname safely from the running config or prompt."""
    try:
        out = send_cmd(shell, "show run | include ^hostname", patterns=("#", ">"), timeout=5)
        m = re.search(r'^\s*hostname\s+(.+)$', out, re.MULTILINE)
        if m: return m.group(1).strip('"')
    except Exception:
        pass
    
    # Fallback: scrape the prompt
    try:
        shell.send("\n")
        time.sleep(0.5)
        if shell.recv_ready():
            out = shell.recv(MAX_READ).decode("utf-8", "ignore")
            last_line = out.strip().splitlines()[-1]
            return re.sub(r'[#>]$', '', last_line).strip()
    except Exception:
        pass
    return "UNKNOWN_HOST"

# ========================= CORE CONNECT ========================
def connect_to_agg(retry=0):
    global AGG_IP, USERNAME, PASSWORD
    if not AGG_IP: AGG_IP = input("Aggregation Switch IP: ").strip()
    if not USERNAME: USERNAME = input("Username: ").strip()
    if not PASSWORD: PASSWORD = getpass.getpass("Password: ").strip()

    try:
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to Aggregation: {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                       look_for_keys=False, allow_agent=False, timeout=10)
        shell = client.invoke_shell()
        expect_prompt(shell, ("#", ">"), timeout=15)
        
        # Handle Enable
        out = send_cmd(shell, "enable", patterns=("assword:", "#", ">"), timeout=5)
        if "assword:" in out:
            send_cmd(shell, PASSWORD, patterns=("#",), timeout=5)
            
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        agg_hostname = get_hostname(shell)
        logger.info(f"[CONNECT] Connected to Aggregation Switch. Hostname: '{agg_hostname}'")
        return client, shell, agg_hostname
    except Exception as e:
        logger.error(f"[CONNECT] Failed: {e}")
        if retry < AGG_MAX_RETRIES - 1:
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry+1)
        raise

# ========================= CONFIGURATION =======================
def apply_config(shell, target_ip, new_ip, new_mask):
    logger.info(f"[CONFIG] {target_ip}: Applying VLAN {VLAN_ID} IP {new_ip} {new_mask}")
    
    # Backup
    out = send_cmd(shell, "show running-config", patterns=("#",), timeout=20)
    
    try:
        # Enter Config
        send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
        
        # Create/Enter VLAN
        send_cmd(shell, f"vlan {VLAN_ID}", patterns=("(config-vlan)#", "(config)#"), timeout=5)
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)
        
        # Enter Interface SVI
        send_cmd(shell, f"interface vlan {VLAN_ID}", patterns=("(config-if)#",), timeout=5)
        send_cmd(shell, f"ip address {new_ip} {new_mask}", patterns=("(config-if)#",), timeout=5)
        send_cmd(shell, "no shutdown", patterns=("(config-if)#",), timeout=5)
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)
        
        # Trunk Configuration
        send_cmd(shell, "end", patterns=("#",), timeout=5)
        out = send_cmd(shell, "show interfaces trunk", patterns=("#",), timeout=10)
        
        trunks = []
        for line in out.splitlines():
            # Regex matches Po1, Gi1/0/1, Te1/1/1, etc
            m = re.match(r'^\s*(Po\d+|[A-Za-z]{2}\d+(?:/\d+){1,2})\s', line, re.I)
            if m: trunks.append(m.group(1))
        
        # --- FIX: REMOVE DUPLICATES ---
        # Ensures we don't configure the same interface multiple times
        trunks = sorted(list(set(trunks))) 

        if trunks:
            logger.info(f"[TRUNKS] Found {len(trunks)} UNIQUE trunks. Configuring...")
            send_cmd(shell, "conf t", patterns=("(config)#",), timeout=5)
            
            for i, t in enumerate(trunks, 1):
                logger.debug(f"[TRUNK-LOOP] {i}/{len(trunks)} Updating {t}")
                send_cmd(shell, f"interface {t}", patterns=("(config-if)#",), timeout=5)
                send_cmd(shell, f"switchport trunk allowed vlan add {VLAN_ID}", patterns=("(config-if)#",), timeout=5)
                send_cmd(shell, "exit", patterns=("(config)#",), timeout=2) 
                
            send_cmd(shell, "end", patterns=("#",), timeout=5)
        
        # Write Mem
        send_cmd(shell, "write memory", patterns=("OK", "#"), timeout=15)
        logger.info(f"[SUCCESS] Configured {target_ip}")
        return True

    except Exception as e:
        logger.error(f"[ERROR] Config failed on {target_ip}: {e}")
        try:
            send_cmd(shell, "end")
        except: pass
        return False

# ========================= EXECUTION LOGIC =====================
def process_hop(shell, agg_hostname, target_ip, new_ip, new_mask):
    """
    Returns: 'success', 'failed_connection', 'failed_config'
    """
    logger.info(f"\n--- Hop Attempt: {target_ip} ---")
    
    # Clean buffer
    if shell.recv_ready(): shell.recv(MAX_READ)

    # 1. Initiate SSH
    shell.send(f"ssh -l {USERNAME} {target_ip}\n")
    
    # 2. Handle SSH handshake
    out = expect_prompt(shell, patterns=("(yes/no)?", "assword:", "#", ">", "refused", "timed out", "unreachable", "Unknown host"), timeout=TARGET_SSH_TIMEOUT)
    
    if any(x in out for x in ["refused", "timed out", "unreachable", "Unknown host", "Connection closed"]):
        logger.warning(f"[FAIL] Connection refused/timed out to {target_ip}")
        return 'failed_connection'

    if "(yes/no)?" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "#", ">"), timeout=10)

    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("#", ">", "assword:", "denied"), timeout=15)
        if "assword:" in out or "denied" in out:
            logger.error(f"[FAIL] Auth failed for {target_ip}")
            return 'failed_connection'

    # 3. Validate we are on the new device
    if ">" in out and "#" not in out:
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=8)
        if "assword:" in out: send_cmd(shell, PASSWORD, patterns=("#",), timeout=8)

    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
    current_hostname = get_hostname(shell)
    
    # SAFETY CHECK: Ensure we actually moved
    if current_hostname == agg_hostname:
        logger.critical(f"[SAFETY] Hop failed! Still on Aggregation Switch ({agg_hostname}). Aborting this device.")
        return 'failed_connection'
    
    logger.info(f"[CONNECTED] On target: {current_hostname}")
    
    # 4. Apply Config
    if apply_config(shell, target_ip, new_ip, new_mask):
        # 5. Exit back to Agg
        try: 
            send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
            # Sometimes need a second exit if enabled
            send_cmd(shell, "exit", patterns=("#", ">"), timeout=2) 
        except: pass
        return 'success'
    else:
        try: send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
        except: pass
        return 'failed_config'

def process_batch(client, shell, agg_hostname, items: List[Dict]) -> Tuple[List[str], List[Dict]]:
    success_list = []
    failed_items = []

    for item in items:
        target = item['target']
        
        # Retry Loop
        status = 'failed'
        for attempt in range(TARGET_MAX_RETRIES):
            if attempt > 0:
                logger.info(f"Retry {attempt+1}/{TARGET_MAX_RETRIES} for {target}...")
            
            # Check Agg Connection
            if getattr(shell, "closed", False) or not shell.get_transport().is_active():
                try: 
                    client, shell, agg_hostname = connect_to_agg()
                except: 
                    sys.exit("Fatal: Aggregation switch died.")

            res = process_hop(shell, agg_hostname, target, item['vip'], item['mask'])
            
            if res == 'success':
                status = 'success'
                break
            else:
                # If failed, wait before retry
                time.sleep(TARGET_RETRY_DELAY)
        
        if status == 'success':
            success_list.append(target)
        else:
            logger.error(f"Failed to configure {target} after retries.")
            failed_items.append(item)
            
    return success_list, failed_items

# ========================= MAIN ================================
def main():
    if len(sys.argv) != 2:
        print("Usage: python vlan_fix.py <file_path.xlsx or .csv>")
        sys.exit(1)

    file_path = sys.argv[1]
    
    try:
        # Load File - Force strings to prevent format issues
        if file_path.endswith('.csv'):
            logger.info("Detected CSV file.")
            df = pd.read_csv(file_path, header=None, dtype=str)
        else:
            logger.info("Detected Excel file.")
            df = pd.read_excel(file_path, header=None, dtype=str)
            
        df = df.dropna(how='all')
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        sys.exit(1)

    plan = []

    logger.info("Parsing file...")
    for index, row in df.iterrows():
        try:
            target = str(row[0]).strip()
            vip = str(row[1]).strip()
            mask = str(row[2]).strip()
            
            # Skip header row if present
            if "ip" in target.lower() or "address" in target.lower(): continue
            
            item = {'target': target, 'vip': vip, 'mask': mask}
            plan.append(item)
        except Exception: continue

    logger.info(f"Loaded {len(plan)} devices.")

    # Connect to Agg
    try:
        client, shell, agg_hostname = connect_to_agg()
    except Exception:
        sys.exit(1)

    # --- PHASE 1: Main Run ---
    logger.info("=== STARTING PHASE 1 ===")
    success_1, failed_1 = process_batch(client, shell, agg_hostname, plan)

    # --- PHASE 2: Retry Failed ---
    final_success = success_1
    final_failed_items = failed_1 

    if failed_1:
        logger.info("\n" + "="*40)
        logger.info(f"PHASE 1 COMPLETE. {len(failed_1)} FAILED.")
        logger.info("WAITING 10 SECONDS BEFORE RETRYING FAILURES...")
        logger.info("="*40 + "\n")
        time.sleep(10)
        
        # Refresh connection for Phase 2
        try:
            client.close()
            client, shell, agg_hostname = connect_to_agg()
        except: pass

        success_2, failed_2 = process_batch(client, shell, agg_hostname, failed_1)
        
        final_success.extend(success_2)
        final_failed_items = failed_2 

    logger.info("\n=== FINAL SUMMARY ===")
    logger.info(f"Successful: {len(final_success)}")
    logger.info(f"Failed:      {len(final_failed_items)}")

    if final_failed_items:
        logger.info("\n=== LIST OF FAILED DEVICES ===")
        for f in final_failed_items:
            logger.error(f" - {f['target']} (Intended: {f['vip']})")

if __name__ == "__main__":
    main()
