



"The Structure"
"The script expects the following layout without any headers:"
"Column A: The management IP of the device you want to configure (Target IP)."
"Column B: The new IP address you want to assign to VLAN 100."
"Column C: The Subnet Mask for that new IP."

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
AGG_IP = input("Aggregation Switch IP: ") if not "" else ""
USERNAME = input("Username: ") if not "" else ""
PASSWORD = getpass.getpass("Password: ") if not "" else ""

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
        'CRITICAL': '\033[35m', # Magenta
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

file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_formatter = LiveFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')

file_handler = logging.FileHandler('vlan_fix.log', mode='a')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(file_formatter)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
console_handler.setFormatter(console_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ========================= EXCEPTIONS ==========================
class NetworkConnectionError(Exception):
    pass

# ========================= SSH HELPERS =========================
def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            for p in patterns:
                if p in buf:
                    return buf
        else:
            time.sleep(0.1)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, log_cmd=True):
    if log_cmd:
        logger.debug(f"Sending: {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

# ========================= UTILS ===============================
IFACE_RE = re.compile(r'^(Po\d+|Gi\d+(?:/\d+){1,2}|Te\d+(?:/\d+){1,2}|Fo\d+(?:/\d+){1,2})\b')

def get_hostname(shell) -> str:
    try:
        out = send_cmd(shell, "show run | include ^hostname", patterns=("#", ">"), timeout=8, log_cmd=False)
        for line in out.splitlines():
            line = line.strip()
            if "show" in line or "|" in line: continue
            if line.startswith("hostname ") and len(line.split()) >= 2:
                name = line.split()[1]
                return name.strip('"')
    except Exception as e:
        logger.debug(f"Hostname detection error: {e}")
        pass
    
    try:
        shell.send("\n")
        time.sleep(1)
        if shell.recv_ready():
            out = shell.recv(MAX_READ).decode("utf-8", "ignore")
            last_line = out.strip().splitlines()[-1]
            if "#" in last_line: return last_line.split("#")[0].strip()
            if ">" in last_line: return last_line.split(">")[0].strip()
    except:
        pass
    return "UNKNOWN_HOST"

# ========================= CORE CONNECT ========================
def connect_to_agg(retry=0):
    try:
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to Aggregation: {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                       look_for_keys=False, allow_agent=False, timeout=10)
        shell = client.invoke_shell()
        expect_prompt(shell, ("#", ">"), timeout=15)
        
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=8, log_cmd=False)
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("#",), timeout=8, log_cmd=False)
            
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=6, log_cmd=False)
        
        agg_hostname = get_hostname(shell)
        logger.info(f"[CONNECT] Connected to Seed Switch. Hostname: '{agg_hostname}'")
        return client, shell, agg_hostname
    except Exception as e:
        logger.error(f"[CONNECT] Failed: {e}")
        if retry < AGG_MAX_RETRIES - 1:
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry+1)
        raise

# ========================= CONFIGURATION =======================
def apply_config(shell, target_ip, new_ip, new_mask, is_seed_switch=False):
    logger.info(f"[CONFIG] {target_ip}: Applying VLAN {VLAN_ID} IP {new_ip} {new_mask}")
    
    out = send_cmd(shell, "show running-config", patterns=("#",), timeout=30)
    fname = f"backup_{target_ip}_{int(time.time())}.cfg"
    with open(fname, "w", encoding="utf-8", errors="ignore") as f:
        f.write(out)
    
    try:
        send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
        send_cmd(shell, f"vlan {VLAN_ID}", patterns=("(config-vlan)#", "(config)#"), timeout=5)
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)
        send_cmd(shell, f"interface vlan {VLAN_ID}", patterns=("(config-if)#",), timeout=5)
        
        if is_seed_switch:
            logger.warning("!!! UPDATING SEED SWITCH IP - CONNECTION WILL DROP !!!")
            shell.send(f"ip address {new_ip} {new_mask}\n")
            time.sleep(1) 
            raise NetworkConnectionError("Seed IP Changed - Disconnect Expected")
        else:
            send_cmd(shell, f"ip address {new_ip} {new_mask}", patterns=("(config-if)#",), timeout=5)
            send_cmd(shell, "no shutdown", patterns=("(config-if)#",), timeout=5)
            send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)
    
        send_cmd(shell, "end", patterns=("#",), timeout=5)
        out = send_cmd(shell, "show interfaces trunk", patterns=("#",), timeout=10)
        trunks = []
        for line in out.splitlines():
            m = IFACE_RE.match(line.strip())
            if m: trunks.append(m.group(1))
        
        if trunks:
            send_cmd(shell, "conf t", patterns=("(config)#",), timeout=5)
            for t in trunks:
                send_cmd(shell, f"interface {t}", patterns=("(config-if)#",), timeout=5)
                send_cmd(shell, f"switchport trunk allowed vlan add {VLAN_ID}", patterns=("(config-if)#",), timeout=5)
                send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)
            send_cmd(shell, "end", patterns=("#",), timeout=5)
        
        logger.info(f"[SUCCESS] Configured {target_ip}")
        return True

    except NetworkConnectionError:
        logger.info(f"[SUCCESS] Seed Switch {target_ip} IP updated. Session terminated as expected.")
        return True
    except Exception as e:
        logger.error(f"[ERROR] Config failed on {target_ip}: {e}")
        return False

# ========================= EXECUTION LOGIC =====================
def process_hop(shell, agg_hostname, target_ip, new_ip, new_mask):
    logger.info(f"\n--- Hop Attempt: {target_ip} ---")
    
    if shell.recv_ready():
        shell.recv(MAX_READ)

    cmd = f"ssh -l {USERNAME} {target_ip}"
    shell.send(cmd + "\n")
    time.sleep(1.0)
    
    out = expect_prompt(shell, patterns=("Destination", "(yes/no)?", "yes/no", "assword:", "#", ">", "refused", "timed out", "unreachable", "Unknown host"), timeout=TARGET_SSH_TIMEOUT)
    logger.debug(f"[HOP LOG] {target_ip}:\n{out}")

    if any(x in out for x in ["refused", "timed out", "unreachable", "Unknown host"]):
        logger.warning(f"[FAIL] SSH refused or timed out to {target_ip}")
        return 'failed_connection'

    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "#", ">"), timeout=10)

    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("#", ">", "assword:"), timeout=15)
        if "assword:" in out: return 'failed_connection'

    if ">" in out and "#" not in out:
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=8)
        if "assword:" in out: send_cmd(shell, PASSWORD, patterns=("#",), timeout=8)

    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5, log_cmd=False)
    current_hostname = get_hostname(shell)
    
    if current_hostname == agg_hostname:
        logger.critical(f"[SAFETY] Hop failed! Still on Seed Switch ({agg_hostname}). Aborting.")
        return 'failed_connection'
    
    logger.info(f"[CONNECTED] On target: {current_hostname}")
    
    if apply_config(shell, target_ip, new_ip, new_mask, is_seed_switch=False):
        try: send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
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
        is_seed = (target == AGG_IP)
        status = 'failed'
        
        if is_seed:
            logger.info(f"\n--- Processing SEED SWITCH: {target} ---")
            curr = get_hostname(shell)
            if curr != agg_hostname:
                logger.critical("Hostname mismatch on Seed update. Aborting.")
            else:
                if apply_config(shell, target, item['vip'], item['mask'], is_seed_switch=True):
                    status = 'success'
        else:
            for attempt in range(TARGET_MAX_RETRIES):
                if attempt > 0:
                    logger.info(f"Retry {attempt+1}/{TARGET_MAX_RETRIES} for {target}...")
                
                if getattr(shell, "closed", False) or not shell.get_transport().is_active():
                    try: 
                        client, shell, agg_hostname = connect_to_agg()
                    except: 
                        sys.exit("Fatal: Aggregation switch died.")

                res = process_hop(shell, agg_hostname, target, item['vip'], item['mask'])
                
                if res == 'success':
                    status = 'success'
                    break
                elif res == 'failed_connection':
                    time.sleep(TARGET_RETRY_DELAY)
                elif res == 'failed_config':
                    time.sleep(TARGET_RETRY_DELAY)
        
        if status == 'success':
            success_list.append(target)
            if is_seed:
                logger.info("Seed switch updated. Terminating.")
                sys.exit(0)
        else:
            logger.error(f"Failed to configure {target} after retries.")
            failed_items.append(item)
            
    return success_list, failed_items

# ========================= MAIN ================================
def main():
    if len(sys.argv) != 2:
        print("Usage: python vlan_fix.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    
    try:
        if file_path.endswith('.csv'):
            logger.info("Detected CSV file.")
            df = pd.read_csv(file_path, header=None)
        else:
            logger.info("Detected Excel file.")
            df = pd.read_excel(file_path, header=None)
        df = df.dropna(how='all')
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        sys.exit(1)

    plan_normal = []
    plan_seed = []

    logger.info("Parsing file...")
    for index, row in df.iterrows():
        try:
            target = str(row[0]).strip()
            vip = str(row[1]).strip()
            mask = str(row[2]).strip()
            if "ip" in target.lower() or "address" in target.lower(): continue
            item = {'target': target, 'vip': vip, 'mask': mask}
            
            if target == AGG_IP: plan_seed.append(item)
            else: plan_normal.append(item)
        except Exception: continue

    full_plan = plan_normal + plan_seed
    logger.info(f"Loaded {len(full_plan)} devices.")

    # Connect
    try:
        client, shell, agg_hostname = connect_to_agg()
    except Exception:
        sys.exit(1)

    # --- PHASE 1: Main Run ---
    logger.info("=== STARTING PHASE 1 ===")
    success_1, failed_1 = process_batch(client, shell, agg_hostname, full_plan)

    # --- PHASE 2: Retry Failed ---
    final_success = success_1
    final_failed_items = failed_1 # Default if no retry happens

    if failed_1:
        logger.info("\n" + "="*40)
        logger.info(f"PHASE 1 COMPLETE. {len(failed_1)} FAILED.")
        logger.info("WAITING 10 SECONDS BEFORE RETRYING FAILURES...")
        logger.info("="*40 + "\n")
        time.sleep(10)
        
        try:
            client.close()
            client, shell, agg_hostname = connect_to_agg()
        except:
            pass

        success_2, failed_2 = process_batch(client, shell, agg_hostname, failed_1)
        
        final_success.extend(success_2)
        final_failed_items = failed_2 # Update final list with remaining failures

    logger.info("\n=== FINAL SUMMARY ===")
    logger.info(f"Successful: {len(final_success)}")
    logger.info(f"Failed:     {len(final_failed_items)}")

    if final_failed_items:
        logger.info("\n=== LIST OF FAILED DEVICES ===")
        for f in final_failed_items:
            logger.error(f" - {f['target']}")

if __name__ == "__main__":
    main()
