#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import re

# ========================= USER CONFIG =========================
AGG_IP = "192.168.1.18"

CREDENTIALS = [
    {"user": "admin", "pass": "/2/_HKX6YvCGMwzAdJp"},
    {"user": "admin", "pass": "cisco"}
]

NEW_IP_PREFIX = "10.17.131."
NEW_SUBNET_MASK = "255.255.255.0"
VLAN_ID = 100

# Retry Settings
TARGET_MAX_RETRIES = 10     
TARGET_RETRY_DELAY = 10     
SSH_TIMEOUT = 20            
# ===============================================================

# ========================= LOGGING SETUP =======================
class LiveFormatter(logging.Formatter):
    COLORS = {'DEBUG': '\033[36m', 'INFO': '\033[32m', 'WARNING': '\033[33m', 'ERROR': '\033[31m'}
    RESET = '\033[0m'
    def format(self, record):
        if sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) 
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(LiveFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ch)
# ===============================================================

def wait_for_patterns(shell, patterns, timeout=SSH_TIMEOUT):
    end_time = time.time() + timeout
    buf = ""
    while time.time() < end_time:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode('utf-8', 'ignore')
            logger.debug(f"[RAW READ] {repr(chunk)}") 
            buf += chunk
            for p in patterns:
                if p in buf:
                    logger.debug(f"[MATCH] Found pattern '{p}'")
                    return p, buf
        time.sleep(0.1)
    
    logger.debug("[TIMEOUT] No pattern matched in buffer.")
    return None, buf

def connect_to_agg():
    logger.info(f"Connecting to Aggregation Switch: {AGG_IP}...")
    try:
        user = CREDENTIALS[0]['user']
        pwd = CREDENTIALS[0]['pass']
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=user, password=pwd, allow_agent=False, look_for_keys=False)
        
        shell = client.invoke_shell()
        time.sleep(1)
        if shell.recv_ready(): shell.recv(65535) 
        
        shell.send("\n")
        time.sleep(1)
        
        if shell.recv_ready():
            buf = shell.recv(65535).decode('utf-8', 'ignore')
        else:
            buf = ""
            
        if ">" in buf or "#" in buf:
            logger.info("Connected to Aggregation Switch.")
            shell.send("terminal length 0\n")
            time.sleep(0.5)
            if shell.recv_ready(): shell.recv(65535)
            return client, shell
        else:
            raise Exception("Did not get a valid prompt from Aggregation Switch")
            
    except Exception as e:
        logger.error(f"Failed to connect to Aggregation Switch: {e}")
        sys.exit(1)

def extract_id_from_hostname(prompt_str):
    match = re.search(r'-(\d+)[#>]$', prompt_str.strip())
    if match: return match.group(1)
    return None

def process_target(shell, target_ip):
    logger.info(f"--- Processing Target: {target_ip} ---")

    # ================= CREDENTIAL LOOP =================
    for cred_idx, cred in enumerate(CREDENTIALS):
        user = cred['user']
        pwd = cred['pass']
        
        logger.info(f"[CREDENTIAL {cred_idx+1}/{len(CREDENTIALS)}] Trying User: {user}")

        # ================= RETRY LOOP (Network Only) =================
        for attempt in range(1, TARGET_MAX_RETRIES + 1):
            
            if shell.recv_ready(): 
                trash = shell.recv(65535)
                logger.debug(f"[CLEAN BUFFER] {repr(trash)}")
            
            logger.debug(f"[CMD] ssh -l {user} {target_ip}")
            shell.send(f"ssh -l {user} {target_ip}\n")
            
            # 1. Wait for Connection or Failure
            pattern, output = wait_for_patterns(shell, ["Password:", "timed out", "refused", "unknown", "closed by foreign host"])
            
            # A. NETWORK TIMEOUT -> RETRY SAME USER
            if pattern == "timed out" or (pattern and "timed out" in output):
                logger.warning(f"   > Attempt {attempt}: Connection timed out. Retrying...")
                time.sleep(TARGET_RETRY_DELAY)
                shell.send("\x03"); time.sleep(1)
                continue 
            
            # B. AUTH REJECTION (Immediate) -> SWITCH USER
            # Capture if the connection is closed immediately before password
            elif pattern == "closed by foreign host":
                logger.warning(f"   > Connection closed immediately. Treating as Auth Fail. Switching user...")
                break

            # C. PASSWORD PROMPT -> TRY LOGIN
            elif pattern == "Password:":
                logger.debug(f"[DEBUG] Sending Password: {pwd}")
                shell.send(f"{pwd}\n")
                
                # Wait for Success (#/>) OR Failure (closed/denied/Password:)
                # We add "Password:" here to catch if it asks again (looping)
                login_p, login_out = wait_for_patterns(shell, ["#", ">", "closed by foreign host", "denied", "Connection closed", "Password:"])
                
                # --- FAILED LOGIN (Switch User) ---
                if login_p in ["closed by foreign host", "denied", "Connection closed"]:
                    logger.warning(f"   > Auth Failed for {user} ({login_p}). Switching to next user...")
                    break 
                
                # --- FAILED LOGIN (Looping Prompt) ---
                elif login_p == "Password:":
                     logger.warning(f"   > Password rejected (Prompted again). Switching to next user...")
                     # Send Ctrl+C to kill the session since it's stuck asking for password
                     shell.send("\x03")
                     time.sleep(1)
                     break

                # --- SUCCESS ---
                elif login_p in ["#", ">"]:
                    logger.info("   > Login Successful!")
                    
                    prompt_line = login_out.strip().splitlines()[-1]
                    device_id = extract_id_from_hostname(prompt_line)
                    
                    if not device_id:
                        logger.error(f"   > Could not parse ID from '{prompt_line}'. Skipping.")
                    else:
                        new_ip = f"{NEW_IP_PREFIX}{device_id}"
                        logger.info(f"   > Hostname ID '{device_id}' -> New IP {new_ip}")
                        
                        cmds = [
                            "enable", pwd, "conf t",
                            f"interface vlan {VLAN_ID}",
                            f"ip address {new_ip} {NEW_SUBNET_MASK}",
                            "end", "write mem", "exit"
                        ]
                        for cmd in cmds:
                            logger.debug(f"[CMD] {cmd}")
                            shell.send(f"{cmd}\n")
                            time.sleep(1)
                        logger.info(f"   > Config Applied.")

                    return True 
            
            # D. SILENT TIMEOUT / OTHER -> RETRY SAME USER
            else:
                logger.warning(f"   > Unexpected: {pattern}. Retrying same user...")
                shell.send("\x03"); time.sleep(1)

        # End of Retry Loop (Attempts exhausted)
        logger.warning(f"   > Max retries reached for {user}. Moving to next credential.")

    logger.error(f"Failed to configure {target_ip} with any credential.")
    return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <targets_file>")
        sys.exit(1)
        
    targets_file = sys.argv[1]

    try:
        with open(targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{targets_file}' not found.")
        sys.exit(1)

    client, shell = connect_to_agg()
    failed_targets = []

    for target in targets:
        if not process_target(shell, target):
            failed_targets.append(target)
        
        shell.send("\n"); time.sleep(0.5)
        if shell.recv_ready(): shell.recv(65535)

    client.close()
    
    logger.info("\n" + "="*50)
    logger.info("BATCH PROCESSING COMPLETE")
    logger.info("="*50)
    
    if failed_targets:
        logger.info("\nFAILED DEVICES SUMMARY:")
        for ft in failed_targets:
            logger.error(f"  [X] {ft}")
    else:
        logger.info("\nSUCCESS: All devices configured.")
    logger.info("="*50 + "\n")

if __name__ == "__main__":
    main()
