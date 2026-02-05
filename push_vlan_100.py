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

TARGET_MAX_RETRIES = 10     # Total cycles (Try all creds -> Wait -> Repeat)
TARGET_RETRY_DELAY = 10     # Wait time between Attempt 1 and Attempt 2
SSH_TIMEOUT = 20            
# ===============================================================

# ========================= LOGGING =============================
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
    logger.debug("[TIMEOUT] No pattern matched.")
    return None, buf

def sync_to_agg_prompt(shell):
    """Clears the line and ensures we are at a clean prompt (# or >)."""
    logger.debug("[SYNC] Cleaning buffer and syncing prompt...")
    while shell.recv_ready(): shell.recv(65535) # Flush
    shell.send("\n")
    
    end_time = time.time() + 10
    while time.time() < end_time:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode('utf-8', 'ignore')
            if ">" in chunk or "#" in chunk:
                logger.debug("[SYNC] Prompt found. Line clear.")
                return True
        time.sleep(0.1)
    
    logger.warning("[SYNC] Failed to find prompt. Sending Ctrl+C...")
    shell.send("\x03"); time.sleep(1)
    return False

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
        if sync_to_agg_prompt(shell):
            logger.info("Connected to Aggregation Switch.")
            shell.send("terminal length 0\n"); time.sleep(0.5)
            if shell.recv_ready(): shell.recv(65535)
            return client, shell
        else: raise Exception("Did not get a valid prompt")
    except Exception as e:
        logger.error(f"Failed to connect to Aggregation Switch: {e}")
        sys.exit(1)

def extract_id_from_hostname(prompt_str):
    match = re.search(r'-(\d+)[#>]$', prompt_str.strip())
    if match: return match.group(1)
    return None

def attempt_enable(shell, current_pwd):
    """
    Tries to elevate to Enable mode (#).
    If the current password fails, it tries the others in the list.
    Returns True if success, False if ALL fail.
    """
    logger.info("      > Attempting Enable...")
    shell.send("enable\n")
    
    # Wait for response
    p, out = wait_for_patterns(shell, ["Password:", "#", "denied", "closed"])
    
    # Already enabled?
    if p == "#":
        logger.info("      > Enable Successful (No password needed).")
        return True
    
    # Connection died?
    if p == "closed" or p is None:
        return False

    # Password Required
    if p == "Password:" or p == "denied":
        # Build list: Try current password first, then unique others
        passwords = [current_pwd]
        seen = {current_pwd}
        for c in CREDENTIALS:
            if c['pass'] not in seen:
                passwords.append(c['pass'])
                seen.add(c['pass'])
        
        for i, pwd in enumerate(passwords):
            logger.debug(f"[ENABLE] Trying password {i+1}/{len(passwords)}")
            if i > 0: time.sleep(0.5) 
            shell.send(f"{pwd}\n")
            
            ep, eout = wait_for_patterns(shell, ["#", "Password:", "denied", "Bad secrets", "closed"])
            
            if ep == "#":
                logger.info("      > Enable Successful!")
                return True
            elif ep == "closed":
                logger.warning("      > Connection closed during enable.")
                return False
            else:
                logger.warning(f"      > Enable password {i+1} rejected. Trying next...")
    
    logger.error("      > All enable passwords failed.")
    return False

def process_target(shell, target_ip):
    logger.info(f"--- Processing Target: {target_ip} ---")

    # OUTER LOOP: ATTEMPTS
    for attempt in range(1, TARGET_MAX_RETRIES + 1):
        logger.info(f"[ATTEMPT {attempt}/{TARGET_MAX_RETRIES}] Starting Credential Cycle...")

        # INNER LOOP: CREDENTIALS
        for cred_idx, cred in enumerate(CREDENTIALS):
            user = cred['user']
            pwd = cred['pass']
            
            if not sync_to_agg_prompt(shell):
                logger.error("   > Sync failed. Skipping credential.")
                continue

            logger.info(f"   [Cred {cred_idx+1}] SSH to {target_ip} as {user}...")
            shell.send(f"ssh -l {user} {target_ip}\n")
            
            pattern, output = wait_for_patterns(shell, ["Password:", "timed out", "refused", "unknown", "closed by foreign host"])
            
            # --- FAIL: NETWORK ---
            if pattern == "timed out" or pattern is None:
                logger.warning(f"      > Network Timeout. Moving to next credential...")
                shell.send("\x03"); time.sleep(1)
                continue 
            
            # --- FAIL: IMMEDIATE CLOSE ---
            elif pattern == "closed by foreign host":
                if target_ip in output or "closed" in output:
                    logger.warning(f"      > Connection closed immediately. Moving to next credential...")
                    time.sleep(2); continue 
            
            # --- SUCCESS: PASSWORD PROMPT ---
            elif pattern == "Password:":
                logger.debug(f"[DEBUG] Sending Password...")
                time.sleep(0.5)
                shell.send(f"{pwd}\n")
                
                login_p, login_out = wait_for_patterns(shell, ["#", ">", "closed by foreign host", "denied", "Connection closed", "Password:"])
                
                # --- FAIL: BAD PASSWORD ---
                if login_p in ["closed by foreign host", "denied", "Connection closed", "Password:"]:
                    logger.warning(f"      > Auth Failed ({login_p}). Moving to next credential...")
                    shell.send("\x03"); time.sleep(1)
                    continue 
                
                # --- SUCCESS: LOGGED IN ---
                elif login_p in ["#", ">"]:
                    logger.info("      > Login Successful!")
                    
                    # 1. HANDLE ENABLE (If needed)
                    if ">" in login_p:
                        # Pass current password to attempt_enable
                        if not attempt_enable(shell, pwd):
                            logger.error("      > Enable failed for this user. Logging out to try next user...")
                            # gracefully EXIT from device to return to Jump Host
                            shell.send("exit\n") 
                            time.sleep(1)
                            # Ensure we are back at Jump Host before loop continues
                            sync_to_agg_prompt(shell)
                            continue # MOVES TO NEXT CREDENTIAL
                    
                    # 2. PARSE HOSTNAME (Get fresh prompt)
                    shell.send("\n") 
                    p, final_prompt = wait_for_patterns(shell, ["#"])
                    
                    prompt_line = final_prompt.strip().splitlines()[-1]
                    device_id = extract_id_from_hostname(prompt_line)
                    
                    if not device_id:
                        logger.error(f"      > Parse error: '{prompt_line}'. Skipping.")
                        return False 
                    else:
                        new_ip = f"{NEW_IP_PREFIX}{device_id}"
                        logger.info(f"      > Hostname ID '{device_id}' -> New IP {new_ip}")
                        
                        cmds = [
                            "conf t",
                            f"interface vlan {VLAN_ID}",
                            f"ip address {new_ip} {NEW_SUBNET_MASK}",
                            "end", "write mem", "exit"
                        ]
                        for cmd in cmds:
                            logger.debug(f"[CMD] {cmd}")
                            shell.send(f"{cmd}\n")
                            time.sleep(1)
                        logger.info(f"      > Config Applied.")
                        return True 

            # --- FAIL: UNKNOWN ---
            else:
                logger.warning(f"      > Unexpected: {pattern}. Moving to next credential...")
                shell.send("\x03"); time.sleep(1)
                continue

        logger.warning(f"   > Attempt {attempt} failed for all users. Waiting {TARGET_RETRY_DELAY}s...")
        time.sleep(TARGET_RETRY_DELAY)

    logger.error(f"Failed to configure {target_ip} after {TARGET_MAX_RETRIES} cycles.")
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
        
    client.close()
    
    logger.info("\n" + "="*50)
    logger.info("BATCH COMPLETE")
    if failed_targets:
        logger.info("FAILED DEVICES:")
        for ft in failed_targets: logger.error(f"  [X] {ft}")
    else:
        logger.info("SUCCESS: All devices configured.")
    logger.info("="*50 + "\n")

if __name__ == "__main__":
    main()
