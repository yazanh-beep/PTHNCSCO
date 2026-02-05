#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
from typing import List

# ========================= USER CONFIG =========================
AGG_IP = "192.168.1.18"

# Define your list of credentials to cycle through
CREDENTIALS = [
    {"user": "admin", "pass": "/2/_HKX6YvCGMwzAdJp"},
    {"user": "admin", "pass": "cisco"}
]

# Retry configuration
AGG_MAX_RETRIES = 3
TARGET_MAX_RETRIES = 10     # Total cycles (Attempts)
TARGET_RETRY_DELAY = 10     # Delay between full attempts
SSH_TIMEOUT = 20            
MAX_READ = 65535
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

# Console Handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG) 
ch.setFormatter(LiveFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ch)

# File Handler
fh = logging.FileHandler('push_config.log', mode='a')
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s'))
logger.addHandler(fh)

# ========================= CORE HELPERS ========================
def wait_for_patterns(shell, patterns, timeout=SSH_TIMEOUT):
    """
    Reads output until one of the patterns is found.
    Returns: (matched_pattern, buffer_text)
    """
    end_time = time.time() + timeout
    buf = ""
    while time.time() < end_time:
        if shell.recv_ready():
            chunk = shell.recv(MAX_READ).decode("utf-8", "ignore")
            # logger.debug(f"[RAW] {repr(chunk)}") 
            buf += chunk
            for p in patterns:
                if p in buf: return p, buf
        time.sleep(0.05)
    return None, buf

def sync_to_agg_prompt(shell):
    """
    CRITICAL: Clears the buffer and ensures we are at a clean Jump Host prompt.
    """
    logger.debug("[SYNC] Cleaning buffer and syncing prompt...")
    try:
        while shell.recv_ready(): shell.recv(MAX_READ) # Flush
        shell.send("\n")
        
        end_time = time.time() + 10
        while time.time() < end_time:
            if shell.recv_ready():
                chunk = shell.recv(MAX_READ).decode("utf-8", "ignore")
                if ">" in chunk or "#" in chunk:
                    logger.debug("[SYNC] Prompt found. Line clear.")
                    return True
            time.sleep(0.1)
    except OSError:
        return False
    
    logger.warning("[SYNC] Failed to find prompt. Sending Ctrl+C...")
    try:
        shell.send("\x03"); time.sleep(1)
    except: pass
    return False

def connect_to_agg():
    """Connects to the Jump Host (Aggregation Switch)."""
    global AGG_IP
    if not AGG_IP: AGG_IP = input("Aggregation Switch IP: ").strip()

    logger.info(f"[CONNECT] Connecting to Aggregation Switch: {AGG_IP}")
    try:
        # Use first credential for Agg Switch
        user = CREDENTIALS[0]['user']
        pwd = CREDENTIALS[0]['pass']
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=user, password=pwd, 
                       look_for_keys=False, allow_agent=False, timeout=10)
        
        shell = client.invoke_shell()
        time.sleep(1)
        if shell.recv_ready(): shell.recv(MAX_READ)
        
        if sync_to_agg_prompt(shell):
            send_cmd(shell, "terminal length 0")
            logger.info("[CONNECT] Connected to Aggregation Switch.")
            return client, shell
        else:
            raise Exception("Did not get a valid prompt from Agg Switch")
            
    except Exception as e:
        logger.error(f"[CONNECT] Failed: {e}")
        sys.exit(1)

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=10):
    logger.debug(f"[SEND] {cmd}")
    shell.send(cmd + "\n")
    p, buf = wait_for_patterns(shell, patterns, timeout)
    return buf

# ========================= LOGIC ENGINE ========================

def attempt_enable(shell, current_pwd):
    """
    Tries to elevate to Enable mode (#).
    Cycles through all passwords if the first one fails.
    """
    logger.info("      > Attempting Enable...")
    shell.send("enable\n")
    
    p, out = wait_for_patterns(shell, ["Password:", "#", "denied", "closed"])
    
    if p == "#":
        logger.info("      > Enable Successful (No password needed).")
        return True
    
    if p == "closed" or p is None: return False

    if p == "Password:" or p == "denied":
        # Try current password first, then others
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
                return False
    
    logger.error("      > All enable passwords failed.")
    return False

def push_config_commands(shell, commands):
    """Actually sends the list of configuration commands."""
    try:
        logger.info("      > Starting Configuration...")
        send_cmd(shell, "terminal length 0")
        send_cmd(shell, "configure terminal", patterns=["(config)#"])
        
        for cmd in commands:
            out = send_cmd(shell, cmd, patterns=["(config)#", "(config-"])
            if "% Invalid" in out or "% Incomplete" in out:
                logger.error(f"[CONFIG ERROR] Command rejected: {cmd}")
        
        send_cmd(shell, "end")
        send_cmd(shell, "write memory", patterns=["OK", "#"], timeout=30)
        logger.info("      > Configuration Saved.")
        return True
    except Exception as e:
        logger.error(f"      > Config Exception: {e}")
        return False

def process_target(shell, target_ip, commands):
    logger.info(f"\n--- Processing Target: {target_ip} ---")

    # OUTER LOOP: ATTEMPTS (1 to 10)
    for attempt in range(1, TARGET_MAX_RETRIES + 1):
        logger.info(f"[ATTEMPT {attempt}/{TARGET_MAX_RETRIES}] Starting Credential Cycle...")

        # INNER LOOP: CREDENTIALS
        for cred_idx, cred in enumerate(CREDENTIALS):
            user = cred['user']
            pwd = cred['pass']
            
            # 1. Clean Session
            if not sync_to_agg_prompt(shell):
                logger.error("   > Sync failed (Jump Host might be busy). Skipping credential.")
                continue

            logger.info(f"   [Cred {cred_idx+1}] SSH to {target_ip} as {user}...")
            shell.send(f"ssh -l {user} {target_ip}\n")
            
            # 2. Wait for Connection
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
                        if not attempt_enable(shell, pwd):
                            logger.error("      > Enable failed. Logging out...")
                            shell.send("exit\n"); time.sleep(1)
                            continue 
                    
                    # 2. PUSH CONFIG
                    config_success = push_config_commands(shell, commands)
                    
                    # 3. EXIT GRACEFULLY
                    logger.info("      > Exiting device...")
                    shell.send("exit\n"); time.sleep(1)
                    
                    # Check if we are back at Agg. If not, send one more exit.
                    # We peek into buffer; if we see "closed" or Jump Host prompt, we are good.
                    if not sync_to_agg_prompt(shell):
                         # If sync fails, maybe we are still on device? Try one more exit.
                         logger.debug("      > Still seems connected to device. Sending second exit.")
                         shell.send("exit\n"); time.sleep(1)

                    if config_success:
                        return True # DONE
                    else:
                        logger.warning("      > Config had errors, but connection was okay.")
                        return False

            # --- FAIL: UNKNOWN ---
            else:
                logger.warning(f"      > Unexpected: {pattern}. Moving to next credential...")
                shell.send("\x03"); time.sleep(1)
                continue

        logger.warning(f"   > Attempt {attempt} failed for all users. Waiting {TARGET_RETRY_DELAY}s...")
        time.sleep(TARGET_RETRY_DELAY)

    logger.error(f"Failed to configure {target_ip} after {TARGET_MAX_RETRIES} cycles.")
    return False

# ========================= MAIN ================================
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 push_config.py <devices_file> <commands_file>")
        sys.exit(1)
    
    devices_file = sys.argv[1]
    commands_file = sys.argv[2]
    
    # Load Files
    try:
        with open(devices_file, "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        with open(commands_file, "r") as f:
            commands = [l.strip() for l in f if l.strip() and not l.startswith("!")]
            
        logger.info(f"Loaded {len(targets)} devices and {len(commands)} commands.")
    except Exception as e:
        logger.error(f"Error reading input files: {e}")
        sys.exit(1)

    # Connect to Agg
    client, shell = connect_to_agg()

    successful = []
    failed = []

    # Processing Loop
    for idx, target in enumerate(targets, 1):
        # --- RECONNECT LOGIC ---
        # Check if shell is dead before trying to process
        if shell is None or not shell.get_transport().is_active():
            logger.warning("!!! Aggregation Connection Lost. Reconnecting... !!!")
            try:
                client.close()
            except: pass
            try:
                client, shell = connect_to_agg()
                logger.info("!!! Reconnected Successfully !!!")
            except Exception as e:
                logger.critical(f"FATAL: Could not reconnect to Aggregation Switch: {e}")
                sys.exit(1)
        # -----------------------

        if process_target(shell, target, commands):
            successful.append(target)
        else:
            failed.append(target)

    client.close()

    # Summary
    logger.info("\n" + "="*40)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("="*40)
    logger.info(f"Total:      {len(targets)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed:     {len(failed)}")
    
    if failed:
        logger.info("\nFAILED DEVICES:")
        for f in failed:
            logger.error(f" - {f}")

if __name__ == "__main__":
    main()
