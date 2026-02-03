#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import getpass
from typing import Tuple, List

# ========================= USER CONFIG =========================
AGG_IP = ""
USERNAME = ""
PASSWORD = ""

TIMEOUT = 10
MAX_READ = 65535

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

# ========================= HELPERS =============================
def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, log_output=True):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            if log_output and data.strip():
                logger.debug(f"[RECV] {data.strip()[-100:]}") 
            for p in patterns:
                if p in buf: return buf
        time.sleep(0.05)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    logger.debug(f"[SEND] {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

# ========================= CONNECTION LOGIC ====================
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
        
        out = send_cmd(shell, "enable", patterns=("assword:", "#", ">"), timeout=5)
        if "assword:" in out:
            send_cmd(shell, PASSWORD, patterns=("#",), timeout=5)
            
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        logger.info(f"[CONNECT] Connected to Aggregation Switch.")
        return client, shell
    except Exception as e:
        logger.error(f"[CONNECT] Failed: {e}")
        if retry < AGG_MAX_RETRIES - 1:
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry+1)
        raise

def process_hop(shell, target_ip, config_commands):
    """
    Returns: 'success', 'failed_connection', 'failed_config'
    """
    logger.info(f"\n--- Hop Attempt: {target_ip} ---")
    
    # Clear buffer
    if shell.recv_ready(): shell.recv(MAX_READ)

    # 1. SSH Hop
    shell.send(f"ssh -l {USERNAME} {target_ip}\n")
    
    # Define Explicit Failure Patterns from Logs
    failure_patterns = [
        "refused", 
        "timed out", 
        "unreachable", 
        "Unknown host", 
        "Connection closed", 
        "not responding",    # Catch: "ote host not responding"
        "Open failed", 
        "Connection reset"
    ]
    
    # We add failure patterns to the expect list so it returns IMMEDIATELY 
    # instead of waiting for the full timeout when an error occurs.
    all_patterns = ("(yes/no)?", "assword:", "#", ">") + tuple(failure_patterns)

    out = expect_prompt(shell, patterns=all_patterns, timeout=TARGET_SSH_TIMEOUT)
    
    # 2. Check for failures in the output
    for error_str in failure_patterns:
        if error_str in out:
            logger.warning(f"[FAIL] SSH Log Error detected: '{error_str}'")
            return 'failed_connection'

    # 3. Handle SSH Negotiation
    if "(yes/no)?" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "#", ">"), timeout=10)

    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("#", ">", "assword:", "denied"), timeout=15)
        if "assword:" in out or "denied" in out:
            logger.error(f"[FAIL] Auth failed for {target_ip}")
            return 'failed_connection'

    # 4. Enable Mode (if needed)
    if ">" in out and "#" not in out:
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=8)
        if "assword:" in out: send_cmd(shell, PASSWORD, patterns=("#",), timeout=8)

    # NO HOSTNAME CHECK HERE - RELYING PURELY ON LOGS
    logger.info(f"[CONNECTED] Log check passed. Proceeding with config on {target_ip}")
    
    # 5. Push Config
    try:
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
        
        for cmd in config_commands:
            out = send_cmd(shell, cmd, patterns=("(config)#", "(config-"), timeout=10)
            if "% Invalid" in out or "% Incomplete" in out:
                logger.error(f"[CONFIG ERROR] Command rejected: {cmd}")
        
        send_cmd(shell, "end", patterns=("#",), timeout=10)
        send_cmd(shell, "write memory", patterns=("OK", "#"), timeout=20)
        logger.info(f"[SUCCESS] Configured {target_ip}")
        
        # Exit back to Aggregation Switch
        try: 
            send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
            # Sometimes need a second exit if enabled
            send_cmd(shell, "exit", patterns=("#", ">"), timeout=2) 
        except: pass
        return 'success'

    except Exception as e:
        logger.error(f"[ERROR] Config failed on {target_ip}: {e}")
        try: send_cmd(shell, "end")
        except: pass
        try: send_cmd(shell, "exit")
        except: pass
        return 'failed_config'

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
    try:
        client, shell = connect_to_agg()
    except Exception:
        sys.exit(1)

    successful = []
    failed = []

    # Processing Loop
    for idx, target in enumerate(targets, 1):
        logger.info(f"\n=== Processing Device {idx}/{len(targets)}: {target} ===")
        status = 'failed'
        
        for attempt in range(TARGET_MAX_RETRIES):
            if attempt > 0:
                logger.info(f"Retry {attempt+1}/{TARGET_MAX_RETRIES} for {target}...")
            
            # Connection Recovery
            if getattr(shell, "closed", False) or not shell.get_transport().is_active():
                try: 
                    client, shell = connect_to_agg()
                except: 
                    sys.exit("Fatal: Aggregation switch died.")

            res = process_hop(shell, target, commands)
            
            if res == 'success':
                status = 'success'
                break
            elif res == 'failed_connection':
                time.sleep(TARGET_RETRY_DELAY)
            else:
                time.sleep(TARGET_RETRY_DELAY)
        
        if status == 'success':
            successful.append(target)
        else:
            logger.error(f"Failed to configure {target} after retries.")
            failed.append(target)

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
            
    try: client.close()
    except: pass

if __name__ == "__main__":
    main()
