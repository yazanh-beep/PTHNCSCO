#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
from typing import Tuple, List, Optional

# USER CONFIG
AGG_IP = "192.168.1.1"
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535
MAX_RETRIES = 3
RETRY_DELAY = 5

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_config.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class NetworkConnectionError(Exception):
    """Custom exception for network connection issues"""
    pass

class ConfigurationError(Exception):
    """Custom exception for configuration issues"""
    pass

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
    """Wait for expected prompt patterns with timeout"""
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
    logger.warning(f"Timeout waiting for prompt. Buffer: {buf[-200:]}")
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, log_cmd=True):
    """Send command and wait for prompt"""
    if log_cmd:
        logger.debug(f"Sending command: {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def connect_to_agg(retry_count=0):
    """Connect to aggregation switch with retry logic"""
    try:
        logger.info(f"[CONNECT] Attempt {retry_count + 1}/{MAX_RETRIES} - SSH to aggregation switch: {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            AGG_IP, 
            username=USERNAME, 
            password=PASSWORD,
            look_for_keys=False, 
            allow_agent=False, 
            timeout=10
        )
        shell = client.invoke_shell()
        
        # Wait for initial prompt
        out = expect_prompt(shell, ("#", ">"))
        if not out:
            raise NetworkConnectionError("No initial prompt received")
        
        # Enter enable mode
        out = send_cmd(shell, "enable", patterns=("assword:", "#"))
        if "assword:" in out:
            send_cmd(shell, PASSWORD, patterns=("#",))
        
        # Disable pagination
        send_cmd(shell, "terminal length 0", patterns=("#",))
        
        logger.info("[CONNECT] Successfully connected to aggregation switch")
        return client, shell
        
    except (paramiko.SSHException, paramiko.AuthenticationException, TimeoutError) as e:
        logger.error(f"[CONNECT] Connection failed: {e}")
        if retry_count < MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {RETRY_DELAY} seconds before retry...")
            time.sleep(RETRY_DELAY)
            return connect_to_agg(retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed to connect after {MAX_RETRIES} attempts: {e}")

def verify_connectivity(shell, target_ip):
    """Verify device is reachable before attempting configuration"""
    logger.info(f"[VERIFY] Testing connectivity to {target_ip}")
    out = send_cmd(shell, f"ping {target_ip} repeat 2", patterns=("#",), timeout=15)
    
    if "!!" in out or "Success rate is" in out:
        logger.info(f"[VERIFY] {target_ip} is reachable")
        return True
    else:
        logger.warning(f"[VERIFY] {target_ip} is not reachable via ping")
        return False

def backup_config(shell, target_ip):
    """Backup running configuration before making changes"""
    try:
        logger.info(f"[BACKUP] Retrieving current config from {target_ip}")
        out = send_cmd(shell, "show running-config", patterns=("#",), timeout=30)
        
        # Save backup to file
        backup_file = f"backup_{target_ip}_{int(time.time())}.cfg"
        with open(backup_file, 'w') as f:
            f.write(out)
        logger.info(f"[BACKUP] Config saved to {backup_file}")
        return backup_file
    except Exception as e:
        logger.error(f"[BACKUP] Failed to backup config: {e}")
        return None

def establish_device_session(shell, target_ip, retry_count=0):
    """Establish SSH session to target device with retry logic"""
    try:
        logger.info(f"[HOP] Attempt {retry_count + 1}/{MAX_RETRIES} - SSH to {target_ip}")
        
        out = send_cmd(
            shell, 
            f"ssh -l {USERNAME} {target_ip}",
            patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">", "Connection refused"),
            timeout=15
        )
        
        # Handle connection refused
        if "Connection refused" in out or "Destination" in out:
            raise NetworkConnectionError(f"SSH connection refused by {target_ip}")
        
        # Handle host key verification
        if "(yes/no)?" in out or "yes/no" in out:
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
        
        # Handle password prompt
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">"), timeout=15)
        
        # Check if authentication failed
        if "%" in out and "fail" in out.lower():
            raise NetworkConnectionError(f"Authentication failed for {target_ip}")
        
        # Enter enable mode if needed
        if out.strip().endswith(">"):
            send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=15)
            send_cmd(shell, PASSWORD, patterns=("#",), timeout=15)
        
        # Disable pagination
        send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        logger.info(f"[CONNECTED] Successfully connected to {target_ip}")
        return True
        
    except NetworkConnectionError as e:
        logger.error(f"[HOP] Connection error: {e}")
        if retry_count < MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {RETRY_DELAY} seconds before retry...")
            # Exit from failed session if partially connected
            try:
                send_cmd(shell, "\x03", patterns=("#",), timeout=2)  # Ctrl+C
                send_cmd(shell, "exit", patterns=("#", ">"), timeout=2)
            except:
                pass
            time.sleep(RETRY_DELAY)
            return establish_device_session(shell, target_ip, retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed to connect to {target_ip} after {MAX_RETRIES} attempts")

def apply_configuration(shell, config_commands, retry_count=0):
    """Apply configuration commands with verification"""
    try:
        # Enter config mode
        out = send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
        if "(config)#" not in out:
            raise ConfigurationError("Failed to enter configuration mode")
        
        failed_commands = []
        
        for cmd in config_commands:
            logger.info(f"[CONFIG] Sending: {cmd}")
            out = send_cmd(shell, cmd, patterns=("(config)#", "(config-"), timeout=10)
            
            # Check for errors in output
            if "Invalid" in out or "incomplete" in out or "% " in out:
                logger.error(f"[CONFIG] Command failed: {cmd}")
                logger.error(f"[CONFIG] Error output: {out[-200:]}")
                failed_commands.append(cmd)
        
        if failed_commands:
            raise ConfigurationError(f"Failed commands: {', '.join(failed_commands)}")
        
        # Save configuration
        logger.info("[CONFIG] Saving configuration with 'do write'")
        out = send_cmd(shell, "do write", patterns=("(config)#", "#", "[OK]"), timeout=20)
        
        if "[OK]" not in out and "Building configuration" not in out:
            logger.warning("[CONFIG] Configuration save verification unclear")
        
        # Exit config mode
        send_cmd(shell, "end", patterns=("#",), timeout=5)
        logger.info("[CONFIG] Configuration applied successfully")
        return True
        
    except ConfigurationError as e:
        logger.error(f"[CONFIG] Configuration error: {e}")
        # Exit config mode on error
        try:
            send_cmd(shell, "end", patterns=("#",), timeout=5)
        except:
            pass
        
        if retry_count < MAX_RETRIES - 1:
            logger.info(f"[RETRY] Retrying configuration (attempt {retry_count + 2}/{MAX_RETRIES})")
            time.sleep(RETRY_DELAY)
            return apply_configuration(shell, config_commands, retry_count + 1)
        else:
            raise ConfigurationError(f"Failed to apply configuration after {MAX_RETRIES} attempts")

def exit_device_session(shell):
    """Safely exit from target device back to aggregation switch"""
    try:
        logger.info("[EXIT] Returning to aggregation switch")
        send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
        time.sleep(1)
        # Verify we're back at aggregation switch
        out = send_cmd(shell, "", patterns=("#",), timeout=2)
        logger.info("[EXIT] Successfully returned to aggregation switch")
    except Exception as e:
        logger.warning(f"[EXIT] Error during exit: {e}")

def push_config(shell, target_ip, config_commands):
    """Main function to push configuration to a target device"""
    backup_file = None
    
    try:
        # Verify connectivity first
        if not verify_connectivity(shell, target_ip):
            raise NetworkConnectionError(f"Device {target_ip} is not reachable")
        
        # Establish session to target device
        establish_device_session(shell, target_ip)
        
        # Backup current configuration
        backup_file = backup_config(shell, target_ip)
        
        # Apply configuration
        apply_configuration(shell, config_commands)
        
        # Exit back to aggregation switch
        exit_device_session(shell)
        
        return True, backup_file
        
    except (NetworkConnectionError, ConfigurationError) as e:
        logger.error(f"[ERROR] Failed to configure {target_ip}: {e}")
        # Attempt to exit gracefully
        try:
            exit_device_session(shell)
        except:
            pass
        return False, backup_file

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 push_config.py <devices_file> <commands_file>")
        sys.exit(1)
    
    devices_file = sys.argv[1]
    commands_file = sys.argv[2]
    
    # Validate input files
    try:
        with open(devices_file, "r") as f:
            target_ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        with open(commands_file, "r") as f:
            config_cmds = [line.rstrip() for line in f if line.strip() and not line.startswith("!")]
        
        logger.info(f"Loaded {len(target_ips)} devices and {len(config_cmds)} commands")
        
    except FileNotFoundError as e:
        logger.error(f"Input file not found: {e}")
        sys.exit(1)
    
    # Connect to aggregation switch
    try:
        client, shell = connect_to_agg()
    except NetworkConnectionError as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)
    
    # Track results
    successful = []
    failed = []
    
    # Configure each device
    for target in target_ips:
        logger.info(f"\n{'='*60}")
        logger.info(f"=== Configuring {target} ===")
        logger.info(f"{'='*60}")
        
        success, backup = push_config(shell, target, config_cmds)
        
        if success:
            logger.info(f"[SUCCESS] Configuration applied to {target}")
            successful.append(target)
        else:
            logger.error(f"[FAILED] Could not configure {target}")
            failed.append(target)
        
        # Small delay between devices
        time.sleep(2)
    
    # Close connection to aggregation switch
    try:
        client.close()
        logger.info("\n[DISCONNECT] Closed connection to aggregation switch")
    except:
        pass
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("="*60)
    logger.info(f"Total devices: {len(target_ips)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed: {len(failed)}")
    
    if successful:
        logger.info(f"\nSuccessful devices: {', '.join(successful)}")
    
    if failed:
        logger.error(f"\nFailed devices: {', '.join(failed)}")
    
    logger.info("\nAll configuration tasks completed.")
    
    # Exit with error code if any failures
    sys.exit(0 if not failed else 1)

if __name__ == "__main__":
    main()
