#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
from typing import Tuple, List, Optional

# USER CONFIG
AGG_IP = "192.168.1.8"
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535

# Retry configuration for aggregation switch connection
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

# Retry configuration for target device connections
TARGET_MAX_RETRIES = 3
TARGET_RETRY_DELAY = 5
TARGET_SSH_TIMEOUT = 90  # How long to wait for SSH connection to target device

# Setup logging with live output
class LiveFormatter(logging.Formatter):
    """Custom formatter for colored, live output"""
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if sys.stdout.isatty():
            log_color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)

# Create formatters
file_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_formatter = LiveFormatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

# File handler with buffering disabled for live writing
file_handler = logging.FileHandler('network_config.log', mode='a')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(file_formatter)
file_handler.stream.reconfigure(line_buffering=True)  # Force flush on newline

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)

# Setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Disable buffering on stdout for immediate output
sys.stdout.reconfigure(line_buffering=True)

class NetworkConnectionError(Exception):
    """Custom exception for network connection issues"""
    pass

class ConfigurationError(Exception):
    """Custom exception for configuration issues"""
    pass

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, show_progress=False):
    """Wait for expected prompt patterns with timeout"""
    buf, end = "", time.time() + timeout
    last_log_time = time.time()
    start_time = time.time()
    last_progress_time = time.time()
    
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            
            # Live log data chunks every 2 seconds or when pattern found
            if time.time() - last_log_time > 2 or any(p in buf for p in patterns):
                if data.strip():
                    logger.debug(f"[RECV] {data.strip()[-100:]}")
                last_log_time = time.time()
            
            for p in patterns:
                if p in buf:
                    return buf
        else:
            # Show progress counter every 5 seconds if enabled
            if show_progress and time.time() - last_progress_time >= 5:
                elapsed = int(time.time() - start_time)
                remaining = int(end - time.time())
                logger.info(f"[WAIT] Elapsed: {elapsed}s, Remaining: {remaining}s...")
                sys.stdout.flush()
                last_progress_time = time.time()
            
            time.sleep(0.1)
    
    logger.warning(f"Timeout waiting for prompt. Buffer: {buf[-200:]}")
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, log_cmd=True, show_progress=False):
    """Send command and wait for prompt"""
    if log_cmd:
        logger.debug(f"Sending command: {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout, show_progress=show_progress)

def connect_to_agg(retry_count=0):
    """Connect to aggregation switch with retry logic"""
    try:
        logger.info(f"[CONNECT] Attempt {retry_count + 1}/{AGG_MAX_RETRIES} - SSH to aggregation switch: {AGG_IP}")
        sys.stdout.flush()
        
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
        logger.info("[CONNECT] Waiting for initial prompt...")
        out = expect_prompt(shell, ("#", ">"))
        if not out:
            raise NetworkConnectionError("No initial prompt received")
        
        # Enter enable mode
        logger.info("[CONNECT] Entering enable mode...")
        out = send_cmd(shell, "enable", patterns=("assword:", "#"))
        if "assword:" in out:
            send_cmd(shell, PASSWORD, patterns=("#",))
        
        # Disable pagination
        logger.info("[CONNECT] Configuring terminal...")
        send_cmd(shell, "terminal length 0", patterns=("#",))
        
        logger.info("[CONNECT] Successfully connected to aggregation switch")
        return client, shell
        
    except (paramiko.SSHException, paramiko.AuthenticationException, TimeoutError) as e:
        logger.error(f"[CONNECT] Connection failed: {e}")
        if retry_count < AGG_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {AGG_RETRY_DELAY} seconds before retry...")
            sys.stdout.flush()
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed to connect after {AGG_MAX_RETRIES} attempts: {e}")

def verify_connectivity(shell, target_ip):
    """Verify device is reachable before attempting configuration"""
    logger.info(f"[VERIFY] Testing connectivity to {target_ip}")
    sys.stdout.flush()
    
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
        sys.stdout.flush()
        
        out = send_cmd(shell, "show running-config", patterns=("#",), timeout=30, show_progress=True)
        
        # Save backup to file
        backup_file = f"backup_{target_ip}_{int(time.time())}.cfg"
        with open(backup_file, 'w') as f:
            f.write(out)
        logger.info(f"[BACKUP] Config saved to {backup_file}")
        return backup_file
    except Exception as e:
        logger.error(f"[BACKUP] Failed to backup config: {e}")
        return None

def cleanup_failed_session(shell):
    """Clean up a failed SSH session attempt"""
    try:
        if shell.closed:
            logger.debug("[CLEANUP] Shell already closed, skipping cleanup")
            return
        
        logger.debug("[CLEANUP] Attempting to clean up failed session")
        
        # Try to send Ctrl+C to interrupt any hanging command
        try:
            if not shell.closed:
                shell.send("\x03")
                time.sleep(0.3)
        except:
            pass
        
        # Try to exit nested session
        for _ in range(3):
            try:
                if shell.closed:
                    break
                shell.send("exit\n")
                time.sleep(0.5)
                
                # Check if we're back at aggregation prompt
                if shell.recv_ready():
                    data = shell.recv(MAX_READ).decode("utf-8", "ignore")
                    if "#" in data:
                        logger.debug("[CLEANUP] Successfully returned to aggregation switch")
                        break
            except:
                break
        
        logger.debug("[CLEANUP] Cleanup completed")
        
    except Exception as e:
        logger.debug(f"[CLEANUP] Cleanup exception (may be expected): {e}")

def establish_device_session(shell, target_ip, retry_count=0):
    """Establish SSH session to target device with retry logic"""
    try:
        logger.info(f"[HOP] Attempt {retry_count + 1}/{TARGET_MAX_RETRIES} - SSH to {target_ip}")
        sys.stdout.flush()
        
        # Check if shell is still alive before attempting connection
        if shell.closed:
            raise NetworkConnectionError("SSH shell to aggregation switch is closed")
        
        # Initiate SSH connection with configurable timeout
        logger.info(f"[HOP] Initiating SSH connection (timeout: {TARGET_SSH_TIMEOUT}s)...")
        out = send_cmd(
            shell, 
            f"ssh -l {USERNAME} {target_ip}",
            patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">", "Connection refused", "Connection timed out"),
            timeout=TARGET_SSH_TIMEOUT,
            show_progress=True
        )
        
        logger.debug(f"[HOP] Initial output: {out[-300:]}")
        
        # Check for immediate connection failures
        if "Connection refused" in out:
            raise NetworkConnectionError(f"SSH connection refused by {target_ip}")
        
        if "Connection timed out" in out or "Destination" in out:
            raise NetworkConnectionError(f"SSH connection timed out to {target_ip}")
        
        if "No route to host" in out or "Host is unreachable" in out:
            raise NetworkConnectionError(f"Network unreachable to {target_ip}")
        
        # Handle host key verification
        if "(yes/no)?" in out or "yes/no" in out:
            logger.debug("[HOP] Accepting host key")
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
            logger.debug(f"[HOP] After host key: {out[-300:]}")
        
        # Handle password prompt
        if "assword:" in out:
            logger.debug("[HOP] Sending password")
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">", "assword:"), timeout=15)
            logger.debug(f"[HOP] After password: {out[-300:]}")
            
            # Check if password was rejected (prompted again or error)
            if "assword:" in out:
                raise NetworkConnectionError(f"Authentication failed for {target_ip} - password rejected")
        
        # Check for authentication/authorization failures
        if "% Authentication failed" in out or "% Authorization failed" in out:
            raise NetworkConnectionError(f"Authentication/Authorization failed for {target_ip}")
        
        if "% Bad passwords" in out or "% Login invalid" in out:
            raise NetworkConnectionError(f"Invalid credentials for {target_ip}")
        
        # Verify we got a prompt
        has_prompt = False
        if "#" in out or ">" in out:
            # Extract the last line to check for proper prompt
            lines = out.strip().split('\n')
            last_line = lines[-1] if lines else ""
            logger.debug(f"[HOP] Last line: {last_line}")
            
            if last_line.endswith("#") or last_line.endswith(">"):
                has_prompt = True
        
        if not has_prompt:
            raise NetworkConnectionError(f"No valid prompt received from {target_ip}")
        
        # Enter enable mode if in user mode (prompt ends with >)
        if out.strip().endswith(">") or (out.count(">") > out.count("#")):
            logger.debug("[HOP] Entering enable mode")
            out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=10)
            
            if "assword:" in out:
                out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=10)
                
            if "#" not in out:
                raise NetworkConnectionError(f"Failed to enter enable mode on {target_ip}")
        
        # Verify we're in enable mode with a test command
        logger.debug("[HOP] Verifying enable mode")
        out = send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        if "#" not in out:
            raise NetworkConnectionError(f"Device session unstable on {target_ip}")
        
        # Additional verification - send empty command and check for prompt
        out = send_cmd(shell, "", patterns=("#",), timeout=3)
        if "#" not in out:
            raise NetworkConnectionError(f"Lost prompt connection to {target_ip}")
        
        logger.info(f"[CONNECTED] Successfully connected to {target_ip}")
        return True
        
    except NetworkConnectionError as e:
        logger.error(f"[HOP] Connection error: {e}")
        
        # Clean up failed connection attempt
        cleanup_failed_session(shell)
        
        if retry_count < TARGET_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {TARGET_RETRY_DELAY} seconds before retry...")
            sys.stdout.flush()
            time.sleep(TARGET_RETRY_DELAY)
            return establish_device_session(shell, target_ip, retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed to connect to {target_ip} after {TARGET_MAX_RETRIES} attempts")
    except OSError as e:
        logger.error(f"[HOP] Socket error: {e}")
        raise NetworkConnectionError(f"Lost connection to aggregation switch: {e}")
        
        # Handle host key verification
        if "(yes/no)?" in out or "yes/no" in out:
            logger.debug("[HOP] Accepting host key")
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
            logger.debug(f"[HOP] After host key: {out[-300:]}")
        
        # Handle password prompt
        if "assword:" in out:
            logger.debug("[HOP] Sending password")
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">", "assword:"), timeout=15)
            logger.debug(f"[HOP] After password: {out[-300:]}")
            
            # Check if password was rejected (prompted again or error)
            if "assword:" in out:
                raise NetworkConnectionError(f"Authentication failed for {target_ip} - password rejected")
        
        # Check for authentication/authorization failures
        if "% Authentication failed" in out or "% Authorization failed" in out:
            raise NetworkConnectionError(f"Authentication/Authorization failed for {target_ip}")
        
        if "% Bad passwords" in out or "% Login invalid" in out:
            raise NetworkConnectionError(f"Invalid credentials for {target_ip}")
        
        # Verify we got a prompt
        has_prompt = False
        if "#" in out or ">" in out:
            # Extract the last line to check for proper prompt
            lines = out.strip().split('\n')
            last_line = lines[-1] if lines else ""
            logger.debug(f"[HOP] Last line: {last_line}")
            
            if last_line.endswith("#") or last_line.endswith(">"):
                has_prompt = True
        
        if not has_prompt:
            raise NetworkConnectionError(f"No valid prompt received from {target_ip}")
        
        # Enter enable mode if in user mode (prompt ends with >)
        if out.strip().endswith(">") or (out.count(">") > out.count("#")):
            logger.debug("[HOP] Entering enable mode")
            out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=10)
            
            if "assword:" in out:
                out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=10)
                
            if "#" not in out:
                raise NetworkConnectionError(f"Failed to enter enable mode on {target_ip}")
        
        # Verify we're in enable mode with a test command
        logger.debug("[HOP] Verifying enable mode")
        out = send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        if "#" not in out:
            raise NetworkConnectionError(f"Device session unstable on {target_ip}")
        
        # Additional verification - send empty command and check for prompt
        out = send_cmd(shell, "", patterns=("#",), timeout=3)
        if "#" not in out:
            raise NetworkConnectionError(f"Lost prompt connection to {target_ip}")
        
        logger.info(f"[CONNECTED] Successfully connected to {target_ip}")
        return True
        
    except NetworkConnectionError as e:
        logger.error(f"[HOP] Connection error: {e}")
        
        # Clean up failed connection attempt
        cleanup_failed_session(shell)
        
        if retry_count < MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {RETRY_DELAY} seconds before retry...")
            sys.stdout.flush()
            time.sleep(RETRY_DELAY)
            return establish_device_session(shell, target_ip, retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed to connect to {target_ip} after {MAX_RETRIES} attempts")
    except OSError as e:
        logger.error(f"[HOP] Socket error: {e}")
        raise NetworkConnectionError(f"Lost connection to aggregation switch: {e}")
        
        # Handle host key verification
        if "(yes/no)?" in out or "yes/no" in out:
            logger.debug("[HOP] Accepting host key")
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
            logger.debug(f"[HOP] After host key: {out[-300:]}")
        
        # Handle password prompt
        if "assword:" in out:
            logger.debug("[HOP] Sending password")
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">", "assword:"), timeout=15)
            logger.debug(f"[HOP] After password: {out[-300:]}")
            
            # Check if password was rejected (prompted again or error)
            if "assword:" in out:
                raise NetworkConnectionError(f"Authentication failed for {target_ip} - password rejected")
        
        # Check for authentication/authorization failures
        if "% Authentication failed" in out or "% Authorization failed" in out:
            raise NetworkConnectionError(f"Authentication/Authorization failed for {target_ip}")
        
        if "% Bad passwords" in out or "% Login invalid" in out:
            raise NetworkConnectionError(f"Invalid credentials for {target_ip}")
        
        # Verify we got a prompt
        has_prompt = False
        if "#" in out or ">" in out:
            # Extract the last line to check for proper prompt
            lines = out.strip().split('\n')
            last_line = lines[-1] if lines else ""
            logger.debug(f"[HOP] Last line: {last_line}")
            
            if last_line.endswith("#") or last_line.endswith(">"):
                has_prompt = True
        
        if not has_prompt:
            raise NetworkConnectionError(f"No valid prompt received from {target_ip}")
        
        # Enter enable mode if in user mode (prompt ends with >)
        if out.strip().endswith(">") or (out.count(">") > out.count("#")):
            logger.debug("[HOP] Entering enable mode")
            out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=10)
            
            if "assword:" in out:
                out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=10)
                
            if "#" not in out:
                raise NetworkConnectionError(f"Failed to enter enable mode on {target_ip}")
        
        # Verify we're in enable mode with a test command
        logger.debug("[HOP] Verifying enable mode")
        out = send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        if "#" not in out:
            raise NetworkConnectionError(f"Device session unstable on {target_ip}")
        
        # Additional verification - send empty command and check for prompt
        out = send_cmd(shell, "", patterns=("#",), timeout=3)
        if "#" not in out:
            raise NetworkConnectionError(f"Lost prompt connection to {target_ip}")
        
        logger.info(f"[CONNECTED] Successfully connected to {target_ip}")
        return True
        
    except NetworkConnectionError as e:
        logger.error(f"[HOP] Connection error: {e}")
        
        # Clean up failed connection attempt
        cleanup_failed_session(shell)
        
        if retry_count < MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {RETRY_DELAY} seconds before retry...")
            sys.stdout.flush()
            time.sleep(RETRY_DELAY)
            return establish_device_session(shell, target_ip, retry_count + 1)
        else:
            raise NetworkConnectionError(f"Failed to connect to {target_ip} after {MAX_RETRIES} attempts")
    except OSError as e:
        logger.error(f"[HOP] Socket error: {e}")
        raise NetworkConnectionError(f"Lost connection to aggregation switch: {e}")

def apply_configuration(shell, config_commands, retry_count=0):
    """Apply configuration commands with verification"""
    try:
        # Enter config mode
        logger.info("[CONFIG] Entering configuration mode...")
        out = send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
        if "(config)#" not in out:
            raise ConfigurationError("Failed to enter configuration mode")
        
        failed_commands = []
        total_cmds = len(config_commands)
        
        for idx, cmd in enumerate(config_commands, 1):
            logger.info(f"[CONFIG] [{idx}/{total_cmds}] Sending: {cmd}")
            sys.stdout.flush()
            
            out = send_cmd(shell, cmd, patterns=("(config)#", "(config-"), timeout=10)
            
            # Check for errors in output
            if "Invalid" in out or "incomplete" in out or "% " in out:
                logger.error(f"[CONFIG] Command failed: {cmd}")
                logger.error(f"[CONFIG] Error output: {out[-200:]}")
                failed_commands.append(cmd)
            else:
                logger.info(f"[CONFIG] Command accepted")
        
        if failed_commands:
            raise ConfigurationError(f"Failed commands: {', '.join(failed_commands)}")
        
        # Save configuration with progress counter
        logger.info("[CONFIG] Saving configuration with 'do write' (timeout: 20s)...")
        sys.stdout.flush()
        out = send_cmd(shell, "do write", patterns=("(config)#", "#", "[OK]"), timeout=20, show_progress=True)
        
        if "[OK]" in out or "Building configuration" in out:
            logger.info("[CONFIG] Configuration saved successfully")
        else:
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
        
        if retry_count < TARGET_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Retrying configuration (attempt {retry_count + 2}/{TARGET_MAX_RETRIES})")
            time.sleep(TARGET_RETRY_DELAY)
            return apply_configuration(shell, config_commands, retry_count + 1)
        else:
            raise ConfigurationError(f"Failed to apply configuration after {TARGET_MAX_RETRIES} attempts")

def exit_device_session(shell):
    """Safely exit from target device back to aggregation switch"""
    try:
        logger.info("[EXIT] Returning to aggregation switch")
        sys.stdout.flush()
        
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
        # Check if aggregation shell is still alive
        if shell.closed:
            raise NetworkConnectionError("Connection to aggregation switch lost")
        
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
        
    except NetworkConnectionError as e:
        logger.error(f"[ERROR] Failed to configure {target_ip}: {e}")
        
        # Check if we need to reconnect to aggregation switch
        if shell.closed or "aggregation switch" in str(e).lower():
            logger.warning("Connection to aggregation switch lost, this device will be skipped")
            return False, backup_file
        
        # Attempt to exit gracefully
        try:
            if not shell.closed:
                exit_device_session(shell)
        except:
            pass
        
        return False, backup_file
        
    except ConfigurationError as e:
        logger.error(f"[ERROR] Configuration failed for {target_ip}: {e}")
        
        # Attempt to exit gracefully
        try:
            if not shell.closed:
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
    
    logger.info("=" * 70)
    logger.info("NETWORK CONFIGURATION AUTOMATION SCRIPT")
    logger.info("=" * 70)
    
    # Validate input files
    try:
        with open(devices_file, "r") as f:
            target_ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        with open(commands_file, "r") as f:
            config_cmds = [line.rstrip() for line in f if line.strip() and not line.startswith("!")]
        
        logger.info(f"Loaded {len(target_ips)} devices and {len(config_cmds)} commands")
        logger.info(f"Log file: network_config.log")
        logger.info("")
        
    except FileNotFoundError as e:
        logger.error(f"Input file not found: {e}")
        sys.exit(1)
    
    # Connect to aggregation switch
    logger.info("Connecting to aggregation switch...")
    try:
        client, shell = connect_to_agg()
    except NetworkConnectionError as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)
    
    # Track results
    successful = []
    failed = []
    start_time = time.time()
    
    # Configure each device
    for idx, target in enumerate(target_ips, 1):
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"DEVICE {idx}/{len(target_ips)}: {target}")
        logger.info("=" * 70)
        
        # Check if aggregation connection is still alive
        if shell.closed:
            logger.error("Connection to aggregation switch lost!")
            logger.info("Attempting to reconnect...")
            try:
                client.close()
                client, shell = connect_to_agg()
            except NetworkConnectionError as e:
                logger.error(f"Failed to reconnect to aggregation switch: {e}")
                logger.error("Remaining devices will be skipped")
                failed.extend(target_ips[idx-1:])
                break
        
        device_start = time.time()
        success, backup = push_config(shell, target, config_cmds)
        device_elapsed = time.time() - device_start
        
        if success:
            logger.info(f"[SUCCESS] Configuration applied to {target} in {device_elapsed:.1f}s")
            successful.append(target)
        else:
            logger.error(f"[FAILED] Could not configure {target} after {device_elapsed:.1f}s")
            failed.append(target)
            
            # If aggregation connection was lost, break the loop
            if shell.closed:
                logger.error("Connection to aggregation switch lost, stopping configuration")
                failed.extend(target_ips[idx:])
                break
        
        # Small delay between devices
        time.sleep(2)
    
    # Close connection to aggregation switch
    try:
        client.close()
        logger.info("")
        logger.info("[DISCONNECT] Closed connection to aggregation switch")
    except:
        pass
    
    # Summary
    total_elapsed = time.time() - start_time
    logger.info("")
    logger.info("=" * 70)
    logger.info("CONFIGURATION SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total time: {total_elapsed:.1f}s")
    logger.info(f"Total devices: {len(target_ips)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed: {len(failed)}")
    logger.info(f"Success rate: {(len(successful)/len(target_ips)*100):.1f}%")
    
    if successful:
        logger.info(f"\nSuccessful devices:")
        for device in successful:
            logger.info(f"   - {device}")
    
    if failed:
        logger.error(f"\nFailed devices:")
        for device in failed:
            logger.error(f"   - {device}")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("All configuration tasks completed")
    logger.info("=" * 70)
    
    # Exit with error code if any failures
    sys.exit(0 if not failed else 1)

if __name__ == "__main__":
    main()
