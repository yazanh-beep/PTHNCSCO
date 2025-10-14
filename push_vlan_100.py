#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
from typing import Tuple, List, Optional
import ipaddress

# USER CONFIG
AGG_IP = "192.168.1.1"
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535

# Retry configuration for aggregation switch connection
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

# Retry configuration for target device connections
TARGET_MAX_RETRIES = 1
TARGET_RETRY_DELAY = 5
TARGET_SSH_TIMEOUT = 60
TARGET_TCP_TIMEOUT = 30

# Setup logging with live output
class LiveFormatter(logging.Formatter):
    """Custom formatter for colored, live output"""
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
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

# File handler
file_handler = logging.FileHandler('vlan_100_config.log', mode='a')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(file_formatter)
file_handler.stream.reconfigure(line_buffering=True)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)

# Setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

sys.stdout.reconfigure(line_buffering=True)

class NetworkConnectionError(Exception):
    """Custom exception for network connection issues"""
    def __init__(self, message, retry_allowed=False, reconnect_needed=False):
        super().__init__(message)
        self.retry_allowed = retry_allowed
        self.reconnect_needed = reconnect_needed

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
            
            if time.time() - last_log_time > 2 or any(p in buf for p in patterns):
                if data.strip():
                    logger.debug(f"[RECV] {data.strip()[-100:]}")
                last_log_time = time.time()
            
            for p in patterns:
                if p in buf:
                    return buf
        else:
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
        
        logger.info("[CONNECT] Waiting for initial prompt...")
        out = expect_prompt(shell, ("#", ">"))
        if not out:
            raise NetworkConnectionError("No initial prompt received")
        
        logger.info("[CONNECT] Entering enable mode...")
        out = send_cmd(shell, "enable", patterns=("assword:", "#"))
        if "assword:" in out:
            send_cmd(shell, PASSWORD, patterns=("#",))
        
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

def cleanup_failed_session(shell):
    """Clean up a failed SSH session attempt"""
    try:
        if shell.closed:
            logger.debug("[CLEANUP] Shell already closed, skipping cleanup")
            return False
        
        logger.debug("[CLEANUP] Attempting to clean up failed session")
        
        try:
            if not shell.closed:
                shell.send("\x03")
                time.sleep(0.5)
        except:
            pass
        
        for attempt in range(3):
            try:
                if shell.closed:
                    logger.debug("[CLEANUP] Shell closed during cleanup")
                    return False
                    
                shell.send("exit\n")
                time.sleep(1)
                
                if shell.recv_ready():
                    data = shell.recv(MAX_READ).decode("utf-8", "ignore")
                    logger.debug(f"[CLEANUP] Received after exit: {data[-200:]}")
                    
                    if "#" in data:
                        logger.debug("[CLEANUP] Successfully returned to aggregation switch")
                        return True
            except Exception as e:
                logger.debug(f"[CLEANUP] Exit attempt {attempt + 1} exception: {e}")
                break
        
        try:
            if not shell.closed:
                shell.send("\n")
                time.sleep(0.5)
                if shell.recv_ready():
                    data = shell.recv(MAX_READ).decode("utf-8", "ignore")
                    if "#" in data:
                        logger.debug("[CLEANUP] Verified aggregation switch prompt")
                        return True
        except:
            pass
        
        logger.warning("[CLEANUP] Could not verify return to aggregation switch")
        return False
        
    except Exception as e:
        logger.debug(f"[CLEANUP] Cleanup exception: {e}")
        return False

def establish_device_session(shell, target_ip, retry_count=0):
    """Establish SSH session to target device with retry logic"""
    try:
        logger.info(f"[HOP] Attempt {retry_count + 1}/{TARGET_MAX_RETRIES} - SSH to {target_ip}")
        sys.stdout.flush()
        
        if shell.closed:
            raise NetworkConnectionError("SSH shell to aggregation switch is closed")
        
        logger.info(f"[HOP] Initiating SSH connection (timeout: {TARGET_SSH_TIMEOUT}s)...")
        out = send_cmd(
            shell, 
            f"ssh -l {USERNAME} {target_ip}",
            patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">", "Connection refused", "Connection timed out"),
            timeout=TARGET_SSH_TIMEOUT,
            show_progress=True
        )
        
        logger.debug(f"[HOP] Initial output: {out[-300:]}")
        
        if "Connection refused" in out:
            raise NetworkConnectionError(f"SSH connection refused by {target_ip} - skipping device")
        
        if "Connection timed out" in out or "Destination" in out:
            raise NetworkConnectionError(f"SSH connection timed out to {target_ip} - device unreachable, skipping")
        
        if "No route to host" in out or "Host is unreachable" in out:
            raise NetworkConnectionError(f"Network unreachable to {target_ip} - skipping device")
        
        if "(yes/no)?" in out or "yes/no" in out:
            logger.debug("[HOP] Accepting host key")
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
            logger.debug(f"[HOP] After host key: {out[-300:]}")
        
        if "assword:" in out:
            logger.debug("[HOP] Sending password")
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">", "assword:"), timeout=15)
            logger.debug(f"[HOP] After password: {out[-300:]}")
            
            if "assword:" in out:
                raise NetworkConnectionError(f"Authentication failed for {target_ip} - password rejected", retry_allowed=True)
        
        if "% Authentication failed" in out or "% Authorization failed" in out:
            raise NetworkConnectionError(f"Authentication/Authorization failed for {target_ip}", retry_allowed=True)
        
        if "% Bad passwords" in out or "% Login invalid" in out:
            raise NetworkConnectionError(f"Invalid credentials for {target_ip}", retry_allowed=True)
        
        has_prompt = False
        if "#" in out or ">" in out:
            lines = out.strip().split('\n')
            last_line = lines[-1] if lines else ""
            logger.debug(f"[HOP] Last line: {last_line}")
            
            if last_line.endswith("#") or last_line.endswith(">"):
                has_prompt = True
        
        if not has_prompt:
            raise NetworkConnectionError(f"No valid prompt received from {target_ip}", retry_allowed=True)
        
        if out.strip().endswith(">") or (out.count(">") > out.count("#")):
            logger.debug("[HOP] Entering enable mode")
            out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=10)
            
            if "assword:" in out:
                out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=10)
                
            if "#" not in out:
                raise NetworkConnectionError(f"Failed to enter enable mode on {target_ip}", retry_allowed=True)
        
        logger.debug("[HOP] Verifying enable mode")
        out = send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
        
        if "#" not in out:
            raise NetworkConnectionError(f"Device session unstable on {target_ip}", retry_allowed=True)
        
        out = send_cmd(shell, "", patterns=("#",), timeout=3)
        if "#" not in out:
            raise NetworkConnectionError(f"Lost prompt connection to {target_ip}", retry_allowed=True)
        
        logger.info(f"[CONNECTED] Successfully connected to {target_ip}")
        return True
        
    except NetworkConnectionError as e:
        logger.error(f"[HOP] Connection error: {e}")
        
        cleanup_successful = cleanup_failed_session(shell)
        
        if not cleanup_successful and not shell.closed:
            logger.warning("[HOP] Cleanup verification failed - shell state uncertain")
        
        retry_allowed = getattr(e, 'retry_allowed', False)
        
        if retry_allowed and retry_count < TARGET_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {TARGET_RETRY_DELAY} seconds before retry...")
            sys.stdout.flush()
            time.sleep(TARGET_RETRY_DELAY)
            return establish_device_session(shell, target_ip, retry_count + 1)
        else:
            if not retry_allowed:
                logger.info(f"[SKIP] Device {target_ip} is unreachable - moving to next device")
            raise NetworkConnectionError(f"Failed to connect to {target_ip} after {retry_count + 1} attempt(s)")
    except OSError as e:
        logger.error(f"[HOP] Socket error: {e}")
        raise NetworkConnectionError(f"Lost connection to aggregation switch: {e}")

def apply_vlan_config(shell, vlan_ip, netmask, retry_count=0):
    """Apply VLAN 100 configuration with IP address"""
    try:
        logger.info("[CONFIG] Entering configuration mode...")
        out = send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)
        if "(config)#" not in out:
            raise ConfigurationError("Failed to enter configuration mode")
        
        # Create VLAN 100
        logger.info("[CONFIG] Creating VLAN 100...")
        out = send_cmd(shell, "vlan 100", patterns=("(config-vlan)#",), timeout=10)
        if "(config-vlan)#" not in out:
            raise ConfigurationError("Failed to create VLAN 100")
        
        # Exit vlan config
        out = send_cmd(shell, "exit", patterns=("(config)#",), timeout=5)
        
        # Configure interface VLAN 100
        logger.info("[CONFIG] Configuring interface VLAN 100...")
        out = send_cmd(shell, "interface vlan 100", patterns=("(config-if)#",), timeout=10)
        if "(config-if)#" not in out:
            raise ConfigurationError("Failed to enter interface VLAN 100")
        
        # Assign IP address
        logger.info(f"[CONFIG] Assigning IP address: {vlan_ip} {netmask}")
        out = send_cmd(shell, f"ip address {vlan_ip} {netmask}", patterns=("(config-if)#",), timeout=10)
        
        if "Invalid" in out or "incomplete" in out or "% " in out:
            logger.error(f"[CONFIG] IP address assignment failed: {out[-200:]}")
            raise ConfigurationError(f"Failed to assign IP address {vlan_ip} {netmask}")
        
        logger.info("[CONFIG] IP address assigned successfully")
        
        # Save configuration
        logger.info("[CONFIG] Saving configuration with 'do write'...")
        sys.stdout.flush()
        out = send_cmd(shell, "do write", patterns=("(config-if)#", "#", "[OK]"), timeout=20, show_progress=True)
        
        if "[OK]" in out or "Building configuration" in out:
            logger.info("[CONFIG] Configuration saved successfully")
        else:
            logger.warning("[CONFIG] Configuration save verification unclear")
        
        # Exit config mode
        send_cmd(shell, "end", patterns=("#",), timeout=5)
        logger.info(f"[CONFIG] VLAN 100 configured with IP {vlan_ip}")
        return True
        
    except ConfigurationError as e:
        logger.error(f"[CONFIG] Configuration error: {e}")
        try:
            send_cmd(shell, "end", patterns=("#",), timeout=5)
        except:
            pass
        
        if retry_count < TARGET_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Retrying configuration (attempt {retry_count + 2}/{TARGET_MAX_RETRIES})")
            time.sleep(TARGET_RETRY_DELAY)
            return apply_vlan_config(shell, vlan_ip, netmask, retry_count + 1)
        else:
            raise ConfigurationError(f"Failed to apply configuration after {TARGET_MAX_RETRIES} attempts")

def exit_device_session(shell):
    """Safely exit from target device back to aggregation switch"""
    try:
        logger.info("[EXIT] Returning to aggregation switch")
        sys.stdout.flush()
        
        send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
        time.sleep(1)
        out = send_cmd(shell, "", patterns=("#",), timeout=2)
        logger.info("[EXIT] Successfully returned to aggregation switch")
    except Exception as e:
        logger.warning(f"[EXIT] Error during exit: {e}")

def configure_device_vlan(shell, target_ip, vlan_ip, netmask):
    """Configure VLAN 100 on a target device"""
    try:
        if shell.closed:
            raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
        
        logger.debug(f"[PUSH] Verifying aggregate prompt before connecting to {target_ip}")
        try:
            out = send_cmd(shell, "", patterns=("#",), timeout=3)
            if "#" not in out:
                logger.warning("[PUSH] Not at aggregate prompt - attempting to recover")
                for _ in range(3):
                    shell.send("exit\n")
                    time.sleep(0.5)
                out = send_cmd(shell, "", patterns=("#",), timeout=3)
                if "#" not in out:
                    raise NetworkConnectionError("Unable to verify aggregate switch prompt", reconnect_needed=True)
        except OSError:
            raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
        
        # Establish session to target device
        establish_device_session(shell, target_ip)
        
        # Apply VLAN configuration
        apply_vlan_config(shell, vlan_ip, netmask)
        
        # Exit back to aggregation switch
        exit_device_session(shell)
        
        return True, False
        
    except NetworkConnectionError as e:
        logger.error(f"[ERROR] Failed to configure {target_ip}: {e}")
        
        reconnect_needed = getattr(e, 'reconnect_needed', False)
        
        if shell.closed or reconnect_needed or "aggregation switch" in str(e).lower():
            logger.warning("Connection to aggregation switch lost")
            return False, True
        
        try:
            if not shell.closed:
                cleanup_successful = cleanup_failed_session(shell)
                if not cleanup_successful:
                    logger.warning("[PUSH] Could not verify clean return to aggregate switch")
        except:
            pass
        
        return False, False
        
    except ConfigurationError as e:
        logger.error(f"[ERROR] Configuration failed for {target_ip}: {e}")
        
        try:
            if not shell.closed:
                exit_device_session(shell)
        except:
            pass
        
        return False, False

def calculate_next_ip(base_ip, increment):
    """Calculate the next IP address by incrementing the last octet"""
    try:
        ip = ipaddress.IPv4Address(base_ip)
        next_ip = ip + increment
        return str(next_ip)
    except Exception as e:
        logger.error(f"Error calculating IP address: {e}")
        return None

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 vlan_100.py <devices_file> <target_vlan_100_subnet> <target_vlan_100_netmask>")
        print("")
        print("Example: python3 vlan_100.py devices.txt 10.2.242.1 255.255.255.0")
        print("")
        print("This will assign:")
        print("  - First device: 10.2.242.1")
        print("  - Second device: 10.2.242.2")
        print("  - Third device: 10.2.242.3")
        print("  - And so on...")
        sys.exit(1)
    
    devices_file = sys.argv[1]
    base_ip = sys.argv[2]
    netmask = sys.argv[3]
    
    logger.info("=" * 70)
    logger.info("VLAN 100 IP ADDRESS ASSIGNMENT SCRIPT")
    logger.info("=" * 70)
    
    # Validate IP address and netmask
    try:
        ipaddress.IPv4Address(base_ip)
        ipaddress.IPv4Address(netmask)
    except Exception as e:
        logger.error(f"Invalid IP address or netmask: {e}")
        sys.exit(1)
    
    # Load devices
    try:
        with open(devices_file, "r") as f:
            target_ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        
        logger.info(f"Loaded {len(target_ips)} devices")
        logger.info(f"Base IP: {base_ip}")
        logger.info(f"Netmask: {netmask}")
        logger.info(f"Log file: vlan_100_config.log")
        logger.info("")
        
    except FileNotFoundError as e:
        logger.error(f"Device file not found: {e}")
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
    for idx, target in enumerate(target_ips):
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"DEVICE {idx + 1}/{len(target_ips)}: {target}")
        logger.info("=" * 70)
        
        # Calculate IP for this device
        vlan_ip = calculate_next_ip(base_ip, idx)
        if not vlan_ip:
            logger.error(f"Failed to calculate IP address for device {idx + 1}")
            failed.append(target)
            continue
        
        logger.info(f"Assigned VLAN 100 IP: {vlan_ip} {netmask}")
        
        # Check if aggregation connection is still alive
        if shell.closed:
            logger.error("Connection to aggregation switch lost!")
            logger.info("Attempting to reconnect...")
            try:
                try:
                    client.close()
                except:
                    pass
                client, shell = connect_to_agg()
                logger.info("Successfully reconnected to aggregation switch")
            except NetworkConnectionError as e:
                logger.error(f"Failed to reconnect to aggregation switch: {e}")
                logger.error("Remaining devices will be skipped")
                failed.extend(target_ips[idx:])
                break
        
        device_start = time.time()
        success, reconnect_needed = configure_device_vlan(shell, target, vlan_ip, netmask)
        device_elapsed = time.time() - device_start
        
        if success:
            logger.info(f"[SUCCESS] VLAN 100 configured on {target} with IP {vlan_ip} in {device_elapsed:.1f}s")
            successful.append((target, vlan_ip))
        else:
            logger.error(f"[FAILED] Could not configure {target} after {device_elapsed:.1f}s")
            failed.append(target)
            
            if reconnect_needed:
                logger.info("Attempting to reconnect to aggregation switch...")
                try:
                    try:
                        client.close()
                    except:
                        pass
                    client, shell = connect_to_agg()
                    logger.info("Successfully reconnected - continuing with remaining devices")
                except NetworkConnectionError as e:
                    logger.error(f"Failed to reconnect to aggregation switch: {e}")
                    logger.error("Stopping configuration for remaining devices")
                    failed.extend(target_ips[idx + 1:])
                    break
        
        time.sleep(2)
    
    # Close connection
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
    logger.info("VLAN 100 CONFIGURATION SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Total time: {total_elapsed:.1f}s")
    logger.info(f"Total devices: {len(target_ips)}")
    logger.info(f"Successful: {len(successful)}")
    logger.info(f"Failed: {len(failed)}")
    logger.info(f"Success rate: {(len(successful)/len(target_ips)*100):.1f}%")
    
    if successful:
        logger.info(f"\nSuccessful configurations:")
        for device, ip in successful:
            logger.info(f"   - {device}: VLAN 100 IP {ip} {netmask}")
    
    if failed:
        logger.error(f"\nFailed devices:")
        for device in failed:
            logger.error(f"   - {device}")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("All VLAN 100 configuration tasks completed")
    logger.info("=" * 70)
    
    sys.exit(0 if not failed else 1)

if __name__ == "__main__":
    main()
