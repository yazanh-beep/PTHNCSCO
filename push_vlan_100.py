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

        # Configure a reasonable SSH timeout on the aggregation switch (10 minutes)
        # This prevents the aggregation switch from disconnecting us during long operations
        logger.info("[CONNECT] Configuring SSH timeout on aggregation switch...")
        send_cmd(shell, "configure terminal", patterns=("(config)#",))
        send_cmd(shell, "ip ssh time-out 10", patterns=("(config)#",))  # 10 minutes
        send_cmd(shell, "end", patterns=("#",))
        logger.info("[CONNECT] SSH timeout set to 10 minutes")
        
        logger.info("[CONNECT] Successfully connected to aggregation switch")
        return client, shell

@@ -227,7 +235,7 @@
        sys.stdout.flush()

        if shell.closed:
            raise NetworkConnectionError("SSH shell to aggregation switch is closed")
            raise NetworkConnectionError("SSH shell to aggregation switch is closed", reconnect_needed=True)

        logger.info(f"[HOP] Initiating SSH connection (timeout: {TARGET_SSH_TIMEOUT}s)...")
        out = send_cmd(
@@ -244,7 +252,7 @@
            raise NetworkConnectionError(f"SSH connection refused by {target_ip} - skipping device")

        if "Connection timed out" in out or "Destination" in out:
            raise NetworkConnectionError(f"SSH connection timed out to {target_ip} - device unreachable, skipping")
            raise NetworkConnectionError(f"SSH connection timed out to {target_ip}", retry_allowed=True)

        if "No route to host" in out or "Host is unreachable" in out:
            raise NetworkConnectionError(f"Network unreachable to {target_ip} - skipping device")
@@ -401,7 +409,7 @@
    except Exception as e:
        logger.warning(f"[EXIT] Error during exit: {e}")

def configure_device_vlan(shell, target_ip, vlan_ip, netmask):
def configure_device_vlan(shell, client, target_ip, vlan_ip, netmask):
    """Configure VLAN 100 on a target device"""
    try:
        if shell.closed:
@@ -421,8 +429,66 @@
        except OSError:
            raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)

        # Establish session to target device
        establish_device_session(shell, target_ip)
        # Establish session to target device with retry support
        max_retries = TARGET_MAX_RETRIES
        for attempt in range(max_retries):
            try:
                establish_device_session(shell, target_ip, retry_count=attempt)
                break  # Success!
            except NetworkConnectionError as e:
                # Check if we need to reconnect to aggregation switch
                if getattr(e, 'reconnect_needed', False) or shell.closed:
                    logger.warning("[RETRY] Aggregation switch connection lost, need to reconnect")
                    raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                
                retry_allowed = getattr(e, 'retry_allowed', False)
                is_last_attempt = (attempt >= max_retries - 1)
                
                if retry_allowed and not is_last_attempt:
                    logger.info(f"[RETRY] Waiting {TARGET_RETRY_DELAY} seconds before retry...")
                    sys.stdout.flush()
                    
                    # Keep aggregation switch alive during retry delay by sending keepalives
                    delay_remaining = TARGET_RETRY_DELAY
                    keepalive_interval = 10  # Send keepalive every 10 seconds
                    
                    while delay_remaining > 0:
                        sleep_time = min(keepalive_interval, delay_remaining)
                        time.sleep(sleep_time)
                        delay_remaining -= sleep_time
                        
                        # Send keepalive to aggregation switch
                        if delay_remaining > 0 and not shell.closed:
                            try:
                                shell.send("\n")  # Send empty line as keepalive
                                time.sleep(0.2)
                                if shell.recv_ready():
                                    shell.recv(MAX_READ)  # Clear any response
                            except:
                                logger.warning("[RETRY] Failed to send keepalive to aggregation switch")
                                break
                    
                    # Verify aggregation switch is still connected after retry delay
                    if shell.closed:
                        logger.warning("[RETRY] Aggregation switch disconnected during retry delay")
                        raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                    
                    # Verify we're still at aggregate prompt
                    try:
                        out = send_cmd(shell, "", patterns=("#",), timeout=3)
                        if "#" not in out:
                            logger.warning("[RETRY] Lost aggregation switch prompt during retry")
                            raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                    except (OSError, Exception):
                        logger.warning("[RETRY] Cannot verify aggregation switch connection")
                        raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                    
                    continue  # Try again
                else:
                    # Either retry not allowed or last attempt failed
                    if not retry_allowed:
                        logger.info(f"[SKIP] Device {target_ip} is unreachable - moving to next device")
                    raise NetworkConnectionError(f"Failed to connect to {target_ip} after {attempt + 1} attempt(s)")

        # Apply VLAN configuration
        apply_vlan_config(shell, vlan_ip, netmask)
@@ -563,69 +629,111 @@
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
        # Retry loop for device configuration with aggregation switch reconnection support
        device_success = False
        device_reconnect_needed = False
        
        for device_attempt in range(TARGET_MAX_RETRIES):
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
                    logger.error("Cannot continue - stopping")
                    failed.extend(target_ips[idx:])
                    device_success = False
                    device_reconnect_needed = False
                    break
            
            success, reconnect_needed = configure_device_vlan(shell, client, target, vlan_ip, netmask)
            
            if success:
                device_success = True
                device_reconnect_needed = False
                break  # Device configured successfully

            if reconnect_needed:
                logger.info("Attempting to reconnect to aggregation switch...")
                # Aggregation switch connection lost - reconnect and retry this device
                logger.info("Connection to aggregation switch lost during device configuration")
                logger.info(f"Attempting to reconnect... (Device attempt {device_attempt + 1}/{TARGET_MAX_RETRIES})")
                try:
                    try:
                        client.close()
                    except:
                        pass
                    client, shell = connect_to_agg()
                    logger.info("Successfully reconnected - continuing with remaining devices")
                    logger.info(f"Successfully reconnected - will retry device {target}")
                    # Loop will continue to next attempt for this device
                except NetworkConnectionError as e:
                    logger.error(f"Failed to reconnect to aggregation switch: {e}")
                    logger.error("Stopping configuration for remaining devices")
                    failed.extend(target_ips[idx + 1:])
                    logger.error("Cannot continue - stopping")
                    failed.extend(target_ips[idx:])
                    device_success = False
                    device_reconnect_needed = False
                    break
            else:
                # Device configuration failed but aggregation switch is OK
                # The configure_device_vlan function already handles retries internally
                device_success = False
                device_reconnect_needed = False
                break  # Don't retry at this level
        
        device_elapsed = time.time() - device_start
        
        if device_success:
            logger.info(f"[SUCCESS] VLAN 100 configured on {target} with IP {vlan_ip} in {device_elapsed:.1f}s")
            successful.append((target, vlan_ip))
        else:
            logger.error(f"[FAILED] Could not configure {target} after {device_elapsed:.1f}s")
            failed.append(target)

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
