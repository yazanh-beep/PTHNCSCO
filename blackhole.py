#!/usr/bin/env python3

import paramiko
import time
import sys
import re
from datetime import datetime

# USER CONFIG
AGG_IP = ""
USERNAME = ""
PASSWORD = ""
TIMEOUT = 20
MAX_READ = 65535
MAX_RETRIES = 3
RETRY_DELAY = 5

# Generate log filename with timestamp
LOG_FILE = f"blackhole_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
log_file_handle = None

def log_print(message):
    """Print to console and write to log file."""
    print(message)
    if log_file_handle:
        log_file_handle.write(message + "\n")
        log_file_handle.flush()

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
    """Wait for expected prompt patterns with timeout."""
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

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    """Send command and wait for response."""
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def connect_to_agg(retries=MAX_RETRIES):
    """Connect to aggregation switch with retry logic."""
    for attempt in range(1, retries + 1):
        try:
            log_print(f"[CONNECT] Attempt {attempt}/{retries}: SSH to aggregation switch: {AGG_IP}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                           look_for_keys=False, allow_agent=False, timeout=TIMEOUT)
            shell = client.invoke_shell()
            expect_prompt(shell, ("#", ">"))
            send_cmd(shell, "enable", patterns=("assword:", "#"))
            send_cmd(shell, PASSWORD, patterns=("#",))
            send_cmd(shell, "terminal length 0", patterns=("#",))
            log_print(f"[SUCCESS] Connected to aggregation switch")
            return client, shell
        except Exception as e:
            log_print(f"[ERROR] Attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                log_print(f"[RETRY] Waiting {RETRY_DELAY} seconds before retry...")
                time.sleep(RETRY_DELAY)
            else:
                log_print(f"[FAILED] Could not connect to aggregation switch after {retries} attempts")
                raise

def read_file_lines(filename):
    """Reads lines from a text file, stripping whitespace."""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        log_print(f"Error: The file '{filename}' was not found.")
        return []

def connect_to_target(shell, target_ip, retries=MAX_RETRIES):
    """Connect to target switch via aggregation switch with retry logic."""
    for attempt in range(1, retries + 1):
        try:
            log_print(f"[HOP] Attempt {attempt}/{retries}: SSH to {target_ip}")
            out = send_cmd(shell, f"ssh -l {USERNAME} {target_ip}",
                           patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">"),
                           timeout=TIMEOUT)

            if "(yes/no)?" in out or "yes/no" in out:
                out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=TIMEOUT)
            
            if "assword:" in out:
                out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">"), timeout=TIMEOUT)
            
            if out.strip().endswith(">"):
                send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=TIMEOUT)
                send_cmd(shell, PASSWORD, patterns=("#",), timeout=TIMEOUT)
            
            send_cmd(shell, "terminal length 0", patterns=("#",), timeout=TIMEOUT)
            log_print(f"[CONNECTED] Successfully connected to {target_ip}#")
            return True
        except Exception as e:
            log_print(f"[ERROR] Attempt {attempt}/{retries} to connect to {target_ip} failed: {e}")
            if attempt < retries:
                log_print(f"[RETRY] Waiting {RETRY_DELAY} seconds before retry...")
                try:
                    send_cmd(shell, "\x03", patterns=("#", ">"), timeout=5)
                    send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
                except:
                    pass
                time.sleep(RETRY_DELAY)
            else:
                log_print(f"[FAILED] Could not connect to {target_ip} after {retries} attempts")
                return False
    return False

def configure_down_ports(shell, target_ip):
    """Find 'down' physical ports only (not 'disabled', 'connected', or 'up') and apply configuration."""
    
    if not connect_to_target(shell, target_ip):
        return False

    log_print("[INFO] Gathering interface data...")
    interface_output = send_cmd(shell, 'show interfaces status', patterns=("#",), timeout=TIMEOUT)
    
    # Log the raw interface output
    log_print("\n[RAW OUTPUT] show interfaces status:")
    log_print("=" * 80)
    log_print(interface_output)
    log_print("=" * 80 + "\n")

    # Look ONLY for physical interfaces with status notconnect
    pattern = r'^((Gi|Te|Fa)\d+(/\d+){1,2})\s+(\S*)\s+(notconnect|disabled|connected)\s+.*$'
    down_ports = re.findall(pattern, interface_output, re.MULTILINE)

    # Filter to ONLY get notconnect ports (not disabled, not connected/up, and no description)
    physical_ports = []
    skipped_with_description = []
    
    for port in down_ports:
        port_name = port[0]
        description = port[3]
        status = port[4]
        
        port_line = re.search(rf'^{re.escape(port_name)}\s+.*$', interface_output, re.MULTILINE)
        
        if port_line:
            line_text = port_line.group().lower()
            
            # ONLY include ports that are physically down (notconnect) and not disabled or connected
            if status == 'notconnect' and 'disabled' not in line_text and 'connected' not in line_text:
                # Check if description field is empty or contains only dashes/whitespace
                if description and description != '' and description != '--' and not description.isspace():
                    skipped_with_description.append((port_name, description))
                else:
                    physical_ports.append(port_name)

    # Report skipped interfaces with descriptions
    if skipped_with_description:
        log_print(f"[INFO] Skipped {len(skipped_with_description)} interface(s) with descriptions:")
        for port_name, desc in skipped_with_description:
            log_print(f"  - {port_name}: {desc}")

    if not physical_ports:
        log_print("[INFO] No physical down ports found (excluding up, connected, administratively down, and ports with descriptions).")
        send_cmd(shell, "exit", patterns=("#", ">"), timeout=TIMEOUT)
        log_print(f"[EXITED] Returned to aggregation switch")
        return True

    log_print(f"[INFO] Found {len(physical_ports)} physical down ports to configure:")
    for port in physical_ports:
        log_print(f"  - {port}")
    
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=TIMEOUT)

    for port_name in physical_ports:
        log_print(f"[CONFIG] Configuring physical port: {port_name}")
        send_cmd(shell, f"interface {port_name}", patterns=("(config-if)#",), timeout=TIMEOUT)
        
        send_cmd(shell, "shutdown", patterns=("(config-if)#",), timeout=TIMEOUT)
        send_cmd(shell, "switchport", patterns=("(config-if)#",), timeout=TIMEOUT)
        send_cmd(shell, "switchport mode access", patterns=("(config-if)#",), timeout=TIMEOUT)
        send_cmd(shell, "switchport access vlan 999", patterns=("(config-if)#",), timeout=TIMEOUT)
        
        send_cmd(shell, "exit", patterns=("(config)#",), timeout=TIMEOUT)
        log_print(f"  ✓ Configured: shutdown, switchport, mode access, vlan 999")

    log_print("[CONFIG] Saving configuration with 'do write'")
    save_output = send_cmd(shell, "do write", patterns=("(config)#", "#"), timeout=30)
    log_print(f"[CONFIG OUTPUT] {save_output.strip()}")

    send_cmd(shell, "end", patterns=("#",), timeout=TIMEOUT)
    send_cmd(shell, "exit", patterns=("#", ">"), timeout=TIMEOUT)
    log_print(f"[EXITED] Returned to aggregation switch")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 blackhole_ports.py <devices_file>")
        print("\nExample:")
        print("  python3 blackhole_ports.py devices.txt")
        print("\nConfiguration applied to down ports:")
        print("  - shutdown")
        print("  - switchport")
        print("  - switchport mode access")
        print("  - switchport access vlan 999")
        sys.exit(1)

    devices_file = sys.argv[1]
    
    # Open log file
    log_file_handle = open(LOG_FILE, 'w')
    log_print(f"{'='*80}")
    log_print(f"BLACKHOLE PORT CONFIGURATION LOG")
    log_print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_print(f"Log File: {LOG_FILE}")
    log_print(f"{'='*80}\n")
    
    target_ips = read_file_lines(devices_file)

    if not target_ips:
        log_print("Script terminated. Please ensure the devices file is present and not empty.")
        log_file_handle.close()
        sys.exit(1)

    log_print(f"[INFO] Loaded {len(target_ips)} target devices")
    log_print(f"[INFO] Configuration: shutdown, switchport, switchport mode access, switchport access vlan 999")
    log_print(f"[INFO] SSH Retries: {MAX_RETRIES}, Timeout: {TIMEOUT}s\n")

    try:
        client, shell = connect_to_agg()
    except Exception as e:
        log_print(f"[FATAL] Could not connect to aggregation switch: {e}")
        log_file_handle.close()
        sys.exit(1)

    success_count = 0
    fail_count = 0
    device_results = []

    for target in target_ips:
        try:
            log_print(f"\n{'='*60}")
            log_print(f"Processing {target}")
            log_print('='*60)
            if configure_down_ports(shell, target):
                log_print(f"[SUCCESS] Completed processing {target}")
                success_count += 1
                device_results.append((target, "SUCCESS"))
            else:
                log_print(f"[FAILED] Could not process {target}")
                fail_count += 1
                device_results.append((target, "FAILED"))
        except Exception as e:
            log_print(f"[ERROR] Exception while processing {target}: {e}")
            fail_count += 1
            device_results.append((target, f"ERROR: {e}"))
            try:
                send_cmd(shell, "\x03", patterns=("#", ">"), timeout=5)
                send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
            except:
                pass
    
    client.close()

    log_print(f"\n{'='*80}")
    log_print("FINAL SUMMARY")
    log_print('='*80)
    log_print(f"Total devices: {len(target_ips)}")
    log_print(f"Successful: {success_count}")
    log_print(f"Failed: {fail_count}")
    log_print(f"\nDevice Results:")
    for device, result in device_results:
        log_print(f"  {device}: {result}")
    log_print(f"\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_print(f"Log saved to: {LOG_FILE}")
    log_print('='*80)
    
    log_file_handle.close()
    print(f"\n✓ Log file saved: {LOG_FILE}")
