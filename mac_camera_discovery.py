#!/usr/bin/env python3
import paramiko
import time
import re
import json
import csv
import logging
from datetime import datetime

# --- USER CONFIG -------------------------------------------------------------
USERNAME = "admin"
PASSWORD = "cisco"
ROOT_IP = "192.168.100.11"
TIMEOUT = 10
MAX_READ = 65535
SSH_RETRY_ATTEMPTS = 2  # Number of times to retry SSH connection on failure
SSH_RETRY_DELAY = 5  # Seconds to wait between retry attempts

# List of aggregate switch IPs to start discovery from
AGGREGATE_IPS = [
    "10.21.128.3" , "10.21.128.4"
    # Add more aggregate switch IPs here
]
# -----------------------------------------------------------------------------

visited_switches = set()
camera_data = []

# Setup logging
log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()  # Also print to console
    ]
)
logger = logging.getLogger(__name__)


def expect_prompt(shell, patterns, timeout=TIMEOUT):
    """Wait for specific patterns in shell output"""
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
    """Send command and wait for response"""
    logger.debug(f"CMD: {cmd}")
    try:
        shell.send(cmd + "\n")
        time.sleep(0.3)  # Small delay for command to process
        out = expect_prompt(shell, patterns, timeout)
        return out
    except Exception as e:
        logger.error(f"Exception in send_cmd: {e}")
        return ""


def connect_switch(ip):
    """Connect to switch via SSH and enter privileged mode"""
    logger.info(f"Connecting to {ip}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=USERNAME, password=PASSWORD,
                       look_for_keys=False, allow_agent=False, timeout=15)
        shell = client.invoke_shell()
        expect_prompt(shell, ("#", ">"))
        send_cmd(shell, "enable", patterns=("assword:", "#"))
        send_cmd(shell, PASSWORD, patterns=("#",))
        send_cmd(shell, "terminal length 0", patterns=("#",))
        logger.info(f"Successfully connected to {ip}")
        return client, shell
    except Exception as e:
        logger.error(f"Failed to connect to {ip}: {e}")
        return None, None


def hop_to_neighbor(shell, ip, attempt=1):
    """SSH hop from current switch to neighbor with retry logic - returns True if successful, False otherwise"""
    logger.info(f"SSH hopping to {ip} (attempt {attempt}/{SSH_RETRY_ATTEMPTS})")
    try:
        out = send_cmd(shell, f"ssh -l {USERNAME} {ip}",
                       patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">", 
                                "Connection refused", "Connection timed out", "Unable to connect"),
                       timeout=60)
        
        # Check for immediate connection failures
        if "Connection refused" in out or "Unable to connect" in out or "% Connection" in out or "Connection timed out" in out:
            logger.error(f"SSH connection failed to {ip} - connection refused/timed out")
            # Send Ctrl+C to cancel the SSH attempt
            shell.send("\x03")
            time.sleep(1)
            shell.send("\n")
            time.sleep(0.5)
            # Clear any remaining output
            if shell.recv_ready():
                shell.recv(MAX_READ)
            
            # Retry if we haven't exhausted attempts
            if attempt < SSH_RETRY_ATTEMPTS:
                logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
                time.sleep(SSH_RETRY_DELAY)
                return hop_to_neighbor(shell, ip, attempt + 1)
            else:
                logger.error(f"SSH to {ip} failed after {SSH_RETRY_ATTEMPTS} attempts")
                return False
        
        # Handle SSH key acceptance
        if "(yes/no)?" in out or "yes/no" in out:
            out = send_cmd(shell, "yes", 
                          patterns=("assword:", "%", "#", ">"), 
                          timeout=30)
        
        # Handle password prompt
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, 
                          patterns=("%", "#", ">", "Permission denied", "Authentication failed"), 
                          timeout=30)
        
        # Check for authentication failures
        if "Permission denied" in out or "Authentication failed" in out or "% Authentication" in out:
            logger.error(f"SSH authentication failed to {ip}")
            # Try to get back to previous prompt
            shell.send("\x03")
            time.sleep(1)
            shell.send("exit\n")
            time.sleep(1)
            
            # Retry if we haven't exhausted attempts
            if attempt < SSH_RETRY_ATTEMPTS:
                logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
                time.sleep(SSH_RETRY_DELAY)
                return hop_to_neighbor(shell, ip, attempt + 1)
            else:
                logger.error(f"SSH authentication to {ip} failed after {SSH_RETRY_ATTEMPTS} attempts")
                return False
        
        # Check if we got a prompt (success)
        if "#" in out or ">" in out:
            # Enter enable mode if needed
            if out.strip().endswith(">"):
                send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=15)
                send_cmd(shell, PASSWORD, patterns=("#",), timeout=15)
            
            send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
            logger.info(f"Successfully hopped to {ip}")
            return True
        else:
            logger.error(f"Failed to get prompt from {ip}")
            # Try to recover
            shell.send("\x03")
            time.sleep(1)
            
            # Retry if we haven't exhausted attempts
            if attempt < SSH_RETRY_ATTEMPTS:
                logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
                time.sleep(SSH_RETRY_DELAY)
                return hop_to_neighbor(shell, ip, attempt + 1)
            else:
                logger.error(f"SSH to {ip} failed to get prompt after {SSH_RETRY_ATTEMPTS} attempts")
                return False
            
    except Exception as e:
        logger.error(f"Exception during SSH to {ip}: {e}")
        # Attempt to recover the shell
        try:
            shell.send("\x03")
            time.sleep(1)
            shell.send("exit\n")
            time.sleep(1)
            # Clear buffer
            if shell.recv_ready():
                shell.recv(MAX_READ)
        except:
            pass
        
        # Retry if we haven't exhausted attempts
        if attempt < SSH_RETRY_ATTEMPTS:
            logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
            time.sleep(SSH_RETRY_DELAY)
            return hop_to_neighbor(shell, ip, attempt + 1)
        else:
            logger.error(f"SSH to {ip} failed with exception after {SSH_RETRY_ATTEMPTS} attempts")
            return False


def exit_device(shell):
    """Exit from current SSH session"""
    try:
        send_cmd(shell, "exit", patterns=("#", ">", "closed", "Connection"), timeout=5)
        time.sleep(1)
        # Clear any remaining output
        if shell.recv_ready():
            shell.recv(MAX_READ)
    except Exception as e:
        logger.debug(f"Exception during exit: {e}")
        # Try to force exit with Ctrl+C
        try:
            shell.send("\x03")  # Ctrl+C
            time.sleep(0.5)
            shell.send("exit\n")
            time.sleep(0.5)
        except:
            pass


def get_hostname(shell):
    """Extract hostname from prompt"""
    shell.send("\n")
    buff = expect_prompt(shell, ("#", ">"), timeout=5)
    for line in reversed(buff.splitlines()):
        if m := re.match(r"^([^#>]+)[#>]", line.strip()):
            return m.group(1)
    return "unknown"


def is_edge_switch(hostname):
    """Check if switch is an edge switch (ACC or IE variants)"""
    if not hostname:
        return False
    upper = hostname.upper()
    
    # Must have SMS in the hostname first
    if "SMS" not in upper:
        return False
    
    sms_pos = upper.find("SMS")
    
    # Check for access switches (ACC after SMS)
    # Example: US-PHX-MSA1A-SMSACC1.9-1-127.CAM.INT
    acc_pos = upper.find("ACC", sms_pos)
    if acc_pos > sms_pos:
        return True
    
    # Check for Industrial Ethernet switches (IE after SMS)
    # Example: US-PHX-MSA1A-SMSIEPN-1A-04-1-56
    # Example: US-PHX-MSA1A-SMSIEMYD-1A-01-1-42
    ie_pos = upper.find("IE", sms_pos)
    if ie_pos > sms_pos:
        return True
    
    return False


def is_aggregate_switch(hostname):
    """Check if switch is an aggregate switch"""
    if not hostname:
        return False
    return "AGG" in hostname.upper()


def is_server_switch(hostname):
    """Check if switch is a server switch"""
    if not hostname:
        return False
    return "SRV" in hostname.upper()


def convert_mac_format(mac_cisco):
    """Convert MAC from xxxx.xxxx.xxxx to XX:XX:XX:XX:XX:XX"""
    # Remove dots and convert to uppercase
    mac_clean = mac_cisco.replace(".", "").upper()
    # Insert colons every 2 characters
    return ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])


def parse_lldp_detail(raw):
    """Parse LLDP neighbor detail output"""
    nbrs = []
    blocks = re.split(r"^-{2,}", raw, flags=re.M)
    
    for blk in blocks:
        if "Local Intf:" not in blk:
            continue
            
        entry = {
            "local_intf": None,
            "port_id": None,
            "remote_name": None,
            "mgmt_ip": None,
            "sys_descr": ""
        }
        
        if m := re.search(r"Local Intf:\s*(\S+)", blk):
            entry["local_intf"] = m.group(1)
        if m := re.search(r"Port id:\s*(\S+)", blk, re.IGNORECASE):
            entry["port_id"] = m.group(1)
        if m := re.search(r"System Name:\s*(\S+)", blk, re.IGNORECASE):
            entry["remote_name"] = m.group(1)
        if m := re.search(r"System Description:\s*([\s\S]+?)(?=\n\s*\n|Time remaining)", blk, re.IGNORECASE):
            entry["sys_descr"] = m.group(1).strip()
        if m := re.search(r"Management Addresses:[\s\S]*?IP:\s*(\d+\.\d+\.\d+\.\d+)", blk, re.IGNORECASE):
            entry["mgmt_ip"] = m.group(1)
            
        nbrs.append(entry)
    
    return nbrs


def get_interface_status(shell):
    """Get list of UP interfaces"""
    out = send_cmd(shell, "show ip interface brief", timeout=10)
    up_interfaces = []
    
    for line in out.splitlines():
        line = line.strip()
        if not line or "Interface" in line or line.startswith("Vlan"):
            continue
        
        parts = re.split(r"\s+", line)
        if len(parts) >= 5:
            intf, ip, ok, method, status = parts[0], parts[1], parts[2], parts[3], parts[4]
            protocol = parts[5] if len(parts) > 5 else ""
            # Check if interface is up
            if status.lower() == "up":
                # Only include physical interfaces (Gig, Ten, etc)
                if re.match(r"(Gig|Ten|FastEthernet|Ethernet)", intf, re.IGNORECASE):
                    up_interfaces.append(intf)
    
    return up_interfaces


def parse_mac_table_interface(raw):
    """Parse MAC address table for specific interface"""
    entries = []
    
    for line in raw.splitlines():
        line = line.strip()
        # Skip headers, separators, empty lines, and total lines
        if not line or "Mac Address Table" in line or line.startswith("---") or \
           line.lower().startswith("vlan") or line.startswith("Total") or \
           "Mac Address" in line or "----" in line:
            continue
        
        # Parse: Vlan    Mac Address       Type        Ports
        # Example: " 800    b8a4.4faa.e158    DYNAMIC pv  Gi1/3"
        # Note: Type can be "DYNAMIC pv" or "DYNAMIC" or "STATIC" etc.
        
        parts = re.split(r"\s+", line)
        if len(parts) >= 4:
            vlan = parts[0]
            mac = parts[1]
            
            # The type field might be multiple words (e.g., "DYNAMIC pv")
            # So we need to find where the port starts
            # Port usually starts with known prefixes: Gi, Te, Fa, Et, Po, etc.
            port = None
            mac_type_parts = []
            
            for i in range(2, len(parts)):
                # Check if this looks like a port
                if re.match(r'^(Gi|Te|Fa|Et|Po|Vl)', parts[i], re.IGNORECASE):
                    port = parts[i]
                    break
                else:
                    mac_type_parts.append(parts[i])
            
            mac_type = " ".join(mac_type_parts)
            
            # Only include DYNAMIC entries (actual learned MACs)
            if port and "DYNAMIC" in mac_type.upper():
                entries.append({
                    "vlan": vlan,
                    "mac_address": mac,
                    "type": mac_type,
                    "port": port
                })
    
    return entries


def map_ie_port(port_id):
    """Map IE switch port-00X to GigX/X format"""
    # port-001 -> Gi1/1, port-002 -> Gi1/2, etc.
    if m := re.match(r"port-(\d+)", port_id, re.IGNORECASE):
        port_num = int(m.group(1))
        return f"Gi1/{port_num}"
    return None


def normalize_interface_name(intf):
    """Normalize interface name for comparison (handles abbreviated forms)"""
    if not intf:
        return ""
    
    # Handle common abbreviations
    normalized = intf
    normalized = re.sub(r'^Gi(\d)', r'GigabitEthernet\1', normalized)
    normalized = re.sub(r'^Te(\d)', r'TenGigabitEthernet\1', normalized)
    normalized = re.sub(r'^Fa(\d)', r'FastEthernet\1', normalized)
    
    # Also create a short version for matching
    return normalized.lower()


def is_same_interface(intf1, intf2):
    """Check if two interface names refer to the same interface"""
    if not intf1 or not intf2:
        return False
    
    # Normalize both
    norm1 = normalize_interface_name(intf1)
    norm2 = normalize_interface_name(intf2)
    
    # Direct match
    if norm1 == norm2:
        return True
    
    # Extract the interface type and numbers for comparison
    # e.g., "gigabitethernet1/1" should match "gi1/1"
    pattern = r'(gigabitethernet|tengigabitethernet|fastethernet|ethernet)(\d+/\d+|\d+)'
    
    match1 = re.search(pattern, norm1)
    match2 = re.search(pattern, norm2)
    
    if match1 and match2:
        type1, num1 = match1.groups()
        type2, num2 = match2.groups()
        
        # Map types
        type_map = {
            'gigabitethernet': 'gi',
            'tengigabitethernet': 'te',
            'fastethernet': 'fa',
            'ethernet': 'eth'
        }
        
        short_type1 = type_map.get(type1, type1)
        short_type2 = type_map.get(type2, type2)
        
        # Compare type and number
        return short_type1 == short_type2 and num1 == num2
    
    return False


def get_uplink_ports_from_lldp(shell):
    """Get all uplink ports by checking LLDP neighbors on edge switch"""
    logger.info("Running 'show lldp neighbors detail' to detect uplinks")
    
    lldp_raw = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=20)
    
    logger.debug(f"LLDP output length: {len(lldp_raw)} chars")
    
    neighbors = parse_lldp_detail(lldp_raw)
    logger.info(f"Found {len(neighbors)} LLDP neighbors")
    
    uplink_ports = []
    for nbr in neighbors:
        remote_name = nbr.get("remote_name", "")
        local_intf = nbr.get("local_intf", "")
        port_id = nbr.get("port_id", "")
        
        logger.debug(f"Neighbor: {remote_name}, Local Intf: {local_intf}, Port ID: {port_id}")
        
        # If neighbor is an aggregate or server switch, this is an uplink
        if remote_name and (is_aggregate_switch(remote_name) or is_server_switch(remote_name)):
            uplink_port = local_intf
            
            # If local_intf is empty but we have port_id, this might be an IE switch
            if not uplink_port and port_id:
                logger.debug(f"No local_intf, attempting to map port_id: {port_id}")
                mapped_port = map_ie_port(port_id)
                if mapped_port:
                    uplink_port = mapped_port
                    logger.debug(f"Mapped {port_id} → {uplink_port}")
            
            if uplink_port:
                uplink_ports.append(uplink_port)
                logger.info(f"UPLINK DETECTED: {uplink_port} → {remote_name}")
            else:
                logger.warning(f"Could not determine uplink port for neighbor {remote_name}")
        else:
            logger.debug(f"Skipping neighbor {remote_name} (not AGG/SRV)")
    
    logger.info(f"Total uplinks identified: {len(uplink_ports)}")
    return uplink_ports


def discover_cameras_from_edge(shell, edge_hostname):
    """Collect camera MAC addresses from edge switch"""
    logger.info("="*80)
    logger.info(f"Scanning edge switch: {edge_hostname}")
    logger.info("="*80)
    
    # Clear dynamic MAC address table to get fresh data
    logger.info("Clearing dynamic MAC address table...")
    send_cmd(shell, "clear mac address-table dynamic", patterns=("#",), timeout=10)
    logger.info("Waiting 5 seconds for MAC table to repopulate...")
    time.sleep(5)
    logger.info("MAC table refresh complete")
    
    # First, identify ALL uplink ports by checking LLDP neighbors
    uplink_ports = get_uplink_ports_from_lldp(shell)
    
    if not uplink_ports:
        logger.warning(f"No uplink ports detected via LLDP on {edge_hostname}")
        logger.warning("This means ALL ports will be scanned - this may be incorrect!")
    else:
        logger.info(f"Uplink ports to exclude: {uplink_ports}")
    
    # Get all UP interfaces
    up_interfaces = get_interface_status(shell)
    logger.info(f"Found {len(up_interfaces)} UP interfaces total")
    
    camera_count = 0
    scanned_count = 0
    
    for intf in up_interfaces:
        # Check if this interface is an uplink using improved matching
        is_uplink = False
        for uplink in uplink_ports:
            if is_same_interface(intf, uplink):
                is_uplink = True
                logger.info(f"SKIP: {intf} - UPLINK PORT (matches {uplink})")
                break
        
        if is_uplink:
            continue
        
        scanned_count += 1
        
        # Get MAC table for this interface on VLAN 800
        cmd = f"show mac address-table interface {intf} vlan 800"
        mac_out = send_cmd(shell, cmd, timeout=10)
        entries = parse_mac_table_interface(mac_out)
        
        if entries:
            logger.info(f"FOUND: {len(entries)} MAC(s) on {intf}")
            for entry in entries:
                mac_formatted = convert_mac_format(entry["mac_address"])
                camera_info = {
                    "switch_name": edge_hostname,
                    "port": entry["port"],
                    "mac_address": mac_formatted,
                    "vlan": entry["vlan"]
                }
                camera_data.append(camera_info)
                camera_count += 1
                logger.info(f"  Camera: {mac_formatted} on port {entry['port']}")
        else:
            logger.debug(f"No MAC entries in VLAN 800 on {intf}")
    
    logger.info("")
    logger.info(f"Summary for {edge_hostname}:")
    logger.info(f"  - Total UP interfaces: {len(up_interfaces)}")
    logger.info(f"  - Uplink ports excluded: {len(uplink_ports)}")
    logger.info(f"  - Ports scanned: {scanned_count}")
    logger.info(f"  - Cameras found: {camera_count}")
    logger.info("="*80)


def process_edge_switch(shell, agg_ip, neighbor_info):
    """Process an edge switch connected to aggregate"""
    edge_ip = neighbor_info["mgmt_ip"]
    edge_name = neighbor_info["remote_name"]
    local_intf = neighbor_info["local_intf"]
    
    if not edge_ip or edge_ip in visited_switches:
        return
    
    logger.info("")
    logger.info("*"*80)
    logger.info(f"Processing EDGE SWITCH: {edge_name} ({edge_ip})")
    logger.info(f"Connected via aggregate port: {local_intf}")
    logger.info("*"*80)
    
    visited_switches.add(edge_ip)
    
    # Hop to edge switch with retry logic
    ssh_success = hop_to_neighbor(shell, edge_ip)
    
    if not ssh_success:
        logger.error(f"Cannot SSH to {edge_name} ({edge_ip}) - SKIPPING after all retry attempts")
        logger.info("Verifying connection to aggregate switch...")
        
        # Verify we're back at the aggregate prompt
        try:
            shell.send("\n")
            time.sleep(1)
            if shell.recv_ready():
                buff = shell.recv(MAX_READ).decode("utf-8", "ignore")
                logger.debug(f"Current prompt after failed SSH: {buff[-100:]}")
        except Exception as e:
            logger.error(f"Shell verification exception: {e}")
        
        return
    
    # Successfully connected - proceed with discovery
    try:
        # Discover cameras - uplinks will be auto-detected from LLDP
        discover_cameras_from_edge(shell, edge_name)
        
    except Exception as e:
        logger.error(f"Error during camera discovery on {edge_name}: {e}", exc_info=True)
    finally:
        # Always try to exit back to aggregate
        try:
            exit_device(shell)
            time.sleep(1)
            logger.info("Returned to aggregate switch")
        except Exception as e:
            logger.error(f"Error exiting from {edge_name}: {e}")


def scan_aggregate_switch(shell, agg_ip):
    """Scan aggregate switch for connected edge switches"""
    if agg_ip in visited_switches:
        logger.info(f"Aggregate {agg_ip} already visited, skipping")
        return
    
    visited_switches.add(agg_ip)
    hostname = get_hostname(shell)
    
    logger.info("")
    logger.info("#"*80)
    logger.info(f"Scanning AGGREGATE: {hostname} ({agg_ip})")
    logger.info("#"*80)
    
    # Get LLDP neighbors
    lldp_raw = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=20)
    neighbors = parse_lldp_detail(lldp_raw)
    
    logger.info(f"Found {len(neighbors)} LLDP neighbors on aggregate")
    
    edge_count = 0
    for nbr in neighbors:
        remote_name = nbr.get("remote_name", "")
        
        # Skip if no name or IP
        if not remote_name or not nbr.get("mgmt_ip"):
            continue
        
        # Filter: only process edge switches (ACC or IE)
        if is_edge_switch(remote_name):
            edge_count += 1
            logger.info(f"Edge switch detected: {remote_name} - {nbr.get('mgmt_ip')}")
            process_edge_switch(shell, agg_ip, nbr)
        elif is_aggregate_switch(remote_name):
            logger.debug(f"Skipping aggregate switch: {remote_name}")
        elif is_server_switch(remote_name):
            logger.debug(f"Skipping server switch: {remote_name}")
        else:
            logger.debug(f"Skipping other device: {remote_name}")
    
    logger.info(f"Processed {edge_count} edge switches from {hostname}")


def main():
    """Main execution function"""
    logger.info("="*80)
    logger.info("CAMERA DISCOVERY SCRIPT STARTED")
    logger.info(f"Log file: {log_filename}")
    logger.info("="*80)
    
    # Connect to root switch (this is our only direct connection)
    client, shell = connect_switch(ROOT_IP)
    if not client:
        logger.error("Failed to connect to root switch. Exiting.")
        return
    
    try:
        # All work must be done from the root switch shell by SSH hopping
        # Process each aggregate switch by hopping from root
        for agg_ip in AGGREGATE_IPS:
            logger.info("")
            logger.info("*"*80)
            logger.info(f"PROCESSING AGGREGATE: {agg_ip}")
            logger.info("*"*80)
            
            # Always hop to aggregate from root
            hop_success = hop_to_neighbor(shell, agg_ip)
            
            if not hop_success:
                logger.error(f"Failed to connect to aggregate {agg_ip} - skipping")
                continue
            
            scan_aggregate_switch(shell, agg_ip)
            
            # Return to root switch
            exit_device(shell)
            time.sleep(1)
            logger.info("Returned to root switch")
        
    except Exception as e:
        logger.error(f"Fatal error during discovery: {e}", exc_info=True)
    finally:
        client.close()
        logger.info("Closed connection to root switch")
    
    # Output results
    logger.info("")
    logger.info("="*80)
    logger.info(f"DISCOVERY COMPLETE - Found {len(camera_data)} cameras")
    logger.info("="*80)
    
    # Save to JSON
    json_file = "camera_inventory.json"
    with open(json_file, "w") as f:
        json.dump(camera_data, f, indent=2)
    logger.info(f"Saved: {json_file}")
    
    # Save to CSV
    if camera_data:
        csv_file = "camera_inventory.csv"
        with open(csv_file, "w", newline="") as f:
            fieldnames = ["switch_name", "port", "mac_address", "vlan"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(camera_data)
        logger.info(f"Saved: {csv_file}")
    
    # Print summary
    logger.info("")
    logger.info("-"*80)
    logger.info("CAMERA INVENTORY SUMMARY")
    logger.info("-"*80)
    for camera in camera_data:
        logger.info(f"{camera['switch_name']:<50} {camera['port']:<15} {camera['mac_address']}")
    
    logger.info("")
    logger.info(f"Total cameras discovered: {len(camera_data)}")
    logger.info(f"Log file saved: {log_filename}")


if __name__ == "__main__":
    main()
