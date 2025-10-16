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
PASSWORD = "flounder"
SEED_SWITCH_IP = "192.168.20.19"  # Starting aggregate switch IP
TIMEOUT = 150
MAX_READ = 65535
SSH_RETRY_ATTEMPTS = 10
SSH_RETRY_DELAY = 30

# Retry configuration for aggregation switch connection
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
# -----------------------------------------------------------------------------

visited_switches = set()
discovered_aggregates = set()
aggregate_hostnames = {}  # Map IP to hostname for better reporting
camera_data = []

# Setup logging
log_filename = f"camera_discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetworkConnectionError(Exception):
    """Custom exception for network connection issues"""
    def __init__(self, message, retry_allowed=False, reconnect_needed=False):
        super().__init__(message)
        self.retry_allowed = retry_allowed
        self.reconnect_needed = reconnect_needed

class ConfigurationError(Exception):
    """Custom exception for configuration issues"""
    pass

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
        time.sleep(0.3)
        out = expect_prompt(shell, patterns, timeout)
        return out
    except Exception as e:
        logger.error(f"Exception in send_cmd: {e}")
        raise NetworkConnectionError(f"Send command failed: {e}", reconnect_needed=True)

def connect_to_seed(retry_count=0):
    """Connect to seed/aggregation switch with retry logic"""
    try:
        logger.info(f"[CONNECT] Attempt {retry_count + 1}/{AGG_MAX_RETRIES} - SSH to seed switch: {SEED_SWITCH_IP}")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            SEED_SWITCH_IP, 
            username=USERNAME, 
            password=PASSWORD,
            look_for_keys=False, 
            allow_agent=False, 
            timeout=15
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
        
        # Configure SSH timeout on the aggregation switch (10 minutes)
        logger.info("[CONNECT] Configuring SSH timeout on aggregation switch...")
        send_cmd(shell, "configure terminal", patterns=("(config)#",))
        send_cmd(shell, "ip ssh time-out 10", patterns=("(config)#",))
        send_cmd(shell, "end", patterns=("#",))
        logger.info("[CONNECT] SSH timeout set to 10 minutes")
        
        logger.info("[CONNECT] Successfully connected to seed switch")
        return client, shell
        
    except (paramiko.SSHException, paramiko.AuthenticationException, TimeoutError, OSError) as e:
        logger.error(f"[CONNECT] Connection failed: {e}")
        if retry_count < AGG_MAX_RETRIES - 1:
            logger.info(f"[RETRY] Waiting {AGG_RETRY_DELAY} seconds before retry...")
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_seed(retry_count + 1)
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

def verify_aggregate_connection(shell):
    """Verify we're still connected to the aggregate switch"""
    try:
        if shell.closed:
            return False
        
        shell.send("\n")
        time.sleep(0.3)
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            if "#" in data:
                return True
        return False
    except (OSError, Exception):
        return False

def hop_to_neighbor(shell, ip, attempt=1):
    """SSH hop from current switch to neighbor with retry logic"""
    logger.info(f"SSH hopping to {ip} (attempt {attempt}/{SSH_RETRY_ATTEMPTS})")
    
    # Verify aggregate connection before attempting hop
    if shell.closed:
        raise NetworkConnectionError(f"SSH shell to aggregation switch is closed", reconnect_needed=True)
    
    try:
        out = send_cmd(
            shell,
            f"ssh -l {USERNAME} {ip}",
            patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">", 
                      "Connection refused", "Connection timed out", "Unable to connect"),
            timeout=60
        )
        
        # Hard failures - network unreachable or connection refused
        if ("Connection refused" in out or "Unable to connect" in out or
            "No route to host" in out or "Host is unreachable" in out):
            logger.error(f"SSH connection failed to {ip} - network unreachable")
            cleanup_failed_session(shell)
            raise NetworkConnectionError(f"Network unreachable to {ip}", retry_allowed=False)
        
        # Timeout - can retry
        if "Connection timed out" in out or "% Connection" in out or "Destination" in out:
            logger.error(f"SSH connection timed out to {ip}")
            cleanup_failed_session(shell)
            raise NetworkConnectionError(f"SSH connection timed out to {ip}", retry_allowed=True)
        
        # New host key prompt
        if "(yes/no)?" in out or "yes/no" in out:
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=30)

        # Password prompt
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">", "Permission denied", "Authentication failed"), timeout=30)

        # Auth failures
        if ("Permission denied" in out or "Authentication failed" in out or 
            "% Authentication" in out or "% Bad passwords" in out or "% Login invalid" in out):
            logger.error(f"SSH authentication failed to {ip}")
            cleanup_failed_session(shell)
            raise NetworkConnectionError(f"Authentication failed for {ip}", retry_allowed=True)

        # Got a prompt
        if "#" in out or ">" in out:
            lines = out.strip().split('\n')
            last_line = lines[-1] if lines else ""
            
            if not (last_line.endswith("#") or last_line.endswith(">")):
                raise NetworkConnectionError(f"No valid prompt received from {ip}", retry_allowed=True)
            
            if out.strip().endswith(">") or (out.count(">") > out.count("#")):
                logger.debug("[HOP] Entering enable mode")
                out = send_cmd(shell, "enable", patterns=("assword:", "#", "%"), timeout=10)
                
                if "assword:" in out:
                    out = send_cmd(shell, PASSWORD, patterns=("#", "%"), timeout=10)
                    
                if "#" not in out:
                    raise NetworkConnectionError(f"Failed to enter enable mode on {ip}", retry_allowed=True)
            
            send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
            
            # Verify connection is stable
            out = send_cmd(shell, "", patterns=("#",), timeout=3)
            if "#" not in out:
                raise NetworkConnectionError(f"Device session unstable on {ip}", retry_allowed=True)
            
            logger.info(f"Successfully hopped to {ip}")
            return True

        # Unknown state
        logger.error(f"Failed to get prompt from {ip}")
        cleanup_failed_session(shell)
        raise NetworkConnectionError(f"No valid prompt from {ip}", retry_allowed=True)

    except NetworkConnectionError as e:
        # Check if aggregate connection was lost
        if not verify_aggregate_connection(shell):
            logger.warning("[HOP] Lost connection to aggregate switch during hop attempt")
            raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
        
        retry_allowed = getattr(e, 'retry_allowed', False)
        
        if retry_allowed and attempt < SSH_RETRY_ATTEMPTS:
            logger.info(f"[RETRY] Waiting {SSH_RETRY_DELAY} seconds before retry...")
            
            # Send keepalives during retry delay
            delay_remaining = SSH_RETRY_DELAY
            keepalive_interval = 10
            
            while delay_remaining > 0:
                sleep_time = min(keepalive_interval, delay_remaining)
                time.sleep(sleep_time)
                delay_remaining -= sleep_time
                
                if delay_remaining > 0 and not shell.closed:
                    try:
                        shell.send("\n")
                        time.sleep(0.2)
                        if shell.recv_ready():
                            shell.recv(MAX_READ)
                    except:
                        logger.warning("[RETRY] Failed to send keepalive to aggregation switch")
                        raise NetworkConnectionError("Lost connection during retry delay", reconnect_needed=True)
            
            # Verify aggregate connection after retry delay
            if not verify_aggregate_connection(shell):
                logger.warning("[RETRY] Lost aggregate connection during retry delay")
                raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
            
            return hop_to_neighbor(shell, ip, attempt + 1)
        else:
            if not retry_allowed:
                logger.info(f"[SKIP] Device {ip} is unreachable - moving to next device")
            raise
            
    except (OSError, Exception) as e:
        logger.error(f"Exception during SSH to {ip}: {e}")
        cleanup_failed_session(shell)
        
        if attempt < SSH_RETRY_ATTEMPTS:
            logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
            time.sleep(SSH_RETRY_DELAY)
            
            # Verify aggregate connection before retry
            if not verify_aggregate_connection(shell):
                raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
            
            return hop_to_neighbor(shell, ip, attempt + 1)
        else:
            raise NetworkConnectionError(f"SSH to {ip} failed after {SSH_RETRY_ATTEMPTS} attempts", reconnect_needed=True)

def exit_device(shell):
    """Exit from current SSH session with robust error handling"""
    try:
        logger.debug("[EXIT] Attempting to exit current session...")
        
        # Send exit command
        shell.send("exit\n")
        time.sleep(1)
        
        # Try to read any response
        exit_response = ""
        if shell.recv_ready():
            exit_response = shell.recv(MAX_READ).decode("utf-8", "ignore")
            logger.debug(f"[EXIT] Exit response: {exit_response[-200:]}")
        
        # Wait a bit more for the session to fully close
        time.sleep(1)
        
        # Verify we're back at a prompt
        shell.send("\n")
        time.sleep(0.5)
        
        if shell.recv_ready():
            prompt_response = shell.recv(MAX_READ).decode("utf-8", "ignore")
            logger.debug(f"[EXIT] Prompt check: {prompt_response[-200:]}")
            
            if "#" in prompt_response:
                logger.debug("[EXIT] Successfully returned to previous device")
                return True
            else:
                logger.warning("[EXIT] Unexpected response after exit")
                return False
        else:
            # No response - might be okay, shell might just be slow
            logger.debug("[EXIT] No immediate response after exit")
            time.sleep(1)
            
            # Try one more time to verify
            shell.send("\n")
            time.sleep(0.5)
            if shell.recv_ready():
                final_check = shell.recv(MAX_READ).decode("utf-8", "ignore")
                logger.debug(f"[EXIT] Final check: {final_check[-200:]}")
                if "#" in final_check:
                    return True
            
            return False
            
    except Exception as e:
        logger.warning(f"[EXIT] Exception during exit: {e}")
        # Try aggressive cleanup
        try:
            shell.send("\x03")  # Ctrl-C
            time.sleep(0.5)
            shell.send("exit\n")
            time.sleep(1)
            if shell.recv_ready():
                shell.recv(MAX_READ)
        except:
            pass
        return False

def get_hostname(shell):
    """Extract hostname from prompt"""
    try:
        shell.send("\n")
        buff = expect_prompt(shell, ("#", ">"), timeout=5)
        for line in reversed(buff.splitlines()):
            if m := re.match(r"^([^#>]+)[#>]", line.strip()):
                return m.group(1)
        return "unknown"
    except:
        return "unknown"

def determine_switch_type(hostname):
    """Determine the type of switch based on hostname"""
    if not hostname:
        return "UNKNOWN"
    upper = hostname.upper()
    
    if "AGG" in upper:
        return "AGGREGATE"
    elif "SRV" in upper:
        return "SERVER"
    elif "SMS" in upper:
        # Check for edge switch patterns
        sms_pos = upper.find("SMS")
        if upper.find("ACC", sms_pos) > sms_pos or upper.find("IE", sms_pos) > sms_pos:
            return "EDGE"
    
    return "OTHER"

def is_edge_switch(hostname):
    """Check if switch is an edge switch (ACC or IE variants)"""
    return determine_switch_type(hostname) == "EDGE"

def is_aggregate_switch(hostname):
    return determine_switch_type(hostname) == "AGGREGATE"

def is_server_switch(hostname):
    return determine_switch_type(hostname) == "SERVER"

def convert_mac_format(mac_cisco):
    mac_clean = mac_cisco.replace(".", "").upper()
    return ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])

def parse_cdp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{20,}", output)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        neighbor = {
            "hostname": None,
            "mgmt_ip": None,
            "local_intf": None,
            "remote_intf": None,
            "platform": None,
            "source": "CDP"
        }
        if m := re.search(r"Device ID:\s*(\S+(?:\.\S+)*)", block):
            neighbor["hostname"] = m.group(1)
        if m := re.search(r"(?:Management address|IP address).*?:\s*(\d+\.\d+\.\d+\.\d+)", block, re.IGNORECASE):
            neighbor["mgmt_ip"] = m.group(1)
        if m := re.search(r"Interface:\s*(\S+)", block):
            neighbor["local_intf"] = m.group(1).rstrip(',')
        if m := re.search(r"Port ID.*?:\s*(\S+)", block):
            neighbor["remote_intf"] = m.group(1)
        if m := re.search(r"Platform:\s*([^,\n]+)", block):
            neighbor["platform"] = m.group(1).strip()
        if neighbor["hostname"] and neighbor["mgmt_ip"]:
            if neighbor["platform"] and "cisco" in neighbor["platform"].lower():
                neighbors.append(neighbor)
    return neighbors

def parse_lldp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{20,}", output)
    for block in blocks:
        if "Local Intf:" not in block and "Chassis id:" not in block:
            continue
        neighbor = {
            "hostname": None,
            "mgmt_ip": None,
            "local_intf": None,
            "remote_intf": None,
            "sys_descr": "",
            "source": "LLDP"
        }
        if m := re.search(r"Local Intf:\s*(\S+)", block):
            neighbor["local_intf"] = m.group(1)
        for pattern in (r"Port id:\s*(\S+)", r"Port ID:\s*(\S+)", r"PortID:\s*(\S+)"):
            m = re.search(pattern, block, re.IGNORECASE)
            if m:
                neighbor["remote_intf"] = m.group(1)
                break
        if m := re.search(r"System Name:\s*([^\n]+)", block, re.IGNORECASE):
            hostname = m.group(1).strip().strip('"').strip("'")
            neighbor["hostname"] = hostname
        if not neighbor["hostname"]:
            if m := re.search(r"System Description:[^\n]*?(\S+)\s+Software", block, re.IGNORECASE):
                neighbor["hostname"] = m.group(1)
        if m := re.search(r"System Description:\s*([\s\S]+?)(?=\n\s*\n|\nTime|\nCapabilities|Management|$)", block, re.IGNORECASE):
            neighbor["sys_descr"] = m.group(1).strip()
        for pattern in (r"Management Addresses:[\s\S]*?IP:\s*(\d+\.\d+\.\d+\.\d+)",
                        r"Management Address:\s*(\d+\.\d+\.\d+\.\d+)",
                        r"Mgmt IP:\s*(\d+\.\d+\.\d+\.\d+)"):
            m = re.search(pattern, block, re.IGNORECASE)
            if m:
                neighbor["mgmt_ip"] = m.group(1)
                break
        if neighbor["mgmt_ip"]:
            if neighbor["sys_descr"] and "cisco" in neighbor["sys_descr"].lower():
                if not neighbor["hostname"]:
                    neighbor["hostname"] = f"LLDP-Device-{neighbor['mgmt_ip']}"
                    logger.warning(f"No hostname found in LLDP for {neighbor['mgmt_ip']}, using placeholder")
                neighbors.append(neighbor)
    return neighbors

def get_interface_status(shell):
    out = send_cmd(shell, "show ip interface brief", timeout=10)
    up_interfaces = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "Interface" in line or line.startswith("Vlan"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 5:
            intf, status = parts[0], parts[4]
            if status.lower() == "up":
                if re.match(r"(Gig|Ten|FastEthernet|Ethernet)", intf, re.IGNORECASE):
                    up_interfaces.append(intf)
    return up_interfaces

def parse_mac_table_interface(raw):
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if (not line or "Mac Address Table" in line or line.startswith("---") or
            line.lower().startswith("vlan") or line.startswith("Total") or
            "Mac Address" in line or "----" in line):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 4:
            vlan = parts[0]
            mac = parts[1]
            port = None
            mac_type_parts = []
            for i in range(2, len(parts)):
                if re.match(r'^(Gi|Te|Fa|Et|Po|Vl)', parts[i], re.IGNORECASE):
                    port = parts[i]
                    break
                else:
                    mac_type_parts.append(parts[i])
            mac_type = " ".join(mac_type_parts)
            if port and "DYNAMIC" in mac_type.upper():
                entries.append({
                    "vlan": vlan,
                    "mac_address": mac,
                    "type": mac_type,
                    "port": port
                })
    return entries

def map_ie_port(port_id):
    if m := re.match(r"port-(\d+)", port_id, re.IGNORECASE):
        port_num = int(m.group(1))
        return f"Gi1/{port_num}"
    return None

def normalize_interface_name(intf):
    if not intf:
        return ""
    replacements = {
        'Te': 'TenGigabitEthernet',
        'Gi': 'GigabitEthernet',
        'Fa': 'FastEthernet',
        'Et': 'Ethernet',
        'Po': 'Port-channel',
        'Vl': 'Vlan'
    }
    intf = intf.strip()
    for short, full in replacements.items():
        if intf.startswith(short) and len(intf) > len(short):
            next_char = intf[len(short)]
            if next_char.isdigit() or next_char == '/':
                return intf.replace(short, full, 1)
    return intf.lower()

def is_same_interface(intf1, intf2):
    if not intf1 or not intf2:
        return False
    
    # Normalize both interfaces
    norm1 = normalize_interface_name(intf1).lower()
    norm2 = normalize_interface_name(intf2).lower()
    
    # Direct match after normalization
    if norm1 == norm2:
        return True
    
    # Extract type and number for comparison
    pattern = r'(gigabitethernet|tengigabitethernet|fastethernet|ethernet|port-channel|vlan)[\s/]*(\d+[/\d]*)'
    match1 = re.search(pattern, norm1)
    match2 = re.search(pattern, norm2)
    
    if match1 and match2:
        type1, num1 = match1.groups()
        type2, num2 = match2.groups()
        
        # Normalize the type names
        type_map = {
            'gigabitethernet': 'gi',
            'tengigabitethernet': 'te',
            'fastethernet': 'fa',
            'ethernet': 'eth',
            'port-channel': 'po',
            'vlan': 'vl'
        }
        
        short_type1 = type_map.get(type1, type1)
        short_type2 = type_map.get(type2, type2)
        
        # Normalize the numbers (remove extra slashes/spaces)
        num1_clean = num1.strip().replace(' ', '')
        num2_clean = num2.strip().replace(' ', '')
        
        return short_type1 == short_type2 and num1_clean == num2_clean
    
    return False

def get_uplink_ports_from_neighbors(shell):
    """Return list of uplink ports on the CURRENT device by parsing CDP/LLDP - these connect to AGG/SRV switches"""
    logger.info("Discovering uplink ports using CDP and LLDP...")
    uplink_ports = []
    hostname_to_ip = {}
    all_neighbors_by_hostname = {}

    # CDP
    logger.info("Checking CDP neighbors...")
    cdp_output = send_cmd(shell, "show cdp neighbors detail", patterns=("#",), timeout=20)
    if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        if cdp_neighbors:
            logger.info(f"Found {len(cdp_neighbors)} CDP neighbors")
            for nbr in cdp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    if nbr["hostname"] not in hostname_to_ip:
                        hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                    all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    else:
        logger.info("CDP not enabled or available")

    # LLDP
    logger.info("Checking LLDP neighbors...")
    lldp_output = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=20)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
            for nbr in lldp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    if nbr["hostname"] in hostname_to_ip:
                        authoritative_ip = hostname_to_ip[nbr["hostname"]]
                        if authoritative_ip != nbr["mgmt_ip"]:
                            nbr["mgmt_ip"] = authoritative_ip
                    else:
                        hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]

                    # Deduplicate by local_intf if CDP already recorded it
                    is_dup = False
                    if nbr["hostname"] in all_neighbors_by_hostname:
                        lldp_intf_norm = normalize_interface_name(nbr["local_intf"])
                        for existing in all_neighbors_by_hostname[nbr["hostname"]]:
                            if (normalize_interface_name(existing.get("local_intf")) == lldp_intf_norm and
                                existing.get("source") == "CDP"):
                                is_dup = True
                                break
                    if not is_dup:
                        all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    else:
        logger.info("LLDP not enabled or available")

    # Any neighbor that is an AGG/SRV is an uplink
    for hostname, links in all_neighbors_by_hostname.items():
        if is_aggregate_switch(hostname) or is_server_switch(hostname):
            for nbr in links:
                uplink_port = nbr.get("local_intf")
                if not uplink_port and nbr.get("remote_intf"):
                    mapped = map_ie_port(nbr.get("remote_intf"))
                    if mapped:
                        uplink_port = mapped
                if uplink_port:
                    uplink_ports.append(uplink_port)
                    logger.info(f"UPLINK DETECTED: {uplink_port} → {hostname} (via {nbr.get('source','?')})")
                else:
                    logger.warning(f"Could not determine uplink port for neighbor {hostname}")
        else:
            logger.debug(f"Skipping neighbor {hostname} (not AGG/SRV)")
    logger.info(f"Total uplinks identified: {len(uplink_ports)}")
    return uplink_ports

def select_camera_mac(entries, interface):
    count = len(entries)
    if count == 0:
        return None
    elif count == 1:
        logger.debug(f"  {interface}: Single MAC found (standard)")
        return entries[0]
    elif count == 2:
        logger.info(f"  {interface}: 2 MACs found - Private VLAN detected (VLANs: {entries[0]['vlan']}, {entries[1]['vlan']})")
        return entries[0]
    else:
        logger.warning(f"  {interface}: {count} MACs found (unexpected!) - Taking first")
        for idx, entry in enumerate(entries):
            logger.warning(f"    MAC {idx+1}: {entry['mac_address']} on VLAN {entry['vlan']}")
        return entries[0]

def discover_cameras_from_switch(shell, switch_hostname, switch_type="UNKNOWN"):
    """Discover cameras on any type of switch - can raise NetworkConnectionError if aggregate connection lost"""
    logger.info("="*80)
    logger.info(f"Scanning {switch_type} switch: {switch_hostname}")
    logger.info("="*80)

    logger.info("Clearing dynamic MAC address table...")
    send_cmd(shell, "clear mac address-table dynamic", patterns=("#",), timeout=10)
    logger.info("Waiting 5 seconds for MAC table to repopulate...")
    time.sleep(5)
    logger.info("MAC table refresh complete")

    uplink_ports = get_uplink_ports_from_neighbors(shell)
    if not uplink_ports:
        logger.warning(f"No uplink ports detected via CDP/LLDP on {switch_hostname}")
        logger.warning("This means ALL ports will be scanned - this may be incorrect!")
    else:
        logger.info(f"Uplink ports to exclude: {uplink_ports}")

    up_interfaces = get_interface_status(shell)
    logger.info(f"Found {len(up_interfaces)} UP interfaces total")

    camera_count = 0
    scanned_count = 0
    
    for intf in up_interfaces:
        # Check if this interface matches any uplink port
        is_uplink = False
        for upl in uplink_ports:
            if is_same_interface(intf, upl):
                is_uplink = True
                logger.info(f"SKIP: {intf} - UPLINK PORT (matches {upl})")
                break
        
        if is_uplink:
            continue
        
        scanned_count += 1
        cmd = f"show mac address-table interface {intf}"
        mac_out = send_cmd(shell, cmd, timeout=10)
        entries = parse_mac_table_interface(mac_out)
        
        if entries:
            selected_entry = select_camera_mac(entries, intf)
            if selected_entry:
                mac_formatted = convert_mac_format(selected_entry["mac_address"])
                camera_info = {
                    "switch_name": switch_hostname,
                    "switch_type": switch_type,
                    "port": selected_entry["port"],
                    "mac_address": mac_formatted,
                    "vlan": selected_entry["vlan"]
                }
                camera_data.append(camera_info)
                camera_count += 1
                logger.info(f"  [+] Camera: {mac_formatted} on port {selected_entry['port']} (VLAN {selected_entry['vlan']})")
        else:
            logger.debug(f"No dynamic MAC entries on {intf}")

    logger.info("")
    logger.info(f"Summary for {switch_hostname}:")
    logger.info(f"  - Total UP interfaces: {len(up_interfaces)}")
    logger.info(f"  - Uplink ports excluded: {len(uplink_ports)}")
    logger.info(f"  - Ports scanned: {scanned_count}")
    logger.info(f"  - Cameras found: {camera_count}")
    logger.info("="*80)

def process_switch(shell, parent_ip, neighbor_info, switch_type="UNKNOWN"):
    """Process any type of switch - includes reconnection logic"""
    switch_ip = neighbor_info["mgmt_ip"]
    switch_name = neighbor_info["remote_name"]
    local_intf = neighbor_info["local_intf"]
    
    if not switch_ip or switch_ip in visited_switches:
        return
    
    logger.info("")
    logger.info("*"*80)
    logger.info(f"Processing {switch_type} SWITCH: {switch_name} ({switch_ip})")
    logger.info(f"Connected via parent port: {local_intf}")
    logger.info("*"*80)
    
    visited_switches.add(switch_ip)
    
    # Retry loop for connecting to switch
    max_retries = SSH_RETRY_ATTEMPTS
    for attempt in range(max_retries):
        try:
            # Verify parent connection before attempting hop
            if not verify_aggregate_connection(shell):
                raise NetworkConnectionError("Parent connection lost before hop", reconnect_needed=True)
            
            ssh_success = hop_to_neighbor(shell, switch_ip, attempt=1)
            if not ssh_success:
                logger.error(f"Cannot SSH to {switch_name} ({switch_ip}) - SKIPPING")
                return
            
            # Successfully connected, now discover cameras
            try:
                discover_cameras_from_switch(shell, switch_name, switch_type)
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False):
                    logger.error(f"Lost parent connection during camera discovery: {e}")
                    raise
                else:
                    logger.error(f"Error during camera discovery on {switch_name}: {e}")
            except Exception as e:
                logger.error(f"Error during camera discovery on {switch_name}: {e}", exc_info=True)
            
            # Exit back to parent
            try:
                logger.debug(f"[EXIT] Exiting from {switch_type} switch {switch_name}")
                exit_success = exit_device(shell)
                
                if not exit_success:
                    logger.warning(f"[EXIT] Exit from {switch_name} may have failed, verifying parent connection...")
                
                time.sleep(1)
                logger.info("Returned to parent switch")
                
                # Verify we're back at parent
                if not verify_aggregate_connection(shell):
                    raise NetworkConnectionError("Lost parent connection after exiting switch", reconnect_needed=True)
                
            except Exception as e:
                logger.error(f"Error exiting from {switch_name}: {e}")
                if not verify_aggregate_connection(shell):
                    raise NetworkConnectionError("Lost parent connection during exit", reconnect_needed=True)
            
            # Success - break out of retry loop
            return
            
        except NetworkConnectionError as e:
            reconnect_needed = getattr(e, 'reconnect_needed', False)
            
            if reconnect_needed:
                logger.error(f"Parent connection lost while processing {switch_name}")
                raise  # Propagate to caller for reconnection
            
            retry_allowed = getattr(e, 'retry_allowed', False)
            is_last_attempt = (attempt >= max_retries - 1)
            
            if retry_allowed and not is_last_attempt:
                logger.info(f"[RETRY] Will retry switch {switch_name} (attempt {attempt + 2}/{max_retries})")
                continue
            else:
                logger.error(f"Cannot connect to {switch_name} after {attempt + 1} attempts - SKIPPING")
                return

def discover_aggregate_neighbors(shell, current_agg_hostname):
    """Discover other aggregate switches using CDP and LLDP. Return list of dicts with hostname & mgmt_ip."""
    logger.info("Discovering neighboring aggregate switches...")
    aggregate_neighbors = []
    hostname_to_ip = {}
    all_neighbors_by_hostname = {}

    # CDP
    logger.info("Checking CDP neighbors...")
    cdp_output = send_cmd(shell, "show cdp neighbors detail", patterns=("#",), timeout=20)
    if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        if cdp_neighbors:
            logger.info(f"Found {len(cdp_neighbors)} CDP neighbors")
            for nbr in cdp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    hostname_to_ip.setdefault(nbr["hostname"], nbr["mgmt_ip"])
                    all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)

    # LLDP
    logger.info("Checking LLDP neighbors...")
    lldp_output = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=20)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
            for nbr in lldp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    if nbr["hostname"] in hostname_to_ip:
                        authoritative_ip = hostname_to_ip[nbr["hostname"]]
                        if authoritative_ip != nbr["mgmt_ip"]:
                            nbr["mgmt_ip"] = authoritative_ip
                    else:
                        hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                    # Dedup vs CDP
                    is_dup = False
                    if nbr["hostname"] in all_neighbors_by_hostname:
                        lldp_intf_norm = normalize_interface_name(nbr["local_intf"])
                        for existing in all_neighbors_by_hostname[nbr["hostname"]]:
                            if (normalize_interface_name(existing.get("local_intf")) == lldp_intf_norm and
                                existing.get("source") == "CDP"):
                                is_dup = True
                                break
                    if not is_dup:
                        all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)
    else:
        logger.info("LLDP not enabled or available")

    for hostname, links in all_neighbors_by_hostname.items():
        if is_aggregate_switch(hostname) and hostname != current_agg_hostname:
            mgmt_ip = hostname_to_ip.get(hostname)
            if mgmt_ip:
                aggregate_neighbors.append({"hostname": hostname, "mgmt_ip": mgmt_ip})
                logger.info(f"  Found aggregate neighbor: {hostname} ({mgmt_ip})")
    return aggregate_neighbors

def scan_aggregate_switch(shell, agg_ip):
    """Scan aggregate switch for ALL connected switches (not just edges) and discover other aggregates"""
    if agg_ip in visited_switches:
        logger.info(f"Aggregate {agg_ip} already visited, skipping")
        return []
    
    visited_switches.add(agg_ip)
    discovered_aggregates.add(agg_ip)
    hostname = get_hostname(shell)
    
    # Store hostname for reporting
    aggregate_hostnames[agg_ip] = hostname
    
    logger.info("")
    logger.info("#"*80)
    logger.info(f"Scanning AGGREGATE: {hostname} ({agg_ip})")
    logger.info("#"*80)

    # Skip scanning the aggregate itself - aggregates don't have cameras, only downstream switches do
    logger.info("")
    logger.info(">>> Skipping camera scan on aggregate switch (aggregates don't have direct camera connections)")
    
    new_aggregates = discover_aggregate_neighbors(shell, hostname)
    logger.info("")
    logger.info(">>> Discovering downstream switches...")

    all_neighbors_by_hostname = {}
    hostname_to_ip = {}

    # Reuse neighbor parsing to find ALL switches
    cdp_output = send_cmd(shell, "show cdp neighbors detail", patterns=("#",), timeout=20)
    if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
        cdp_neighbors = parse_cdp_neighbors(cdp_output)
        if cdp_neighbors:
            for nbr in cdp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                    all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)

    lldp_output = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=20)
    if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
        lldp_neighbors = parse_lldp_neighbors(lldp_output)
        if lldp_neighbors:
            for nbr in lldp_neighbors:
                if nbr["hostname"] and nbr["mgmt_ip"]:
                    if nbr["hostname"] in hostname_to_ip:
                        authoritative_ip = hostname_to_ip[nbr["hostname"]]
                        if authoritative_ip != nbr["mgmt_ip"]:
                            nbr["mgmt_ip"] = authoritative_ip
                    else:
                        hostname_to_ip[nbr["hostname"]] = nbr["mgmt_ip"]
                    is_dup = False
                    if nbr["hostname"] in all_neighbors_by_hostname:
                        lldp_intf_norm = normalize_interface_name(nbr["local_intf"])
                        for existing in all_neighbors_by_hostname[nbr["hostname"]]:
                            if (normalize_interface_name(existing.get("local_intf")) == lldp_intf_norm and
                                existing.get("source") == "CDP"):
                                is_dup = True
                                break
                    if not is_dup:
                        all_neighbors_by_hostname.setdefault(nbr["hostname"], []).append(nbr)

    logger.info(f"Found {len(all_neighbors_by_hostname)} total neighbors")

    # Count switches by type
    switch_counts = {"EDGE": 0, "AGGREGATE": 0, "SERVER": 0, "OTHER": 0}
    
    for nhost, links in all_neighbors_by_hostname.items():
        switch_type = determine_switch_type(nhost)
        mgmt_ip = hostname_to_ip.get(nhost)
        
        # Skip aggregates - they'll be processed separately
        if switch_type == "AGGREGATE":
            logger.debug(f"Skipping aggregate switch: {nhost} (will be processed separately)")
            continue
        
        # Process all other switch types
        switch_counts[switch_type] += 1
        logger.info(f"{switch_type} switch detected: {nhost} - {mgmt_ip}")
        
        for link in links:
            neighbor_info = {
                "remote_name": nhost,
                "mgmt_ip": mgmt_ip,
                "local_intf": link.get("local_intf")
            }
            try:
                process_switch(shell, agg_ip, neighbor_info, switch_type)
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False):
                    logger.error(f"Lost aggregate connection while processing {switch_type} {nhost}")
                    raise  # Propagate to caller for reconnection
            break  # Only process first link

    logger.info("")
    logger.info(f"Summary for {hostname}:")
    logger.info(f"  - Edge switches: {switch_counts['EDGE']}")
    logger.info(f"  - Server switches: {switch_counts['SERVER']}")
    logger.info(f"  - Other switches: {switch_counts['OTHER']}")
    logger.info(f"  - Total processed: {sum(switch_counts.values())}")
    
    return new_aggregates

def main():
    logger.info("="*80)
    logger.info("CAMERA DISCOVERY SCRIPT STARTED")
    logger.info(f"Seed switch: {SEED_SWITCH_IP}")
    logger.info(f"Log file: {log_filename}")
    logger.info("="*80)

    # Initial connection to seed switch
    try:
        client, shell = connect_to_seed()
    except NetworkConnectionError as e:
        logger.error(f"Failed to connect to seed switch: {e}")
        return

    try:
        aggregates_to_process = []
        logger.info("")
        logger.info("="*80)
        logger.info("PHASE 1: DISCOVERING AGGREGATE SWITCHES")
        logger.info("="*80)

        # Scan seed aggregate with reconnection support
        reconnect_attempts = 0
        max_reconnects = AGG_MAX_RETRIES
        
        while reconnect_attempts < max_reconnects:
            try:
                new_aggregates = scan_aggregate_switch(shell, SEED_SWITCH_IP)
                for agg in new_aggregates:
                    if agg["mgmt_ip"] not in discovered_aggregates:
                        aggregates_to_process.append(agg["mgmt_ip"])
                        logger.info(f"Added aggregate to queue: {agg['hostname']} ({agg['mgmt_ip']})")
                break  # Success
                
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False) or shell.closed:
                    reconnect_attempts += 1
                    logger.error(f"Connection to seed switch lost during Phase 1")
                    if reconnect_attempts < max_reconnects:
                        logger.info(f"Attempting to reconnect to seed switch (attempt {reconnect_attempts + 1}/{max_reconnects})...")
                        try:
                            try:
                                client.close()
                            except:
                                pass
                            client, shell = connect_to_seed()
                            logger.info("Successfully reconnected to seed switch")
                        except NetworkConnectionError as reconnect_error:
                            logger.error(f"Failed to reconnect: {reconnect_error}")
                            if reconnect_attempts >= max_reconnects - 1:
                                logger.error("Max reconnection attempts reached. Exiting.")
                                return
                    else:
                        logger.error("Max reconnection attempts reached. Exiting.")
                        return
                else:
                    raise

        logger.info("")
        logger.info("="*80)
        logger.info(f"PHASE 2: PROCESSING {len(aggregates_to_process)} ADDITIONAL AGGREGATES")
        logger.info("="*80)

        while aggregates_to_process:
            agg_ip = aggregates_to_process.pop(0)
            if agg_ip in discovered_aggregates:
                logger.info(f"Aggregate {agg_ip} already processed, skipping")
                continue

            logger.info("")
            logger.info("*"*80)
            logger.info(f"PROCESSING AGGREGATE: {agg_ip}")
            logger.info("*"*80)

            # Process this aggregate with reconnection support
            aggregate_reconnect_attempts = 0  # Separate counter for this aggregate
            aggregate_processed = False
            
            while aggregate_reconnect_attempts < max_reconnects and not aggregate_processed:
                try:
                    # Verify seed connection
                    if shell.closed or not verify_aggregate_connection(shell):
                        raise NetworkConnectionError("Seed connection lost", reconnect_needed=True)
                    
                    logger.info("Hopping to aggregate from seed switch...")
                    hop_success = hop_to_neighbor(shell, agg_ip)
                    if not hop_success:
                        logger.error(f"Failed to connect to aggregate {agg_ip} - skipping")
                        break

                    new_aggregates = scan_aggregate_switch(shell, agg_ip)
                    for agg in new_aggregates:
                        if (agg["mgmt_ip"] not in discovered_aggregates and
                            agg["mgmt_ip"] not in aggregates_to_process):
                            aggregates_to_process.append(agg["mgmt_ip"])
                            logger.info(f"Added new aggregate to queue: {agg['hostname']} ({agg['mgmt_ip']})")

                    logger.info("Returning to seed switch...")
                    exit_success = exit_device(shell)
                    
                    if not exit_success:
                        logger.warning("[EXIT] Exit may have failed, verifying connection...")
                    
                    time.sleep(1)
                    
                    # Verify we're back at seed
                    if not verify_aggregate_connection(shell):
                        raise NetworkConnectionError("Lost seed connection after exiting aggregate", reconnect_needed=True)
                    
                    logger.info("[EXIT] Successfully returned to seed switch")
                    aggregate_processed = True
                    
                except NetworkConnectionError as e:
                    if getattr(e, 'reconnect_needed', False) or shell.closed:
                        aggregate_reconnect_attempts += 1
                        logger.error(f"Connection to seed switch lost while processing aggregate {agg_ip}")
                        if aggregate_reconnect_attempts < max_reconnects:
                            logger.info(f"Attempting to reconnect to seed switch (attempt {aggregate_reconnect_attempts + 1}/{max_reconnects})...")
                            try:
                                try:
                                    client.close()
                                except:
                                    pass
                                client, shell = connect_to_seed()
                                logger.info("Successfully reconnected to seed switch - will retry this aggregate")
                            except NetworkConnectionError as reconnect_error:
                                logger.error(f"Failed to reconnect: {reconnect_error}")
                                if aggregate_reconnect_attempts >= max_reconnects - 1:
                                    logger.error("Max reconnection attempts reached for this aggregate. Moving to next aggregate.")
                                    break
                        else:
                            logger.error("Max reconnection attempts reached for this aggregate. Moving to next aggregate.")
                            break
                    else:
                        # Some other error - skip this aggregate
                        logger.error(f"Error processing aggregate {agg_ip}: {e}")
                        break

    except Exception as e:
        logger.error(f"Fatal error during discovery: {e}", exc_info=True)
    finally:
        try:
            client.close()
            logger.info("Closed connection to seed switch")
        except:
            pass

    logger.info("")
    logger.info("="*80)
    logger.info("DISCOVERY COMPLETE")
    logger.info("="*80)
    logger.info(f"Aggregates discovered: {len(discovered_aggregates)}")
    for agg_ip in sorted(discovered_aggregates):
        agg_name = aggregate_hostnames.get(agg_ip, "Unknown")
        is_seed = " (SEED)" if agg_ip == SEED_SWITCH_IP else ""
        logger.info(f"  - {agg_name:<40} {agg_ip}{is_seed}")
    logger.info(f"Total cameras found: {len(camera_data)}")
    logger.info("="*80)

    # Save results with aggregate info in filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_file = f"camera_inventory_{len(camera_data)}cameras_{len(discovered_aggregates)}aggs_{timestamp}.json"
    
    # Create enhanced output with metadata
    output_data = {
        "discovery_metadata": {
            "timestamp": timestamp,
            "seed_switch": SEED_SWITCH_IP,
            "total_cameras": len(camera_data),
            "total_aggregates": len(discovered_aggregates),
            "aggregates": [
                {
                    "ip": agg_ip,
                    "hostname": aggregate_hostnames.get(agg_ip, "Unknown"),
                    "is_seed": agg_ip == SEED_SWITCH_IP
                }
                for agg_ip in sorted(discovered_aggregates)
            ]
        },
        "cameras": camera_data
    }
    
    with open(json_file, "w") as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved: {json_file}")

    if camera_data:
        csv_file = f"camera_inventory_{len(camera_data)}cameras_{len(discovered_aggregates)}aggs_{timestamp}.csv"
        with open(csv_file, "w", newline="") as f:
            fieldnames = ["switch_name", "switch_type", "port", "mac_address", "vlan"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(camera_data)
        logger.info(f"Saved: {csv_file}")

    logger.info("")
    logger.info("-"*80)
    logger.info("CAMERA INVENTORY SUMMARY")
    logger.info("-"*80)
    
    # Group cameras by switch type for summary
    cameras_by_type = {"EDGE": 0, "AGGREGATE": 0, "SERVER": 0, "OTHER": 0, "UNKNOWN": 0}
    for camera in camera_data:
        switch_type = camera.get("switch_type", "UNKNOWN")
        cameras_by_type[switch_type] = cameras_by_type.get(switch_type, 0) + 1
    
    logger.info("Cameras by switch type:")
    for sw_type, count in cameras_by_type.items():
        if count > 0:
            logger.info(f"  - {sw_type}: {count}")
    logger.info("")
    
    for camera in camera_data:
        switch_type = camera.get("switch_type", "UNKNOWN")
        logger.info(f"{camera['switch_name']:<50} [{switch_type:<9}] {camera['port']:<15} {camera['mac_address']:<20} VLAN {camera['vlan']}")
    logger.info("")
    logger.info(f"Total cameras discovered: {len(camera_data)}")
    logger.info(f"Log file saved: {log_filename}")

if __name__ == "__main__":
    main()
