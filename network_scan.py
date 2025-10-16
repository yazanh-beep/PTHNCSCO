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
SEED_SWITCH_IP = "192.168.1.8"  # Starting aggregate switch IP
TIMEOUT = 10
MAX_READ = 65535
SSH_RETRY_ATTEMPTS = 2
SSH_RETRY_DELAY = 5
# -----------------------------------------------------------------------------

visited_switches = set()
discovered_aggregates = set()
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
    """SSH hop from current switch to neighbor with retry logic"""
    logger.info(f"SSH hopping to {ip} (attempt {attempt}/{SSH_RETRY_ATTEMPTS})")
    try:
        out = send_cmd(
            shell,
            f"ssh -l {USERNAME} {ip}",
            patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">", 
                      "Connection refused", "Connection timed out", "Unable to connect"),
            timeout=60
        )
        # Hard failures
        if ("Connection refused" in out or "Unable to connect" in out or
            "% Connection" in out or "Connection timed out" in out):
            logger.error(f"SSH connection failed to {ip}")
            shell.send("\x03"); time.sleep(1); shell.send("\n"); time.sleep(0.5)
            if shell.recv_ready():
                shell.recv(MAX_READ)
            if attempt < SSH_RETRY_ATTEMPTS:
                logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
                time.sleep(SSH_RETRY_DELAY)
                return hop_to_neighbor(shell, ip, attempt + 1)
            logger.error(f"SSH to {ip} failed after {SSH_RETRY_ATTEMPTS} attempts")
            return False

        # New host key prompt
        if "(yes/no)?" in out or "yes/no" in out:
            out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=30)

        # Password prompt
        if "assword:" in out:
            out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">", "Permission denied", "Authentication failed"), timeout=30)

        # Auth failures
        if ("Permission denied" in out or "Authentication failed" in out or "% Authentication" in out):
            logger.error(f"SSH authentication failed to {ip}")
            shell.send("\x03"); time.sleep(1); shell.send("exit\n"); time.sleep(1)
            if attempt < SSH_RETRY_ATTEMPTS:
                logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
                time.sleep(SSH_RETRY_DELAY)
                return hop_to_neighbor(shell, ip, attempt + 1)
            logger.error(f"SSH authentication to {ip} failed after {SSH_RETRY_ATTEMPTS} attempts")
            return False

        # Got a prompt
        if "#" in out or ">" in out:
            if out.strip().endswith(">"):
                send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=15)
                send_cmd(shell, PASSWORD, patterns=("#",), timeout=15)
            send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
            logger.info(f"Successfully hopped to {ip}")
            return True

        # Unknown state
        logger.error(f"Failed to get prompt from {ip}")
        shell.send("\x03"); time.sleep(1)
        if attempt < SSH_RETRY_ATTEMPTS:
            logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
            time.sleep(SSH_RETRY_DELAY)
            return hop_to_neighbor(shell, ip, attempt + 1)
        logger.error(f"SSH to {ip} failed after {SSH_RETRY_ATTEMPTS} attempts")
        return False

    except Exception as e:
        logger.error(f"Exception during SSH to {ip}: {e}")
        try:
            shell.send("\x03"); time.sleep(1); shell.send("exit\n"); time.sleep(1)
            if shell.recv_ready():
                shell.recv(MAX_READ)
        except:
            pass
        if attempt < SSH_RETRY_ATTEMPTS:
            logger.warning(f"Retrying SSH to {ip} in {SSH_RETRY_DELAY} seconds...")
            time.sleep(SSH_RETRY_DELAY)
            return hop_to_neighbor(shell, ip, attempt + 1)
        logger.error(f"SSH to {ip} failed with exception after {SSH_RETRY_ATTEMPTS} attempts")
        return False

def exit_device(shell):
    """Exit from current SSH session"""
    try:
        send_cmd(shell, "exit", patterns=("#", ">", "closed", "Connection"), timeout=5)
        time.sleep(1)
        if shell.recv_ready():
            shell.recv(MAX_READ)
    except Exception as e:
        logger.debug(f"Exception during exit: {e}")
        try:
            shell.send("\x03"); time.sleep(0.5); shell.send("exit\n"); time.sleep(0.5)
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
    if "SMS" not in upper:
        return False
    sms_pos = upper.find("SMS")
    acc_pos = upper.find("ACC", sms_pos)
    if acc_pos > sms_pos:
        return True
    ie_pos = upper.find("IE", sms_pos)
    if ie_pos > sms_pos:
        return True
    return False

def is_aggregate_switch(hostname):
    return bool(hostname) and "AGG" in hostname.upper()

def is_server_switch(hostname):
    return bool(hostname) and "SRV" in hostname.upper()

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
    norm1 = normalize_interface_name(intf1)
    norm2 = normalize_interface_name(intf2)
    if norm1 == norm2:
        return True
    pattern = r'(gigabitethernet|tengigabitethernet|fastethernet|ethernet)(\d+/\d+|\d+)'
    match1 = re.search(pattern, norm1)
    match2 = re.search(pattern, norm2)
    if match1 and match2:
        type1, num1 = match1.groups()
        type2, num2 = match2.groups()
        type_map = {
            'gigabitethernet': 'gi',
            'tengigabitethernet': 'te',
            'fastethernet': 'fa',
            'ethernet': 'eth'
        }
        short_type1 = type_map.get(type1, type1)
        short_type2 = type_map.get(type2, type2)
        return short_type1 == short_type2 and num1 == num2
    return False

def get_uplink_ports_from_neighbors(shell):
    """Return list of uplink ports on the CURRENT device by parsing CDP/LLDP."""
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

    # Any neighbor that is an AGG/SRV is an uplink from the edge perspective; from AGG, other AGG/SRV links are uplinks, too.
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

def discover_cameras_from_edge(shell, edge_hostname):
    logger.info("="*80)
    logger.info(f"Scanning edge switch: {edge_hostname}")
    logger.info("="*80)

    logger.info("Clearing dynamic MAC address table...")
    send_cmd(shell, "clear mac address-table dynamic", patterns=("#",), timeout=10)
    logger.info("Waiting 5 seconds for MAC table to repopulate...")
    time.sleep(5)
    logger.info("MAC table refresh complete")

    uplink_ports = get_uplink_ports_from_neighbors(shell)
    if not uplink_ports:
        logger.warning(f"No uplink ports detected via CDP/LLDP on {edge_hostname}")
        logger.warning("This means ALL ports will be scanned - this may be incorrect!")
    else:
        logger.info(f"Uplink ports to exclude: {uplink_ports}")

    up_interfaces = get_interface_status(shell)
    logger.info(f"Found {len(up_interfaces)} UP interfaces total")

    camera_count = 0
    scanned_count = 0
    for intf in up_interfaces:
        if any(is_same_interface(intf, upl) for upl in uplink_ports):
            logger.info(f"SKIP: {intf} - UPLINK PORT")
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
                    "switch_name": edge_hostname,
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
    logger.info(f"Summary for {edge_hostname}:")
    logger.info(f"  - Total UP interfaces: {len(up_interfaces)}")
    logger.info(f"  - Uplink ports excluded: {len(uplink_ports)}")
    logger.info(f"  - Ports scanned: {scanned_count}")
    logger.info(f"  - Cameras found: {camera_count}")
    logger.info("="*80)

def process_edge_switch(shell, agg_ip, neighbor_info):
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
    ssh_success = hop_to_neighbor(shell, edge_ip)
    if not ssh_success:
        logger.error(f"Cannot SSH to {edge_name} ({edge_ip}) - SKIPPING after all retry attempts")
        logger.info("Verifying connection to aggregate switch...")
        try:
            shell.send("\n"); time.sleep(1)
            if shell.recv_ready():
                buff = shell.recv(MAX_READ).decode("utf-8", "ignore")
                logger.debug(f"Current prompt after failed SSH: {buff[-100:]}")
        except Exception as e:
            logger.error(f"Shell verification exception: {e}")
        return
    try:
        discover_cameras_from_edge(shell, edge_name)
    except Exception as e:
        logger.error(f"Error during camera discovery on {edge_name}: {e}", exc_info=True)
    finally:
        try:
            exit_device(shell); time.sleep(1)
            logger.info("Returned to aggregate switch")
        except Exception as e:
            logger.error(f"Error exiting from {edge_name}: {e}")

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
    """Scan aggregate switch for connected edge switches and discover other aggregates"""
    if agg_ip in visited_switches:
        logger.info(f"Aggregate {agg_ip} already visited, skipping")
        return []
    visited_switches.add(agg_ip)
    discovered_aggregates.add(agg_ip)
    hostname = get_hostname(shell)
    logger.info("")
    logger.info("#"*80)
    logger.info(f"Scanning AGGREGATE: {hostname} ({agg_ip})")
    logger.info("#"*80)

    new_aggregates = discover_aggregate_neighbors(shell, hostname)
    logger.info("Discovering edge switches...")

    all_neighbors_by_hostname = {}
    hostname_to_ip = {}

    # Reuse neighbor parsing to find edges
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

    edge_count = 0
    for nhost, links in all_neighbors_by_hostname.items():
        if is_edge_switch(nhost):
            edge_count += 1
            mgmt_ip = hostname_to_ip.get(nhost)
            logger.info(f"Edge switch detected: {nhost} - {mgmt_ip}")
            for link in links:
                neighbor_info = {
                    "remote_name": nhost,
                    "mgmt_ip": mgmt_ip,
                    "local_intf": link.get("local_intf")
                }
                process_edge_switch(shell, agg_ip, neighbor_info)
                break
        elif is_aggregate_switch(nhost):
            logger.debug(f"Skipping aggregate switch: {nhost} (will be processed separately)")
        elif is_server_switch(nhost):
            logger.debug(f"Skipping server switch: {nhost}")

    logger.info(f"Processed {edge_count} edge switches from {hostname}")
    return new_aggregates

def main():
    logger.info("="*80)
    logger.info("CAMERA DISCOVERY SCRIPT STARTED")
    logger.info(f"Seed switch: {SEED_SWITCH_IP}")
    logger.info(f"Log file: {log_filename}")
    logger.info("="*80)

    client, shell = connect_switch(SEED_SWITCH_IP)
    if not client:
        logger.error("Failed to connect to seed switch. Exiting.")
        return

    try:
        aggregates_to_process = []
        logger.info("")
        logger.info("="*80)
        logger.info("PHASE 1: DISCOVERING AGGREGATE SWITCHES")
        logger.info("="*80)

        new_aggregates = scan_aggregate_switch(shell, SEED_SWITCH_IP)
        for agg in new_aggregates:
            if agg["mgmt_ip"] not in discovered_aggregates:
                aggregates_to_process.append(agg["mgmt_ip"])
                logger.info(f"Added aggregate to queue: {agg['hostname']} ({agg['mgmt_ip']})")

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

            logger.info("Returning to seed switch...")
            exit_device(shell); time.sleep(1)

            hop_success = hop_to_neighbor(shell, agg_ip)
            if not hop_success:
                logger.error(f"Failed to connect to aggregate {agg_ip} - skipping")
                continue

            new_aggregates = scan_aggregate_switch(shell, agg_ip)
            for agg in new_aggregates:
                if (agg["mgmt_ip"] not in discovered_aggregates and
                    agg["mgmt_ip"] not in aggregates_to_process):
                    aggregates_to_process.append(agg["mgmt_ip"])
                    logger.info(f"Added new aggregate to queue: {agg['hostname']} ({agg['mgmt_ip']})")

        logger.info("")
        logger.info("Returning to seed switch...")
        exit_device(shell); time.sleep(1)

    except Exception as e:
        logger.error(f"Fatal error during discovery: {e}", exc_info=True)
    finally:
        client.close()
        logger.info("Closed connection to seed switch")

    logger.info("")
    logger.info("="*80)
    logger.info("DISCOVERY COMPLETE")
    logger.info("="*80)
    logger.info(f"Aggregates discovered: {len(discovered_aggregates)}")
    for agg_ip in sorted(discovered_aggregates):
        logger.info(f"  - {agg_ip}")
    logger.info(f"Total cameras found: {len(camera_data)}")
    logger.info("="*80)

    json_file = "camera_inventory.json"
    with open(json_file, "w") as f:
        json.dump(camera_data, f, indent=2)
    logger.info(f"Saved: {json_file}")

    if camera_data:
        csv_file = "camera_inventory.csv"
        with open(csv_file, "w", newline="") as f:
            fieldnames = ["switch_name", "port", "mac_address", "vlan"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(camera_data)
        logger.info(f"Saved: {csv_file}")

    logger.info("")
    logger.info("-"*80)
    logger.info("CAMERA INVENTORY SUMMARY")
    logger.info("-"*80)
    for camera in camera_data:
        logger.info(f"{camera['switch_name']:<50} {camera['port']:<15} {camera['mac_address']:<20} VLAN {camera['vlan']}")
    logger.info("")
    logger.info(f"Total cameras discovered: {len(camera_data)}")
    logger.info(f"Log file saved: {log_filename}")

if __name__ == "__main__":
    main()
