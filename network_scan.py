#!/usr/bin/env python3
"""
Smart Network Topology Discovery Tool
Discovers Cisco network topology using CDP (with LLDP fallback) via SSH
"""
import paramiko
import time
import re
import json
from datetime import datetime
from collections import deque

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
USERNAME = "admin"
PASSWORD = "cisco"
AGGREGATE_ENTRY_IP = "192.168.1.1"  # Entry point from server
AGGREGATE_MGMT_IPS = [
    # Add your aggregate switch management IPs here (VLAN 100 IPs)
    # Example: "10.0.100.1", "10.0.100.2"
]
TIMEOUT = 10
MAX_READ = 65535
# ─────────────────────────────────────────────────────────────────────────────

class NetworkDiscovery:
    def __init__(self):
        self.devices = {}  # Key: mgmt_ip, Value: device_info
        self.to_visit = deque()  # Queue of IPs to visit
        self.visited = set()  # IPs we've already processed
        self.seed_aggregate_ip = None  # IP of the initial aggregate switch
        self.agg_shell = None  # Persistent shell to aggregate switch
        self.agg_client = None
        self.log_file = None  # File handle for logging
        self.start_time = datetime.now()
        self.link_tracking = {}  # Track connections between devices
        
    def log(self, msg, level="INFO"):
        """Clean logging output - prints to console and file"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] [{level}] {msg}"
        print(log_line)
        
        # Also write to log file if it's open
        if self.log_file:
            self.log_file.write(log_line + "\n")
            self.log_file.flush()  # Ensure it's written immediately

    def determine_device_role(self, hostname):
        """Determine device role based on hostname"""
        hostname_upper = hostname.upper()
        
        if "SRV" in hostname_upper:
            return "server"
        elif "AGG" in hostname_upper:
            return "aggregate"
        elif "ACC" in hostname_upper:
            return "access"
        elif "IE" in hostname_upper:
            return "field"
        else:
            return "unknown"

    def expect_prompt(self, shell, patterns, timeout=TIMEOUT):
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

    def send_cmd(self, shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, silent=False):
        """Send command and wait for prompt"""
        if not silent:
            self.log(f"CMD: {cmd}", "DEBUG")
        shell.send(cmd + "\n")
        time.sleep(0.3)  # Small delay for command to process
        out = self.expect_prompt(shell, patterns, timeout)
        return out

    def connect_to_aggregate(self):
        """Initial SSH connection from server to aggregate switch"""
        self.log(f"Connecting to aggregate switch: {AGGREGATE_ENTRY_IP}")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(AGGREGATE_ENTRY_IP, username=USERNAME, password=PASSWORD,
                          look_for_keys=False, allow_agent=False, timeout=15)
            shell = client.invoke_shell()
            self.expect_prompt(shell, ("#", ">"))
            
            # Enable mode
            self.send_cmd(shell, "enable", patterns=("assword:", "#"), silent=True)
            self.send_cmd(shell, PASSWORD, patterns=("#",), silent=True)
            self.send_cmd(shell, "terminal length 0", patterns=("#",), silent=True)
            
            self.agg_client = client
            self.agg_shell = shell
            self.log("Successfully connected to aggregate switch")
            
            # Get the actual management IP (VLAN 100) of this aggregate switch
            mgmt_ip = self.get_management_ip(shell)
            if mgmt_ip:
                self.log(f"Aggregate switch VLAN 100 IP: {mgmt_ip}")
                self.seed_aggregate_ip = mgmt_ip  # Store seed aggregate IP
                return mgmt_ip
            else:
                self.log("WARNING: Could not determine VLAN 100 IP, using entry IP", "WARN")
                self.seed_aggregate_ip = AGGREGATE_ENTRY_IP
                return AGGREGATE_ENTRY_IP
                
        except Exception as e:
            self.log(f"Failed to connect to aggregate: {e}", "ERROR")
            raise

    def ssh_to_device(self, shell, target_ip):
        """SSH from aggregate switch to target device"""
        self.log(f"SSH hop to {target_ip}")
        try:
            out = self.send_cmd(shell, f"ssh -l {USERNAME} {target_ip}",
                               patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">"),
                               timeout=20, silent=True)
            
            # Handle SSH key acceptance
            if "(yes/no)?" in out or "yes/no" in out:
                out = self.send_cmd(shell, "yes", 
                                   patterns=("assword:", "%", "#", ">"), 
                                   timeout=15, silent=True)
            
            # Handle password prompt
            if "assword:" in out:
                out = self.send_cmd(shell, PASSWORD, 
                                   patterns=("%", "#", ">"), 
                                   timeout=15, silent=True)
            
            # Check for connection refused or unreachable
            if "Connection refused" in out or "Unable to connect" in out or "% Connection" in out:
                self.log(f"SSH connection refused to {target_ip}", "ERROR")
                return False
            
            # Enter enable mode if needed
            if out.strip().endswith(">"):
                self.send_cmd(shell, "enable", 
                             patterns=("assword:", "#"), 
                             timeout=10, silent=True)
                self.send_cmd(shell, PASSWORD, 
                             patterns=("#",), 
                             timeout=10, silent=True)
            
            # Disable paging
            self.send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5, silent=True)
            self.log(f"Successfully connected to {target_ip}")
            return True
            
        except Exception as e:
            self.log(f"Failed to SSH to {target_ip}: {e}", "ERROR")
            return False

    def exit_device(self, shell):
        """Exit from current SSH session"""
        try:
            self.send_cmd(shell, "exit", patterns=("#", ">", "closed"), timeout=5, silent=True)
            time.sleep(0.5)
        except:
            pass

    def get_hostname(self, shell):
        """Extract hostname from prompt"""
        shell.send("\n")
        time.sleep(0.2)
        buff = self.expect_prompt(shell, ("#", ">"), timeout=3)
        for line in reversed(buff.splitlines()):
            line = line.strip()
            # Match the full hostname including dots, up to # or >
            if m := re.match(r"^([^#>\s]+(?:\.[^#>\s]+)*)[#>]", line):
                hostname = m.group(1)
                # Keep the full hostname as-is, no domain stripping
                return hostname
        return "Unknown"

    def get_management_ip(self, shell):
        """Get VLAN 100 management IP from 'show run int vlan 100'"""
        output = self.send_cmd(shell, "show run int vlan 100", timeout=10, silent=True)
        # Look for: ip address 10.0.100.1 255.255.255.0
        if m := re.search(r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", output):
            ip = m.group(1)
            mask = m.group(2)
            # Convert mask to CIDR if needed, or just return IP
            return ip  # Return just IP for simplicity
        return None

    def get_serial_number(self, shell):
        """Extract serial number from 'show version'"""
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        # Try multiple patterns for different IOS versions
        patterns = [
            r"System [Ss]erial [Nn]umber\s*:?\s*(\S+)",
            r"Processor board ID\s+(\S+)",
            r"System Serial Number\s*:?\s*(\S+)"
        ]
        for pattern in patterns:
            if m := re.search(pattern, output):
                sn = m.group(1)
                if sn.lower() not in ["unknown", "n/a"]:
                    return sn
        return None

    def get_ios_version(self, shell):
        """Extract IOS version from 'show version'"""
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        # Try multiple patterns for different IOS formats
        patterns = [
            r"Cisco IOS Software.*?Version\s+([^,\s]+)",
            r"IOS.*?Software.*?Version\s+([^,\s]+)",
            r"Version\s+(\d+\.\d+[^\s,]*)"
        ]
        for pattern in patterns:
            if m := re.search(pattern, output, re.IGNORECASE):
                return m.group(1)
        return None

    def get_switch_model(self, shell):
        """Extract switch model from 'show version'"""
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        # Try multiple patterns for different output formats
        patterns = [
            r"Model [Nn]umber\s*:?\s*(\S+)",
            r"cisco\s+([A-Z0-9\-]+)\s+\([^\)]+\)\s+processor",
            r"Model:\s*(\S+)",
            r"Hardware:\s*(\S+)",
            r"cisco\s+(WS-[A-Z0-9\-]+)",
            r"cisco\s+(C[0-9]{4}[A-Z0-9\-]*)",
            r"cisco\s+(IE-[0-9]{4}[A-Z0-9\-]*)",
            r"System image file is.*?:([A-Z0-9\-]+)"
        ]
        for pattern in patterns:
            if m := re.search(pattern, output, re.IGNORECASE):
                model = m.group(1)
                # Clean up the model name
                if model.lower() not in ["unknown", "n/a", "bytes"]:
                    return model
        return None

    def parse_cdp_neighbors(self, output):
        """Parse 'show cdp neighbors detail' output"""
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
            
            # Device ID / Hostname - preserve full name exactly as-is
            if m := re.search(r"Device ID:\s*(\S+(?:\.\S+)*)", block):
                hostname = m.group(1)
                # Keep full hostname with no domain stripping
                neighbor["hostname"] = hostname
            
            # Management IP
            if m := re.search(r"(?:Management address|IP address).*?:\s*(\d+\.\d+\.\d+\.\d+)", block, re.IGNORECASE):
                neighbor["mgmt_ip"] = m.group(1)
            
            # Local Interface
            if m := re.search(r"Interface:\s*(\S+)", block):
                neighbor["local_intf"] = m.group(1).rstrip(',')
            
            # Remote Interface (Port ID)
            if m := re.search(r"Port ID.*?:\s*(\S+)", block):
                neighbor["remote_intf"] = m.group(1)
            
            # Platform (to check if Cisco)
            if m := re.search(r"Platform:\s*([^,\n]+)", block):
                neighbor["platform"] = m.group(1).strip()
            
            # Only add if we have essential info and it's a Cisco device
            if neighbor["hostname"] and neighbor["mgmt_ip"]:
                if neighbor["platform"] and "cisco" in neighbor["platform"].lower():
                    neighbors.append(neighbor)
                    
        return neighbors

    def parse_lldp_neighbors(self, output):
        """Parse 'show lldp neighbors detail' output"""
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
            
            # Local Interface
            if m := re.search(r"Local Intf:\s*(\S+)", block):
                neighbor["local_intf"] = m.group(1)
            
            # Remote Interface (Port ID) - try multiple patterns
            patterns = [
                r"Port id:\s*(\S+)",
                r"Port ID:\s*(\S+)",
                r"PortID:\s*(\S+)"
            ]
            for pattern in patterns:
                if m := re.search(pattern, block, re.IGNORECASE):
                    neighbor["remote_intf"] = m.group(1)
                    break
            
            # System Name (hostname) - extract full name from detail output exactly as-is
            if m := re.search(r"System Name:\s*([^\n]+)", block, re.IGNORECASE):
                hostname = m.group(1).strip()
                # Remove quotes if present
                hostname = hostname.strip('"').strip("'")
                # Keep the full hostname with no domain stripping
                neighbor["hostname"] = hostname
            
            # If hostname is still None or empty, try to extract from System Description
            if not neighbor["hostname"]:
                if m := re.search(r"System Description:[^\n]*?(\S+)\s+Software", block, re.IGNORECASE):
                    neighbor["hostname"] = m.group(1)
            
            # System Description
            if m := re.search(r"System Description:\s*([\s\S]+?)(?=\n\s*\n|\nTime|\nCapabilities|Management|$)", block, re.IGNORECASE):
                neighbor["sys_descr"] = m.group(1).strip()
            
            # Management IP - try multiple patterns
            mgmt_patterns = [
                r"Management Addresses:[\s\S]*?IP:\s*(\d+\.\d+\.\d+\.\d+)",
                r"Management Address:\s*(\d+\.\d+\.\d+\.\d+)",
                r"Mgmt IP:\s*(\d+\.\d+\.\d+\.\d+)"
            ]
            for pattern in mgmt_patterns:
                if m := re.search(pattern, block, re.IGNORECASE):
                    neighbor["mgmt_ip"] = m.group(1)
                    break
            
            # Only add Cisco devices with management IP
            if neighbor["mgmt_ip"]:
                # Check if Cisco device
                if neighbor["sys_descr"] and "cisco" in neighbor["sys_descr"].lower():
                    # If hostname is still missing, use a placeholder with IP
                    if not neighbor["hostname"]:
                        neighbor["hostname"] = f"LLDP-Device-{neighbor['mgmt_ip']}"
                        self.log(f"  Warning: No hostname found in LLDP for {neighbor['mgmt_ip']}, using placeholder", "WARN")
                    neighbors.append(neighbor)
                    
        return neighbors

    def group_links_by_neighbor(self, neighbors):
        """Group neighbors by IP to detect multiple links to same device"""
        neighbor_groups = {}
        
        for nbr in neighbors:
            neighbor_ip = nbr["mgmt_ip"]
            if neighbor_ip not in neighbor_groups:
                neighbor_groups[neighbor_ip] = []
            neighbor_groups[neighbor_ip].append(nbr)
        
        return neighbor_groups

    def discover_neighbors(self, shell, current_device_ip):
        """Discover neighbors using BOTH CDP and LLDP, merge results intelligently"""
        all_neighbors_by_ip = {}  # Key: mgmt_ip, Value: list of neighbor entries
        protocols_used = []
        
        # Try CDP first
        self.log("Checking CDP neighbors...")
        cdp_output = self.send_cmd(shell, "show cdp neighbors detail", timeout=20, silent=True)
        
        if "CDP is not enabled" not in cdp_output and "Invalid input" not in cdp_output:
            cdp_neighbors = self.parse_cdp_neighbors(cdp_output)
            if cdp_neighbors:
                self.log(f"Found {len(cdp_neighbors)} CDP neighbors")
                protocols_used.append("CDP")
                for nbr in cdp_neighbors:
                    if nbr["mgmt_ip"]:
                        nbr["discovered_via"] = "CDP"
                        if nbr["mgmt_ip"] not in all_neighbors_by_ip:
                            all_neighbors_by_ip[nbr["mgmt_ip"]] = []
                        all_neighbors_by_ip[nbr["mgmt_ip"]].append(nbr)
        else:
            self.log("CDP not enabled or available")
        
        # Also try LLDP
        self.log("Checking LLDP neighbors...")
        lldp_output = self.send_cmd(shell, "show lldp neighbors detail", timeout=20, silent=True)
        
        if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
            lldp_neighbors = self.parse_lldp_neighbors(lldp_output)
            if lldp_neighbors:
                self.log(f"Found {len(lldp_neighbors)} LLDP neighbors")
                protocols_used.append("LLDP")
                for nbr in lldp_neighbors:
                    if nbr["mgmt_ip"]:
                        nbr["discovered_via"] = "LLDP"
                        if nbr["mgmt_ip"] not in all_neighbors_by_ip:
                            all_neighbors_by_ip[nbr["mgmt_ip"]] = []
                        else:
                            # Check if this is a duplicate of a CDP entry (same interface)
                            is_duplicate = False
                            for existing in all_neighbors_by_ip[nbr["mgmt_ip"]]:
                                if (existing.get("local_intf") == nbr["local_intf"] and 
                                    existing.get("discovered_via") == "CDP"):
                                    is_duplicate = True
                                    self.log(f"  Skipping LLDP entry for {nbr['hostname']} on {nbr['local_intf']} - already found via CDP")
                                    break
                            if is_duplicate:
                                continue
                        
                        all_neighbors_by_ip[nbr["mgmt_ip"]].append(nbr)
        else:
            self.log("LLDP not enabled or available")
        
        if not all_neighbors_by_ip:
            self.log("No neighbors found via CDP or LLDP", "WARN")
            return [], None
        
        # Process neighbor groups and detect multiple links to same device
        all_neighbors = []
        for neighbor_ip, links in all_neighbors_by_ip.items():
            if len(links) > 1:
                # Multiple links to same device
                self.log(f"  ⚠️  Multiple links detected to {links[0]['hostname']} ({neighbor_ip}): {len(links)} links")
                
                # Add all links with a note
                for idx, nbr in enumerate(links, 1):
                    nbr["link_note"] = f"Multiple links to same device ({len(links)} total) - Link {idx}"
                    all_neighbors.append(nbr)
            else:
                # Single link
                all_neighbors.append(links[0])
        
        # Return list of neighbors
        protocol_str = "+".join(protocols_used) if protocols_used else None
        return all_neighbors, protocol_str

    def collect_device_info(self, mgmt_ip, skip_discovery=False):
        """Collect information from a single device"""
        self.log(f"\n{'='*60}")
        self.log(f"Collecting data from: {mgmt_ip}")
        
        if skip_discovery:
            self.log("⏭️  Skipping discovery for seed aggregate switch")
            return None
        
        # SSH to the device (unless it's the aggregate we're already on)
        ssh_accessible = True
        if mgmt_ip != AGGREGATE_ENTRY_IP and mgmt_ip not in [AGGREGATE_ENTRY_IP]:
            if not self.ssh_to_device(self.agg_shell, mgmt_ip):
                ssh_accessible = False
                self.log(f"⚠️  Cannot SSH to {mgmt_ip} - marking as inaccessible", "WARN")
                # Return minimal device info
                return {
                    "hostname": "Unknown",
                    "management_ip": mgmt_ip,
                    "serial_number": None,
                    "ios_version": None,
                    "switch_model": None,
                    "device_role": "unknown",
                    "discovery_protocol": None,
                    "notes": "Inaccessible via SSH",
                    "neighbors": []
                }
        
        try:
            # Collect device information
            hostname = self.get_hostname(self.agg_shell)
            self.log(f"Hostname: {hostname}")
            
            actual_mgmt_ip = self.get_management_ip(self.agg_shell)
            if not actual_mgmt_ip:
                actual_mgmt_ip = mgmt_ip
            self.log(f"Management IP (VLAN 100): {actual_mgmt_ip}")
            
            serial = self.get_serial_number(self.agg_shell)
            self.log(f"Serial Number: {serial}")
            
            ios_version = self.get_ios_version(self.agg_shell)
            self.log(f"IOS Version: {ios_version}")
            
            switch_model = self.get_switch_model(self.agg_shell)
            self.log(f"Switch Model: {switch_model}")
            
            # Determine device role
            device_role = self.determine_device_role(hostname)
            self.log(f"Device Role: {device_role}")
            
            # Discover neighbors
            neighbors, protocol = self.discover_neighbors(self.agg_shell, actual_mgmt_ip)
            
            # Build device info structure
            device_info = {
                "hostname": hostname,
                "management_ip": actual_mgmt_ip,
                "serial_number": serial,
                "ios_version": ios_version,
                "switch_model": switch_model,
                "device_role": device_role,
                "discovery_protocol": protocol,
                "notes": None,
                "neighbors": []
            }
            
            # Process neighbors
            for nbr in neighbors:
                discovery_method = nbr.get("discovered_via", "Unknown")
                link_note = nbr.get("link_note", "")
                note_str = f" [{link_note}]" if link_note else ""
                
                self.log(f"  → Neighbor: {nbr['hostname']} ({nbr['mgmt_ip']}) "
                        f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]{note_str}")
                
                neighbor_entry = {
                    "neighbor_hostname": nbr["hostname"],
                    "neighbor_mgmt_ip": nbr["mgmt_ip"],
                    "local_interface": nbr["local_intf"],
                    "remote_interface": nbr["remote_intf"],
                    "discovered_via": discovery_method
                }
                
                # Add link note if present
                if "link_note" in nbr:
                    neighbor_entry["link_note"] = nbr["link_note"]
                
                device_info["neighbors"].append(neighbor_entry)
                
                # Add to visit queue if not already visited and not the seed aggregate
                if (nbr["mgmt_ip"] not in self.visited and 
                    nbr["mgmt_ip"] not in [d for d in self.to_visit] and
                    nbr["mgmt_ip"] != self.seed_aggregate_ip):
                    self.to_visit.append(nbr["mgmt_ip"])
                    self.log(f"    Added {nbr['mgmt_ip']} to discovery queue")
                elif nbr["mgmt_ip"] == self.seed_aggregate_ip:
                    self.log(f"    Skipping seed aggregate {nbr['mgmt_ip']} - already discovered")
            
            # Exit back to aggregate (unless we're on the aggregate)
            if mgmt_ip != AGGREGATE_ENTRY_IP:
                self.exit_device(self.agg_shell)
                time.sleep(1)
            
            return device_info
            
        except Exception as e:
            self.log(f"Error collecting device info: {e}", "ERROR")
            # Try to exit anyway
            try:
                if mgmt_ip != AGGREGATE_ENTRY_IP:
                    self.exit_device(self.agg_shell)
            except:
                pass
            return None

    def run_discovery(self):
        """Main discovery loop"""
        self.log("="*60)
        self.log("Starting Network Topology Discovery")
        self.log("="*60)
        
        # Connect to aggregate
        agg_mgmt_ip = self.connect_to_aggregate()
        
        # Mark seed aggregate as visited but DON'T collect its info
        self.log("\n" + "="*60)
        self.log(f"Seed aggregate: {agg_mgmt_ip} - Skipping detailed collection")
        self.log("="*60)
        
        self.visited.add(agg_mgmt_ip)
        
        # Discover neighbors from seed aggregate to populate the queue
        self.log("Discovering neighbors from seed aggregate...")
        neighbors, protocol = self.discover_neighbors(self.agg_shell, agg_mgmt_ip)
        
        # Add neighbors to discovery queue
        for nbr in neighbors:
            discovery_method = nbr.get("discovered_via", "Unknown")
            link_note = nbr.get("link_note", "")
            note_str = f" [{link_note}]" if link_note else ""
            
            self.log(f"  → Found neighbor: {nbr['hostname']} ({nbr['mgmt_ip']}) "
                    f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]{note_str}")
            
            # Add to visit queue
            if nbr["mgmt_ip"] not in self.to_visit:
                self.to_visit.append(nbr["mgmt_ip"])
                self.log(f"    Added {nbr['mgmt_ip']} to discovery queue")
        
        # Add any additional aggregate IPs from config (but not the seed)
        for ip in AGGREGATE_MGMT_IPS:
            if ip != agg_mgmt_ip and ip not in self.to_visit:
                self.to_visit.append(ip)
        
        # Discovery loop for remaining devices
        while self.to_visit:
            current_ip = self.to_visit.popleft()
            
            if current_ip in self.visited:
                self.log(f"Skipping {current_ip} - already visited")
                continue
            
            self.visited.add(current_ip)
            device_info = self.collect_device_info(current_ip)
            
            if device_info:
                self.devices[current_ip] = device_info
            else:
                self.log(f"Failed to collect info from {current_ip}", "ERROR")
        
        # Cleanup
        if self.agg_client:
            self.agg_client.close()
        
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        self.log("="*60)
        self.log(f"Discovery complete! Found {len(self.devices)} devices")
        self.log(f"Total discovery time: {duration:.1f} seconds")
        self.log("="*60)

    def generate_json(self, filename="network_topology.json"):
        """Generate clean JSON output as a simple array of devices"""
        # Output just the list of devices, no wrapper
        devices_list = list(self.devices.values())
        
        with open(filename, "w") as f:
            json.dump(devices_list, f, indent=2)
        
        self.log(f"\n✅ Topology saved to {filename}")
        
        # Print summary
        self.log("\n" + "="*60)
        self.log("DISCOVERY SUMMARY")
        self.log("="*60)
        self.log(f"Total devices discovered: {len(devices_list)}")
        
        # Count by role
        role_counts = {}
        for device in devices_list:
            role = device.get("device_role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1
        
        self.log("\nDevices by role:")
        for role, count in sorted(role_counts.items()):
            self.log(f"  {role}: {count}")
        
        self.log("="*60)
        
        for device in devices_list:
            notes_str = f" [{device['notes']}]" if device.get('notes') else ""
            self.log(f"\n{device['hostname']} ({device['management_ip']}) - {device['device_role']}{notes_str}")
            self.log(f"  Model: {device.get('switch_model', 'N/A')}")
            self.log(f"  IOS Version: {device.get('ios_version', 'N/A')}")
            self.log(f"  Serial: {device['serial_number']}")
            self.log(f"  Neighbors: {len(device['neighbors'])}")
            for nbr in device["neighbors"]:
                discovered = nbr.get("discovered_via", "Unknown")
                link_note = nbr.get("link_note", "")
                link_str = f" - {link_note}" if link_note else ""
                self.log(f"    • {nbr['neighbor_hostname']} via "
                        f"{nbr['local_interface']} ↔ {nbr['remote_interface']} [{discovered}]{link_str}")
    
    def write_metadata(self, filename="discovery_metadata.txt"):
        """Write discovery metadata and statistics to a separate file"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        with open(filename, "w") as f:
            f.write("="*60 + "\n")
            f.write("NETWORK TOPOLOGY DISCOVERY METADATA\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Discovery Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Entry Point: {AGGREGATE_ENTRY_IP}\n")
            f.write(f"Seed Aggregate: {self.seed_aggregate_ip}\n")
            f.write(f"Duration: {duration:.1f} seconds\n")
            f.write(f"Total Devices Discovered: {len(self.devices)}\n\n")
            
            # Device role breakdown
            f.write("="*60 + "\n")
            f.write("DEVICE ROLES\n")
            f.write("="*60 + "\n")
            role_counts = {}
            for device in self.devices.values():
                role = device.get("device_role", "unknown")
                role_counts[role] = role_counts.get(role, 0) + 1
            
            for role, count in sorted(role_counts.items()):
                f.write(f"  {role}: {count}\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write("AGGREGATE SWITCHES CONFIGURED\n")
            f.write("="*60 + "\n")
            if AGGREGATE_MGMT_IPS:
                for ip in AGGREGATE_MGMT_IPS:
                    f.write(f"  • {ip}\n")
            else:
                f.write("  None configured (auto-discovery only)\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write("DISCOVERY STATISTICS\n")
            f.write("="*60 + "\n")
            
            # Count protocols used
            cdp_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") and "CDP" in d["discovery_protocol"])
            lldp_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") and "LLDP" in d["discovery_protocol"])
            both_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") == "CDP+LLDP")
            no_protocol = sum(1 for d in self.devices.values() if not d.get("discovery_protocol"))
            
            f.write(f"Devices with CDP only: {cdp_count - both_count}\n")
            f.write(f"Devices with LLDP only: {lldp_count - both_count}\n")
            f.write(f"Devices with both CDP+LLDP: {both_count}\n")
            if no_protocol > 0:
                f.write(f"Devices without discovery protocol: {no_protocol}\n")
            
            # Total neighbors
            total_neighbors = sum(len(d["neighbors"]) for d in self.devices.values())
            f.write(f"Total neighbor relationships: {total_neighbors}\n")
            
            # Count inaccessible devices
            inaccessible = sum(1 for d in self.devices.values() if d.get("notes") == "Inaccessible via SSH")
            if inaccessible > 0:
                f.write(f"Inaccessible devices (via SSH): {inaccessible}\n")
            
            # Count multiple links
            multiple_link_count = 0
            for device in self.devices.values():
                for nbr in device["neighbors"]:
                    if "link_note" in nbr and "Multiple links" in nbr["link_note"]:
                        multiple_link_count += 1
            
            if multiple_link_count > 0:
                f.write(f"Connections with multiple links: {multiple_link_count}\n")
            
        self.log(f"📊 Metadata saved to {filename}")


if __name__ == "__main__":
    discovery = NetworkDiscovery()
    
    # Open log file
    log_filename = "discovery_log.txt"
    try:
        discovery.log_file = open(log_filename, "w")
        discovery.log(f"Log file created: {log_filename}")
    except Exception as e:
        print(f"Warning: Could not create log file: {e}")
    
    try:
        discovery.run_discovery()
        discovery.generate_json()
        discovery.write_metadata()
        
        # Close log file
        if discovery.log_file:
            discovery.log_file.close()
            
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Discovery stopped by user")
        if discovery.log_file:
            discovery.log_file.write("\n\n[INTERRUPTED] Discovery stopped by user\n")
            discovery.log_file.close()
    except Exception as e:
        print(f"\n\n[FATAL ERROR] {e}")
        if discovery.log_file:
            discovery.log_file.write(f"\n\n[FATAL ERROR] {e}\n")
            discovery.log_file.close()
        import traceback
        traceback.print_exc()
