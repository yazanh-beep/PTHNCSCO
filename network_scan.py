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
AGGREGATE_ENTRY_IP = "192.168.100.1"  # Entry point from server
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
        self.agg_shell = None  # Persistent shell to aggregate switch
        self.agg_client = None
        self.log_file = None  # File handle for logging
        self.start_time = datetime.now()
        
    def log(self, msg, level="INFO"):
        """Clean logging output - prints to console and file"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] [{level}] {msg}"
        print(log_line)
        
        # Also write to log file if it's open
        if self.log_file:
            self.log_file.write(log_line + "\n")
            self.log_file.flush()  # Ensure it's written immediately

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
                return mgmt_ip
            else:
                self.log("WARNING: Could not determine VLAN 100 IP, using entry IP", "WARN")
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
            if m := re.match(r"^([^#>\s]+)[#>]", line):
                return m.group(1)
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
            
            # Device ID / Hostname
            if m := re.search(r"Device ID:\s*(\S+)", block):
                neighbor["hostname"] = m.group(1).split('.')[0]  # Remove domain if present
            
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
            
            # System Name (hostname) - extract full name from detail output
            # The System Name line format is: "System Name: FULL-HOSTNAME-HERE"
            # It can span to the next line, and may include dots/dashes
            if m := re.search(r"System Name:\s*([^\n]+)", block, re.IGNORECASE):
                hostname = m.group(1).strip()
                # Remove quotes if present
                hostname = hostname.strip('"').strip("'")
                # Remove domain suffix only if it ends with common TLDs
                # Keep internal dots like "SWITCH.2-1-1" intact
                if hostname.endswith(('.com', '.net', '.org', '.local', '.int', '.INT')):
                    hostname = hostname.rsplit('.', 1)[0]
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

    def discover_neighbors(self, shell):
        """Discover neighbors using BOTH CDP and LLDP, merge results with CDP priority"""
        all_neighbors = {}  # Key: mgmt_ip, Value: neighbor info
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
                        all_neighbors[nbr["mgmt_ip"]] = nbr
        else:
            self.log("CDP not enabled or available")
        
        # Also try LLDP
        self.log("Checking LLDP neighbors...")
        lldp_output = self.send_cmd(shell, "show lldp neighbors detail", timeout=20, silent=True)
        
        # Debug: Print raw LLDP output to see what we're getting
        if lldp_output and "LLDP is not enabled" not in lldp_output:
            self.log("DEBUG: LLDP raw output (first 2000 chars):", "DEBUG")
            print(lldp_output[:2000])
            print("="*60)
        
        if "LLDP is not enabled" not in lldp_output and "Invalid input" not in lldp_output:
            lldp_neighbors = self.parse_lldp_neighbors(lldp_output)
            if lldp_neighbors:
                self.log(f"Found {len(lldp_neighbors)} LLDP neighbors")
                protocols_used.append("LLDP")
                for nbr in lldp_neighbors:
                    if nbr["mgmt_ip"]:
                        # Only add if not already found via CDP (CDP takes priority)
                        if nbr["mgmt_ip"] not in all_neighbors:
                            nbr["discovered_via"] = "LLDP"
                            all_neighbors[nbr["mgmt_ip"]] = nbr
                        else:
                            self.log(f"  Device {nbr['hostname']} ({nbr['mgmt_ip']}) already in CDP - using CDP data")
        else:
            self.log("LLDP not enabled or available")
        
        if not all_neighbors:
            self.log("No neighbors found via CDP or LLDP", "WARN")
            return [], None
        
        # Return list of unique neighbors
        protocol_str = "+".join(protocols_used) if protocols_used else None
        return list(all_neighbors.values()), protocol_str

    def collect_device_info(self, mgmt_ip):
        """Collect information from a single device"""
        self.log(f"\n{'='*60}")
        self.log(f"Collecting data from: {mgmt_ip}")
        
        # SSH to the device (unless it's the aggregate we're already on)
        if mgmt_ip != AGGREGATE_ENTRY_IP and mgmt_ip not in [AGGREGATE_ENTRY_IP]:
            if not self.ssh_to_device(self.agg_shell, mgmt_ip):
                return None
        
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
            
            # Discover neighbors
            neighbors, protocol = self.discover_neighbors(self.agg_shell)
            
            # Build device info structure
            device_info = {
                "hostname": hostname,
                "management_ip": actual_mgmt_ip,
                "serial_number": serial,
                "discovery_protocol": protocol,
                "neighbors": []
            }
            
            # Process neighbors
            for nbr in neighbors:
                discovery_method = nbr.get("discovered_via", "Unknown")
                self.log(f"  → Neighbor: {nbr['hostname']} ({nbr['mgmt_ip']}) "
                        f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]")
                
                neighbor_entry = {
                    "neighbor_hostname": nbr["hostname"],
                    "neighbor_mgmt_ip": nbr["mgmt_ip"],
                    "local_interface": nbr["local_intf"],
                    "remote_interface": nbr["remote_intf"],
                    "discovered_via": discovery_method
                }
                device_info["neighbors"].append(neighbor_entry)
                
                # Add to visit queue if not already visited
                if nbr["mgmt_ip"] not in self.visited and nbr["mgmt_ip"] not in [d for d in self.to_visit]:
                    self.to_visit.append(nbr["mgmt_ip"])
                    self.log(f"    Added {nbr['mgmt_ip']} to discovery queue")
            
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
        
        # Start with aggregate switch
        self.to_visit.append(agg_mgmt_ip)
        
        # Add any additional aggregate IPs from config
        for ip in AGGREGATE_MGMT_IPS:
            if ip not in self.to_visit:
                self.to_visit.append(ip)
        
        # Discovery loop
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
        self.log("="*60)
        
        for device in devices_list:
            self.log(f"\n{device['hostname']} ({device['management_ip']})")
            self.log(f"  Serial: {device['serial_number']}")
            self.log(f"  Neighbors: {len(device['neighbors'])}")
            for nbr in device["neighbors"]:
                discovered = nbr.get("discovered_via", "Unknown")
                self.log(f"    • {nbr['neighbor_hostname']} via "
                        f"{nbr['local_interface']} ↔ {nbr['remote_interface']} [{discovered}]")
    
    def write_metadata(self, filename="discovery_metadata.txt"):
        """Write discovery metadata and statistics to a separate file"""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        with open(filename, "w") as f:
            f.write("="*60 + "\n")
            f.write("NETWORK TOPOLOGY DISCOVERY METADATA\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Discovery Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Entry Point: {AGGREGATE_ENTRY_IP}\n")
            f.write(f"Duration: {duration:.1f} seconds\n")
            f.write(f"Total Devices Discovered: {len(self.devices)}\n\n")
            
            f.write("="*60 + "\n")
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
            cdp_count = sum(1 for d in self.devices.values() if "CDP" in d.get("discovery_protocol", ""))
            lldp_count = sum(1 for d in self.devices.values() if "LLDP" in d.get("discovery_protocol", ""))
            both_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") == "CDP+LLDP")
            
            f.write(f"Devices with CDP: {cdp_count}\n")
            f.write(f"Devices with LLDP: {lldp_count}\n")
            f.write(f"Devices with both CDP+LLDP: {both_count}\n")
            
            # Total neighbors
            total_neighbors = sum(len(d["neighbors"]) for d in self.devices.values())
            f.write(f"Total neighbor relationships: {total_neighbors}\n")
            
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
