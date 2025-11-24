#!/usr/bin/env python3
"""
Smart Network Topology Discovery Tool (Cisco-CLI Nested SSH, Depth-Safe)

- Cisco CDP/LLDP topology discovery via nested SSH hops (from aggregate CLI)
- Interactive SSH hop state machine handles banners/yes-no/Username/Password
- Multi-credential login+enable fallback (per-device caching)
- Session depth tracking to avoid exiting the seed accidentally
- Robust cleanup on failed hops; reconnect seed only when truly lost
- Hostname-change verification after hop (prevents false successes)
- Exports: network_topology.json + discovery_metadata.txt
"""

import paramiko
import time
import re
import json
from datetime import datetime
from collections import deque

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
AGGREGATE_ENTRY_IP = ""  # First hop from the server

# Ordered credential sets to try (add more as needed)
# "enable": "" means "reuse the login password as enable"
CREDENTIAL_SETS = [
    {"username": "",  "password": "",  "enable": ""}
]

# Optional: pre-known aggregate SVI mgmt IPs (besides seed)
AGGREGATE_MGMT_IPS = [
    # "10.0.100.2", "10.0.100.3",
]

# Timeouts/retries
TIMEOUT = 12
MAX_READ = 65535
SSH_RETRY_ATTEMPTS = 10
SSH_RETRY_DELAY = 30
CDP_LLDP_TIMEOUT = 35

# Aggregate (seed) reconnect policy
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
# ─────────────────────────────────────────────────────────────────────────────

# Prompt detection: a line ending in '>' or '#'
PROMPT_RE = re.compile(r"(?m)^[^\r\n#>\s][^\r\n#>]*[>#]\s?$")

# Failure snippets (IOS/SSH variations)
FAIL_SNIPPETS = (
    "Connection refused", "Unable to connect", "Connection timed out",
    "No route to host", "Host is unreachable", "Closed by remote host",
    "Connection closed by", "Could not resolve", "Unknown host",
    "Host key verification failed", "% Authentication failed",
    "Permission denied", "% Bad passwords", "% Login invalid"
)

CDP_IP_PATTERNS = (
    r"IPv4 [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
    r"IP [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
    r"Management [Aa]ddress(?:es)?:.*?IP(?:v4)?:\s*(\d+\.\d+\.\d+\.\d+)",
)

LLDP_IP_PATTERNS = (
    r"Management [Aa]ddresses?:.*?IP(?:v4)?:\s*(\d+\.\d+\.\d+\.\d+)",
    r"Management [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)",
    r"Mgmt IP:\s*(\d+\.\d+\.\d+\.\d+)",
)

# ─── Exceptions ──────────────────────────────────────────────────────────────
class NetworkConnectionError(Exception):
    """Network/SSH issues that may allow retry or require reconnect to seed."""
    def __init__(self, message, retry_allowed=False, reconnect_needed=False):
        super().__init__(message)
        self.retry_allowed = retry_allowed
        self.reconnect_needed = reconnect_needed

class ConfigurationError(Exception):
    """Static config issues."""
    pass

class NetworkDiscovery:
    def __init__(self):
        # State
        self.devices = {}
        self.to_visit = deque()
        self.visited = set()
        self.hostname_to_ip = {}
        self.seed_aggregate_ip = None
        self.agg_shell = None
        self.agg_client = None
        self.start_time = datetime.now()
        self.link_tracking = {}
        self.agg_creds = None
        self.device_creds = {}
        self.agg_hostname = None
        self.session_depth = 0
        self._neighbor_platform_cache = {}

        # Logging
        self.log_file = None
        self.log_filename = "discovery_log.txt"

    # ── Logging ────────────────────────────────────────────────────────────
    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        print(line)
        if self.log_file:
            try:
                self.log_file.write(line + "\n")
                self.log_file.flush()
            except Exception:
                pass

    # ── Shell helpers ─────────────────────────────────────────────────────
    def _drain(self, shell):
        time.sleep(0.05)
        buf = ""
        while shell and not shell.closed and shell.recv_ready():
            try:
                buf += shell.recv(MAX_READ).decode("utf-8", "ignore")
            except Exception:
                break
            time.sleep(0.02)
        return buf

    def expect_prompt(self, shell, timeout=TIMEOUT):
        buf, end = "", time.time() + timeout
        while time.time() < end:
            if shell and not shell.closed and shell.recv_ready():
                try:
                    buf += shell.recv(MAX_READ).decode("utf-8", "ignore")
                except Exception:
                    break
                if PROMPT_RE.search(buf):
                    return buf
            else:
                time.sleep(0.05)
        return buf

    def send_cmd(self, shell, cmd, timeout=TIMEOUT, silent=False):
        if not silent:
            self.log(f"CMD: {cmd}", "DEBUG")
        if not shell or shell.closed:
            raise NetworkConnectionError("SSH shell is closed", reconnect_needed=True)
        try:
            _ = self._drain(shell)
            shell.send(cmd + "\n")
            return self.expect_prompt(shell, timeout=timeout)
        except Exception as e:
            self.log(f"Exception in send_cmd('{cmd}'): {e}", "ERROR")
            raise NetworkConnectionError(f"Send command failed: {e}", reconnect_needed=True)

    # ── Privilege handling ────────────────────────────────────────────────
    def _ensure_enable(self, shell, enable_candidates, timeout=10):
        """Ensure privileged EXEC. Try each enable password only if prompted."""
        out = self.send_cmd(shell, "", timeout=3, silent=True)
        if out.strip().endswith("#"):
            return True
        en = self.send_cmd(shell, "enable", timeout=5, silent=True)
        if en.strip().endswith("#"):
            return True
        if re.search(r"[Pp]assword:", en):
            for pw in enable_candidates:
                if pw is None:
                    continue
                if pw == "":
                    continue
                test = self.send_cmd(shell, pw, timeout=timeout, silent=True)
                if test.strip().endswith("#"):
                    return True
            test = self.send_cmd(shell, "", timeout=timeout, silent=True)
            if test.strip().endswith("#"):
                return True
            self.log("Enable failed with all provided enable passwords", "ERROR")
            return False
        out2 = self.send_cmd(shell, "", timeout=3, silent=True)
        return out2.strip().endswith("#")

    # ── Aggregate verification & reconnection ─────────────────────────────
    def verify_aggregate_connection(self):
        """Return True if the aggregate shell is alive and responsive."""
        try:
            if not self.agg_shell or self.agg_shell.closed:
                return False
            self.agg_shell.send("\n")
            time.sleep(0.3)
            if self.agg_shell.recv_ready():
                data = self.agg_shell.recv(MAX_READ).decode("utf-8", "ignore")
                return bool(PROMPT_RE.search(data))
            return False
        except Exception:
            return False

    def cleanup_failed_session(self):
        """Clean up a failed nested SSH attempt without logging out of the seed."""
        sh = self.agg_shell
        try:
            if not sh or sh.closed:
                self.log("[CLEANUP] Shell closed; skipping cleanup", "DEBUG")
                return False

            self.log("[CLEANUP] Cleaning up failed SSH attempt", "DEBUG")

            try:
                sh.send("\x03")
                time.sleep(0.2)
            except Exception:
                pass

            _ = self._drain(sh)

            if self.session_depth > 0:
                try:
                    sh.send("exit\n")
                    time.sleep(0.6)
                    _ = self._drain(sh)
                    self.session_depth = max(0, self.session_depth - 1)
                except Exception:
                    pass

            try:
                sh.send("\n")
                time.sleep(0.2)
                data = self._drain(sh)
                ok = bool(PROMPT_RE.search(data))
            except Exception:
                ok = False

            if not ok:
                self.log("[CLEANUP] Could not verify prompt", "WARN")
            return ok
        except Exception as e:
            self.log(f"[CLEANUP] Exception: {e}", "DEBUG")
            return False

    def reconnect_to_aggregate(self, reason=""):
        """Reconnect to the seed/aggregate with retries."""
        last_err = None
        if reason:
            self.log(f"[RECONNECT] Reconnecting to aggregate: {reason}", "WARN")
        try:
            if self.agg_client:
                self.agg_client.close()
        except Exception:
            pass
        for attempt in range(AGG_MAX_RETRIES):
            self.log(f"[RECONNECT] Attempt {attempt+1}/{AGG_MAX_RETRIES} to {AGGREGATE_ENTRY_IP}")
            try:
                mgmt_ip = self._connect_to_aggregate_internal()
                self.log("[RECONNECT] Reconnected to seed", "INFO")
                return mgmt_ip
            except Exception as e:
                last_err = e
                time.sleep(AGG_RETRY_DELAY)
        raise NetworkConnectionError(
            f"Failed to reconnect to seed after {AGG_MAX_RETRIES} attempts: {last_err}",
            reconnect_needed=True
        )

    # ── Hostname normalization ────────────────────────────────────────────
def normalize_hostname(self, hostname):
    """
    Normalize hostname by stripping domain suffixes only.
    Preserves unique device identifiers in the hostname.
    
    Examples:
        "CL-SCL-CNO1A-SMSACC1.4-1-12.CAM.INT" -> "CL-SCL-CNO1A-SMSACC1.4-1-12"
        "CL-SCL-CNO1A-SMSACC1.1K-1-17.CAM.INT" -> "CL-SCL-CNO1A-SMSACC1.1K-1-17"
        "AGG-SW1.example.com" -> "AGG-SW1.example.com" (if not in known domains)
    """
    if not hostname:
        return hostname
    
    # List of known domain suffixes to remove
    domain_suffixes = [
        r'\.CAM\.INT$',
        r'\.cam\.int$',
        # Add more domain patterns here if needed
        # r'\.example\.com$',
    ]
    
    # Try to remove each known domain suffix
    for suffix_pattern in domain_suffixes:
        hostname = re.sub(suffix_pattern, '', hostname, flags=re.IGNORECASE)
    
    return hostname
    # ── Device role helper ────────────────────────────────────────────────
    def determine_device_role(self, hostname):
        up = (hostname or "").upper()
        if "SRV" in up: return "server"
        if "AGG" in up: return "aggregate"
        if "ACC" in up: return "access"
        if "IE"  in up: return "field"
        return "unknown"

    # ── Basic getters ─────────────────────────────────────────────────────
    def get_hostname(self, shell):
        shell.send("\n")
        time.sleep(0.2)
        buff = self.expect_prompt(shell, timeout=4)
        for line in reversed(buff.splitlines()):
            line = line.strip()
            m = re.match(r"^([^#>\s]+(?:\.[^#>\s]+)*)[#>]", line)
            if m:
                return self.normalize_hostname(m.group(1))
        return "Unknown"

    def get_management_ip(self, shell):
        """Try Vlan100 first, then any up/up Vlan with IP (pref Vlan100), else None."""
        out = self.send_cmd(shell, "show run interface vlan 100", timeout=8, silent=True)
        m = re.search(r"\bip address\s+(\d+\.\d+\.\d+\.\d+)\s+\d+", out)
        if m:
            return m.group(1)

        out = self.send_cmd(shell, "show ip interface brief | include Vlan", timeout=6, silent=True)
        candidates = []
        for line in out.splitlines():
            mm = re.search(r"^(Vlan\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+up\s+up", line.strip())
            if mm:
                svi, ip = mm.groups()
                candidates.append((svi.lower(), ip))
        if candidates:
            for svi, ip in candidates:
                if svi == "vlan100":
                    return ip
            return sorted(candidates)[0][1]
        return None

    def get_serial_number(self, shell):
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        for pat in (r"System [Ss]erial [Nn]umber\s*:?\s*(\S+)",
                    r"Processor board ID\s+(\S+)",
                    r"System Serial Number\s*:?\s*(\S+)"):
            m = re.search(pat, output)
            if m and m.group(1).lower() not in ("unknown", "n/a"):
                return m.group(1)
        return None

    def get_ios_version(self, shell):
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        for pat in (r"Cisco IOS Software.*?Version\s+([^,\s]+)",
                    r"IOS.*?Software.*?Version\s+([^,\s]+)",
                    r"Version\s+(\d+\.\d+[^\s,]*)"):
            m = re.search(pat, output, re.I)
            if m:
                return m.group(1)
        return None

    def get_switch_model(self, shell):
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        pats = (
            r"Model [Nn]umber\s*:?\s*(\S+)",
            r"cisco\s+([A-Z0-9\-]+)\s+\([^\)]+\)\s+processor",
            r"Model:\s*(\S+)",
            r"Hardware:\s*(\S+)",
            r"cisco\s+(WS-[A-Z0-9\-]+)",
            r"cisco\s+(C[0-9]{4}[A-Z0-9\-]*)",
            r"cisco\s+(IE-[0-9]{4}[A-Z0-9\-]*)",
            r"System image file is.*?:([A-Z0-9\-]+)",
        )
        for pat in pats:
            m = re.search(pat, output, re.I)
            if m:
                model = m.group(1)
                if model.lower() not in ("unknown", "n/a", "bytes"):
                    return model
        return None

    # ── Discovery pieces ──────────────────────────────────────────────────
    def normalize_interface_name(self, interface):
        if not interface:
            return interface
        repl = {
            'Te': 'TenGigabitEthernet',
            'Gi': 'GigabitEthernet',
            'Fa': 'FastEthernet',
            'Et': 'Ethernet',
            'Po': 'Port-channel',
            'Vl': 'Vlan'
        }
        interface = interface.strip()
        for short, full in repl.items():
            if interface.startswith(short) and len(interface) > len(short):
                nxt = interface[len(short)]
                if nxt.isdigit() or nxt == '/':
                    return interface.replace(short, full, 1)
        return interface

    def parse_cdp_neighbors(self, output):
        neighbors = []
        blocks = re.split(r"(?=^Device ID:\s*)", output, flags=re.M)
        for block in blocks:
            if "Device ID:" not in block:
                continue
            nbr = {
                "hostname": None,
                "mgmt_ip": None,
                "local_intf": None,
                "remote_intf": None,
                "platform": None,
                "source": "CDP"
            }
            m = re.search(r"Device ID:\s*([^\s]+)", block)
            if m:
                nbr["hostname"] = self.normalize_hostname(m.group(1))

            for pat in CDP_IP_PATTERNS:
                m = re.search(pat, block, flags=re.I | re.S)
                if m:
                    nbr["mgmt_ip"] = m.group(1)
                    break

            m = re.search(r"Interface:\s*([^\s,]+)", block)
            if m:
                nbr["local_intf"] = m.group(1)

            m = re.search(r"Port ID[^:]*:\s*([^\s]+)", block, flags=re.I)
            if m:
                nbr["remote_intf"] = m.group(1)

            m = re.search(r"Platform:\s*([^,\n]+)", block)
            if m:
                nbr["platform"] = m.group(1).strip()
                if nbr["mgmt_ip"]:
                    self._neighbor_platform_cache[nbr["mgmt_ip"]] = nbr["platform"]

            if nbr["hostname"] and nbr["mgmt_ip"]:
                if not nbr["platform"] or "cisco" in nbr["platform"].lower():
                    neighbors.append(nbr)
        return neighbors

    def parse_lldp_neighbors(self, output):
        """
        Parse 'show lldp neighbors detail' output and extract neighbor information.
        Filters out non-Cisco devices based on hostname patterns and system description.
        
        Returns: list of dicts with keys: hostname, mgmt_ip, local_intf, remote_intf
        """
        # Patterns to identify non-Cisco devices
        NON_CISCO_PATTERNS = [
            r'^axis-',           # Axis cameras
            r'^SEP[A-F0-9]{12}', # Cisco IP phones
            r'^AP[A-F0-9]+',     # Standalone access points
            r'^printer-',
            r'^camera-',
            r'^phone-',
        ]
        
        neighbors = []
        
        if not output or "Total entries displayed: 0" in output:
            return neighbors
        
        # Split by separator to get individual neighbor blocks
        blocks = output.split("------------------------------------------------")
        
        for block in blocks:
            # Skip empty blocks or blocks without interface info
            if "Local Intf:" not in block:
                continue
            
            try:
                neighbor = {}
                
                # Extract local interface
                local_match = re.search(r"Local Intf:\s*(\S+)", block)
                if not local_match:
                    self.log("  Warning: LLDP block missing Local Intf", "DEBUG")
                    continue
                neighbor["local_intf"] = local_match.group(1)
                
                # Extract system name (hostname)
                name_match = re.search(r"System Name:\s*(\S+)", block)
                if not name_match:
                    self.log(f"  Warning: LLDP block on {neighbor['local_intf']} missing System Name", "DEBUG")
                    continue
                hostname = self.normalize_hostname(name_match.group(1))
                neighbor["hostname"] = hostname
                
                # FILTER 1: Check hostname pattern for non-Cisco devices
                is_non_cisco = any(re.match(pattern, hostname, re.IGNORECASE) 
                                  for pattern in NON_CISCO_PATTERNS)
                if is_non_cisco:
                    self.log(f"  ⊗ Skipping non-Cisco device (pattern match): {hostname}", "DEBUG")
                    continue
                
                # FILTER 2: Check System Description for Cisco IOS/NX-OS
                has_cisco_desc = ("Cisco IOS" in block or 
                                "Cisco NX-OS" in block or
                                "IOS-XE" in block or
                                "IOS XE" in block)
                
                if not has_cisco_desc:
                    # Extract a snippet of the description for logging
                    desc_match = re.search(r"System Description:\s*\n(.{0,50})", block)
                    desc_snippet = desc_match.group(1).strip() if desc_match else "Unknown"
                    self.log(f"  ⊗ Skipping non-Cisco device (no Cisco OS): {hostname} - {desc_snippet}", "DEBUG")
                    continue
                
                # Extract remote port ID
                port_match = re.search(r"Port id:\s*(\S+)", block)
                if port_match:
                    neighbor["remote_intf"] = port_match.group(1)
                else:
                    self.log(f"  Warning: No Port ID found for {hostname}", "DEBUG")
                    neighbor["remote_intf"] = "Unknown"
                
                # Extract management IP address
                # Try multiple patterns as different IOS versions format it differently
                mgmt_ip = None
                
                # Pattern 1: Multi-line format with "Management Addresses:" header
                ip_match1 = re.search(r"Management Addresses:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)", block)
                if ip_match1:
                    mgmt_ip = ip_match1.group(1)
                
                # Pattern 2: Single line format
                if not mgmt_ip:
                    ip_match2 = re.search(r"Management Address:\s*(\d+\.\d+\.\d+\.\d+)", block)
                    if ip_match2:
                        mgmt_ip = ip_match2.group(1)
                
                # Pattern 3: IPv4 prefix
                if not mgmt_ip:
                    ip_match3 = re.search(r"Management.*?IPv4:\s*(\d+\.\d+\.\d+\.\d+)", block)
                    if ip_match3:
                        mgmt_ip = ip_match3.group(1)
                
                # Pattern 4: Direct IP pattern anywhere in Management section
                if not mgmt_ip:
                    mgmt_section = re.search(r"Management.*?(?=\n[A-Z]|\n\n|$)", block, re.DOTALL)
                    if mgmt_section:
                        ip_match4 = re.search(r"(\d+\.\d+\.\d+\.\d+)", mgmt_section.group(0))
                        if ip_match4:
                            mgmt_ip = ip_match4.group(1)
                
                if mgmt_ip:
                    neighbor["mgmt_ip"] = mgmt_ip
                else:
                    self.log(f"  Warning: No management IP found for {hostname} on {neighbor['local_intf']}", "WARN")
                    # Still add the neighbor but mark it as inaccessible
                    neighbor["mgmt_ip"] = None
                    neighbor["note"] = "No management IP in LLDP"
                
                # Optional: Extract chassis ID for additional info
                chassis_match = re.search(r"Chassis id:\s*([a-fA-F0-9.:]+)", block)
                if chassis_match:
                    neighbor["chassis_id"] = chassis_match.group(1)
                
                # Optional: Extract system capabilities
                cap_match = re.search(r"System Capabilities:\s*([A-Z,\s]+)", block)
                if cap_match:
                    neighbor["capabilities"] = cap_match.group(1).strip()
                
                # Optional: Extract port description
                port_desc_match = re.search(r"Port Description:\s*(.+?)(?=\n|$)", block)
                if port_desc_match:
                    neighbor["port_description"] = port_desc_match.group(1).strip()
                
                # Add discovery method marker
                neighbor["discovered_via"] = "LLDP"
                
                # Only add if we have the minimum required fields
                if neighbor.get("hostname") and neighbor.get("local_intf"):
                    neighbors.append(neighbor)
                    self.log(f"  ✓ Parsed LLDP neighbor: {neighbor['hostname']} "
                            f"({neighbor.get('mgmt_ip', 'No-IP')}) via "
                            f"{neighbor['local_intf']} ↔ {neighbor['remote_intf']}", "DEBUG")
                
            except Exception as e:
                self.log(f"  Error parsing LLDP block: {e}", "ERROR")
                self.log(f"  Block content: {block[:200]}...", "DEBUG")
                continue
        
        return neighbors

    def discover_neighbors(self, shell, current_device_ip):
        """Discover neighbors using CDP then LLDP; prefer CDP IP globally."""
        all_by_host = {}
        protocols_used = []

        self.log("Checking CDP neighbors...")
        cdp_out = self.send_cmd(shell, "show cdp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
        if "Invalid input" not in cdp_out and "CDP is not enabled" not in cdp_out:
            cdp_neighbors = self.parse_cdp_neighbors(cdp_out)
            if cdp_neighbors:
                self.log(f"Found {len(cdp_neighbors)} CDP neighbors")
                protocols_used.append("CDP")
                for nbr in cdp_neighbors:
                    nbr["discovered_via"] = "CDP"
                    normalized_hn = nbr["hostname"]  # Already normalized by parser
                    self.log(f"  [CDP] Storing {normalized_hn} -> {nbr['mgmt_ip']} globally", "DEBUG")
                    # Store in global hostname_to_ip (CDP always wins)
                    self.hostname_to_ip[normalized_hn] = nbr["mgmt_ip"]
                    all_by_host.setdefault(normalized_hn, []).append(nbr)
        else:
            self.log("CDP not enabled or available")

        self.log("Checking LLDP neighbors...")
        lldp_out = self.send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
        
        try:
            debug_filename = f"lldp_debug_{current_device_ip.replace('.', '_')}.txt"
            with open(debug_filename,  "w" ,encoding='utf-8') as f:
                f.write(lldp_out)
            self.log(f"[DEBUG] LLDP output saved to {debug_filename}", "DEBUG")
        except Exception as e:
            self.log(f"[DEBUG] Could not save LLDP debug output: {e}", "DEBUG")
        
        if "Invalid input" not in lldp_out and "LLDP is not enabled" not in lldp_out:
            lldp_neighbors = self.parse_lldp_neighbors(lldp_out)
            if lldp_neighbors:
                self.log(f"Found {len(lldp_neighbors)} LLDP neighbors")
                protocols_used.append("LLDP")
                for nbr in lldp_neighbors:
                    nbr["discovered_via"] = "LLDP"
                    normalized_hn = nbr["hostname"]  # Already normalized by parser
                    
                    self.log(f"  [LLDP] Processing {normalized_hn} with IP {nbr.get('mgmt_ip')}", "DEBUG")
                    
                    # Check for duplicates BEFORE modifying IP or adding to all_by_host
                    is_dup_intf = False
                    if normalized_hn in all_by_host:
                        lldp_intf_norm = self.normalize_interface_name(nbr["local_intf"]) if nbr["local_intf"] else None
                        for existing in all_by_host[normalized_hn]:
                            exist_intf_norm = self.normalize_interface_name(existing.get("local_intf"))
                            if existing.get("discovered_via") == "CDP" and exist_intf_norm == lldp_intf_norm:
                                self.log(f"  [LLDP] Skipping LLDP entry for {nbr['hostname']} on {nbr['local_intf']} (CDP already on same interface)", "DEBUG")
                                is_dup_intf = True
                                break
                    
                    # Skip this neighbor if it's a duplicate
                    if is_dup_intf:
                        continue
                    
                    # Process IP address (prefer globally-known CDP IP if available)
                    if normalized_hn in self.hostname_to_ip:
                        auth_ip = self.hostname_to_ip[normalized_hn]
                        if nbr["mgmt_ip"] != auth_ip:
                            self.log(f"  [LLDP] IP differs: Global={auth_ip} vs LLDP={nbr['mgmt_ip']}, using Global IP", "INFO")
                            nbr["lldp_ip"] = nbr["mgmt_ip"]
                            nbr["mgmt_ip"] = auth_ip
                        else:
                            self.log(f"  [LLDP] IPs match, both are {auth_ip}", "DEBUG")
                    else:
                        self.log(f"  [LLDP] {normalized_hn} NOT in global map, using LLDP IP {nbr['mgmt_ip']}", "DEBUG")
                        self.hostname_to_ip[normalized_hn] = nbr["mgmt_ip"]
                    
                    # Add to all_by_host only if not a duplicate
                    all_by_host.setdefault(normalized_hn, []).append(nbr)
        else:
            self.log("LLDP not enabled or available")

        if not all_by_host:
            self.log("No neighbors found via CDP or LLDP", "WARN")
            return [], None

        all_neighbors = []
        for h, links in all_by_host.items():
            if len(links) > 1:
                self.log(f"   Multiple links detected to {h}: {len(links)} links")
                for idx, nbr in enumerate(links, 1):
                    nbr["link_note"] = f"Multiple links to same device ({len(links)} total) - Link {idx}"
                    all_neighbors.append(nbr)
            else:
                all_neighbors.append(links[0])

        proto = "+".join(protocols_used) if protocols_used else None
        return all_neighbors, proto

    # ── SSH connect/hop/exits ─────────────────────────────────────────────
    def _enable_candidates_for(self, ip):
        cands = []
        if ip in self.device_creds:
            c = self.device_creds[ip]
            cands += [c.get("enable") or c.get("password"), c.get("password")]
        if self.agg_creds:
            c = self.agg_creds
            cands += [c.get("enable") or c.get("password"), c.get("password")]
        seen = set()
        out = []
        for x in cands:
            if x and x not in seen:
                out.append(x)
                seen.add(x)
        return out or [""]

    def _interactive_hop(self, shell, ip, username, password, overall_timeout=90):
        """Drive IOS 'ssh' interactively until we reach a prompt or timeout."""
        start = time.time()
        buf = ""

        def feed(s):
            try:
                shell.send(s)
            except Exception:
                pass

        while time.time() - start < overall_timeout:
            time.sleep(0.15)
            if shell.recv_ready():
                try:
                    chunk = shell.recv(MAX_READ).decode("utf-8", "ignore")
                except Exception:
                    chunk = ""
                if chunk:
                    buf += chunk

            if PROMPT_RE.search(buf):
                return True, buf

            low = buf.lower()

            if "(yes/no)" in low or "yes/no" in low:
                feed("yes\n")
                continue

            if "username:" in low:
                feed(username + "\n")
                continue

            if "password:" in low:
                feed(password + "\n")
                time.sleep(0.5)
                continue

            fail_keys = (
                "connection refused", "unable to connect", "timed out",
                "no route to host", "host is unreachable",
                "closed by foreign host", "connection closed by",
                "authentication failed", "permission denied",
                "% bad passwords", "% login invalid"
            )
            if any(k in low for k in fail_keys):
                return False, buf

            if (time.time() - start) % 5 < 0.2:
                feed("\n")

        return False, buf

    def _connect_to_aggregate_internal(self):
        """Internal connect used by first connect and reconnect logic."""
        last_err = None
        for cred in CREDENTIAL_SETS:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    AGGREGATE_ENTRY_IP,
                    username=cred["username"],
                    password=cred["password"],
                    look_for_keys=False,
                    allow_agent=False,
                    timeout=15
                )
                transport = client.get_transport()
                if transport:
                    transport.set_keepalive(30)

                shell = client.invoke_shell()
                self.expect_prompt(shell, timeout=TIMEOUT)

                en_list = [cred.get("enable") or cred.get("password"), cred.get("password")]
                if not self._ensure_enable(shell, en_list, timeout=8):
                    self.log("Enable escalation failed on seed with this credential set", "WARN")
                    client.close()
                    continue

                self.send_cmd(shell, "terminal length 0", silent=True)
                self.agg_client = client
                self.agg_shell = shell
                self.agg_creds = cred

                self.agg_hostname = self.get_hostname(self.agg_shell) or "UNKNOWN"
                self.log(f"Seed hostname: {self.agg_hostname}", "DEBUG")
                self.log("Successfully connected to aggregate switch")

                mgmt_ip = self.get_management_ip(shell)
                if mgmt_ip:
                    self.log(f"Aggregate switch VLAN 100 IP: {mgmt_ip}")
                    self.seed_aggregate_ip = mgmt_ip
                else:
                    self.log("WARNING: Could not determine VLAN 100 IP, using entry IP", "WARN")
                    self.seed_aggregate_ip = AGGREGATE_ENTRY_IP
                return self.seed_aggregate_ip
            except Exception as e:
                last_err = e
                self.log(f"Seed connection failed with this credential set: {e}", "WARN")
        raise last_err or Exception("Unable to connect to aggregate with any credential set")

    def connect_to_aggregate(self):
        """First connection to seed with retry policy."""
        self.log(f"[CONNECT] SSH to seed switch: {AGGREGATE_ENTRY_IP}")
        last_err = None
        for attempt in range(AGG_MAX_RETRIES):
            try:
                return self._connect_to_aggregate_internal()
            except Exception as e:
                last_err = e
                self.log(f"[CONNECT] Attempt {attempt+1}/{AGG_MAX_RETRIES} failed: {e}", "WARN")
                time.sleep(AGG_RETRY_DELAY)
        raise NetworkConnectionError(f"Failed to connect to seed after {AGG_MAX_RETRIES} attempts: {last_err}")

    def ssh_to_device(self, target_ip, attempt=1):
        """SSH hop from aggregate to target using IOS CLI."""
        if not self.agg_shell or self.agg_shell.closed:
            raise NetworkConnectionError("SSH shell to aggregation switch is closed", reconnect_needed=True)

        self.log(f"SSH hop to {target_ip} (attempt {attempt}/{SSH_RETRY_ATTEMPTS})")

        try:
            pre_host = self.get_hostname(self.agg_shell) or self.agg_hostname or "UNKNOWN"
        except Exception:
            pre_host = self.agg_hostname or "UNKNOWN"

        cred_order = []
        if target_ip in self.device_creds:
            cred_order.append(self.device_creds[target_ip])
        if self.agg_creds and self.agg_creds not in cred_order:
            cred_order.append(self.agg_creds)
        for cs in CREDENTIAL_SETS:
            if cs not in cred_order:
                cred_order.append(cs)

        for cred in cred_order:
            user = cred["username"]
            pwd = cred["password"]
            enable = cred.get("enable") or cred["password"]

            syntaxes = [
                f"ssh -l {user} {target_ip}",
                f"ssh {user}@{target_ip}",
                f"ssh {target_ip}",
            ]

            for cmd in syntaxes:
                _ = self.send_cmd(self.agg_shell, cmd, timeout=3, silent=True)

                ok, out = self._interactive_hop(self.agg_shell, target_ip, user, pwd, overall_timeout=90)

                if not ok:
                    self.log(f"SSH (syntax '{cmd}') failed to {target_ip} with {user}", "WARN")
                    self.cleanup_failed_session()
                    if not self.verify_aggregate_connection():
                        raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                    continue

                if out.strip().endswith(">"):
                    if not self._ensure_enable(self.agg_shell, [enable, pwd], timeout=10):
                        self.log(f"Enable failed on {target_ip} with {user}", "WARN")
                        self.cleanup_failed_session()
                        if not self.verify_aggregate_connection():
                            raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                        continue

                post_host = self.get_hostname(self.agg_shell) or ""
                if post_host.strip() == pre_host.strip():
                    self.log(f"Hop to {target_ip} did not change hostname (still '{pre_host}'). Treating as failure.", "WARN")
                    self.cleanup_failed_session()
                    if not self.verify_aggregate_connection():
                        raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                    continue

                self.session_depth += 1
                self.send_cmd(self.agg_shell, "terminal length 0", timeout=5, silent=True)
                self.log(f"Successfully connected to {target_ip} as {user} (host: {post_host})")
                self.device_creds[target_ip] = cred
                return True

        if attempt < SSH_RETRY_ATTEMPTS:
            self.log(f"[RETRY] Waiting {SSH_RETRY_DELAY}s before retry...", "INFO")
            delay_remaining = SSH_RETRY_DELAY
            while delay_remaining > 0:
                time.sleep(min(10, delay_remaining))
                delay_remaining -= 10
                if not self.verify_aggregate_connection():
                    raise NetworkConnectionError("Lost connection to aggregation switch during retry delay", reconnect_needed=True)
            return self.ssh_to_device(target_ip, attempt + 1)

        raise NetworkConnectionError(f"SSH to {target_ip} failed after {SSH_RETRY_ATTEMPTS} attempts",
                                     reconnect_needed=False, retry_allowed=False)

    def exit_device(self):
        """Exit from current nested SSH session with session-depth guard."""
        sh = self.agg_shell
        if not sh or sh.closed:
            return False
        try:
            if self.session_depth > 0:
                self.log("[EXIT] Leaving nested session...", "DEBUG")
                sh.send("exit\n")
                time.sleep(0.6)
                _ = self._drain(sh)
                self.session_depth = max(0, self.session_depth - 1)

            sh.send("\n")
            time.sleep(0.2)
            data = self._drain(sh)
            return bool(PROMPT_RE.search(data))
        except Exception as e:
            self.log(f"[EXIT] Exception during exit: {e}", "WARN")
            return False

    # ── Core collection ───────────────────────────────────────────────────
    def collect_device_info(self, mgmt_ip, skip_discovery=False):
        self.log("\n" + "="*60)
        self.log(f"Collecting data from: {mgmt_ip}")

        if skip_discovery:
            self.log("  Skipping discovery for seed aggregate switch")
            return None

        if not self.verify_aggregate_connection():
            self.reconnect_to_aggregate("Seed connection lost before hop")

        ssh_accessible = True
        if mgmt_ip != AGGREGATE_ENTRY_IP:
            try:
                if not self.ssh_to_device(mgmt_ip):
                    ssh_accessible = False
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False) or not self.verify_aggregate_connection():
                    self.reconnect_to_aggregate("Lost while hopping to device")
                    try:
                        if not self.ssh_to_device(mgmt_ip):
                            ssh_accessible = False
                    except Exception:
                        ssh_accessible = False
                else:
                    ssh_accessible = False

            if ssh_accessible:
                current_host = self.get_hostname(self.agg_shell)
                if current_host.strip() == (self.agg_hostname or "").strip():
                    self.log("Detected aggregate prompt after hop; retrying hop once...", "WARN")
                    self.cleanup_failed_session()
                    if not self.verify_aggregate_connection():
                        self.reconnect_to_aggregate("Seed lost after false hop")
                    if not self.ssh_to_device(mgmt_ip):
                        ssh_accessible = False

            if not ssh_accessible:
                self.log(f" Cannot SSH to {mgmt_ip} - marking as inaccessible", "WARN")
                hostname = "Unknown"
                platform = None
                discovered_via = None
                
                for device_ip, device_data in self.devices.items():
                    for nbr in device_data.get("neighbors", []):
                        if nbr.get("neighbor_mgmt_ip") == mgmt_ip:
                            hostname = nbr.get("neighbor_hostname", "Unknown")
                            discovered_via = nbr.get("discovered_via")
                            if hasattr(self, '_neighbor_platform_cache'):
                                platform = self._neighbor_platform_cache.get(mgmt_ip)
                            break
                    if hostname != "Unknown":
                        break
                
                if hostname == "Unknown":
                    for hn, ip in self.hostname_to_ip.items():
                        if ip == mgmt_ip:
                            hostname = hn
                            break
                
                device_role = self.determine_device_role(hostname) if hostname != "Unknown" else "unknown"
                
                note_parts = ["Inaccessible via SSH"]
                if discovered_via:
                    note_parts.append(f"Discovered via {discovered_via}")
                
                return {
                    "hostname": hostname,
                    "management_ip": mgmt_ip,
                    "serial_number": None,
                    "ios_version": None,
                    "switch_model": platform,
                    "device_role": device_role,
                    "discovery_protocol": None,
                    "notes": " - ".join(note_parts),
                    "neighbors": []
                }

        try:
            shell = self.agg_shell

            hostname = self.get_hostname(shell)
            self.log(f"Hostname: {hostname}")

            actual_mgmt_ip = self.get_management_ip(shell) or mgmt_ip
            self.log(f"Management IP (SVI): {actual_mgmt_ip}")

            if hostname not in self.hostname_to_ip:
                self.hostname_to_ip[hostname] = actual_mgmt_ip

            serial = self.get_serial_number(shell)
            ios_version = self.get_ios_version(shell)
            switch_model = self.get_switch_model(shell)
            device_role = self.determine_device_role(hostname)

            self.log(f"Serial Number: {serial}")
            self.log(f"IOS Version: {ios_version}")
            self.log(f"Switch Model: {switch_model}")
            self.log(f"Device Role: {device_role}")

            neighbors, protocol = self.discover_neighbors(shell, actual_mgmt_ip)

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

            for nbr in neighbors:
                discovery_method = nbr.get("discovered_via", "Unknown")
                link_note = nbr.get("link_note", "")

                self.log(f"  → Neighbor: {nbr['hostname']} ({nbr['mgmt_ip']}) "
                         f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]"
                         f"{' ['+link_note+']' if link_note else ''}")

                neighbor_entry = {
                    "neighbor_hostname": nbr["hostname"],
                    "neighbor_mgmt_ip": nbr["mgmt_ip"],
                    "local_interface": nbr["local_intf"],
                    "remote_interface": nbr["remote_intf"],
                    "discovered_via": discovery_method
                }
                if link_note:
                    neighbor_entry["link_note"] = link_note

                device_info["neighbors"].append(neighbor_entry)

                if nbr["mgmt_ip"] not in self.visited and nbr["mgmt_ip"] != self.seed_aggregate_ip:
                    if nbr["mgmt_ip"] not in self.to_visit:
                        self.to_visit.append(nbr["mgmt_ip"])
                        self.log(f"    Added {nbr['mgmt_ip']} to discovery queue")
                    else:
                        self.log(f"    {nbr['mgmt_ip']} already in discovery queue")
                elif nbr["mgmt_ip"] == self.seed_aggregate_ip:
                    self.log(f"    Skipping seed aggregate {nbr['mgmt_ip']} - already discovered")

            if mgmt_ip != AGGREGATE_ENTRY_IP:
                ok = self.exit_device()
                if not ok:
                    if not self.verify_aggregate_connection():
                        self.reconnect_to_aggregate("Lost after exiting device")

            return device_info

        except NetworkConnectionError as e:
            if getattr(e, 'reconnect_needed', False) or not self.verify_aggregate_connection():
                self.reconnect_to_aggregate("During device collection")
            return None
        except Exception as e:
            self.log(f"Error collecting device info: {e}", "ERROR")
            try:
                if mgmt_ip != AGGREGATE_ENTRY_IP:
                    self.exit_device()
            except Exception:
                pass
            return None

    # ── Main run ──────────────────────────────────────────────────────────
    def run_discovery(self):
        self.log("="*60)
        self.log("Starting Network Topology Discovery")
        self.log("="*60)

        agg_mgmt_ip = self.connect_to_aggregate()

        self.log("\n" + "="*60)
        self.log(f"Collecting seed aggregate information: {agg_mgmt_ip}")
        self.log("="*60)

        try:
            hostname = self.get_hostname(self.agg_shell)
            self.log(f"Hostname: {hostname}")

            if hostname not in self.hostname_to_ip:
                self.hostname_to_ip[hostname] = agg_mgmt_ip

            serial = self.get_serial_number(self.agg_shell)
            ios_version = self.get_ios_version(self.agg_shell)
            switch_model = self.get_switch_model(self.agg_shell)
            device_role = self.determine_device_role(hostname)
            neighbors, protocol = self.discover_neighbors(self.agg_shell, agg_mgmt_ip)

            seed_info = {
                "hostname": hostname,
                "management_ip": agg_mgmt_ip,
                "serial_number": serial,
                "ios_version": ios_version,
                "switch_model": switch_model,
                "device_role": device_role,
                "discovery_protocol": protocol,
                "notes": "Seed aggregate switch",
                "neighbors": []
            }

            for nbr in neighbors:
                discovery_method = nbr.get("discovered_via", "Unknown")
                link_note = nbr.get("link_note", "")
                self.log(f"  → Neighbor: {nbr['hostname']} ({nbr['mgmt_ip']}) "
                         f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]"
                         f"{' ['+link_note+']' if link_note else ''}")

                entry = {
                    "neighbor_hostname": nbr["hostname"],
                    "neighbor_mgmt_ip": nbr["mgmt_ip"],
                    "local_interface": nbr["local_intf"],
                    "remote_interface": nbr["remote_intf"],
                    "discovered_via": discovery_method
                }
                if link_note:
                    entry["link_note"] = link_note
                seed_info["neighbors"].append(entry)

                if nbr["mgmt_ip"] not in self.to_visit:
                    self.to_visit.append(nbr["mgmt_ip"])
                    self.log(f"    Added {nbr['mgmt_ip']} to discovery queue")
                else:
                    self.log(f"    {nbr['mgmt_ip']} already in discovery queue")

            self.devices[agg_mgmt_ip] = seed_info
            self.visited.add(agg_mgmt_ip)

        except NetworkConnectionError:
            self.reconnect_to_aggregate("During seed info collection")
        except Exception as e:
            self.log(f"Error collecting seed aggregate info: {e}", "ERROR")

        for ip in AGGREGATE_MGMT_IPS:
            if ip != agg_mgmt_ip and ip not in self.visited and ip not in self.to_visit:
                self.to_visit.append(ip)

        while self.to_visit:
            current_ip = self.to_visit.popleft()
            if current_ip in self.visited:
                self.log(f"Skipping {current_ip} - already visited")
                continue

            if not self.verify_aggregate_connection():
                self.reconnect_to_aggregate("Before visiting next device")

            self.visited.add(current_ip)
            info = self.collect_device_info(current_ip)
            if info:
                self.devices[current_ip] = info
            else:
                self.log(f"Failed to collect info from {current_ip}", "ERROR")

        try:
            if self.agg_client:
                self.agg_client.close()
        except Exception:
            pass

        duration = (datetime.now() - self.start_time).total_seconds()
        self.log("="*60)
        self.log(f"Discovery complete! Found {len(self.devices)} devices")
        self.log(f"Total discovery time: {duration:.1f} seconds")
        self.log("="*60)

    # ── Output writers ────────────────────────────────────────────────────
    def generate_json(self, filename="network_topology.json"):
        devices_list = list(self.devices.values())
        with open(filename,  "w" , encoding='utf-8') as f:
            json.dump(devices_list, f, indent=2)
        self.log(f"\n Topology saved to {filename}")

        self.log("\n" + "="*60)
        self.log("DISCOVERY SUMMARY")
        self.log("="*60)
        self.log(f"Total devices discovered: {len(devices_list)}")

        role_counts = {}
        for d in devices_list:
            role = d.get("device_role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1

        self.log("\nDevices by role:")
        for role, count in sorted(role_counts.items()):
            self.log(f"  {role}: {count}")
        self.log("="*60)

        for d in devices_list:
            notes_str = f" [{d['notes']}]" if d.get('notes') else ""
            self.log(f"\n{d['hostname']} ({d['management_ip']}) - {d['device_role']}{notes_str}")
            self.log(f"  Model: {d.get('switch_model', 'N/A')}")
            self.log(f"  IOS Version: {d.get('ios_version', 'N/A')}")
            self.log(f"  Serial: {d.get('serial_number')}")
            self.log(f"  Neighbors: {len(d['neighbors'])}")
            for nbr in d["neighbors"]:
                discovered = nbr.get("discovered_via", "Unknown")
                link_note = nbr.get("link_note", "")
                link_str = f" - {link_note}" if link_note else ""
                self.log(f"    • {nbr['neighbor_hostname']} via "
                         f"{nbr['local_interface']} ↔ {nbr['remote_interface']} [{discovered}]{link_str}")

    def write_metadata(self, filename="discovery_metadata.txt"):
        duration = (datetime.now() - self.start_time).total_seconds()
        with open(filename,  "w" ,  encoding='utf-8' ) as f:
            f.write("="*60 + "\n")
            f.write("NETWORK TOPOLOGY DISCOVERY METADATA\n")
            f.write("="*60 + "\n\n")
            f.write(f"Discovery Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Entry Point: {AGGREGATE_ENTRY_IP}\n")
            f.write(f"Seed Aggregate: {self.seed_aggregate_ip}\n")
            f.write(f"Duration: {duration:.1f} seconds\n")
            f.write(f"Total Devices Discovered: {len(self.devices)}\n\n")

            f.write("="*60 + "\n")
            f.write("DEVICE ROLES\n")
            f.write("="*60 + "\n")
            role_counts = {}
            for d in self.devices.values():
                role = d.get("device_role", "unknown")
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
            cdp_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") and "CDP" in d["discovery_protocol"])
            lldp_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") and "LLDP" in d["discovery_protocol"])
            both_count = sum(1 for d in self.devices.values() if d.get("discovery_protocol") == "CDP+LLDP")
            no_protocol = sum(1 for d in self.devices.values() if not d.get("discovery_protocol"))

            f.write(f"Devices with CDP only: {cdp_count - both_count}\n")
            f.write(f"Devices with LLDP only: {lldp_count - both_count}\n")
            f.write(f"Devices with both CDP+LLDP: {both_count}\n")
            if no_protocol > 0:
                f.write(f"Devices without discovery protocol: {no_protocol}\n")

            total_neighbors = sum(len(d["neighbors"]) for d in self.devices.values())
            f.write(f"Total neighbor relationships: {total_neighbors}\n")

            inaccessible = sum(1 for d in self.devices.values() if d.get("notes") and "Inaccessible via SSH" in d["notes"])
            if inaccessible > 0:
                f.write(f"Inaccessible devices (via SSH): {inaccessible}\n")

            multiple_link_count = 0
            for d in self.devices.values():
                for nbr in d["neighbors"]:
                    if "link_note" in nbr and "Multiple links" in nbr["link_note"]:
                        multiple_link_count += 1
            if multiple_link_count > 0:
                f.write(f"Connections with multiple links: {multiple_link_count}\n")

            f.write("\n" + "="*60 + "\n")
            f.write("HOSTNAME TO IP MAPPING\n")
            f.write("="*60 + "\n")
            for hostname, ip in sorted(self.hostname_to_ip.items()):
                f.write(f"{hostname} → {ip}\n")

        self.log(f" Metadata saved to {filename}")

if __name__ == "__main__":
    nd = NetworkDiscovery()

    try:
        nd.log_file = open(nd.log_filename, "w", encoding="utf-8")
        nd.log(f"Log file created: {nd.log_filename}")
    except Exception as e:
        print(f"Warning: Could not create log file: {e}")

    try:
        nd.run_discovery()
        nd.generate_json()
        nd.write_metadata()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Discovery stopped by user")
        if nd.log_file:
            nd.log_file.write("\n\n[INTERRUPTED] Discovery stopped by user\n")
            nd.log_file.close()
    except Exception as e:
        print(f"\n\n[FATAL ERROR] {e}")
        if nd.log_file:
            nd.log_file.write(f"\n\n[FATAL ERROR] {e}\n")
            nd.log_file.close()
        import traceback
        traceback.print_exc()
