#!/usr/bin/env python3
"""
Smart Network Topology Discovery Tool (Cisco-CLI Nested SSH, Depth-Safe)
- Cisco CDP/LLDP topology discovery via nested SSH hops (from aggregate CLI)
- Interactive SSH hop state machine handles banners/yes-no/Username/Password
- Multi-credential login+enable fallback (per-device caching)
- Session depth tracking to avoid exiting the seed accidentally
- Robust cleanup on failed hops; reconnect seed only when truly lost
- Hostname-change verification after hop (prevents false successes)
- Handles hostnames with special characters (including # in the name)
- Hardware-based device role recognition (C3850=aggregate, IE=field, etc.)
- Tracks visited devices by hostname only (simpler, more reliable)
- Records neighbors without management IPs with notes (including MAC addresses)
- Recognizes IE switches and other Cisco devices without standard IOS descriptions
- Exports: network_topology.json + discovery_metadata.txt

FIXED: 
1. "Local IP" false positive logic removed. 
2. If hostname doesn't change, it is treated as a failure and RETRIED.
"""
import paramiko
import time
import re
import json
from datetime import datetime
from collections import deque

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
AGGREGATE_ENTRY_IP = "192.168.100.13"  # First hop from the server

# Ordered credential sets to try (add more as needed)
# "enable": "" means "reuse the login password as enable"
CREDENTIAL_SETS = [
    {"username": "admin",  "password": "cisco",  "enable": ""}
]

# Optional: pre-known aggregate SVI mgmt IPs (besides seed)
AGGREGATE_MGMT_IPS = [
    # "10.0.100.2", "10.0.100.3",
]

# Timeouts/retries
TIMEOUT = 12
MAX_READ = 65535
SSH_RETRY_ATTEMPTS = 10  # Will retry connection refused/timeouts up to this many times
SSH_RETRY_DELAY = 30     # Wait time between retries
CDP_LLDP_TIMEOUT = 35

# Aggregate (seed) reconnect policy
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

# ─────────────────────────────────────────────────────────────────────────────

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
        self.to_visit = deque()  # Queue of (ip, hostname) tuples
        self.visited_hostnames = set()  # Track by hostname only
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
    
    # ── Device Tracking Helpers ───────────────────────────────────────────
    def is_device_visited(self, hostname):
        """Check if a device has been visited by hostname."""
        if not hostname:
            return False
        return hostname in self.visited_hostnames
    
    def mark_device_visited(self, hostname):
        """Mark a device as visited using hostname."""
        if hostname:
            self.visited_hostnames.add(hostname)
            self.log(f"  [TRACK] Marked hostname as visited: {hostname}", "DEBUG")
    
    def is_seed_device(self, hostname):
        """Check if a hostname belongs to the seed aggregate switch."""
        if not hostname or not self.agg_hostname:
            return False
        return hostname == self.agg_hostname
    
    def should_visit_device(self, ip, hostname):
        """
        Determine if a device should be added to the visit queue.
        Returns True only if hostname has not been visited.
        """
        if not hostname:
            self.log(f"  [TRACK] Skipping {ip} - no hostname", "DEBUG")
            return False
        
        # Check if it's the seed device
        if self.is_seed_device(hostname):
            self.log(f"  [TRACK] Skipping seed device {hostname} ({ip})", "DEBUG")
            return False
        
        # Check if already visited
        if self.is_device_visited(hostname):
            self.log(f"  [TRACK] Skipping {hostname} ({ip}) - already visited", "DEBUG")
            return False
        
        # Check if already in queue
        for queued_ip, queued_hostname in self.to_visit:
            if queued_hostname == hostname:
                self.log(f"  [TRACK] Skipping {hostname} ({ip}) - already in queue", "DEBUG")
                return False
        
        return True
    
    def get_device_identifier(self, ip=None, hostname=None):
        """Get a string identifier for a device (for logging)."""
        if hostname and ip:
            return f"{hostname} ({ip})"
        elif hostname:
            return hostname
        elif ip:
            return ip
        else:
            return "Unknown"
    
    # ── Prompt Detection ──────────────────────────────────────────────────
    def _looks_like_prompt(self, text):
        """
        Check if text ends with a Cisco prompt.
        Handles hostnames with special characters like # in them.
        Strips ANSI escape codes before checking.
        """
        if not text:
            return False
        
        # Strip ANSI escape codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', text)
        
        # Get last non-empty line
        lines = [l for l in clean_text.strip().split('\n') if l.strip()]
        if not lines:
            return False
        
        last_line = lines[-1].strip()
        
        # Prompt should end with > or #
        if not (last_line.endswith('>') or last_line.endswith('#')):
            return False
        
        # Should not be a question or password prompt
        if any(keyword in last_line.lower() for keyword in ['password:', 'username:', '(yes/no)', 'confirm']):
            return False
        
        # Should have at least one alphanumeric character before the prompt symbol
        prompt_char = last_line[-1]
        hostname_part = last_line[:-1].strip()
        
        if not hostname_part:
            return False
        
        # Valid hostname should contain alphanumeric characters
        if not any(c.isalnum() for c in hostname_part):
            return False
        
        return True


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
                if self._looks_like_prompt(buf):
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
                return self._looks_like_prompt(data)
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
            
            # Send Ctrl+C to interrupt
            try:
                sh.send("\x03")
                time.sleep(0.3)
            except Exception:
                pass
            
            _ = self._drain(sh)
            
            # Try to exit if we're in a nested session
            if self.session_depth > 0:
                try:
                    sh.send("exit\n")
                    time.sleep(0.8)
                    _ = self._drain(sh)
                    self.session_depth = max(0, self.session_depth - 1)
                except Exception:
                    pass
            
            # Multiple verification attempts
            for _ in range(3):
                try:
                    sh.send("\n")
                    time.sleep(0.3)
                    data = self._drain(sh)
                    if self._looks_like_prompt(data):
                        self.log("[CLEANUP] Successfully verified prompt", "DEBUG")
                        return True
                except Exception:
                    pass
                time.sleep(0.2)
            
            self.log("[CLEANUP] Could not verify prompt after cleanup", "WARN")
            return False
            
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
        Normalize hostname by stripping ALL domain suffixes.
        Returns just the short hostname (upper case).
        """
        if not hostname:
            return hostname
        
        # Remove everything after the first dot
        if '.' in hostname:
            hostname = hostname.split('.')[0]
            
        return hostname.upper().strip()
    
    # ── MAC address formatting ────────────────────────────────────────────
    def format_mac_address(self, mac_string):
        """
        Format MAC address from various formats to standard colon-separated format.
        """
        if not mac_string:
            return None
        
        # Remove all non-alphanumeric characters
        mac_clean = re.sub(r'[^0-9A-Fa-f]', '', mac_string)
        
        # Check if we have a valid MAC length (12 hex digits)
        if len(mac_clean) < 12:
            return mac_string  # Return original if can't parse
        
        # Take first 12 characters and format as MAC
        mac_clean = mac_clean[:12].upper()
        
        # Format as XX:XX:XX:XX:XX:XX
        mac_formatted = ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
        
        return mac_formatted
    
    # ── Device role determination (hardware + hostname based) ────────────
    def determine_device_role(self, hostname, switch_model=None):
        """
        Determine device role based on hardware model and hostname.
        """
        # Normalize inputs
        hostname_upper = (hostname or "").upper()
        model_upper = (switch_model or "").upper()
        
        # ═══════════════════════════════════════════════════════════════
        # HARDWARE-BASED RECOGNITION (Highest Priority)
        # ═══════════════════════════════════════════════════════════════
        
        # Rule 1: Catalyst 3850 → Always aggregate
        if any(pattern in model_upper for pattern in ['C3850', 'WS-C3850', 'CATALYST3850']):
            self.log(f"  [ROLE] Hardware match: {switch_model} → aggregate (C3850 series)", "DEBUG")
            return "aggregate"
        
        # Rule 2: Industrial Ethernet (IE-*) → Always field
        if any(pattern in model_upper for pattern in ['IE-', 'INDUSTRIAL']):
            self.log(f"  [ROLE] Hardware match: {switch_model} → field (Industrial Ethernet)", "DEBUG")
            return "field"
        
        # Rule 3: Catalyst 9300 → Check hostname for server/access distinction
        if any(pattern in model_upper for pattern in ['C9300', 'WS-C9300', 'CATALYST9300', 'C93']):
            if "SRV" in hostname_upper or "SERVER" in hostname_upper:
                self.log(f"  [ROLE] Hardware+Name match: {switch_model} + {hostname} → server (C9300 with SRV)", "DEBUG")
                return "server"
            else:
                self.log(f"  [ROLE] Hardware match: {switch_model} → access (C9300 default)", "DEBUG")
                return "access"
        
        # Rule 4: Other Catalyst 9000 series (9200, 9400, 9500, etc.)
        if any(pattern in model_upper for pattern in ['C9200', 'C9400', 'C9500', 'C9600', 'WS-C9']):
            # 9400/9500/9600 are typically aggregates or cores
            if any(core in model_upper for core in ['C9400', 'C9500', 'C9600']):
                self.log(f"  [ROLE] Hardware match: {switch_model} → aggregate (C9400/9500/9600 series)", "DEBUG")
                return "aggregate"
            # 9200 are typically access
            if 'C9200' in model_upper:
                self.log(f"  [ROLE] Hardware match: {switch_model} → access (C9200 series)", "DEBUG")
                return "access"
        
        # Rule 5: Catalyst 2960 → Typically access
        if any(pattern in model_upper for pattern in ['C2960', 'WS-C2960', 'CATALYST2960']):
            self.log(f"  [ROLE] Hardware match: {switch_model} → access (C2960 series)", "DEBUG")
            return "access"
        
        # Rule 6: Catalyst 2950 → Access
        if any(pattern in model_upper for pattern in ['C2950', 'WS-C2950', 'CATALYST2950']):
            self.log(f"  [ROLE] Hardware match: {switch_model} → access (C2950 series)", "DEBUG")
            return "access"
        
        # Rule 7: Catalyst 3650 → Access (typically)
        if any(pattern in model_upper for pattern in ['C3650', 'WS-C3650', 'CATALYST3650']):
            self.log(f"  [ROLE] Hardware match: {switch_model} → access (C3650 series)", "DEBUG")
            return "access"
        
        # Rule 8: Catalyst 3750 → Could be aggregate or access, check hostname
        if any(pattern in model_upper for pattern in ['C3750', 'WS-C3750', 'CATALYST3750']):
            if "AGG" in hostname_upper or "CORE" in hostname_upper or "DIST" in hostname_upper:
                self.log(f"  [ROLE] Hardware+Name match: {switch_model} + {hostname} → aggregate (C3750 with AGG/CORE)", "DEBUG")
                return "aggregate"
            else:
                self.log(f"  [ROLE] Hardware match: {switch_model} → access (C3750 default)", "DEBUG")
                return "access"
        
        # Rule 9: Nexus switches → Typically aggregates/cores
        if any(pattern in model_upper for pattern in ['NEXUS', 'N9K', 'N7K', 'N5K', 'N3K']):
            self.log(f"  [ROLE] Hardware match: {switch_model} → aggregate (Nexus series)", "DEBUG")
            return "aggregate"
        
        # ═══════════════════════════════════════════════════════════════
        # HOSTNAME-BASED RECOGNITION (Fallback)
        # ═══════════════════════════════════════════════════════════════
        
        if "SRV" in hostname_upper or "SERVER" in hostname_upper:
            self.log(f"  [ROLE] Hostname match: {hostname} → server (SRV pattern)", "DEBUG")
            return "server"
        
        if "AGG" in hostname_upper or "CORE" in hostname_upper or "DIST" in hostname_upper:
            self.log(f"  [ROLE] Hostname match: {hostname} → aggregate (AGG/CORE pattern)", "DEBUG")
            return "aggregate"
        
        if "ACC" in hostname_upper or "ACCESS" in hostname_upper:
            self.log(f"  [ROLE] Hostname match: {hostname} → access (ACC pattern)", "DEBUG")
            return "access"
        
        if "EDGE" in hostname_upper:
            self.log(f"  [ROLE] Hostname match: {hostname} → access (EDGE pattern)", "DEBUG")
            return "access"
        
        if "IE" in hostname_upper or "FIELD" in hostname_upper:
            self.log(f"  [ROLE] Hostname match: {hostname} → field (IE/FIELD pattern)", "DEBUG")
            return "field"
        
        # ═══════════════════════════════════════════════════════════════
        # DEFAULT
        # ═══════════════════════════════════════════════════════════════
        
        self.log(f"  [ROLE] No match for hostname='{hostname}' model='{switch_model}' → unknown", "DEBUG")
        return "unknown"
    
    # ── Basic getters ─────────────────────────────────────────────────────
    def get_hostname(self, shell):
        """Extract hostname from prompt, handling special characters like # in hostname."""
        shell.send("\n")
        time.sleep(0.2)
        buff = self.expect_prompt(shell, timeout=4)
        
        # Get last non-empty line
        lines = [l.strip() for l in buff.splitlines() if l.strip()]
        if not lines:
            return "Unknown"
        
        last_line = lines[-1]
        
        # Extract hostname - everything before the final > or #
        if last_line.endswith('>') or last_line.endswith('#'):
            hostname = last_line[:-1].strip()
            return self.normalize_hostname(hostname)
        
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
        """
        Extract switch model from 'show version' output.
        Returns the most specific model identifier found.
        """
        output = self.send_cmd(shell, "show version", timeout=10, silent=True)
        
        # Ordered patterns - more specific first
        pats = (
            # Exact model number formats
            r"Model [Nn]umber\s*:?\s*(\S+)",
            r"Model:\s*(\S+)",
            
            # Catalyst formats (WS-C3850-24P, etc.)
            r"cisco\s+(WS-C\d{4}[A-Z0-9\-]+)",
            
            # Modern Catalyst formats (C9300-24P, C3850-48T, etc.)
            r"cisco\s+(C\d{4}[A-Z0-9\-]+)",
            
            # Industrial Ethernet formats (IE-4000-4TC4G-E, etc.)
            r"cisco\s+(IE-\d{4}[A-Z0-9\-]+)",
            
            # Nexus formats
            r"cisco\s+(N\d+K[A-Z0-9\-]*)",
            
            # Generic Cisco processor format
            r"cisco\s+([A-Z0-9\-]+)\s+\([^\)]+\)\s+processor",
            
            # Hardware line
            r"Hardware:\s*(\S+)",
            
            # System image file (less reliable)
            r"System image file is.*?:([A-Z0-9\-]+)",
        )
        
        for pat in pats:
            m = re.search(pat, output, re.I)
            if m:
                model = m.group(1)
                # Filter out common false positives
                if model.lower() not in ("unknown", "n/a", "bytes", "memory"):
                    self.log(f"  [MODEL] Detected: {model}", "DEBUG")
                    return model
        
        self.log(f"  [MODEL] Could not detect switch model", "DEBUG")
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
        """
        Parse CDP neighbors and include devices without management IPs with notes.
        Extracts MAC addresses when no IP is available.
        """
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
            
            # Try to find IP address
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
            
            # Only add if we have a hostname
            if nbr["hostname"]:
                # Check if it's a Cisco device (or at least has a platform)
                if not nbr["platform"] or "cisco" in nbr["platform"].lower():
                    # Handle missing management IP
                    if not nbr["mgmt_ip"]:
                        # Try to extract MAC address from various CDP fields
                        mac_addr = None
                        
                        # Pattern 1: Look for "Management address(es):" section with MAC
                        mac_match = re.search(r"Management address\(es\):.*?([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", block, re.DOTALL | re.I)
                        if not mac_match:
                            # Pattern 2: Look for chassis ID or device ID with MAC format
                            mac_match = re.search(r"(?:Chassis|Device) ID.*?([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", block, re.I)
                        
                        if mac_match:
                            mac_addr = self.format_mac_address(mac_match.group(1))
                        
                        if mac_addr:
                            self.log(f"  [CDP] Warning: {nbr['hostname']} has MAC only (no IP): {mac_addr}", "WARN")
                            nbr["note"] = f"No management IP in CDP (MAC: {mac_addr})"
                        else:
                            self.log(f"  [CDP] Warning: No management IP found for {nbr['hostname']}", "WARN")
                            nbr["note"] = "No management IP in CDP"
                    
                    neighbors.append(nbr)
        
        return neighbors
    
    def parse_lldp_neighbors(self, output):
        """
        Parse 'show lldp neighbors detail' output and extract neighbor information.
        Filters out non-Cisco devices based on hostname patterns and system description.
        Includes devices without management IPs with notes (including MAC addresses).
        Recognizes IE switches and other Cisco devices without standard IOS descriptions.
        """
        # Patterns to identify non-Cisco devices
        NON_CISCO_PATTERNS = [
            r'^axis-',            # Axis cameras
            r'^SEP[A-F0-9]{12}', # Cisco IP phones
            r'^AP[A-F0-9]+',     # Standalone access points (when not managed)
            r'^printer-',
            r'^camera-',
            r'^phone-',
        ]
        
        # Cisco device identifiers in System Description
        CISCO_DEVICE_PATTERNS = [
            r'Cisco IOS',
            r'Cisco NX-OS',
            r'IOS-XE',
            r'IOS XE',
            r'IE\d{4}',                     # IE1000, IE2000, IE3000, IE4000, etc.
            r'Industrial Ethernet Switch', # IE switches
            r'Catalyst',
            r'Nexus',
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
                
                # FILTER 2: Check System Description for Cisco device patterns
                has_cisco_desc = any(re.search(pattern, block, re.IGNORECASE) 
                                   for pattern in CISCO_DEVICE_PATTERNS)
                
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
                    ip_match3 = re.search(r"Management.*?IPv4:\s*(\d+\.\d+\.\d+\.\d+)", block, re.DOTALL)
                    if ip_match3:
                        mgmt_ip = ip_match3.group(1)
                
                # Pattern 4: Direct IP pattern anywhere in Management section
                if not mgmt_ip:
                    mgmt_section = re.search(r"Management Addresses:.*?(?=\n[A-Z]|\n\n|$)", block, re.DOTALL)
                    if mgmt_section:
                        ip_match4 = re.search(r"(\d+\.\d+\.\d+\.\d+)", mgmt_section.group(0))
                        if ip_match4:
                            mgmt_ip = ip_match4.group(1)
                
                if mgmt_ip:
                    neighbor["mgmt_ip"] = mgmt_ip
                else:
                    # No IP found - try to extract MAC address or Chassis ID
                    mac_addr = None
                    
                    # Pattern 1: Management Addresses with "Other:" MAC format
                    mac_match1 = re.search(r"Management Addresses:\s*\n\s*Other:\s*([0-9A-Fa-f\s]+)", block)
                    if mac_match1:
                        mac_addr = self.format_mac_address(mac_match1.group(1))
                    
                    # Pattern 2: Chassis ID (often MAC address)
                    if not mac_addr:
                        chassis_match = re.search(r"Chassis id:\s*([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", block)
                        if chassis_match:
                            mac_addr = self.format_mac_address(chassis_match.group(1))
                    
                    if mac_addr:
                        self.log(f"  [LLDP] Warning: {hostname} on {neighbor['local_intf']} has MAC only (no IP): {mac_addr}", "WARN")
                        neighbor["note"] = f"No management IP in LLDP (MAC: {mac_addr})"
                    else:
                        self.log(f"  [LLDP] Warning: No management IP found for {hostname} on {neighbor['local_intf']}", "WARN")
                        neighbor["note"] = "No management IP in LLDP"
                    
                    neighbor["mgmt_ip"] = None
                
                # Add discovery method marker
                neighbor["discovered_via"] = "LLDP"
                
                # Only add if we have the minimum required fields
                if neighbor.get("hostname") and neighbor.get("local_intf"):
                    neighbors.append(neighbor)
                    ip_display = neighbor.get('mgmt_ip', 'No-IP')
                    note_str = f" (NOTE: {neighbor.get('note')})" if neighbor.get('note') else ""
                    self.log(f"  ✓ Parsed LLDP neighbor: {neighbor['hostname']} "
                             f"({ip_display}) via "
                             f"{neighbor['local_intf']} ↔ {neighbor['remote_intf']}{note_str}", "DEBUG")
            
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
                    normalized_hn = nbr["hostname"]
                    all_by_host.setdefault(normalized_hn, []).append(nbr)
        else:
            self.log("CDP not enabled or available")
        
        self.log("Checking LLDP neighbors...")
        lldp_out = self.send_cmd(shell, "show lldp neighbors detail", timeout=CDP_LLDP_TIMEOUT, silent=True)
        
        try:
            debug_filename = f"lldp_debug_{current_device_ip.replace('.', '_')}.txt"
            with open(debug_filename, "w", encoding='utf-8') as f:
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
                    normalized_hn = nbr["hostname"]
                    
                    # Check for duplicates BEFORE adding
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
                    
                    # Add to all_by_host
                    all_by_host.setdefault(normalized_hn, []).append(nbr)
        else:
            self.log("LLDP not enabled or available")
        
        if not all_by_host:
            self.log("No neighbors found via CDP or LLDP", "WARN")
            return [], None
        
        all_neighbors = []
        for h, links in all_by_host.items():
            if len(links) > 1:
                self.log(f"    Multiple links detected to {h}: {len(links)} links")
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
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FUNCTION: _interactive_hop (REPLACED)
    # ═══════════════════════════════════════════════════════════════════════════
    def _interactive_hop(self, shell, ip, username, password, enable_password, overall_timeout=120):
        """
        Drive IOS 'ssh' interactively until we reach a privileged prompt or timeout.
        
        IMPROVED: Better state tracking and connection state detection.
        
        Returns:
            tuple: (success: bool, output: str, connection_state: str)
            connection_state can be: "success", "auth_failed", "connection_refused", "timeout"
        """
        start = time.time()
        buf = ""
        enable_sent = False
        password_attempts = 0
        max_password_attempts = 3
        last_enable_attempt = 0
        connection_state = "unknown"
        
        def feed(s):
            try:
                shell.send(s)
            except Exception:
                pass
        
        def strip_ansi(text):
            """Remove ANSI escape codes from text."""
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', text)
        
        def get_last_line(text):
            """Get the last non-empty line from text."""
            clean = strip_ansi(text)
            lines = [l.strip() for l in clean.split('\n') if l.strip()]
            return lines[-1] if lines else ""
        
        while time.time() - start < overall_timeout:
            time.sleep(0.15)
            if shell.recv_ready():
                try:
                    chunk = shell.recv(MAX_READ).decode("utf-8", "ignore")
                except Exception:
                    chunk = ""
                if chunk:
                    buf += chunk
            
            last_line = get_last_line(buf)
            low = buf.lower()
            
            # ===== SUCCESS: Privileged prompt =====
            if self._looks_like_prompt(buf) and last_line.endswith("#"):
                self.log(f"[HOP] Got privileged prompt: {last_line}", "DEBUG")
                return True, buf, "success"
            
            # ===== Need to enable =====
            if self._looks_like_prompt(buf) and last_line.endswith(">"):
                current_time = time.time()
                # Send enable if we haven't sent it, or if it's been 5+ seconds since last attempt
                if not enable_sent or (current_time - last_enable_attempt > 5):
                    self.log(f"[HOP] At user mode ({last_line}), sending 'enable'", "DEBUG")
                    feed("enable\n")
                    enable_sent = True
                    last_enable_attempt = current_time
                    time.sleep(0.5)
                    continue
            
            # ===== SSH key verification =====
            if "(yes/no)" in low or "yes/no" in low:
                self.log(f"[HOP] Accepting SSH key", "DEBUG")
                feed("yes\n")
                time.sleep(0.5)
                buf = ""  # Clear after yes/no to avoid re-detecting
                continue
            
            # ===== Username prompt =====
            if "username:" in low and password_attempts == 0:
                self.log(f"[HOP] Sending username", "DEBUG")
                feed(username + "\n")
                time.sleep(0.3)
                buf = ""  # Clear to wait for next prompt
                continue
            
            # ===== Password prompt =====
            if "password:" in low:
                password_attempts += 1
                
                if password_attempts > max_password_attempts:
                    self.log(f"[HOP] Max password attempts ({max_password_attempts}) reached", "WARN")
                    connection_state = "auth_failed"
                    break
                
                if enable_sent:
                    self.log(f"[HOP] Sending enable password (attempt {password_attempts})", "DEBUG")
                    feed(enable_password + "\n")
                else:
                    self.log(f"[HOP] Sending login password (attempt {password_attempts})", "DEBUG")
                    feed(password + "\n")
                
                time.sleep(1.0)  # Wait for authentication response
                
                # DON'T clear buffer yet - we need to see if auth succeeds
                continue
            
            # ===== Failure detection =====
            fail_keys = (
                "connection refused", "unable to connect", "timed out",
                "no route to host", "host is unreachable",
                "closed by foreign host", "connection closed by",
                "authentication failed", "permission denied",
                "% bad passwords", "% login invalid", "access denied"
            )
            
            for fail_key in fail_keys:
                if fail_key in low:
                    self.log(f"[HOP] Detected failure: {fail_key}", "DEBUG")
                    
                    # Determine connection state
                    if fail_key in ("connection refused", "unable to connect", "no route to host", 
                                   "host is unreachable", "closed by foreign host"):
                        connection_state = "connection_refused"
                    elif fail_key in ("authentication failed", "permission denied", 
                                     "% bad passwords", "% login invalid", "access denied"):
                        connection_state = "auth_failed"
                    
                    return False, buf, connection_state
            
            # Send periodic newline to refresh prompt
            if (time.time() - start) > 2 and (time.time() - start) % 3 < 0.2:
                feed("\n")
        
        # Timeout
        self.log(f"[HOP] Timeout after {overall_timeout}s", "WARN")
        self.log(f"[HOP] Last line was: {last_line}", "WARN")
        self.log(f"[HOP] enable_sent={enable_sent}, password_attempts={password_attempts}", "WARN")
        return False, buf, "timeout"

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
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FUNCTION: ssh_to_device (UPDATED - Aggressive Retry for Cisco Busy/Refused)
    # ═══════════════════════════════════════════════════════════════════════════
    def ssh_to_device(self, target_ip, target_hostname=None, attempt=1):
        """
        SSH hop from aggregate to target using IOS CLI.
        
        UPDATED: Treats 'Connection Refused/Timeout' as temporary errors and 
                retries them up to the full SSH_RETRY_ATTEMPTS limit.
        """
        if not self.agg_shell or self.agg_shell.closed:
            raise NetworkConnectionError("SSH shell to aggregation switch is closed", reconnect_needed=True)
        
        # Don't try to SSH to the seed IP itself (circular loop)
        if target_ip == self.seed_aggregate_ip:
            self.log(f"[SSH] Skipping SSH to seed IP {target_ip} to avoid loop", "DEBUG")
            return False

        self.log(f"SSH hop to {self.get_device_identifier(target_ip, target_hostname)} (attempt {attempt}/{SSH_RETRY_ATTEMPTS})")
        
        try:
            pre_host = self.get_hostname(self.agg_shell) or self.agg_hostname or "UNKNOWN"
        except Exception:
            pre_host = self.agg_hostname or "UNKNOWN"
        
        # Build credential order
        cred_order = []
        if target_ip in self.device_creds:
            cred_order.append(self.device_creds[target_ip])
        if self.agg_creds and self.agg_creds not in cred_order:
            cred_order.append(self.agg_creds)
        for cs in CREDENTIAL_SETS:
            if cs not in cred_order:
                cred_order.append(cs)
        
        connection_refused_count = 0
        auth_failed_count = 0
        
        for cred_idx, cred in enumerate(cred_order):
            user = cred["username"]
            pwd = cred["password"]
            enable = cred.get("enable") or cred["password"]
            
            syntaxes = [
                f"ssh -l {user} {target_ip}",
                f"ssh {user}@{target_ip}",
            ]
            
            for syntax_idx, cmd in enumerate(syntaxes):
                self.log(f"[SSH] Trying: {cmd} (cred {cred_idx+1}/{len(cred_order)})", "DEBUG")
                _ = self.send_cmd(self.agg_shell, cmd, timeout=3, silent=True)
                
                ok, out, connection_state = self._interactive_hop(
                    self.agg_shell, target_ip, user, pwd, enable, overall_timeout=120
                )
                
                if not ok:
                    # Track failure types
                    if connection_state == "connection_refused":
                        self.log(f"[SSH] Connection refused/timed out (common on busy Cisco VTY lines)", "WARN")
                        connection_refused_count += 1
                    elif connection_state == "auth_failed":
                        self.log(f"[SSH] Authentication failed for {user}", "WARN")
                        auth_failed_count += 1
                    else:
                        self.log(f"[SSH] Failed with state: {connection_state}", "WARN")

                    self.cleanup_failed_session()
                    
                    if not self.verify_aggregate_connection():
                        raise NetworkConnectionError("Connection to aggregation switch lost", reconnect_needed=True)
                    
                    # If connection was refused, it's not a credential issue. 
                    # Don't try other syntaxes/creds in THIS attempt loop; just fail this attempt so we can wait and retry.
                    if connection_state == "connection_refused":
                        break 
                    
                    continue
                
                # Verify hostname changed
                try:
                    post_host = self.get_hostname(self.agg_shell) or ""
                except Exception as e:
                    self.log(f"[SSH] Could not get post-hop hostname: {e}", "WARN")
                    post_host = ""
                
                # Check if we're still on the same switch
                if post_host.strip() == pre_host.strip():
                    self.log(f"[SSH] Hostname did not change (still '{pre_host}'). Treating as FAILED connection.", "WARN")
                    
                    # It's a failure (silent or refused). Treat it as such to force a retry.
                    connection_refused_count += 1
                    self.cleanup_failed_session()
                    break # Break syntax loop to force retry
                
                # Success - hostname changed!
                self.session_depth += 1
                self.send_cmd(self.agg_shell, "terminal length 0", timeout=5, silent=True)
                self.log(f"Successfully connected to {target_ip} as {user} (host: {post_host})")
                self.device_creds[target_ip] = cred
                return True
            
            # Break credential loop if connection refused (wait for retry delay)
            if connection_refused_count > 0:
                break

        # ===== RETRY LOGIC =====

        # If auth failed specifically, we generally don't retry unless mixed with connection issues
        if auth_failed_count > 0 and connection_refused_count == 0:
            self.log(f"[SSH] Authentication failed with all credential sets", "ERROR")
            raise NetworkConnectionError(
                f"Authentication failed to {target_ip} - check credentials",
                reconnect_needed=False, retry_allowed=False
            )

        # For everything else (Refused, Timeout, Unknown, Silent Failure) -> RETRY aggressively
        if attempt < SSH_RETRY_ATTEMPTS:
            self.log(f"[RETRY] Connection failed/refused. Waiting {SSH_RETRY_DELAY}s before retry {attempt+1}/{SSH_RETRY_ATTEMPTS}...", "INFO")
            time.sleep(SSH_RETRY_DELAY)
            
            if not self.verify_aggregate_connection():
                raise NetworkConnectionError("Lost connection to aggregation switch during retry delay", reconnect_needed=True)
                
            return self.ssh_to_device(target_ip, target_hostname, attempt + 1)
        
        # Final Give up
        raise NetworkConnectionError(
            f"SSH to {target_ip} failed after {SSH_RETRY_ATTEMPTS} attempts",
            reconnect_needed=False, retry_allowed=False
        )
    
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
            return self._looks_like_prompt(data)
        except Exception as e:
            self.log(f"[EXIT] Exception during exit: {e}", "WARN")
            return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FUNCTION: diagnose_connection (NEW)
    # ═══════════════════════════════════════════════════════════════════════════
    def diagnose_connection(self, target_ip):
        """
        Run diagnostic commands to understand why SSH might be failing.
        Returns: "local_ip", "device_down", "reachable", or "unknown"
        """
        self.log(f"[DIAG] Running diagnostics for {target_ip}", "INFO")
        
        try:
            # Check if it's a local interface FIRST (fastest check)
            show_ip = self.send_cmd(self.agg_shell, "show ip interface brief | include " + target_ip, timeout=5, silent=True)
            if target_ip in show_ip and ("up" in show_ip.lower() or "administratively" in show_ip.lower()):
                self.log(f"[DIAG] ✓ Found {target_ip} in local interface list - this IS a local IP", "INFO")
                return "local_ip"
            
            # Test IP reachability
            ping_out = self.send_cmd(self.agg_shell, f"ping {target_ip} repeat 3", timeout=10, silent=True)
            if "Success rate is 100" in ping_out or "!!!" in ping_out:
                self.log(f"[DIAG] ✓ IP {target_ip} is reachable via ping", "INFO")
                ping_success = True
            else:
                self.log(f"[DIAG] ✗ IP {target_ip} ping failed - may be down or blocked", "WARN")
                ping_success = False
            
            # Check ARP table
            arp_out = self.send_cmd(self.agg_shell, f"show ip arp {target_ip}", timeout=5, silent=True)
            if "Incomplete" in arp_out:
                self.log(f"[DIAG] ✗ ARP entry incomplete - device may be down", "WARN")
                return "device_down"
            elif target_ip in arp_out:
                self.log(f"[DIAG] ✓ ARP entry found for {target_ip}", "INFO")
                if ping_success:
                    return "reachable"
                else:
                    return "reachable_no_ping"  # Has ARP but ping failed (ICMP blocked?)
            
            # No ARP entry
            if not ping_success:
                return "device_down"
            
            return "reachable"
            
        except Exception as e:
            self.log(f"[DIAG] Diagnostic error: {e}", "WARN")
            return "unknown"

    # ── Core collection ───────────────────────────────────────────────────
    def collect_device_info(self, mgmt_ip, hostname=None, skip_discovery=False):
        self.log("\n" + "="*60)
        self.log(f"Collecting data from: {self.get_device_identifier(mgmt_ip, hostname)}")
        
        if skip_discovery:
            self.log("  Skipping discovery for seed aggregate switch")
            return None
        
        if not self.verify_aggregate_connection():
            self.reconnect_to_aggregate("Seed connection lost before hop")
        
        ssh_accessible = True
        if mgmt_ip != AGGREGATE_ENTRY_IP:
            try:
                if not self.ssh_to_device(mgmt_ip, hostname):
                    ssh_accessible = False
            except NetworkConnectionError as e:
                if getattr(e, 'reconnect_needed', False) or not self.verify_aggregate_connection():
                    self.reconnect_to_aggregate("Lost while hopping to device")
                    try:
                        if not self.ssh_to_device(mgmt_ip, hostname):
                            ssh_accessible = False
                    except Exception:
                        ssh_accessible = False
                else:
                    ssh_accessible = False
            
            if not ssh_accessible:
                self.log(f" Cannot SSH to {mgmt_ip} - running diagnostics", "WARN")
                
                # Run diagnostics to determine why
                diag_result = self.diagnose_connection(mgmt_ip)
                
                if diag_result == "local_ip":
                    self.log(f"Diagnostics confirm {mgmt_ip} is a local IP on seed - skipping", "INFO")
                    return None  # Don't create a record for local IPs
                
                # Continue marking as inaccessible
                self.log(f"Diagnostics result: {diag_result} - marking as inaccessible", "INFO")
                
                # Use the hostname from the queue if available
                if not hostname:
                    # Search through neighbor data
                    for device_ip, device_data in self.devices.items():
                        for nbr in device_data.get("neighbors", []):
                            if nbr.get("neighbor_mgmt_ip") == mgmt_ip:
                                hostname = nbr.get("neighbor_hostname", "Unknown")
                                discovered_via = nbr.get("discovered_via")
                                if hasattr(self, '_neighbor_platform_cache'):
                                    platform = self._neighbor_platform_cache.get(mgmt_ip)
                                break
                        if hostname:
                            break
                
                if not hostname:
                    hostname = "Unknown"
                
                platform = self._neighbor_platform_cache.get(mgmt_ip) if hasattr(self, '_neighbor_platform_cache') else None
                
                # Use hardware-based role determination with platform info
                device_role = self.determine_device_role(hostname, platform)
                
                note_parts = [f"Inaccessible via SSH"]
                if diag_result == "device_down":
                    note_parts.append("appears to be powered off or unreachable")
                elif diag_result == "reachable_no_ping":
                    note_parts.append("has ARP entry but ICMP blocked")
                
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
            
            serial = self.get_serial_number(shell)
            ios_version = self.get_ios_version(shell)
            switch_model = self.get_switch_model(shell)
            
            # Use hardware + hostname based role determination
            device_role = self.determine_device_role(hostname, switch_model)
            
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
                neighbor_hostname = nbr['hostname']
                neighbor_ip = nbr.get('mgmt_ip')  # Changed to use .get() to handle None
                
                # Handle devices without management IPs
                if not neighbor_ip:
                    self.log(f"  → Neighbor: {neighbor_hostname} (No Management IP) "
                             f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}] "
                             f"[NOTE: {nbr.get('note', 'No IP')}]")
                else:
                    self.log(f"  → Neighbor: {neighbor_hostname} ({neighbor_ip}) "
                             f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]"
                             f"{' ['+link_note+']' if link_note else ''}")
                
                neighbor_entry = {
                    "neighbor_hostname": neighbor_hostname,
                    "neighbor_mgmt_ip": neighbor_ip,
                    "local_interface": nbr["local_intf"],
                    "remote_interface": nbr["remote_intf"],
                    "discovered_via": discovery_method
                }
                
                # Add note if present (for devices without management IPs)
                if nbr.get("note"):
                    neighbor_entry["note"] = nbr["note"]
                
                if link_note:
                    neighbor_entry["link_note"] = link_note
                
                device_info["neighbors"].append(neighbor_entry)
                
                # Only queue for discovery if we have an IP
                if neighbor_ip and self.should_visit_device(neighbor_ip, neighbor_hostname):
                    self.to_visit.append((neighbor_ip, neighbor_hostname))
                    self.log(f"    Added {self.get_device_identifier(neighbor_ip, neighbor_hostname)} to discovery queue")
                elif not neighbor_ip:
                    self.log(f"    Cannot visit {neighbor_hostname} - no management IP available")
            
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
            
            serial = self.get_serial_number(self.agg_shell)
            ios_version = self.get_ios_version(self.agg_shell)
            switch_model = self.get_switch_model(self.agg_shell)
            
            # Use hardware + hostname based role determination
            device_role = self.determine_device_role(hostname, switch_model)
            
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
                neighbor_hostname = nbr['hostname']
                neighbor_ip = nbr.get('mgmt_ip')  # Changed to use .get() to handle None
                
                # Handle devices without management IPs
                if not neighbor_ip:
                    self.log(f"  → Neighbor: {neighbor_hostname} (No Management IP) "
                             f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}] "
                             f"[NOTE: {nbr.get('note', 'No IP')}]")
                else:
                    self.log(f"  → Neighbor: {neighbor_hostname} ({neighbor_ip}) "
                             f"via {nbr['local_intf']} ↔ {nbr['remote_intf']} [{discovery_method}]"
                             f"{' ['+link_note+']' if link_note else ''}")
                
                entry = {
                    "neighbor_hostname": neighbor_hostname,
                    "neighbor_mgmt_ip": neighbor_ip,
                    "local_interface": nbr["local_intf"],
                    "remote_interface": nbr["remote_intf"],
                    "discovered_via": discovery_method
                }
                
                # Add note if present
                if nbr.get("note"):
                    entry["note"] = nbr["note"]
                
                if link_note:
                    entry["link_note"] = link_note
                
                seed_info["neighbors"].append(entry)
                
                # Only queue for discovery if we have an IP
                if neighbor_ip and self.should_visit_device(neighbor_ip, neighbor_hostname):
                    self.to_visit.append((neighbor_ip, neighbor_hostname))
                    self.log(f"    Added {self.get_device_identifier(neighbor_ip, neighbor_hostname)} to discovery queue")
                elif not neighbor_ip:
                    self.log(f"    Cannot visit {neighbor_hostname} - no management IP available")
            
            self.devices[hostname] = seed_info  # Store by hostname
            self.mark_device_visited(hostname)
        
        except NetworkConnectionError:
            self.reconnect_to_aggregate("During seed info collection")
        except Exception as e:
            self.log(f"Error collecting seed aggregate info: {e}", "ERROR")
        
        # Add any pre-configured aggregate IPs
        for ip in AGGREGATE_MGMT_IPS:
            # We don't know the hostname yet, so we'll discover it when we visit
            if (ip, None) not in self.to_visit:
                self.to_visit.append((ip, None))
                self.log(f"  Added pre-configured aggregate {ip} to queue")
        
        # Main discovery loop
        while self.to_visit:
            current_ip, current_hostname = self.to_visit.popleft()
            
            # Double-check if already visited by hostname
            if current_hostname and self.is_device_visited(current_hostname):
                self.log(f"Skipping {self.get_device_identifier(current_ip, current_hostname)} - already visited")
                continue
            
            if not self.verify_aggregate_connection():
                self.reconnect_to_aggregate("Before visiting next device")
            
            # Collect device info
            info = self.collect_device_info(current_ip, current_hostname)
            if info:
                discovered_hostname = info.get("hostname")
                if discovered_hostname and discovered_hostname != "Unknown":
                    self.devices[discovered_hostname] = info  # Store by hostname
                    self.mark_device_visited(discovered_hostname)
                else:
                    # Fallback to IP if no hostname
                    self.devices[current_ip] = info
                    if current_hostname:
                        self.mark_device_visited(current_hostname)
            else:
                self.log(f"Failed to collect info from {current_ip}", "ERROR")
                # Still mark as visited to avoid retrying
                if current_hostname:
                    self.mark_device_visited(current_hostname)
        
        try:
            if self.agg_client:
                self.agg_client.close()
        except Exception:
            pass
        
        duration = (datetime.now() - self.start_time).total_seconds()
        self.log("="*60)
        self.log(f"Discovery complete! Found {len(self.devices)} devices")
        self.log(f"Total discovery time: {duration:.1f} seconds")
        self.log(f"Devices tracked by hostname: {len(self.visited_hostnames)}")
        self.log("="*60)
    
    # ── Output writers ────────────────────────────────────────────────────
    def generate_json(self, filename="network_topology.json"):
        devices_list = list(self.devices.values())
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(devices_list, f, indent=2)
        self.log(f"\n✓ Topology saved to {filename}")
        
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
        
        # Count neighbors without IPs
        neighbors_without_ip = 0
        for d in devices_list:
            for nbr in d.get("neighbors", []):
                if not nbr.get("neighbor_mgmt_ip"):
                    neighbors_without_ip += 1
        
        if neighbors_without_ip > 0:
            self.log(f"\nNeighbors without management IP: {neighbors_without_ip}")
        
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
                nbr_note = nbr.get("note", "")
                link_str = f" - {link_note}" if link_note else ""
                note_str = f" - {nbr_note}" if nbr_note else ""
                ip_display = nbr.get('neighbor_mgmt_ip') or 'No IP'
                self.log(f"    • {nbr['neighbor_hostname']} ({ip_display}) via "
                         f"{nbr['local_interface']} ↔ {nbr['remote_interface']} [{discovered}]{link_str}{note_str}")
    
    def write_metadata(self, filename="discovery_metadata.txt"):
        duration = (datetime.now() - self.start_time).total_seconds()
        with open(filename, "w", encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("NETWORK TOPOLOGY DISCOVERY METADATA\n")
            f.write("="*60 + "\n\n")
            f.write(f"Discovery Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Entry Point: {AGGREGATE_ENTRY_IP}\n")
            f.write(f"Seed Aggregate: {self.seed_aggregate_ip}\n")
            f.write(f"Seed Hostname: {self.agg_hostname}\n")
            f.write(f"Duration: {duration:.1f} seconds\n")
            f.write(f"Total Devices Discovered: {len(self.devices)}\n")
            f.write(f"Devices Tracked by Hostname: {len(self.visited_hostnames)}\n\n")
            
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
            
            # Count neighbors without management IPs
            neighbors_without_ip = 0
            for d in self.devices.values():
                for nbr in d.get("neighbors", []):
                    if not nbr.get("neighbor_mgmt_ip"):
                        neighbors_without_ip += 1
            
            if neighbors_without_ip > 0:
                f.write(f"Neighbors without management IP: {neighbors_without_ip}\n")
            
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
            f.write("DISCOVERED DEVICES (BY HOSTNAME)\n")
            f.write("="*60 + "\n")
            for hostname in sorted(self.visited_hostnames):
                # Find the device info
                device_info = self.devices.get(hostname)
                if device_info:
                    f.write(f"{hostname} → {device_info.get('management_ip', 'N/A')}\n")
                else:
                    f.write(f"{hostname} → (info not available)\n")
        
        self.log(f"✓ Metadata saved to {filename}")

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
