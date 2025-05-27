"""

MAC-LLDP Crawler Script
1. Purpose
This Python script automates the discovery and collection of MAC-address tables across a fabric of Cisco switches, using LLDP to hop switch-to-switch. It:

SSHes into a “root” switch.

Runs show mac address-table and parses the entries.

Parses show lldp neighbors detail to discover directly connected Cisco neighbors.

Recursively SSH-hops into each unvisited neighbor and repeats steps 2–3.

Outputs a JSON file mapping each switch’s hostname to its list of MAC-table entries.

2. Prerequisites
Python 3.7+

Paramiko library installed (pip install paramiko).

Network access: credentials (USERNAME/PASSWORD) must allow SSH and enable-mode on all target switches.

LLDP enabled on all switches to discover neighbors.

3. Configuration
At the top of the script, update:

python
Copy
Edit
USERNAME   = "admin"          # SSH user on all switches
PASSWORD   = "cisco"          # SSH/enable password
ROOT_IP    = "192.168.1.8"    # Management IP of the root switch
TIMEOUT    = 10               # Seconds to wait for prompt responses
MAX_READ   = 65535            # Max bytes to read at once from SSH channel
4. High-Level Workflow
connect_switch(ROOT_IP)

Opens an SSHClient to the root switch.

Enters enable mode.

Disables paging (terminal length 0).

crawl_mac(shell, ip)

If ip has not yet been visited:

Runs show mac address-table, captures raw output.

Calls parse_mac_table() to split and structure each entry.

Stores the parsed list under the switch’s hostname in mac_tables.

Always runs show lldp neighbors detail and uses parse_lldp_detail() to extract neighbor IPs & descriptors.

For each new Cisco neighbor, calls hop_to_neighbor(), then recurses into crawl_mac() on that neighbor, finally sending exit to return.

parse_mac_table(raw)

Splits the raw output into lines.

Ignores header/footer/separator lines.

Uses regex \s+ to break each valid line into four parts:

VLAN

MAC address

Type (e.g. DYNAMIC, STATIC, BLOCKED)

Port (e.g. Te1/0/23)

Returns a list of dictionaries:

json
Copy
Edit
[
  {
    "vlan": "801",
    "mac_address": "accc.8ead.f99e",
    "type": "BLOCKED",
    "port": "Te1/0/23"
  },
  …
]
Output

After traversal, writes mac_tables.json:

json
Copy
Edit
{
  "SW1": [
    { "vlan": "10", "mac_address": "001a.2b3c.4d5e", "type": "DYNAMIC", "port": "Gi1/0/1" },
    …
  ],
  "SW2": [ … ],
  …
}
5. Function Reference
expect_prompt(shell, patterns, timeout)
Reads from the Paramiko shell until one of the patterns substrings appears in the buffer or timeout expires.

Returns: Full buffer string.

send_cmd(shell, cmd, patterns, timeout)
Logs the command ([CMD]) and last‐line output ([OUT]).

Sends cmd\n to the shell.

Uses expect_prompt() to wait for the next prompt.

Returns: The raw multi-line output.

connect_switch(ip)
Creates a SSHClient, ignores unknown host keys.

Connects to ip, invokes an interactive shell.

Executes:

enable → enters privileged mode.

terminal length 0 → disables paging.

Returns: Tuple (client, shell) for further commands.

hop_to_neighbor(shell, ip)
From the existing shell, issues ssh -l USERNAME <ip>.

Handles:

Host‐key confirmation (yes/no)?.

Password prompt.

Mode escalation to enable if needed.

Disables paging again.

Leaves you at the neighbor’s prompt on the same shell.

get_hostname(shell)
Sends a blank line and captures the prompt.

Regex matches the last line ending in # or > to extract the hostname prefix.

parse_lldp_detail(raw)
Splits the LLDP detail output on lines of dashes.

For each block containing Local Intf::

Extracts local_intf, port_id, remote_name, sys_descr, and mgmt_ip via regex.

Returns: List of neighbor‐info dicts.

parse_mac_table(raw)
Filters out non-data lines (headers, separators).

Splits each MAC-table line on whitespace.

Maps the first four columns to vlan, mac_address, type, port.

Returns: List of parsed MAC entries.

crawl_mac(shell, ip)
Orchestrates the entire recursion:

Gathers & parses MAC table if first visit.

Discovers neighbors via LLDP.

For each unvisited Cisco neighbor:

hop_to_neighbor()

Recursively crawl_mac() on neighbor’s IP.

Sends exit to return.

6. Usage
bash
Copy
Edit
$ python3 mac_lldp_crawl.py
[CONNECT] → 192.168.1.8
[CMD] enable
...
[INFO] Crawling 192.168.1.8
[CMD] show mac address-table
[OUT] ...
[CMD] show lldp neighbors detail
...
[HOP] to neighbor 192.168.1.9
...
✅ MAC table crawl complete; output in mac_tables.json
Open mac_tables.json to inspect structured tables for each switch.

7. Next-Steps & Extensions
CSV Export: Convert each parsed entry list to a CSV file for spreadsheet analysis.

Parallel Crawling: Use threads or asyncio to speed up large fabrics.

Error Handling: Wrap SSH operations in try/except to recover from timeouts or auth failures.

Logging Framework: Replace print() with the logging module for adjustable verbosity.

Feel free to adapt or extend any section to match your team’s style guide!








"""
#!/usr/bin/env python3
import paramiko
import time
import re
import json

# --- USER CONFIG -------------------------------------------------------------
USERNAME = "admin"
PASSWORD = "cisco"
ROOT_IP  = "192.168.1.8"
TIMEOUT   = 10
MAX_READ  = 65535
# -----------------------------------------------------------------------------

visited = set()
mac_tables = {}


def expect_prompt(shell, patterns, timeout=TIMEOUT):
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
    print(f"[CMD] {cmd}")
    shell.send(cmd + "\n")
    out = expect_prompt(shell, patterns, timeout)
    last = out.splitlines()[-1] if out else "<no output>"
    print(f"[OUT] {last}")
    return out


def connect_switch(ip):
    print(f"[CONNECT] → {ip}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=USERNAME, password=PASSWORD,
                   look_for_keys=False, allow_agent=False, timeout=10)
    shell = client.invoke_shell()
    expect_prompt(shell, ("#", ">"))
    send_cmd(shell, "enable", patterns=("assword:", "#"))
    send_cmd(shell, PASSWORD, patterns=("#",))
    send_cmd(shell, "terminal length 0", patterns=("#",))
    return client, shell


def hop_to_neighbor(shell, ip):
    print(f"[HOP] ssh → {ip}")
    out = send_cmd(shell, f"ssh -l {USERNAME} {ip}",
                   patterns=("Destination","(yes/no)?","assword:","%","#",">"),
                   timeout=15)
    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:","%","#",">"), timeout=15)
    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("%","#",">"), timeout=15)
    if out.strip().endswith(">"):
        send_cmd(shell, "enable", patterns=("assword:","#"), timeout=15)
        send_cmd(shell, PASSWORD, patterns=("#",), timeout=15)
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
    print(f"[HOP] now at {ip}#\n")


def get_hostname(shell):
    shell.send("\n")
    buff = expect_prompt(shell, ("#", ">"), timeout=5)
    for line in reversed(buff.splitlines()):
        if m := re.match(r"^([^#>]+)[#>]", line.strip()):
            return m.group(1)
    return "unknown"


def parse_lldp_detail(raw):
    nbrs = []
    blocks = re.split(r"^-{2,}", raw, flags=re.M)
    for blk in blocks:
        if "Local Intf:" not in blk:
            continue
        entry = {"local_intf": None, "port_id": None,
                 "remote_name": None, "mgmt_ip": None,
                 "sys_descr": ""}
        if m := re.search(r"Local Intf:\s*(\S+)", blk):
            entry["local_intf"] = m.group(1)
        if m := re.search(r"Port id:\s*(\S+)", blk, re.IGNORECASE):
            entry["port_id"] = m.group(1)
        if m := re.search(r"System Name:\s*(\S+)", blk, re.IGNORECASE):
            entry["remote_name"] = m.group(1)
        if m := re.search(r"System Description:\s*([\s\S]+?)\n\s*\n", blk, re.IGNORECASE):
            entry["sys_descr"] = m.group(1).strip()
        if m := re.search(r"Management Addresses:[\s\S]*?IP:\s*(\d+\.\d+\.\d+\.\d+)", blk, re.IGNORECASE):
            entry["mgmt_ip"] = m.group(1)
        nbrs.append(entry)
    return nbrs


def parse_mac_table(raw):
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        # Skip headers, separators, or empty lines
        if not line or line.lower().startswith("vlan") or line.startswith("----"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 4:
            vlan, mac, type_, port = parts[0], parts[1], parts[2], parts[3]
            entries.append({
                "vlan": vlan,
                "mac_address": mac,
                "type": type_,
                "port": port
            })
    return entries


def crawl_mac(shell, ip):
    """
    Recursively crawl switches:
     - run 'show mac address-table'
     - parse and store entries per hostname
     - find unvisited Cisco neighbors via LLDP and recurse
    """
    print(f"\n[INFO] Crawling {ip}")
    hostname = get_hostname(shell)

    if ip not in visited:
        visited.add(ip)
        mac_raw = send_cmd(shell, "show mac address-table")
        parsed = parse_mac_table(mac_raw)
        mac_tables[hostname] = parsed
    else:
        print(f"[SKIP] {ip} already visited")
        return

    # Discover neighbors
    lldp_raw = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=15)
    nbrs = parse_lldp_detail(lldp_raw)
    for n in nbrs:
        ip_mgmt = n.get("mgmt_ip")
        if not ip_mgmt or ip_mgmt in visited:
            continue
        if "cisco" not in n.get("sys_descr", "").lower():
            continue

        print(f"[HOP] to neighbor {ip_mgmt}")
        hop_to_neighbor(shell, ip_mgmt)
        crawl_mac(shell, ip_mgmt)
        send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)


if __name__ == "__main__":
    client, shell = connect_switch(ROOT_IP)
    crawl_mac(shell, ROOT_IP)
    client.close()

    # Write structured MAC tables
    with open("mac_tables.json", "w") as f:
        json.dump(mac_tables, f, indent=2)

    print("\n✅ MAC table crawl complete; output in mac_tables.json")
