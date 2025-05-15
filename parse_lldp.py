'''
This script drives a single Paramiko shell on your root Cisco switch, crawling LLDP neighbors, hopping SSH from switch to switch, gathering VLAN, version, serial info on first visit, and building a nested JSON map of your Cisco LLDP topology—all fully automated via Python.

1. Configuration & Global State
python
Copy
Edit
USERNAME = "admin"
PASSWORD = "cisco"
ROOT_IP  = "192.168.1.1"
TIMEOUT  = 10
MAX_READ = 65535

visited = set()
Credentials and root switch IP are hard-coded.

visited tracks which management IPs have already been crawled to avoid loops.

2. Core SSH Helpers
expect_prompt(shell, patterns, timeout)
Reads from the Paramiko shell until one of the given prompt strings (e.g. "#", ">") appears, or until the timeout.

Buffers all received text so multi-line prompts or error messages can be matched.

send_cmd(shell, cmd, patterns, timeout)
Sends cmd + "\n" to the shell.

Calls expect_prompt() to wait for the next prompt.

Returns the full output, which the caller can parse.

3. Initial Connection
connect_switch(ip)
SSHes from your PC into the root switch at ip.

Invokes an interactive shell.

Disables paging with terminal length 0 so long outputs stream without --More-- pauses.

Returns the Paramiko client and shell for further commands.

4. Prompt‐Based Hostname
get_root_name(shell)
Sends a blank line to redraw the prompt (e.g. SW1#).

Scans the returned buffer backwards to find the first line ending in # or >, and treats the text before it as the hostname.

Falls back to ROOT_IP if parsing fails.

5. In-Shell Neighbor Hopping
hop_to_neighbor(shell, ip)
From the current switch’s CLI, runs ssh -l admin <ip>.

Answers any “yes/no” host-key prompt.

Sends the password when asked.

If it lands in user-exec (>), issues enable + the same password to get into privileged mode (#).

Disables paging again on the neighbor.

Leaves you at the neighbor’s # prompt, ready for further commands, all within the same Paramiko shell.

6. LLDP Parsing
parse_lldp_detail(raw)
Splits the output of show lldp neighbors detail on dashed separators (------…).

For each block containing Local Intf:, extracts:

Local interface

Port ID

Remote system name

System description (for filtering)

Management IP

Returns a list of neighbor dictionaries.

7. Recursive Topology Assembly
build_topology(shell, ip)
Log & Hostname

Prints [INFO] Mapping <ip>

Determines the device’s hostname from the prompt.

First-Visit Data Collection

If ip not in visited:

Adds it to visited.

Collects:

show interface vlan 100 → VLAN-100 IP/subnet & MAC

show version → IOS version & system serial

Otherwise skips those.

LLDP Neighbor Discovery

Always runs show lldp neighbors detail

Parses into all_nbrs and prints the raw list for debugging.

Filter & Recurse

python
Copy
Edit
if (n["mgmt_ip"]
    and "cisco" in n["sys_descr"].lower()
    and n["mgmt_ip"] not in visited):
    # hop & recurse
Skips neighbors without a management IP.

Skips non-Cisco devices (sys_descr must contain “cisco”).

Skips already-visited IPs.

For each remaining neighbor:

Calls hop_to_neighbor() to SSH into it.

Recursively calls build_topology() on that IP.

(Optional) Would exit back up—though the exit line is currently commented out, so the script stays at the deepest level.

Return Structure

Builds a list of entries with:

json
Copy
Edit
{
  "local_interface": "...",
  "remote_name":     "...",
  "remote_port":     "...",
  "port_description":"...",    # if parsed
  "management_ip":   "...",
  "system_description":"...",
  "neighbors":      [ ... ]    # recursively built
}
Returns the list as topo under each recursion.

8. Main Execution
python
Copy
Edit
if __name__ == "__main__":
    visited.add(ROOT_IP)
    client, shell = connect_switch(ROOT_IP)
    root_name = get_root_name(shell)
    neighbors = build_topology(shell, ROOT_IP)
    client.close()
    # Assemble JSON:
    # { "<root-name>": { "management_ip": ROOT_IP, "neighbors": [ ... ] } }
    with open("topology.json","w") as f:
        json.dump({root_name: {"management_ip": ROOT_IP, "neighbors": neighbors}}, f, indent=2)
    print(f"✅ Topology written for root switch '{root_name}'")
SSHes once into the root switch.

Populates visited with the root IP.

Discovers and parses the entire topology recursively.

Dumps the final nested structure to topology.json.

'''
#!/usr/bin/env python3
import paramiko
import time
import re
import json

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
USERNAME = "admin"
PASSWORD = "cisco"
ROOT_IP  = "192.168.1.1"
TIMEOUT  = 10
MAX_READ = 65535
# ───────────────────────────────────────────────────────────────────────────────

visited = set()

def expect_prompt(shell, patterns, timeout=TIMEOUT):
    buff, end = "", time.time()+timeout
    while time.time()<end:
        if shell.recv_ready():
            buff += shell.recv(MAX_READ).decode("utf-8","ignore")
            for p in patterns:
                if p in buff:
                    return buff
        else:
            time.sleep(0.1)
    return buff

def send_cmd(shell, cmd, patterns=("#",">"), timeout=TIMEOUT):
    shell.send(cmd+"\n")
    return expect_prompt(shell, patterns, timeout)

def connect_switch(ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=USERNAME, password=PASSWORD,
                   look_for_keys=False, allow_agent=False)
    shell = client.invoke_shell()
    expect_prompt(shell, patterns=("#",">"))
    send_cmd(shell, "terminal length 0", patterns=("#",))
    return client, shell

def get_root_name(shell):
    """
    Send a blank line to elicit the prompt (e.g. 'SW1#'), then
    capture output and parse the hostname from the prompt.
    """
    # send a newline to cause the switch to re-display its prompt
    shell.send("\n")
    buff = expect_prompt(shell, patterns=("#", ">"), timeout=5)

    # scan from the bottom up for a prompt line
    for line in reversed(buff.splitlines()):
        line = line.strip()
        m = re.match(r"^([^#>]+)[#>]", line)
        if m:
            return m.group(1)

    # fallback
    return ROOT_IP

def hop_to_neighbor(shell, ip):
    """
    From the current shell, SSH into a neighbor at 'ip',
    handle host-key and password prompts, then enter enable mode.
    """
    out = send_cmd(shell, f"ssh -l {USERNAME} {ip}", patterns=("yes/no", "assword:"), timeout=5)
    if "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:",), timeout=5)
    out = send_cmd(shell, PASSWORD, patterns=("#", ">"), timeout=5)
    # if we end up at '>', escalate
    if out.strip().endswith(">"):
        out = send_cmd(shell, "enable", patterns=("assword:",), timeout=5)
        out = send_cmd(shell, PASSWORD, patterns=("#",), timeout=5)
    # disable paging
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)

def parse_lldp_detail(raw):
    """
    Parse 'show lldp neighbors detail' into list of dicts:
    local_intf, port_id, port_desc, remote_name, sys_descr, mgmt_ip
    """
    neighbors = []
    # split on the dashed-line separators
    blocks = re.split(r"^-{2,}", raw, flags=re.M)
    for blk in blocks:
        if "Local Intf:" not in blk:
            continue
        nd = {
            "local_intf":  None,
            "port_id":     None,
            "port_desc":   None,
            "remote_name": None,
            "sys_descr":   "",
            "mgmt_ip":     None
        }
        if m := re.search(r"Local Intf:\s*(\S+)", blk):
            nd["local_intf"] = m.group(1)
        if m := re.search(r"Port id:\s*(\S+)", blk, re.IGNORECASE):
            nd["port_id"] = m.group(1)
        if m := re.search(r"Port Description:\s*(\S+)", blk, re.IGNORECASE):
            nd["port_desc"] = m.group(1)
        if m := re.search(r"System Name:\s*(\S+)", blk, re.IGNORECASE):
            nd["remote_name"] = m.group(1)
        if m := re.search(r"System Description:\s*([\s\S]+?)\n\s*\n", blk, re.IGNORECASE):
            nd["sys_descr"] = m.group(1).strip()
        if m := re.search(r"Management Addresses:[\s\S]*?IP:\s*(\d+\.\d+\.\d+\.\d+)",
                          blk, re.IGNORECASE):
            nd["mgmt_ip"] = m.group(1)
        neighbors.append(nd)
    return neighbors

def build_topology(shell, ip):
    """
    Recursively map LLDP on 'ip', SSH into any Cisco neighbors
    with management IPs, and build a topology tree.
    """
    print(f"[INFO] Mapping {ip}")
    raw = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=15)
    nbrs = parse_lldp_detail(raw)

    topo = []
    for n in nbrs:
        entry = {
            "local_interface":    n["local_intf"],
            "remote_name":        n["remote_name"],
            "remote_port":        n["port_id"],
            "port_description":   n["port_desc"],
            "management_ip":      n["mgmt_ip"],
            "system_description": n["sys_descr"],
            "neighbors":          []
        }
        topo.append(entry)

        # Recurse if it's a Cisco switch with a mgmt IP we haven't seen
        if (n["mgmt_ip"]
            and "cisco" in n["sys_descr"].lower()
            and n["mgmt_ip"] not in visited):

            visited.add(n["mgmt_ip"])
            hop_to_neighbor(shell, n["mgmt_ip"])
            entry["neighbors"] = build_topology(shell, n["mgmt_ip"])
            #send_cmd(shell, "exit", patterns=("#",), timeout=5)

    return topo

def get_hostname(shell):
    """
    Runs 'show run | include ^hostname' on the current shell
    and returns the parsed hostname.
    """
    out = send_cmd(shell, "show running-config | include ^hostname", patterns=("#",), timeout=5)
    # out will look like 'hostname SW1\n\r\nSW1#'
    m = re.search(r"hostname\s+(\S+)", out)
    return m.group(1) if m else ROOT_IP


if __name__ == "__main__":
    visited.add(ROOT_IP)
    client, shell = connect_switch(ROOT_IP)

    # 1) pull the hostname from the prompt
    root_name = get_root_name(shell)

    # 2) build the LLDP topology
    neighbors = build_topology(shell, ROOT_IP)
    client.close()

    # 3) assemble and write out JSON
    full_topo = {
        root_name: {
            "management_ip": ROOT_IP,
            "neighbors":     neighbors
        }
    }
    with open("topology.json","w") as f:
        json.dump(full_topo, f, indent=2)

    print(f"✅ Topology written for root switch '{root_name}'")
