'''
This script automates an LLDP-based topology crawl entirely from within the CLI of a “root” Cisco switch, by SSH-ing from switch to switch and gathering per-device details. Here’s what each part does:

1. Configuration & State
python
Copy
Edit
USERNAME  = "admin"
PASSWORD  = "cisco"
ROOT_IP   = "192.168.1.1"
TIMEOUT   = 10
MAX_READ  = 65535

visited = set()
Defines your SSH credentials, the root switch’s management IP, read timeouts, and a visited set to avoid revisiting devices.

2. Low-Level SSH Helpers
expect_prompt(shell, patterns, timeout)
Reads from the Paramiko shell until one of the specified prompt “patterns” (e.g. "#" or ">") appears, or until timeout seconds elapse.

Buffers all incoming data so you can match multi-line prompts or errors.

send_cmd(shell, cmd, patterns, timeout)
Sends a command (cmd + "\n") to the shell.

Calls expect_prompt() to wait for the next prompt.

Prints both the command and the last line of its output for debugging.

3. Connecting & Paging
connect_switch(ip)
SSHes from your PC into the root switch at ip.

Invokes an interactive shell.

Enters enable mode (answers the enable password).

Disables paging (terminal length 0) so commands like show lldp neighbors detail stream without --More-- pauses.

4. In-Shell Hopping
hop_to_neighbor(shell, ip)
From inside the current switch’s CLI, runs ssh -l admin <ip>.

Answers the “yes/no” host-key prompt if needed.

Sends the password when prompted.

If it lands in user-exec prompt (>), sends enable + password to get #.

Turns off paging on the neighbor too.

Leaves you at the neighbor’s # prompt, all within the same Paramiko shell.

5. Parsing Utilities
get_hostname(shell)
Sends a blank line to redraw the prompt.

Scans backwards through the buffered output for the first line ending in # or >, and grabs the text before it as the switch’s hostname.

parse_lldp_detail(raw)
Splits the output of show lldp neighbors detail on the dashed separators (------…).

For each block containing “Local Intf:”, extracts:

Local interface (Local Intf:)

Port ID (Port id:)

Neighbor system name (System Name:)

Management IP (Management Addresses: … IP:)

System description (for later filtering)

Returns a list of neighbor-dicts.

6. Recursive Topology Build
build_topology(shell, ip)
Entry Logging
Prints [INFO] Mapping <ip>.

First-Time Data Collection
If this ip is not in visited:

Adds it to visited.

Collects VLAN 100 info via show interface vlan 100 (IP address and MAC).

Collects software version and serial number via show version.
Otherwise, it skips those “heavy” commands.

LLDP Neighbor Discovery
Always runs show lldp neighbors detail, parses with parse_lldp_detail(), and prints the raw neighbor list for debugging.

Neighbor Filtering
For each neighbor entry:

Skips if no management IP.

Skips if already in visited.

Skips if the system description does not contain “cisco” (so you only SSH into Cisco boxes).

Recursive SSH Hops
For each remaining neighbor:

Calls hop_to_neighbor() to SSH into that neighbor’s CLI.

Recursively calls build_topology(shell, neighbor_ip) to repeat the process on the neighbor.

After returning, sends exit to go back up one level in the switch-to-switch chain.

Assembles each neighbor into a JSON-serializable dict under the "neighbors" list.

7. Main Execution
python
Copy
Edit
if __name__ == "__main__":
    client, shell = connect_switch(ROOT_IP)
    topology = build_topology(shell, ROOT_IP)
    client.close()
    # Write nested JSON: { "<root-hostname>": { … } }
    with open("topology.json", "w") as f:
        json.dump({topology["hostname"]: topology}, f, indent=2)
SSHes once into the root switch.

Kicks off the recursive crawl.

Closes the SSH client.

Saves the entire nested topology (with VLAN100 info, version, serial, and LLDP-based links) into topology.json.

In Summary
This script automates exactly what a network engineer would do manually:

SSH into a root switch.

Enter enable mode and turn off paging.

Examine LLDP detail to find Cisco neighbors.

SSH from switch to switch inside the CLI, collecting VLAN100, version, and serial on the first visit.

Build a nested JSON map of the topology.

Write it out for reporting or further processing.

It ensures you never revisit the same device, and only hops into genuine Cisco neighbors, yielding a clean, hierarchical topology tree in JSON form.
'''
#!/usr/bin/env python3
import paramiko
import time
import re
import json

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
USERNAME  = "admin"
PASSWORD  = "cisco"
ROOT_IP   = "192.168.1.1"
TIMEOUT   = 10
MAX_READ  = 65535
# ─────────────────────────────────────────────────────────────────────────────

visited = set()

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
    """SSH from PC into the root switch, enable + disable paging."""
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
    """SSH from inside root shell into <ip>, then enable + disable paging."""
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
    """Extract the hostname from the current prompt (e.g. 'SW1#')."""
    shell.send("\n")
    buff = expect_prompt(shell, ("#", ">"), timeout=5)
    for line in reversed(buff.splitlines()):
        if m := re.match(r"^([^#>]+)[#>]", line.strip()):
            return m.group(1)
    return "unknown"

def parse_lldp_detail(raw):
    """Parse 'show lldp neighbors detail' into a list of neighbor dicts."""
    nbrs = []
    blocks = re.split(r"^-{2,}", raw, flags=re.M)
    for blk in blocks:
        if "Local Intf:" not in blk:
            continue
        entry = {
            "local_intf":    None,
            "port_id":       None,
            "remote_name":   None,
            "mgmt_ip":       None,
            "sys_descr":     ""
        }
        if m := re.search(r"Local Intf:\s*(\S+)", blk):
            entry["local_intf"] = m.group(1)
        if m := re.search(r"Port id:\s*(\S+)", blk, re.IGNORECASE):
            entry["port_id"] = m.group(1)
        if m := re.search(r"System Name:\s*(\S+)", blk, re.IGNORECASE):
            entry["remote_name"] = m.group(1)
        if m := re.search(r"System Description:\s*([\s\S]+?)\n\s*\n", blk, re.IGNORECASE):
            entry["sys_descr"] = m.group(1).strip()
        if m := re.search(
            r"Management Addresses:[\s\S]*?IP:\s*(\d+\.\d+\.\d+\.\d+)",
            blk, re.IGNORECASE
        ):
            entry["mgmt_ip"] = m.group(1)
        nbrs.append(entry)
    return nbrs

def build_topology(shell, ip):
    """
    Recursively crawl from root-switch shell:
     - collect VLAN100, version, serial once per IP
     - parse LLDP detail and debug-log each neighbor
     - hop into unvisited Cisco neighbors only
     - exit back up after each recursion
    """
    print(f"\n[INFO] Mapping {ip}")
    first_time = ip not in visited
    hostname = get_hostname(shell)

    if first_time:
        visited.add(ip)
        # VLAN100
        vlan_raw = send_cmd(shell, "show interface vlan 100")
        ip_m  = re.search(r"Internet address is (\S+)", vlan_raw)
        mac_m = re.search(r"address is (\S+)", vlan_raw)
        vlan_ip  = ip_m.group(1) if ip_m else None
        vlan_mac = mac_m.group(1) if mac_m else None
        # Version & Serial
        ver_raw = send_cmd(shell, "show version")
        ver_m   = re.search(r"Version\s+(\S+)", ver_raw)
        ser_m   = re.search(r"System serial number\s*:\s*(\S+)", ver_raw, re.IGNORECASE)
        version = ver_m.group(1) if ver_m else None
        serial  = ser_m.group(1) if ser_m else None
    else:
        print(f"[SKIP] Data already collected for {ip}")
        vlan_ip = vlan_mac = version = serial = None

    # LLDP detail & debug
    lldp_raw = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=15)
    all_nbrs = parse_lldp_detail(lldp_raw)
    print(f"[DEBUG] raw neighbors: {all_nbrs}")

    node = {
        "hostname":         hostname,
        "management_ip":    ip,
        "vlan_100_ip":      vlan_ip,
        "vlan_100_mac":     vlan_mac,
        "software_version": version,
        "serial_number":    serial,
        "neighbors":        []
    }

    for n in all_nbrs:
        print(f"[FOUND] Neighbor: {n['remote_name']} @ {n['mgmt_ip']} on {n['local_intf']}")
        if not n["mgmt_ip"]:
            print("  [SKIP] no mgmt IP")
            continue
        if n["mgmt_ip"] in visited:
            print("  [SKIP] already visited")
            continue
        if "cisco" not in n["sys_descr"].lower():
            print(f"  [SKIP] non-Cisco switch ({n['sys_descr'][:30]})")
            continue

        print(f"  [HOP] Cisco neighbor → hopping to {n['mgmt_ip']}")
        hop_to_neighbor(shell, n["mgmt_ip"])
        child = build_topology(shell, n["mgmt_ip"])
        send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)

        entry = {
            "local_interface": n["local_intf"],
            "remote_device":   n["remote_name"],
            "remote_port":     n["port_id"],
            "child":           child
        }
        node["neighbors"].append(entry)

    return node

if __name__ == "__main__":
    client, shell = connect_switch(ROOT_IP)
    topology = build_topology(shell, ROOT_IP)
    client.close()

    with open("topology.json", "w") as f:
        json.dump({topology["hostname"]: topology}, f, indent=2)

    print("\n✅ Topology written to topology.json")
