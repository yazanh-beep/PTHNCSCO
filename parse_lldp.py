#this code will login to the root ip and will recursively lldp across all the neighbors until it reaches #a non-cisco ip that it cannot ssh into, it will log it as child and move forward. 

#written by yazan (yazanh@google.com)

#!/usr/bin/env python3
import paramiko
import time
import re
import json

# ─── USER CONFIGURATION ────────────────────────────────────────────────────────
USERNAME = "admin"
PASSWORD = "cisco"
ROOT_IP  = "192.168.1.1"
TIMEOUT  = 10           # seconds to wait for prompts
MAX_READ = 65535        # max bytes to read per recv()
# ────────────────────────────────────────────────────────────────────────────────

visited = set()

def expect_prompt(shell, patterns, timeout=TIMEOUT):
    """
    Read until one of the given patterns appears in the buffer or timeout.
    Returns everything read.
    """
    buff = ""
    end_time = time.time() + timeout
    while time.time() < end_time:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", errors="ignore")
            buff += data
            for p in patterns:
                if p in buff:
                    return buff
        else:
            time.sleep(0.1)
    return buff

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    """
    Send a command and wait for one of the patterns to appear.
    """
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def connect_switch(ip):
    """
    SSH to the given switch IP, disable paging, and return (client, shell).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=USERNAME, password=PASSWORD,
                   look_for_keys=False, allow_agent=False)
    shell = client.invoke_shell()
    expect_prompt(shell, patterns=("#", ">"))
    send_cmd(shell, "terminal length 0", patterns=("#",))
    return client, shell

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

if __name__ == "__main__":
    visited.add(ROOT_IP)
    client, shell = connect_switch(ROOT_IP)

    full_topo = { ROOT_IP: build_topology(shell, ROOT_IP) }
    client.close()

    with open("topology.json", "w") as f:
        json.dump(full_topo, f, indent=2)

    print("✅ Topology written to topology.json")


