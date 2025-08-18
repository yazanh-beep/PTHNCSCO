'''
Purpose

This script logs into a root Cisco switch, then SSH-hops to its LLDP neighbors (Cisco only). On the first visit to each device, it captures show running-config and saves it locally as:

backups/YYYY-MM-DD_<management-ip>_<hostname>.txt


It prevents loops with a visited set and returns to the parent device after each hop.

Features

Single Paramiko session to the root device; all other hops occur device-to-device.

Auto-elevation to privileged EXEC (enable) on each device.

Paging disabled (terminal length 0) before long outputs.

Robust LLDP parsing heuristic to find management IP, system name, and system description.

Skips:

Devices already visited

Neighbors without management IP

Non-Cisco neighbors (based on system description)

Backups are time-stamped and sanitized for filesystem safety.

Requirements
Environment

Python 3.8+

paramiko library

pip install paramiko


If your environment requires legacy KEX/ciphers (older Cisco images), you may need to adjust Paramiko’s SSH negotiation preferences in code or upgrade device crypto settings.

Network Assumptions

You can SSH to the root switch from your workstation.

From that switch, you can SSH to neighbor switches (in-band device-to-device SSH is allowed).

The enable password equals the login password (or adjust the code).

show lldp neighbors detail is enabled and populated across your Cisco estate.'''
#!/usr/bin/env python3
import paramiko
import time
import re
import os
from pathlib import Path

# ─── USER CONFIG ─────────────────────────────────────────────────────────────
USERNAME  = "admin"
PASSWORD  = "cisco"
ROOT_IP   = "192.168.1.1"
TIMEOUT   = 10
MAX_READ  = 65535
BACKUP_DIR = Path("backups")
DATE_STR   = time.strftime("%Y-%m-%d")  # file date component
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

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, sensitive=False):
    if not sensitive:
        print(f"[CMD] {cmd}")
    shell.send(cmd + "\n")
    out = expect_prompt(shell, patterns, timeout)
    last = out.splitlines()[-1] if out else "<no output>"
    if not sensitive:
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
    send_cmd(shell, PASSWORD, patterns=("#",), sensitive=True)
    send_cmd(shell, "terminal length 0", patterns=("#",))
    return client, shell

def hop_to_neighbor(shell, ip):
    """SSH from inside current device shell into <ip>, then enable + disable paging."""
    print(f"[HOP] ssh → {ip}")
    out = send_cmd(shell, f"ssh -l {USERNAME} {ip}",
                   patterns=("Destination","(yes/no)?","assword:","%","#",">"),
                   timeout=20)
    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:","%","#",">"), timeout=15)
    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("%","#",">"), timeout=15, sensitive=True)
    if out.strip().endswith(">"):
        send_cmd(shell, "enable", patterns=("assword:","#"), timeout=15)
        send_cmd(shell, PASSWORD, patterns=("#",), timeout=15, sensitive=True)
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

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")

def backup_running_config(shell, mgmt_ip: str, hostname: str):
    """Run 'show running-config' and save to backups/YYYY-MM-DD_ip_hostname.txt."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    safe_host = sanitize_filename(hostname) or "unknown"
    fn = BACKUP_DIR / f"{DATE_STR}_{mgmt_ip}_{safe_host}.txt"
    print(f"[BACKUP] {hostname} ({mgmt_ip}) → {fn}")
    # Some devices page anyway; make sure paging is off before the dump
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
    # Running config can be long; allow generous timeout
    raw = send_cmd(shell, "show running-config", patterns=("#",), timeout=90)
    with open(fn, "w", encoding="utf-8", errors="ignore") as f:
        f.write(raw)
    print("[OK] Saved.\n")

def crawl(shell, ip):
    """
    From the current device shell:
      - capture hostname
      - if first time, back up running-config
      - parse LLDP neighbors
      - hop into unvisited Cisco neighbors and repeat
      - 'exit' back one hop after each child
    """
    print(f"\n[INFO] Visiting {ip}")
    hostname = get_hostname(shell)

    first_time = ip not in visited
    if first_time:
        visited.add(ip)
        backup_running_config(shell, ip, hostname)
    else:
        print(f"[SKIP] Already backed up {ip}")

    lldp_raw = send_cmd(shell, "show lldp neighbors detail", patterns=("#",), timeout=15)
    neighbors = parse_lldp_detail(lldp_raw)

    for n in neighbors:
        rem_ip   = n.get("mgmt_ip")
        rem_name = n.get("remote_name") or "unknown"
        sysdesc  = (n.get("sys_descr") or "").lower()

        print(f"[FOUND] {rem_name} @ {rem_ip} via {n.get('local_intf')}")
        if not rem_ip:
            print("  [SKIP] no management IP")
            continue
        if rem_ip in visited:
            print("  [SKIP] already visited")
            continue
        if "cisco" not in sysdesc:
            print(f"  [SKIP] non-Cisco neighbor ({n.get('sys_descr', '')[:30]})")
            continue

        print(f"  [HOP] → {rem_ip}")
        hop_to_neighbor(shell, rem_ip)
        try:
            crawl(shell, rem_ip)
        finally:
            # Return to parent device
            send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)

if __name__ == "__main__":
    client, shell = connect_switch(ROOT_IP)
    try:
        crawl(shell, ROOT_IP)
    finally:
        client.close()
    print("\n✅ Backups complete. Files are in ./backups/")
