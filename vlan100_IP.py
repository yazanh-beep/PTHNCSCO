'''

Usage example (with your jump at 192.168.1.11):

python3 vlan100_assign.py \
  --devices devices.txt \
  --agg-ip 192.168.1.11 \
  --username admin \
  --password cisco \
  --new-prefix 10.2.240 \
  --mask 255.255.255.0 \
  --force-legacy-kex


where devices.txt contains one IP per line (e.g. 192.168.100.2, 192.168.100.3, …).

1. Overview

This Python script automates re-IP of VLAN 100 SVIs on multiple Cisco switches.

It logs into a jump (aggregation) switch first.

From the jump, it SSH hops into each device in the provided list.

For each device, it:

Determines its hostname.

Builds a new VLAN100 IP address based on the last octet of its current management IP.

Configures interface Vlan100 with the new IP/mask.

Saves the configuration.
'''
#!/usr/bin/env python3
import paramiko
import time
import argparse
from datetime import datetime
import ipaddress

# Defaults (override with CLI flags)
AGG_IP   = "192.168.1.1"
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT  = 12
MAX_READ = 65535

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            if "Permission denied" in data or "\n%" in data:
                return buf
            for p in patterns:
                if p in buf:
                    return buf
        else:
            time.sleep(0.1)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def force_legacy_kex(transport):
    sec = transport.get_security_options()
    if 'diffie-hellman-group-exchange-sha1' in sec.kex:
        sec.kex = ['diffie-hellman-group-exchange-sha1'] + [k for k in sec.kex if k != 'diffie-hellman-group-exchange-sha1']

def connect_to_agg(agg_ip, username, password, force_legacy=False):
    print(f"[CONNECT] SSH to jump/agg {agg_ip} as {username}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        agg_ip, username=username, password=password,
        look_for_keys=False, allow_agent=False, timeout=10
    )
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(30)
        if force_legacy:
            force_legacy_kex(transport)
    shell = client.invoke_shell()
    expect_prompt(shell, ("#", ">"))
    out = send_cmd(shell, "enable", patterns=("assword:", "#"))
    if "assword:" in out:
        send_cmd(shell, password, patterns=("#",))
    send_cmd(shell, "terminal length 0", patterns=("#",))
    print("[READY] Jump session established")
    return client, shell

def hop_to_target(shell, username, password, ip):
    print(f"\n[HOP] ssh {ip}")
    out = send_cmd(shell, f"ssh -l {username} {ip}",
                   patterns=("yes/no", "(yes/no)?", "assword:", "Permission denied", "%", "#", ">"),
                   timeout=20)
    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
    if "assword:" in out:
        out = send_cmd(shell, password, patterns=("Permission denied", "%", "#", ">"), timeout=20)
    if "Permission denied" in out or "\n%" in out:
        raise RuntimeError(f"SSH/auth error on {ip}:\n{out.strip()[-200:]}")
    if out.strip().endswith(">"):
        out = send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=15)
        if "assword:" in out:
            send_cmd(shell, password, patterns=("#",), timeout=15)
    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
    return True

def get_hostname(shell):
    out = send_cmd(shell, "show run | i ^hostname", patterns=("#",), timeout=8)
    for line in out.splitlines():
        if line.strip().startswith("hostname "):
            return line.strip().split(None, 1)[1]
    return "unknown"

def build_vlan100_cmds(target_ip, new_prefix, mask):
    """
    Keep last octet from target_ip, apply to new_prefix.X
    """
    try:
        ip_obj = ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError(f"Invalid IP in devices file: {target_ip}")

    last_octet = int(str(ip_obj).split(".")[-1])
    base_parts = new_prefix.split(".")
    if len(base_parts) != 3:
        raise ValueError("--new-prefix must be like A.B.C (e.g., 10.2.240)")
    new_ip = ".".join(base_parts + [str(last_octet)])

    cmds = [
        "vlan 100",
        "exit",
        "interface Vlan100",
        "no ip address",  # idempotent; clears any previous IP if present
        f"ip address {new_ip} {mask}",
        "no shutdown",
        f"description SVI migrated by tool {now_str()}",
    ]
    return new_ip, cmds

def push_vlan100(shell, target_ip, new_prefix, mask):
    hop_to_target(shell, args.username, args.password, target_ip)
    hostname = get_hostname(shell)
    if hostname == "unknown":
      raise RuntimeError(f"Hostname could not be determined on {target_ip}. Stopping script.")
    print(f"[TARGET] {hostname} ({target_ip})")

    new_ip, cmds = build_vlan100_cmds(target_ip, new_prefix, mask)

    out = send_cmd(shell, "configure terminal", patterns=("(config)#", "#", "%"), timeout=10)
    if "\n%" in out:
        raise RuntimeError(f"Failed to enter config mode on {target_ip}:\n{out.strip()[-200:]}")

    for c in cmds:
        print(f"[CONFIG] {c}")
        out = send_cmd(shell, c, patterns=("(config)#", "%", "#"), timeout=12)
        if "\n%" in out:
            print(f"[WARN] Device reported an issue with '{c}':\n{out.strip()[-200:]}")

    # Save config
    print("[SAVE] write memory")
    out = send_cmd(shell, "do write", patterns=("(config)#", "#", "%"), timeout=25)
    if "\n%" in out:
        send_cmd(shell, "end", patterns=("#",), timeout=6)
        send_cmd(shell, "write memory", patterns=("#",), timeout=25)
    else:
        send_cmd(shell, "end", patterns=("#",), timeout=6)

    send_cmd(shell, "exit", patterns=("#", ">"), timeout=6)  # back to jump
    print(f"[DONE] {hostname} VLAN100 set to {new_ip}")

def read_targets(path):
    with open(path, "r") as f:
        return [ln.strip() for ln in f if ln.strip()]

def main():
    global args
    parser = argparse.ArgumentParser(description="Assign VLAN100 SVI based on device IP last octet via jump host.")
    parser.add_argument("--devices", required=True, help="File with device IPs (one per line)")
    parser.add_argument("--agg-ip", default=AGG_IP)
    parser.add_argument("--username", default=USERNAME)
    parser.add_argument("--password", default=PASSWORD)
    parser.add_argument("--new-prefix", required=True, help="New /24 prefix (first 3 octets), e.g., 10.2.240")
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--force-legacy-kex", action="store_true")
    args = parser.parse_args()

    targets = read_targets(args.devices)
    client, shell = connect_to_agg(args.agg_ip, args.username, args.password, args.force_legacy_kex)

    try:
        for ip in targets:
            try:
                print(f"\n=== Processing {ip} ===")
                push_vlan100(shell, ip, args.new_prefix, args.mask)
            except Exception as e:
                print(f"[ERROR] {ip}: {e}")
                # stay on jump and continue
    finally:
        client.close()
        print("\n[DONE] All targets processed.")

if __name__ == "__main__":
    main()
