'''
Purpose

This script automates migrating the IP address of VLAN interfaces (SVIs) on Cisco switches by hopping through an aggregate/jump switch.
It works in a pairwise mapping manner:

devices.txt → list of current management IPs (one per line).

new_ips.txt → list of the new IPs (one per line, same order).
Each current IP in line N is mapped to the new IP in line N.

The script connects to the jump switch, then uses ssh -l <user> <target> to reach each device, update Vlan<id>, save the config, and (optionally) verify.

Features

Persistent jump switch session (no reconnecting for each device).

Handles legacy key exchange (diffie-hellman-group-exchange-sha1) if needed.

Automatically enters enable mode on both jump and target.

Idempotent configuration (no ip address before assigning new one).

Saves the configuration (write memory).

Optional verification of SVI configuration after change.

Robust error handling (continues to next device if one fails).
'''
#!/usr/bin/env python3
import argparse
import ipaddress
import paramiko
import time
from datetime import datetime

# Defaults (override with flags)
AGG_IP   = "192.168.1.11"
USERNAME = "admin"
PASSWORD = "cisco"
ENABLE_PWD = "cisco"
MASK     = "255.255.255.0"
VLAN     = 100
TIMEOUT  = 12
MAX_READ = 65535

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            # fail-fast on common IOS errors
            if "Permission denied" in data or "\n%" in data:
                return buf
            for p in patterns:
                if p in buf:
                    return buf
        else:
            time.sleep(0.1)
    return buf

def send(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def force_legacy_kex(transport):
    try:
        sec = transport.get_security_options()
        if 'diffie-hellman-group-exchange-sha1' in sec.kex:
            sec.kex = ['diffie-hellman-group-exchange-sha1'] + [k for k in sec.kex if k != 'diffie-hellman-group-exchange-sha1']
    except Exception:
        pass

def connect_to_jump(agg_ip, username, password, enable_pwd, legacy_kex=False):
    print(f"[JUMP] SSH {agg_ip} as {username}")
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(agg_ip, username=username, password=password,
                look_for_keys=False, allow_agent=False, timeout=10)
    tr = cli.get_transport()
    if tr:
        tr.set_keepalive(30)
        if legacy_kex:
            force_legacy_kex(tr)
    sh = cli.invoke_shell()
    expect_prompt(sh, ("#", ">"))
    # enter enable on jump
    out = send(sh, "enable", patterns=("assword:", "#"))
    if "assword:" in out:
        send(sh, enable_pwd, patterns=("#",))
    send(sh, "terminal length 0", patterns=("#",))
    print("[JUMP] Ready")
    return cli, sh

def hop_to_target(shell, username, password, enable_pwd, ip):
    print(f"\n[HOP] ssh {ip}")
    out = send(shell, f"ssh -l {username} {ip}",
               patterns=("yes/no", "(yes/no)?", "assword:", "Permission denied", "%", "#", ">"),
               timeout=20)
    if "(yes/no)?" in out or "yes/no" in out:
        out = send(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
    if "assword:" in out:
        out = send(shell, password, patterns=("Permission denied", "%", "#", ">"), timeout=20)
    if "Permission denied" in out or "\n%" in out:
        raise RuntimeError(f"SSH/auth error on {ip}:\n{out.strip()[-200:]}")
    # if user exec mode, elevate
    if out.strip().endswith(">"):
        out = send(shell, "enable", patterns=("assword:", "#"), timeout=12)
        if "assword:" in out:
            send(shell, enable_pwd, patterns=("#",), timeout=8)
    send(shell, "terminal length 0", patterns=("#",), timeout=5)
    return True

def get_hostname(shell):
    out = send(shell, "show run | i ^hostname", patterns=("#",), timeout=8)
    for line in out.splitlines():
        if line.strip().startswith("hostname "):
            return line.strip().split(None, 1)[1]
    return "unknown"

def set_vlan_ip(shell, vlan, ip, mask):
    out = send(shell, "configure terminal", patterns=("(config)#", "%", "#"))
    if "\n%" in out:
        raise RuntimeError("Failed to enter config mode")

    cmds = [
        f"vlan {vlan}",
        "exit",
        f"interface Vlan{vlan}",
        "no ip address",                 # idempotent reset
        f"ip address {ip} {mask}",
        "no shutdown",
        f"description management SVI",
    ]
    for c in cmds:
        print(f"[CONFIG] {c}")
        out = send(shell, c, patterns=("(config)#", "(config-if)#", "%", "#"), timeout=12)
        if "\n%" in out:
            raise RuntimeError(f"Command failed: {c}\n{out.strip()[-200:]}")

    send(shell, "end", patterns=("#",))
    print("[SAVE] write memory")
    out = send(shell, "write memory", patterns=("#", "%"), timeout=25)
    if "\n%" in out:
        raise RuntimeError(f"write memory returned error:\n{out.strip()[-200:]}")

def verify_vlan_ip(shell, vlan, ip, mask):
    out = send(shell, f"show run interface Vlan{vlan} | i ip address", patterns=("#",), timeout=8)
    line = next((l for l in out.splitlines() if "ip address" in l), "")
    ok = (ip in line) and (mask in line)
    print(f"[VERIFY] {'OK' if ok else 'MISMATCH'}: {line.strip() or 'no ip address line'}")
    return ok

def read_list(path, label):
    with open(path, "r") as f:
        items = [ln.strip() for ln in f if ln.strip()]
    if not items:
        raise ValueError(f"{label} file is empty: {path}")
    return items

def main():
    p = argparse.ArgumentParser(description="Pairwise Vlan SVI IP migration via aggregate jump switch.")
    p.add_argument("--devices", required=True, help="File with current device IPs (one per line)")
    p.add_argument("--new-ips", required=True, help="File with new IPs (one per line, same order as devices)")
    p.add_argument("--agg-ip", default=AGG_IP, help="Aggregate/jump switch IP")
    p.add_argument("--username", default=USERNAME)
    p.add_argument("--password", default=PASSWORD)
    p.add_argument("--enable", dest="enable_pwd", default=ENABLE_PWD)
    p.add_argument("--mask", default=MASK)
    p.add_argument("--vlan", type=int, default=VLAN)
    p.add_argument("--verify", action="store_true", help="Verify SVI IP after change")
    p.add_argument("--force-legacy-kex", action="store_true", help="Force diffie-hellman-group-exchange-sha1 on jump")
    args = p.parse_args()

    # Validate lists
    devs = read_list(args.devices, "Devices")
    news = read_list(args.new_ips, "New IPs")
    if len(devs) != len(news):
        raise ValueError(f"Line count mismatch: {len(devs)} devices vs {len(news)} new IPs")

    # Validate IP syntax early
    for i, ip in enumerate(devs):
        try: ipaddress.ip_address(ip)
        except ValueError: raise ValueError(f"Invalid device IP on line {i+1}: {ip}")
    for i, ip in enumerate(news):
        try: ipaddress.ip_address(ip)
        except ValueError: raise ValueError(f"Invalid new IP on line {i+1}: {ip}")

    # Single persistent jump session
    jump_cli, jump_sh = connect_to_jump(args.agg_ip, args.username, args.password, args.enable_pwd, args.force_legacy_kex)

    try:
        for cur_ip, new_ip in zip(devs, news):
            print(f"\n=== {cur_ip} -> {new_ip} (Vlan{args.vlan}/{args.mask}) ===")
            try:
                hop_to_target(jump_sh, args.username, args.password, args.enable_pwd, cur_ip)
                host = get_hostname(jump_sh)
                print(f"[TARGET] {host} ({cur_ip})")
                set_vlan_ip(jump_sh, args.vlan, new_ip, args.mask)
                if args.verify:
                    verify_vlan_ip(jump_sh, args.vlan, new_ip, args.mask)
            except Exception as e:
                print(f"[ERROR] {cur_ip}: {e}")
            finally:
                # Back to jump (close remote session) without tearing down the jump itself
                send(jump_sh, "exit", patterns=("#", ">"), timeout=6)
    finally:
        jump_cli.close()
        print("\n[DONE] All pairs processed.")

if __name__ == "__main__":
    main()
