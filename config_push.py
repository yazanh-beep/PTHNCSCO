"""
Input:

A plain text file (argument 1) containing target device IPs (one per line).

Another plain text file (argument 2) containing one or more config commands (one per line) to be sent (without needing quotes).

For each device:

SSH from agg switch (jump host) to device.

Enter config mode, send all config commands from file (in order), then issue do write.

Exit back to agg, continue to next device.

Sample Usage
sh
Copy
Edit
python3 push_config.py devices.txt commands.txt
Where:

devices.txt contains:

Copy
Edit
10.2.129.62
10.2.129.82
10.21.129.82
commands.txt contains:

kotlin
Copy
Edit
interface GigabitEthernet1/0/10
shutdown
description TEST-AUTOMATION


"""


#!/usr/bin/env python3

import paramiko
import time
import sys

# USER CONFIG
AGG_IP = "192.168.1.1"
USERNAME = "admin"
PASSWORD = "cisco"
TIMEOUT = 10
MAX_READ = 65535

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT):
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
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

def connect_to_agg():
    print(f"[CONNECT] SSH to aggregation switch: {AGG_IP}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                   look_for_keys=False, allow_agent=False, timeout=10)
    shell = client.invoke_shell()
    expect_prompt(shell, ("#", ">"))
    send_cmd(shell, "enable", patterns=("assword:", "#"))
    send_cmd(shell, PASSWORD, patterns=("#",))
    send_cmd(shell, "terminal length 0", patterns=("#",))
    return client, shell

def push_config(shell, target_ip, config_commands):
    print(f"\n[HOP] ssh to {target_ip}")
    out = send_cmd(shell, f"ssh -l {USERNAME} {target_ip}",
                   patterns=("Destination", "(yes/no)?", "assword:", "%", "#", ">"),
                   timeout=15)

    if "(yes/no)?" in out or "yes/no" in out:
        out = send_cmd(shell, "yes", patterns=("assword:", "%", "#", ">"), timeout=15)
    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, patterns=("%", "#", ">"), timeout=15)
    if out.strip().endswith(">"):
        send_cmd(shell, "enable", patterns=("assword:", "#"), timeout=15)
        send_cmd(shell, PASSWORD, patterns=("#",), timeout=15)

    send_cmd(shell, "terminal length 0", patterns=("#",), timeout=5)
    print(f"[CONNECTED] at {target_ip}#")

    # Enter config mode
    send_cmd(shell, "configure terminal", patterns=("(config)#",), timeout=10)

    for cmd in config_commands:
        print(f"[CONFIG] Sending: {cmd}")
        send_cmd(shell, cmd, patterns=("(config)#",), timeout=10)

    # Issue 'do write' to save config
    print("[CONFIG] Saving with 'do write'")
    send_cmd(shell, "do write", patterns=("(config)#", "#"), timeout=20)

    # Exit config and back to agg switch
    send_cmd(shell, "end", patterns=("#",), timeout=5)
    send_cmd(shell, "exit", patterns=("#", ">"), timeout=5)
    print(f"[EXITED] back to aggregation switch prompt")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 push_config.py <devices_file> <commands_file>")
        sys.exit(1)

    devices_file = sys.argv[1]
    commands_file = sys.argv[2]

    with open(devices_file, "r") as f:
        target_ips = [line.strip() for line in f if line.strip()]

    with open(commands_file, "r") as f:
        config_cmds = [line.rstrip() for line in f if line.strip()]

    client, shell = connect_to_agg()

    for target in target_ips:
        try:
            print(f"\n=== Configuring {target} ===")
            push_config(shell, target, config_cmds)
            print(f"[SUCCESS] Config applied to {target}")

        except Exception as e:
            print(f"[ERROR] Failed to configure {target}: {e}")

    client.close()
    print("\nAll configurations completed.")
