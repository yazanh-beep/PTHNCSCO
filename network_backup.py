"""
Imports
python
Copy
Edit
import paramiko
import time
import re
paramiko is the SSH library (for Python).
time is used for timeouts and sleep loops.
re is for regular expressions (prompt matching etc.).

Why?
Paramiko gives you programmatic SSH. It can open an interactive shell session on the agg-switch, just like you would manually.

User Configuration Section
python
Copy
Edit
AGG_IP = "192.168.1.1"           # The aggregation switch (jump host)
USERNAME = "admin"
PASSWORD = "cisco"
TARGET_SWITCHES = [
    "10.1.1.2",
    "10.1.1.3",
    "10.1.1.4",
]
TIMEOUT = 10
MAX_READ = 65535
These variables define all your inputs:

AGG_IP – IP address of the aggregation switch. Your PC only connects to this.

USERNAME/PASSWORD – SSH credentials. Used for the agg-switch and also when hopping to target switches.

TARGET_SWITCHES – List of IPs of the switches whose configs you want.

TIMEOUT – How long to wait for prompts.

MAX_READ – How much data to buffer from SSH output.

expect_prompt() function
python
Copy
Edit
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
Purpose:
Waits for the CLI prompt in an interactive shell.

How it works:

Continuously reads SSH output.

Appends data to buf.

Checks if any of the patterns (e.g. #, >, assword:) is seen in the output.

Returns the entire buffer when it sees the prompt.

Why?
You can't just "send a command and hope it finishes". You have to know when the switch CLI is ready for the next command. This waits until it sees a known prompt.

send_cmd()
python
Copy
Edit
def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)
Purpose:
Sends a command to the interactive shell, and waits for the prompt.

How it works:

Sends the command (with newline).

Calls expect_prompt() to wait until the switch finishes and shows prompt again.

Returns all output (including command echo and results).

Why?
So you can sequentially automate CLI commands like:

pgsql
Copy
Edit
ssh -l admin 10.1.1.2
<wait for password prompt>
password
<wait for prompt>
enable
password
terminal length 0
show running-config
connect_to_agg()
python
Copy
Edit
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
Purpose:
Log in to the aggregation switch from your PC, and prepare the CLI for use.

Step by step:
Creates SSH client and ignores missing host key checks.
Connects using AGG_IP, USERNAME, PASSWORD.
Invokes an interactive shell.
Waits for initial prompt.
Enters enable mode (and handles password prompt).
Turns off paging with terminal length 0.

Why?
This sets up your jump host session, so you can issue commands from within the agg-switch CLI to hop to other switches.

get_running_config()
python
Copy
Edit
def get_running_config(shell, target_ip):
    ...
Purpose:
SSH from inside the agg-switch CLI to the target switch, run show running-config, and capture the output.

Detailed steps:

➜ A. SSH from agg-switch to target
python
Copy
Edit
out = send_cmd(shell, f"ssh -l {USERNAME} {target_ip}", ...)
Runs Cisco CLI command:

nginx
Copy
Edit
ssh -l admin 10.1.1.2
Expects prompts for "yes/no", "password", errors, #, >.

➜ B. Handle host-key confirmation
python
Copy
Edit
if "(yes/no)?" in out or "yes/no" in out:
    out = send_cmd(shell, "yes", ...)
Answers "yes" if asked to confirm the remote SSH key.

➜ C. Handle password prompt
python
Copy
Edit
if "assword:" in out:
    out = send_cmd(shell, PASSWORD, ...)
Sends the password when prompted.

➜ D. Enter enable mode if needed
python
Copy
Edit
if out.strip().endswith(">"):
    send_cmd(shell, "enable", ...)
    send_cmd(shell, PASSWORD, ...)
If landed in user-exec mode (>), promotes to enable mode (#).

➜ E. Disable paging on target
python
Copy
Edit
send_cmd(shell, "terminal length 0", ...)
Avoids --More-- pagination when collecting large configs.

➜ F. Run show running-config
python
Copy
Edit
running_config = send_cmd(shell, "show running-config", ...)
Gets the entire configuration output.

➜ G. Exit back to aggregation switch
python
Copy
Edit
send_cmd(shell, "exit", ...)
Closes the CLI SSH session to target, returning to agg-switch prompt.

Returns the entire running-config output as a single string.

Main script block
python
Copy
Edit
if __name__ == "__main__":
    client, shell = connect_to_agg()

    for target in TARGET_SWITCHES:
        ...
    client.close()
    print("\n All backups completed.")
Purpose:

Establishes SSH connection from your PC to the agg-switch.

Opens the interactive shell.

Loops over each target switch in the list.

Calls get_running_config() to SSH hop from agg → target, run commands, and get config.

Saves output to a local text file.

Closes the SSH session at the end.

➜ Target loop
python
Copy
Edit
for target in TARGET_SWITCHES:
    ...
Iterates over your list of switches.

➜ Calling get_running_config
python
Copy
Edit
config_output = get_running_config(shell, target)
Runs the entire hopping logic.

➜ Saving to file
python
Copy
Edit
fname = f"{target.replace('.', '_')}_running_config.txt"
with open(fname, "w") as f:
    f.write(config_output)
Replaces dots in IP with underscores for filenames.

Saves config output to uniquely named text file.

➜ Error Handling
python
Copy
Edit
except Exception as e:
    print(f"[ERROR] Failed to backup {target}: {e}")
Catches and logs errors per target, without stopping the whole process.

Example File Output
For switch 10.1.1.2, you'd get:

Copy
Edit
10_1_1_2_running_config.txt
containing the full show running-config output.

"""
#!/usr/bin/env python3

import paramiko
import time
import re

# USER CONFIG
AGG_IP = "192.168.1.1"           # The aggregation switch (jump host)
USERNAME = "admin"
PASSWORD = "cisco"
TARGET_SWITCHES = [
"10.2.129.62", "10.2.129.82",  "10.21.129.82"
]
TIMEOUT = 10
MAX_READ = 65535

# Utility to wait for CLI prompt
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

# Send command + wait for prompt
def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

# Connect from PC to aggregation switch
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

# From agg-shell, SSH to target, get running-config, return output
def get_running_config(shell, target_ip):
    print(f"\n[HOP] ssh to {target_ip}")
    out = send_cmd(shell, f"ssh -l {USERNAME} {target_ip}",
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
    print(f"[CONNECTED] at {target_ip}#")

    # Run show running-config
    print("[INFO] Running 'show running-config'")
    running_config = send_cmd(shell, "show running-config", patterns=("#",), timeout=30)

    # Exit back to agg-switch
    send_cmd(shell, "exit", patterns=("#",">"), timeout=5)
    print(f"[EXITED] back to aggregation switch prompt")

    return running_config

if __name__ == "__main__":
    client, shell = connect_to_agg()

    for target in TARGET_SWITCHES:
        try:
            print(f"\n=== Backing up {target} ===")
            config_output = get_running_config(shell, target)

            # Clean filename
            fname = f"{target.replace('.', '_')}_running_config.txt"
            with open(fname, "w") as f:
                f.write(config_output)

            print(f"[SUCCESS] Backup saved to {fname}")

        except Exception as e:
            print(f"[ERROR] Failed to backup {target}: {e}")

    client.close()
    print("\nAll backups completed.")


