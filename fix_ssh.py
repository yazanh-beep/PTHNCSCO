#!/usr/bin/env python3
import paramiko
import time
import sys

print("Attempting to fix 192.168.1.8...")

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    print("[1/6] Connecting...")
    client.connect(
        '',
        username='',
        password='',
        look_for_keys=False,
        allow_agent=False,
        timeout=10
    )
    
    print("[2/6] Opening shell...")
    shell = client.invoke_shell()
    time.sleep(1)
    
    # Clear initial banner
    if shell.recv_ready():
        shell.recv(65535)
    
    print("[3/6] Entering enable mode...")
    shell.send('enable\n')
    time.sleep(0.5)
    shell.send('cisco\n')
    time.sleep(0.5)
    
    print("[4/6] Entering config mode...")
    shell.send('configure terminal\n')
    time.sleep(0.5)
    
    print("[5/6] Removing timeout settings...")
    shell.send('no ip ssh time-out\n')
    time.sleep(0.3)
    shell.send('no ip tcp synwait-time\n')
    time.sleep(0.3)
    shell.send('end\n')
    time.sleep(0.5)
    
    print("[6/6] Saving configuration...")
    shell.send('write memory\n')
    time.sleep(2)
    
    # Get output
    output = ""
    while shell.recv_ready():
        output += shell.recv(65535).decode('utf-8', 'ignore')
    
    print("\n" + "="*70)
    print("Switch Output:")
    print("="*70)
    print(output[-1000:])  # Last 1000 chars
    
    client.close()
    
    print("\n" + "="*70)
    print("✓ SUCCESS! Switch configuration fixed!")
    print("="*70)
    print("\nYou can now SSH normally to 192.168.1.8")
    
except paramiko.AuthenticationException:
    print("\n✗ ERROR: Authentication failed - check username/password")
    sys.exit(1)
except paramiko.SSHException as e:
    print(f"\n✗ ERROR: SSH connection failed: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n✗ ERROR: {e}")
    sys.exit(1)
