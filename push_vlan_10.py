#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import ipaddress
from typing import List

# ========================= USER CONFIG =========================
AGG_IP = "192.168.100.11"      # Seed aggregation switch
USERNAME = "admin"
PASSWORD = "cisco"

TIMEOUT = 10
MAX_READ = 65535

AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

TARGET_MAX_RETRIES = 1
TARGET_RETRY_DELAY = 5
TARGET_SSH_TIMEOUT = 60
TARGET_TCP_TIMEOUT = 30
# ===============================================================

# ========================= LOGGING =============================
class LiveFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[35m',
    }
    RESET = '\033[0m'
    def format(self, record):
        try:
            is_tty = sys.stdout.isatty()
        except Exception:
            is_tty = False
        if is_tty:
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

file_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_formatter = LiveFormatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

file_handler = logging.FileHandler('vlan_10_config.log', mode='a')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(file_formatter)
try:
    file_handler.stream.reconfigure(line_buffering=True)
except:
    pass

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

try:
    sys.stdout.reconfigure(line_buffering=True)
except:
    pass
# ===============================================================

# ======================= EXCEPTIONS ============================
class NetworkConnectionError(Exception):
    def __init__(self, message, retry_allowed=False, reconnect_needed=False):
        super().__init__(message)
        self.retry_allowed = retry_allowed
        self.reconnect_needed = reconnect_needed

class ConfigurationError(Exception):
    pass
# ===============================================================

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, show_progress=False):
    buf, end = "", time.time() + timeout
    last_log = time.time()
    start = time.time()
    last_progress = time.time()

    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            if time.time() - last_log > 2 or any(p in buf for p in patterns):
                if data.strip():
                    logger.debug(f"[RECV] {data.strip()[-100:]}")
                last_log = time.time()
            for p in patterns:
                if p in buf:
                    return buf
        else:
            if show_progress and time.time() - last_progress >= 5:
                logger.info(f"[WAIT] Elapsed: {int(time.time()-start)}s ...")
                last_progress = time.time()
            time.sleep(0.1)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT, log_cmd=True, show_progress=False):
    if log_cmd:
        logger.debug(f"Sending: {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout, show_progress)

def connect_to_agg(retry=0):
    try:
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=USERNAME, password=PASSWORD, look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()

        expect_prompt(shell, ("#", ">"))
        send_cmd(shell, "enable", ("assword:", "#"))
        send_cmd(shell, PASSWORD, ("#",))
        send_cmd(shell, "terminal length 0", ("#",))
        return client, shell

    except Exception as e:
        logger.error(f"[CONNECT] {e}")
        if retry < AGG_MAX_RETRIES - 1:
            time.sleep(AGG_RETRY_DELAY)
            return connect_to_agg(retry+1)
        else:
            raise

def cleanup_failed_session(shell):
    for _ in range(3):
        try:
            shell.send("\x03")
            shell.send("exit\n")
            time.sleep(0.6)
            if shell.recv_ready():
                data = shell.recv(MAX_READ).decode("utf-8", "ignore")
                if "#" in data:
                    return True
        except:
            pass
    return False

def establish_device_session(shell, target_ip, retry=0):
    logger.info(f"[HOP] SSH to {target_ip}")
    out = send_cmd(
        shell,
        f"ssh -l {USERNAME} {target_ip}",
        patterns=("assword:", "yes/no", "#", ">", "%", "Connection"),
        timeout=TARGET_SSH_TIMEOUT,
        show_progress=True
    )
    if "yes/no" in out:
        out = send_cmd(shell, "yes", ("assword:", "#", ">"), timeout=10)
    if "assword:" in out:
        out = send_cmd(shell, PASSWORD, ("#", ">",))
    # enable + no paging on the target
    send_cmd(shell, "enable", ("assword:", "#"))
    send_cmd(shell, PASSWORD, ("#",))
    send_cmd(shell, "terminal length 0", ("#",))
    return True

def verify_connectivity(shell, target_ip):
    out = send_cmd(shell, f"ping {target_ip} repeat 2", ("#",), timeout=15)
    return "!!" in out or "Success rate" in out

def backup_config(shell, target_ip):
    logger.info("[BACKUP] Capturing running config...")
    out = send_cmd(shell, "show running-config", ("#",), timeout=30, show_progress=True)
    fname = f"backup_{target_ip}_{int(time.time())}.cfg"
    with open(fname, "w") as f:
        f.write(out)
    logger.info(f"[BACKUP] Saved to {fname}")
    return fname

def apply_vlan10_config(shell, vlan_ip, netmask):
    logger.info("[CONFIG] Applying VLAN 10 SVI")
    send_cmd(shell, "configure terminal", ("(config)#",))
    cmds = [
        "vlan 10",
        "exit",
        "interface Vlan10",
        "no ip address",
        f"ip address {vlan_ip} {netmask}",
        "no shutdown",
    ]
    for cmd in cmds:
        send_cmd(shell, cmd, ("(config", "#"))
    send_cmd(shell, "do write", ("OK", "#"), timeout=20)
    send_cmd(shell, "end", ("#",))
    return True

# --------- NEW: discover trunk interfaces on the TARGET device ----------
def get_trunk_interfaces(shell) -> List[str]:
    """Parse 'show interfaces trunk' and return a list of trunk interface names."""
    logger.info("[TRUNK] Identifying trunk interfaces...")
    out = send_cmd(shell, "show interfaces trunk", ("#",), timeout=15)
    trunk_intfs: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("port", "portchannel", "vlans", "----", "name")):
            continue
        # Simple first-token extraction; matches common Cisco names (Gi, Fa, Te, Et, Po)
        first = line.split()[0] if line.split() else ""
        if any(first.startswith(pfx) for pfx in ("Gi", "Fa", "Te", "Et", "Po")):
            if first not in trunk_intfs:
                trunk_intfs.append(first)

    if trunk_intfs:
        logger.info(f"[TRUNK] Found {len(trunk_intfs)} trunk interface(s): {', '.join(trunk_intfs)}")
    else:
        logger.info("[TRUNK] No trunk interfaces found")
    return trunk_intfs

def configure_trunk_vlan(shell, interfaces: List[str]) -> bool:
    """Add VLAN 10 to allowed VLANs on each trunk interface."""
    if not interfaces:
        logger.info("[TRUNK] No trunks to update")
        return True

    logger.info("[TRUNK] Adding VLAN 10 to trunk allowed lists")
    send_cmd(shell, "configure terminal", ("(config)#",), timeout=5)
    success = 0
    for intf in interfaces:
        logger.info(f"[TRUNK] Updating {intf}")
        out = send_cmd(shell, f"interface {intf}", ("(config-if)#",), timeout=5)
        if "(config-if)#" not in out:
            logger.warning(f"[TRUNK] Could not enter interface {intf}, skipping")
            continue
        send_cmd(shell, "switchport trunk allowed vlan add 10", ("(config-if)#",), timeout=5)
        success += 1
    send_cmd(shell, "end", ("#",), timeout=5)
    logger.info(f"[TRUNK] Successfully updated {success}/{len(interfaces)} trunk interface(s)")
    return True
# ------------------------------------------------------------------------

def exit_device_session(shell):
    logger.info("[EXIT] Returning to aggregation switch")
    send_cmd(shell, "exit", ("#", ">"), timeout=5)
    time.sleep(0.5)
    send_cmd(shell, "", ("#",), timeout=3)

# ============================ MAIN =============================
def main():
    if len(sys.argv) != 4:
        print("Usage: python vlan_10.py <devices_file> <starting_vlan_ip> <netmask>")
        sys.exit(1)

    devices_file = sys.argv[1]
    starting_ip = sys.argv[2]
    netmask = sys.argv[3]

    with open(devices_file, "r") as f:
        targets = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    try:
        base_ip = ipaddress.IPv4Address(starting_ip)
    except Exception:
        print(f"Invalid IP: {starting_ip}")
        sys.exit(1)

    vlan_ips = [str(base_ip + i) for i in range(len(targets))]

    logger.info("=" * 70)
    logger.info("VLAN 10 CONFIGURATION SCRIPT")
    logger.info("=" * 70)
    logger.info(f"Aggregation Switch: {AGG_IP}")
    logger.info(f"Devices: {len(targets)}")
    for t, ip in zip(targets, vlan_ips):
        logger.info(f"  - {t} -> Vlan10 {ip} {netmask}")
    logger.info("")

    try:
        client, shell = connect_to_agg()
    except Exception as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)

    success, failed = [], []

    for idx, (target, vip) in enumerate(zip(targets, vlan_ips), 1):
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"DEVICE {idx}/{len(targets)}: {target}")
        logger.info("=" * 70)
        try:
            if shell.closed:
                raise NetworkConnectionError("Aggregation shell closed", reconnect_needed=True)

            if not verify_connectivity(shell, target):
                raise NetworkConnectionError("Unreachable")

            establish_device_session(shell, target)

            # Optional: backup
            try:
                backup_config(shell, target)
            except Exception as be:
                logger.warning(f"[BACKUP] Skipped (error: {be})")

            # Configure SVI
            apply_vlan10_config(shell, vip, netmask)

            # NEW: Add VLAN 10 to all trunk allowed lists on the target
            trunks = get_trunk_interfaces(shell)
            configure_trunk_vlan(shell, trunks)

            # Exit back to aggregate
            exit_device_session(shell)
            logger.info(f"[SUCCESS] {target} configured")
            success.append(target)

        except Exception as e:
            logger.error(f"[FAILED] {target}: {e}")
            # Try to clean up session so we’re back at agg
            try:
                if not shell.closed:
                    cleanup_failed_session(shell)
            except:
                pass
            failed.append(target)

        time.sleep(1)

    try:
        client.close()
        logger.info("[DISCONNECT] Closed connection to aggregation switch")
    except:
        pass

    logger.info("")
    logger.info("=" * 70)
    logger.info("VLAN 10 CONFIGURATION SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Successful: {len(success)}")
    logger.info(f"Failed: {len(failed)}")
    if success:
        logger.info("OK:")
        for d in success:
            logger.info(f"  - {d}")
    if failed:
        logger.info("NOK:")
        for d in failed:
            logger.info(f"  - {d}")

    sys.exit(0 if not failed else 1)

if __name__ == "__main__":
    main()
