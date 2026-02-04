#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import ipaddress
from typing import List

# Try to import openpyxl, warn if missing
try:
    import openpyxl
except ImportError:
    print("CRITICAL: 'openpyxl' library is missing. Please run: pip install openpyxl")
    sys.exit(1)

# ========================= USER CONFIG =========================
AGG_IP = "192.168.1.18"       # Seed aggregation switch

# Define multiple credentials here. The script tries them in order.
CREDENTIALS = [
    {"user": "admin", "pass": "/2/_HKX6YvCGMwzAdJp"},
    {"user": "admin", "pass": "cisco"}
]

TIMEOUT = 10
MAX_READ = 65535

AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5

TARGET_MAX_RETRIES = 10
TARGET_SSH_TIMEOUT = 60
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
# ===============================================================

def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, show_progress=False):
    buf, end = "", time.time() + timeout
    last_log = time.time()
    start = time.time()
    last_progress = time.time()
    last_nudge = time.time()

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
            if time.time() - last_nudge >= 10:
                try:
                    shell.send("\n")
                except Exception:
                    pass
                last_nudge = time.time()

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
    if retry >= AGG_MAX_RETRIES:
        raise NetworkConnectionError("Max retries reached for Aggregation Switch.")

    logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to {AGG_IP}")
    last_exception = None
    
    for cred in CREDENTIALS:
        user = cred['user']
        pwd = cred['pass']
        try:
            logger.info(f"[AUTH] Trying credential: {user}")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                AGG_IP,
                username=user,
                password=pwd,
                look_for_keys=False,
                allow_agent=False,
                timeout=15,
            )
            try:
                client.get_transport().set_keepalive(30)
            except Exception:
                pass

            shell = client.invoke_shell()
            expect_prompt(shell, ("#", ">"))
            
            out = send_cmd(shell, "enable", ("assword:", "#"))
            if "assword:" in out:
                send_cmd(shell, pwd, ("#",))
            
            send_cmd(shell, "terminal length 0", ("#",))
            logger.info(f"[SUCCESS] Connected to Aggregation Switch as {user}")
            return client, shell

        except paramiko.AuthenticationException:
            logger.warning(f"[AUTH] Authentication failed for user {user}. Trying next...")
            continue
        except Exception as e:
            logger.error(f"[CONNECT] Error with {user}: {e}")
            last_exception = e
            continue

    logger.error("[CONNECT] All credentials failed.")
    if retry < AGG_MAX_RETRIES - 1:
        time.sleep(AGG_RETRY_DELAY)
        return connect_to_agg(retry+1)
    else:
        raise last_exception if last_exception else NetworkConnectionError("Auth failed")

def cleanup_failed_session(shell):
    for _ in range(3):
        try:
            shell.send("\x03")
            time.sleep(0.5)
            shell.send("\n")
            if shell.recv_ready():
                data = shell.recv(MAX_READ).decode("utf-8", "ignore")
                if "#" in data or ">" in data:
                    return True
        except:
            pass
    return False

def establish_device_session(shell, target_ip):
    logger.info(f"[HOP] SSH to {target_ip}")
    
    for cred in CREDENTIALS:
        user = cred['user']
        pwd = cred['pass']
        
        # Clean buffer
        shell.send("\n")
        time.sleep(0.5)
        if shell.recv_ready():
             shell.recv(MAX_READ)

        out = send_cmd(
            shell,
            f"ssh -l {user} {target_ip}",
            patterns=("assword:", "yes/no", "#", ">", "%", "Connection", "denied", "closed"),
            timeout=TARGET_SSH_TIMEOUT,
            show_progress=True
        )

        if "yes/no" in out:
            out = send_cmd(shell, "yes", ("assword:", "#", ">", "denied", "closed"), timeout=10)
        
        if "assword:" in out:
            out = send_cmd(shell, pwd, ("#", ">", "denied", "failed", "closed"), timeout=15)
        
        if "#" in out or ">" in out:
            if ">" in out:
                out = send_cmd(shell, "enable", ("assword:", "#"))
                if "assword:" in out:
                    send_cmd(shell, pwd, ("#",))
            send_cmd(shell, "terminal length 0", ("#",))
            logger.info(f"[SUCCESS] Logged into {target_ip} with {user}")
            return True
        
        if "denied" in out or "failed" in out or "closed" in out:
            logger.warning(f"[AUTH] Failed on {target_ip} with {user}. Retrying next...")
            cleanup_failed_session(shell)
            continue
            
    raise NetworkConnectionError(f"All credentials failed for {target_ip}")

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

def get_trunk_interfaces(shell) -> List[str]:
    logger.info("[TRUNK] Identifying trunk interfaces...")
    out = send_cmd(shell, "show interfaces trunk", ("#",), timeout=120, show_progress=True)
    trunk_intfs: List[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("port", "portchannel", "vlans", "----", "name")):
            continue
        toks = line.split()
        first = toks[0] if toks else ""
        if any(first.startswith(pfx) for pfx in ("Gi", "Fa", "Te", "Et", "Po")):
            if first not in trunk_intfs:
                trunk_intfs.append(first)
    if trunk_intfs:
        logger.info(f"[TRUNK] Found {len(trunk_intfs)} trunks")
    return trunk_intfs

def configure_trunk_vlan(shell, interfaces: List[str]) -> bool:
    if not interfaces:
        return True
    logger.info("[TRUNK] Adding VLAN 10 to trunks")
    send_cmd(shell, "configure terminal", ("(config)#",), timeout=5)
    for intf in interfaces:
        out = send_cmd(shell, f"interface {intf}", ("(config-if)#",), timeout=8)
        if "(config-if)#" in out:
            send_cmd(shell, "switchport trunk allowed vlan add 10", ("(config-if)#",), timeout=8)
    send_cmd(shell, "end", ("#",), timeout=5)
    return True

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

    # FIX: Use utf-8-sig to handle BOM from Notepad files
    try:
        with open(devices_file, "r", encoding="utf-8-sig") as f:
            targets = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except FileNotFoundError:
        print(f"Error: File {devices_file} not found.")
        sys.exit(1)

    try:
        base_ip = ipaddress.IPv4Address(starting_ip)
    except Exception:
        print(f"Invalid IP: {starting_ip}")
        sys.exit(1)

    vlan_ips = [str(base_ip + i) for i in range(len(targets))]

    logger.info("=" * 70)
    logger.info("VLAN 10 CONFIGURATION SCRIPT")
    logger.info("=" * 70)

    # ------------------ EXCEL GENERATION START ------------------
    logger.info("[EXCEL] Generating vlan_mapping.xlsx...")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "VLAN Mapping"
    
    # Header
    #ws.append(["VLAN 10 Address", "Target Switch IP", "Netmask"])
    
    # Data Rows
    for vip, tgt in zip(vlan_ips, targets):
        ws.append([vip, tgt, netmask])
        
    excel_filename = "vlan_mapping.xlsx"
    wb.save(excel_filename)
    logger.info(f"[EXCEL] Saved to {excel_filename}")
    # ------------------ EXCEL GENERATION END --------------------

    # Initial agg connection
    try:
        client, shell = connect_to_agg()
    except Exception as e:
        logger.error(f"Failed to connect to aggregation switch: {e}")
        sys.exit(1)

    success, failed = [], []
    idx = 0
    while idx < len(targets):
        target = targets[idx]
        vip = vlan_ips[idx]

        logger.info("")
        logger.info("=" * 70)
        logger.info(f"DEVICE {idx+1}/{len(targets)}: {target}")
        logger.info("=" * 70)

        retry_after_reconnect = False
        try:
            if shell.closed:
                raise NetworkConnectionError("Aggregation shell closed", reconnect_needed=True)

            if not verify_connectivity(shell, target):
                raise NetworkConnectionError("Unreachable")

            establish_device_session(shell, target)

            try:
                backup_config(shell, target)
            except Exception as be:
                logger.warning(f"[BACKUP] Skipped (error: {be})")

            apply_vlan10_config(shell, vip, netmask)
            trunks = get_trunk_interfaces(shell)
            configure_trunk_vlan(shell, trunks)
            exit_device_session(shell)
            
            logger.info(f"[SUCCESS] {target} configured")
            success.append(target)
            idx += 1

        except (NetworkConnectionError, OSError) as e:
            msg = str(e)
            dropped = ("Aggregation shell closed" in msg) or ("Socket is closed" in msg)
            logger.error(f"[FAILED] {target}: {msg if msg else type(e).__name__}")

            try:
                if not shell.closed:
                    cleanup_failed_session(shell)
            except:
                pass

            if dropped:
                logger.info("[RECOVER] Reconnecting to aggregation switch...")
                try:
                    try:
                        client.close()
                    except:
                        pass
                    client, shell = connect_to_agg()
                    logger.info("[RECOVER] Reconnected. Retrying current device.")
                    retry_after_reconnect = True
                except Exception as re:
                    logger.error(f"[RECOVER] Reconnect failed: {re}")
                    failed.append(target)
                    idx += 1
            else:
                failed.append(target)
                idx += 1

            if retry_after_reconnect:
                try:
                    if not verify_connectivity(shell, target):
                        raise NetworkConnectionError("Unreachable after reconnect")
                    establish_device_session(shell, target)
                    apply_vlan10_config(shell, vip, netmask)
                    trunks = get_trunk_interfaces(shell)
                    configure_trunk_vlan(shell, trunks)
                    exit_device_session(shell)
                    logger.info(f"[SUCCESS] {target} configured (after reconnect)")
                    success.append(target)
                except Exception as e2:
                    logger.error(f"[FAILED] {target} after reconnect: {e2}")
                    try:
                        cleanup_failed_session(shell)
                    except:
                        pass
                    failed.append(target)
                finally:
                    idx += 1

        time.sleep(1)

    try:
        client.close()
    except:
        pass

    logger.info("")
    logger.info("=" * 70)
    logger.info("SUMMARY")
    logger.info(f"Mapping File: {excel_filename}")
    logger.info(f"Successful: {len(success)}")
    logger.info(f"Failed: {len(failed)}")
    sys.exit(0 if not failed else 1)

if __name__ == "__main__":
    main()
