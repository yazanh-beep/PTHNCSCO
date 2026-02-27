#!/usr/bin/env python3
import paramiko
import time
import re
import csv
import logging
import sys
import warnings
from datetime import datetime
from collections import deque

warnings.filterwarnings("ignore")

# ============================================================================
# CONFIG
# ============================================================================
MAX_RETRIES = 10
RETRY_DELAY = 10  # seconds

# ============================================================================
# LOGGING (Always Enabled)
# ============================================================================
def setup_logging():
    # Force UTF-8 encoding for the log file and the console stream
    file_handler = logging.FileHandler("scan_full_log.txt", mode='w', encoding='utf-8')
    stream_handler = logging.StreamHandler(sys.stdout)
    
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        handlers=[file_handler, stream_handler]
    )

def normalize_intf(name):
    """Normalize interface names to a consistent format."""
    if not name: return ""
    n = name.lower().replace("pv", "").replace("vlan", "")
    n = re.sub(r'[^a-z0-9/]', '', n)
    n = n.replace("gigabitethernet", "gi").replace("tengigabitethernet", "te")
    n = n.replace("fastethernet", "fa").replace("portchannel", "po")
    return n

def is_valid_ip(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)

# ============================================================================
# PARSER
# ============================================================================
def _parse_neighbor_detail(output, protocol, port_to_meta, neighbor_jump_list, infra_ports):
    INFRA_CDP_CAPS  = re.compile(r"\b(?:Switch|Router|IGMP)\b", re.I)
    INFRA_LLDP_CAPS = re.compile(r"\b(?:B|R)\b")

    current_intf = current_ip = current_name = current_cdp_caps = current_lldp_enabled_caps = None

    def _flush_block():
        nonlocal current_intf, current_ip, current_name, current_cdp_caps, current_lldp_enabled_caps
        if current_intf and current_ip:
            infra = (protocol == "CDP" and current_cdp_caps and INFRA_CDP_CAPS.search(current_cdp_caps)) or \
                    (protocol == "LLDP" and current_lldp_enabled_caps and INFRA_LLDP_CAPS.search(current_lldp_enabled_caps))
            
            if infra:
                neighbor_jump_list[current_intf] = current_ip
                infra_ports.add(current_intf)
            elif not infra:
                if current_intf not in port_to_meta:
                    port_to_meta[current_intf] = {"ip": current_ip, "name": current_name or "Unknown", "source": protocol}
        current_intf = current_ip = current_name = current_cdp_caps = current_lldp_enabled_caps = None

    for line in output.splitlines():
        if re.match(r"-{10,}", line.strip()):
            _flush_block()
            continue
        m = re.search(r"(?:Local Intf|Interface)\s*:\s*(\S+?)(?:,|$)", line, re.I)
        if m:
            _flush_block()
            current_intf = normalize_intf(m.group(1))
            continue
        m = re.search(r"(?:System Name|Device ID)\s*:\s*(.+)", line, re.I)
        if m: current_name = m.group(1).strip()
        m = re.search(r"^\s+IP(?:\s+address)?\s*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.I)
        if m and current_intf and not current_ip: current_ip = m.group(1)
        m = re.search(r"^Capabilities\s*:\s*(.+)", line, re.I)
        if m: current_cdp_caps = m.group(1).strip()
        m = re.search(r"Enabled [Cc]apabilities\s*:\s*(.+)", line, re.I)
        if m: current_lldp_enabled_caps = m.group(1).strip()
    _flush_block()

# ============================================================================
# SCANNER CORE
# ============================================================================
def scan_current_switch(switch_ip, switch_name, agg_shell, inventory_map, stats):
    neighbor_jump_list, port_to_meta, infra_ports, mac_to_ip = {}, {}, set(), {}

    send_cmd(agg_shell, "terminal length 0")
    trunk_out = send_cmd(agg_shell, "show interfaces trunk")
    trunks = re.findall(r"(?m)^(\S+)\s+(?:on|desirable|auto|off|nonegotiate|trunking)", trunk_out)
    for t in trunks: infra_ports.add(normalize_intf(t))

    _parse_neighbor_detail(send_cmd(agg_shell, "show lldp neighbors detail"), "LLDP", port_to_meta, neighbor_jump_list, infra_ports)
    _parse_neighbor_detail(send_cmd(agg_shell, "show cdp neighbors detail"), "CDP", port_to_meta, neighbor_jump_list, infra_ports)

    if len(neighbor_jump_list) > 20:
        logging.warning(f" [!] {switch_name} is a Core Hub. Skipping MAC sweep.")
        return [ip for ip in neighbor_jump_list.values() if is_valid_ip(ip)]

    arp_out = send_cmd(agg_shell, "show ip arp")
    for line in arp_out.splitlines():
        m = re.match(r"\s*Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", line, re.I)
        if m: mac_to_ip[m.group(2).lower()] = m.group(1)

    mac_table = send_cmd(agg_shell, "show mac address-table dynamic")
    seen_macs, port_mac_count = set(), {}

    for line in mac_table.splitlines():
        if not re.search(r'[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}', line, re.I): continue
        parts = line.split()
        if len(parts) < 4: continue
        try:
            vlan, mac, raw_port = parts[0], parts[1].lower(), parts[-1]
            norm = normalize_intf(raw_port)
            if not norm or norm in infra_ports or "po" in norm or mac in seen_macs: continue
            port_mac_count[norm] = port_mac_count.get(norm, 0) + 1
            multi_port = port_mac_count[norm] > 1

            camera_ip = mac_to_ip.get(mac)
            meta = port_to_meta.get(norm)
            if camera_ip:
                ip_source = "ARP"
                if meta and meta["ip"] == camera_ip: ip_source = meta["source"]
                camera_name = meta["name"] if (meta and not multi_port) else "Unknown (multi-MAC port)"
            elif meta and not multi_port:
                camera_ip, camera_name, ip_source = meta["ip"], meta["name"], meta["source"]
            else:
                camera_ip, camera_name, ip_source = "None", "Unknown", "Unknown"

            inventory_map.append({
                "switch_name": switch_name, "switch_ip": switch_ip, "port": raw_port,
                "vlan": vlan, "mac_address": mac, "camera_ip": camera_ip,
                "camera_name": camera_name, "ip_source": ip_source, "multi_mac_port": multi_port
            })
            logging.info(f"   [MAPPED] {raw_port} -> {mac} | IP: {camera_ip} | Source: {ip_source}")
            stats["total_macs_found"] += 1
            seen_macs.add(mac)
        except Exception: continue
    return [ip for ip in neighbor_jump_list.values() if is_valid_ip(ip)]

# ============================================================================
# UTILS
# ============================================================================
def send_cmd(shell, cmd, timeout=30):
    while shell.recv_ready(): shell.recv(65535)
    shell.send(cmd + "\n")
    time.sleep(1.2)
    buf = ""
    start = time.time()
    while (time.time() - start) < timeout:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", "ignore")
            buf += chunk
            if re.search(r"(?m)^[^\r\n>\s][^\r\n>]*[>#]\s?$", buf): break
        time.sleep(0.1)
    return buf

def clean_shell(shell, curr_host):
    shell.send("\x03\n")
    time.sleep(0.5)
    buf = send_cmd(shell, "\n")
    m = re.search(r"([\w\d\.\-]+)[>#]\s*$", buf.strip())
    return m.group(1) if m else curr_host

def try_login(shell, target_ip, cred, current_host):
    logging.info(f" -> Attempting SSH to {target_ip}...")
    while shell.recv_ready(): shell.recv(65535)
    shell.send(f"ssh -l {cred['username']} {target_ip}\n")
    start, pwd_sent, buf = time.time(), False, ""
    while (time.time() - start) < 45:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8", "ignore")
            buf += chunk
            if "yes/no" in chunk.lower(): shell.send("yes\n"); buf = ""
            if "password:" in chunk.lower():
                if pwd_sent: shell.send("\x03\n"); time.sleep(1); return None
                shell.send(cred["password"] + "\n")
                pwd_sent = True; buf = ""; start = time.time()
            m = re.search(r"([\w\d\.\-]+)[>#]\s*$", buf.strip())
            if m and m.group(1) != current_host:
                send_cmd(shell, "terminal length 0")
                return m.group(1)
            if any(x in buf.lower() for x in ["refused", "timed out", "no route", "permission denied"]): return None
        time.sleep(0.15)
    shell.send("\x03\n"); time.sleep(1); return None

def try_login_with_retry(shell, target_ip, creds, current_host, stats):
    """Attempts SSH to target_ip trying all credentials each retry."""
    for attempt in range(1, MAX_RETRIES + 1):
        logging.info(f"   [ATTEMPT {attempt}/{MAX_RETRIES}] SSH to {target_ip}...")
        for cred in creds:
            host = try_login(shell, target_ip, cred, current_host)
            if host: return host, current_host
            current_host = clean_shell(shell, current_host)
        
        if attempt < MAX_RETRIES:
            stats["total_retries"] += 1
            logging.info(f"   [RETRY] All creds failed for {target_ip}, waiting {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)
    return None, current_host

def main():
    setup_logging()
    SEED_IP = "192.168.0.251"
    SEED_IP_ALIASES = {"192.168.1.252"}
    CREDS = [
        {"username": "admin", "password": "admin"},
        {"username": "Admin", "password": "/2/_HKX6YvCGMwzAdJp"},
        {"username": "Admin", "password": "cisco"}
    ]
    
    visited_ips = {SEED_IP} | SEED_IP_ALIASES
    visited_hosts, inventory_map = set(), []
    stats = {
        "total_macs_found": 0, "switches_attempted": 0, 
        "switches_success": 0, "switches_failed": 0, "total_retries": 0
    }
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(SEED_IP, username=CREDS[0]['username'], password=CREDS[0]['password'], timeout=15)
        shell = client.invoke_shell(); time.sleep(2)
        send_cmd(shell, "terminal length 0")
        seed_host = re.search(r"([\w\d\.\-]+)[>#]", send_cmd(shell, "\n")).group(1)
        visited_hosts.add(seed_host)
    except Exception as e:
        logging.error(f"Failed to connect to seed: {e}")
        return

    queue = deque([SEED_IP])
    curr_host = seed_host
    
    while queue:
        ip = queue.popleft()
        if ip != SEED_IP:
            stats["switches_attempted"] += 1
            host, curr_host = try_login_with_retry(shell, ip, CREDS, curr_host, stats)
            
            if host:
                if host in visited_hosts:
                    logging.info(f"   [SKIP] {host} ({ip}) already visited.")
                    visited_ips.add(ip)
                    shell.send("exit\n"); time.sleep(1.0)
                    curr_host = clean_shell(shell, curr_host)
                    continue
                visited_hosts.add(host)
                stats["switches_success"] += 1
                logging.info(f"-> Processing {host} ({ip})")
            else:
                stats["switches_failed"] += 1
                logging.error(f"   [X] Jump Failed for {ip} after {MAX_RETRIES} attempts.")
                continue
        else:
            stats["switches_attempted"] += 1
            stats["switches_success"] += 1
            host = seed_host
            
        send_cmd(shell, "terminal length 0")
        new_ips = scan_current_switch(ip, host, shell, inventory_map, stats)
        for n_ip in new_ips:
            if n_ip not in visited_ips:
                visited_ips.add(n_ip)
                queue.append(n_ip)
        
        if ip != SEED_IP:
            shell.send("exit\n"); time.sleep(1.0)
            curr_host = clean_shell(shell, curr_host)

    # Summary Report
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    generated_files = []
    if inventory_map:
        csv_name = f"camera_inventory_{ts}.csv"
        with open(csv_name, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=inventory_map[0].keys())
            writer.writeheader()
            writer.writerows(inventory_map)
        generated_files.append(csv_name)
    generated_files.append("scan_full_log.txt")
    
    print("\n" + "="*60 + "\n  SCAN COMPLETE\n" + "="*60)
    print(f"  Switches attempted  : {stats['switches_attempted']}")
    print(f"  Switches successful : {stats['switches_success']}")
    print(f"  Switches failed     : {stats['switches_failed']}")
    print(f"  Total retries       : {stats['total_retries']}")
    print(f"  Cameras/endpoints   : {stats['total_macs_found']}")
    print("-" * 60 + "\n  Generated files:")
    for f in generated_files: print(f"    -> {f}")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
