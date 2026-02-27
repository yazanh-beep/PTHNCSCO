"""
This script is a recursive network discovery and asset auditing tool. It’s designed to start at a single "seed" switch and autonomously map out an entire network by hopping across links, harvesting hardware and endpoint data as it goes.

How It Works
You can think of this as a "Network Spider" that builds a graph of your infrastructure and indexes the devices connected to it.

1. The Traversal (Breadth-First Search)
Discovery: It uses a queue (starting with your SEED_IP). It connects to a switch, reads the neighbor table (LLDP/CDP), and adds any newly discovered infrastructure switches to the queue.

Identity De-duplication: It tracks visited_hosts by hostname. If it finds a switch via a different IP, it recognizes it as a device it has already visited, skips the redundant work, and cleanly exits the session.

Resilience: It features a robust, multi-credential retry loop. If a switch doesn't respond, it tries different credentials and waits (with a configurable delay) before giving up, ensuring it doesn't fail just because of a temporary network glitch or slow authentication.

2. The Data Extraction (Switch Audit)
Once logged into a switch, the script performs a multi-stage audit:

Infrastructure Audit: It uses show interfaces trunk to identify uplinks, ensuring it doesn't try to "map" the contents of a trunk port (which would create false positives).

Hardware Profiling: It scrapes show inventory to determine the exact model, serial number, and stack members. The new parsing logic is "stack-aware," meaning it skips fans, power supplies, and transceiver modules, focusing only on the active stack members.

Endpoint Mapping: It correlates the MAC address table with the ARP table. By cross-referencing this with LLDP/CDP neighbor data, it identifies "who" is on each port (e.g., a camera) and provides an IP, device name, and the "Source of Truth" for that data (ARP vs. LLDP/CDP).

3. Reporting
Automation-Ready Output: The script writes to both CSV (for human review) and JSON (for programmatic consumption). The JSON output is structured, containing nested stack members and hardware stats, making it ready to be pushed into a CMDB or a dashboard.

Summary
The logic is essentially: Navigate -> Identify -> Audit -> Resolve -> Report.

Because it relies on capability bits (the "Switch" and "Bridge/Router" flags) rather than hardcoded IP ranges, it is completely network-agnostic. It will follow your network wherever the cabling goes, regardless of the IP scheme.

"""
#!/usr/bin/env python3
import paramiko
import time
import re
import csv
import json
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
CORE_HUB_THRESHOLD = 40

# ============================================================================
# LOGGING
# ============================================================================
def setup_logging():
    file_handler = logging.FileHandler("scan_full_log.txt", mode='w', encoding='utf-8')
    stream_handler = logging.StreamHandler(sys.stdout)
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        handlers=[file_handler, stream_handler]
    )

def normalize_intf(name):
    if not name: return ""
    n = name.lower().replace("pv", "").replace("vlan", "")
    n = re.sub(r'[^a-z0-9/]', '', n)
    n = n.replace("gigabitethernet", "gi").replace("tengigabitethernet", "te")
    n = n.replace("fastethernet", "fa").replace("portchannel", "po")
    return n

def is_valid_ip(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)

def _classify_link_role(remote_name, caps):
    name_upper = (remote_name or "").upper()
    if any(x in name_upper for x in ["CORE", "AGG", "AGGREGATE", "DIST", "DISTRIBUTION"]):
        return "uplink-core" if "CORE" in name_upper else "uplink-agg"
    if caps and re.search(r"C93\d\d|C38\d\d|9300|3850", caps, re.I):
        return "uplink-agg"
    return "daisy-chain"

# ============================================================================
# SWITCH INFO COLLECTOR
# ============================================================================
def collect_switch_info(shell, switch_ip, switch_name, neighbor_jump_list, infra_ports):
    info = {
        "switch_name": switch_name, "switch_ip": switch_ip, "serial_number": "Unknown",
        "management_ip": "Unknown", "management_svi": "Unknown", "is_vlan100": False,
        "model": "Unknown", "is_stacked": False, "stack_count": 1, "stack_members": [],
        "firmware_version": "Unknown", "switch_links": []
    }
    
    # Inventory
    inv_out = send_cmd(shell, "show inventory")
    blocks = re.split(r'\n(?=NAME:)', inv_out)
    stack_members = []
    for block in blocks:
        name_match = re.search(r'NAME:\s*"([^"]+)"', block)
        pid_match  = re.search(r'PID:\s*(\S+)', block)
        sn_match   = re.search(r'SN:\s*(\S+)', block)
        if not name_match or not sn_match: continue
        if not re.match(r'^Switch\s+\d+$', name_match.group(1).strip(), re.I): continue
        
        stack_members.append({
            "member": int(re.search(r'\d+', name_match.group(1)).group()),
            "model": pid_match.group(1).strip() if pid_match else "",
            "serial": sn_match.group(1).strip()
        })
    stack_members.sort(key=lambda x: x["member"])
    if stack_members:
        info.update({"model": stack_members[0]["model"], "serial_number": stack_members[0]["serial"], 
                     "stack_members": stack_members, "stack_count": len(stack_members), "is_stacked": len(stack_members) > 1})

    # Management IP
    ip_int_out = send_cmd(shell, "show ip interface brief")
    for line in ip_int_out.splitlines():
        m = re.match(r'\s*(Vlan\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+up\s+up', line, re.I)
        if m:
            svi, ip = m.group(1), m.group(2)
            if svi.lower() == "vlan100": info.update({"management_ip": ip, "management_svi": "Vlan100", "is_vlan100": True})
            elif not info["is_vlan100"] and info["management_ip"] == "Unknown": info.update({"management_ip": ip, "management_svi": svi})
    
    # Firmware
    ver_out = send_cmd(shell, "show version")
    ver_match = re.search(r'(?:Cisco IOS Software.*?Version\s+(\S+)|IOS-XE Software.*?Version\s+(\S+))', ver_out, re.I)
    if ver_match: info["firmware_version"] = ver_match.group(1) or ver_match.group(2)
    
    # Inter-Switch Links
    lldp_out = send_cmd(shell, "show lldp neighbors detail")
    curr_intf = curr_r_name = curr_r_port = curr_ip = curr_caps = None
    def flush_link():
        nonlocal curr_intf, curr_r_name, curr_r_port, curr_ip, curr_caps
        if curr_intf and curr_r_name and normalize_intf(curr_intf) in infra_ports:
            info["switch_links"].append({
                "local_port": curr_intf, "remote_switch": curr_r_name,
                "remote_port": curr_r_port or "Unknown", "remote_ip": curr_ip or "Unknown",
                "role": _classify_link_role(curr_r_name, curr_caps)
            })
        curr_intf = curr_r_name = curr_r_port = curr_ip = curr_caps = None

    for line in lldp_out.splitlines():
        if re.match(r"-{10,}", line.strip()): flush_link(); continue
        m = re.search(r"Local Intf:\s*(\S+)", line, re.I)
        if m: flush_link(); curr_intf = m.group(1); continue
        m = re.search(r"System Name:\s*(.+)", line, re.I)
        if m: curr_r_name = m.group(1).strip()
        m = re.search(r"Port Description:\s*(.+)", line, re.I)
        if m: curr_r_port = m.group(1).strip()
        m = re.search(r"^\s+IP(?:\s+address)?\s*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.I)
        if m and curr_intf and not curr_ip: curr_ip = m.group(1)
        m = re.search(r"Enabled [Cc]apabilities\s*:\s*(.+)", line, re.I)
        if m: curr_caps = m.group(1).strip()
    flush_link()
    return info

# ============================================================================
# PARSER & SCANNER
# ============================================================================
def _parse_neighbor_detail(output, protocol, port_to_meta, neighbor_jump_list, infra_ports):
    INFRA_CDP_CAPS, INFRA_LLDP_CAPS = re.compile(r"\b(?:Switch|Router|IGMP)\b", re.I), re.compile(r"\b(?:B|R)\b")
    current_intf = current_ip = current_name = current_cdp_caps = current_lldp_enabled_caps = None

    def _flush_block():
        nonlocal current_intf, current_ip, current_name, current_cdp_caps, current_lldp_enabled_caps
        if current_intf and current_ip:
            infra = (protocol == "CDP" and current_cdp_caps and INFRA_CDP_CAPS.search(current_cdp_caps)) or \
                    (protocol == "LLDP" and current_lldp_enabled_caps and INFRA_LLDP_CAPS.search(current_lldp_enabled_caps))
            if infra:
                neighbor_jump_list[current_intf] = current_ip
                infra_ports.add(current_intf)
            elif not infra and current_intf not in port_to_meta:
                port_to_meta[current_intf] = {"ip": current_ip, "name": current_name or "Unknown", "source": protocol}
        current_intf = current_ip = current_name = current_cdp_caps = current_lldp_enabled_caps = None

    for line in output.splitlines():
        if re.match(r"-{10,}", line.strip()): _flush_block(); continue
        m = re.search(r"(?:Local Intf|Interface)\s*:\s*(\S+?)(?:,|$)", line, re.I)
        if m: _flush_block(); current_intf = normalize_intf(m.group(1))
        m = re.search(r"(?:System Name|Device ID)\s*:\s*(.+)", line, re.I)
        if m: current_name = m.group(1).strip()
        m = re.search(r"^\s+IP(?:\s+address)?\s*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.I)
        if m and current_intf and not current_ip: current_ip = m.group(1)
        m = re.search(r"^Capabilities\s*:\s*(.+)", line, re.I)
        if m: current_cdp_caps = m.group(1).strip()
        m = re.search(r"Enabled [Cc]apabilities\s*:\s*(.+)", line, re.I)
        if m: current_lldp_enabled_caps = m.group(1).strip()
    _flush_block()

def scan_current_switch(switch_ip, switch_name, agg_shell, inventory_map, switch_inventory, stats):
    neighbor_jump_list, port_to_meta, infra_ports, mac_to_ip = {}, {}, set(), {}
    send_cmd(agg_shell, "terminal length 0")
    
    trunk_out = send_cmd(agg_shell, "show interfaces trunk")
    trunks = re.findall(r"(?m)^(\S+)\s+(?:on|desirable|auto|off|nonegotiate|trunking)", trunk_out)
    for t in trunks: infra_ports.add(normalize_intf(t))

    _parse_neighbor_detail(send_cmd(agg_shell, "show lldp neighbors detail"), "LLDP", port_to_meta, neighbor_jump_list, infra_ports)
    _parse_neighbor_detail(send_cmd(agg_shell, "show cdp neighbors detail"), "CDP", port_to_meta, neighbor_jump_list, infra_ports)

    # Collect Info
    info = collect_switch_info(agg_shell, switch_ip, switch_name, neighbor_jump_list, infra_ports)
    switch_inventory.append(info)
    
    logging.info(f"   [SWITCH] Name    : {info['switch_name']}")
    logging.info(f"   [SWITCH] Model   : {info['model']}")
    logging.info(f"   [SWITCH] Serial  : {info['serial_number']}")
    logging.info(f"   [SWITCH] Firmware: {info['firmware_version']}")
    logging.info(f"   [SWITCH] Mgmt IP : {info['management_ip']} ({info['management_svi']}) {'[VLAN100]' if info['is_vlan100'] else '[NOT VLAN100]'}")
    
    if info['switch_links']:
        logging.info(f"   [LINKS ] {len(info['switch_links'])} inter-switch link(s):")
        for lnk in info['switch_links']:
            logging.info(f"   [LINKS ]   [{lnk['role']:<14}] {lnk['local_port']} -> {lnk['remote_switch']} | {lnk['remote_port']} | {lnk['remote_ip']}")
    else: logging.info(f"   [LINKS ] No inter-switch links detected")
    
    if info['is_stacked']:
        logging.info(f"   [STACK ] YES — {info['stack_count']} members:")
        for m in info['stack_members']: logging.info(f"   [STACK ]   Member {m['member']}: {m['model']} | SN: {m['serial']}")
    else:
        logging.info(f"   [STACK ] No — Single unit: {info['stack_members'][0]['model']} | SN: {info['stack_members'][0]['serial']}" if info['stack_members'] else "   [STACK ] No")
    logging.info(f"   {'-'*60}")

    if len(neighbor_jump_list) > CORE_HUB_THRESHOLD:
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
            camera_ip, meta = mac_to_ip.get(mac), port_to_meta.get(norm)
            if camera_ip:
                ip_source = "ARP"; 
                if meta and meta["ip"] == camera_ip: ip_source = meta["source"]
                camera_name = meta["name"] if (meta and not multi_port) else "Unknown (multi-MAC port)"
            elif meta and not multi_port: camera_ip, camera_name, ip_source = meta["ip"], meta["name"], meta["source"]
            else: camera_ip, camera_name, ip_source = "None", "Unknown", "Unknown"
            inventory_map.append({
                "switch_name": switch_name, "switch_ip": switch_ip, "port": raw_port,
                "vlan": vlan, "mac_address": mac, "camera_ip": camera_ip,
                "camera_name": camera_name, "ip_source": ip_source, "multi_mac_port": multi_port
            })
            logging.info(f"   [CAMERA] Port: {raw_port:<12} | VLAN: {vlan:<6} | MAC: {mac:<18} | IP: {camera_ip:<16} | Name: {camera_name:<30} | Src: {ip_source}" + (" [MULTI]" if multi_port else ""))
            stats["total_macs_found"] += 1; seen_macs.add(mac)
        except Exception: continue
    logging.info(f"   [SWEEP ] {len(seen_macs)} cameras/endpoints found on {switch_name}")
    logging.info(f"   {'='*60}")
    return [ip for ip in neighbor_jump_list.values() if is_valid_ip(ip)]

# ============================================================================
# UTILS & MAIN
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
    CREDS = [{"username": "admin", "password": "admin"}, {"username": "Admin", "password": "/2/_HKX6YvCGMwzAdJp"},  {"username": "Admin", "password": "cisco"}]
    
    visited_ips = {SEED_IP} | SEED_IP_ALIASES
    visited_hosts, inventory_map, switch_inventory = set(), [], []
    stats = {"total_macs_found": 0, "switches_attempted": 0, "switches_success": 0, "switches_failed": 0, "total_retries": 0}
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(SEED_IP, username=CREDS[0]['username'], password=CREDS[0]['password'], timeout=15)
        shell = client.invoke_shell(); time.sleep(2)
        send_cmd(shell, "terminal length 0")
        seed_host = re.search(r"([\w\d\.\-]+)[>#]", send_cmd(shell, "\n")).group(1)
        visited_hosts.add(seed_host)
    except Exception as e:
        logging.error(f"Failed to connect: {e}")
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
                    visited_ips.add(ip); shell.send("exit\n"); time.sleep(1.0); curr_host = clean_shell(shell, curr_host); continue
                visited_hosts.add(host); stats["switches_success"] += 1; logging.info(f"-> Processing {host} ({ip})")
            else:
                curr_host = clean_shell(shell, curr_host); stats["switches_failed"] += 1; logging.error(f"   [X] Jump Failed for {ip}."); continue
        else:
            stats["switches_attempted"] += 1; stats["switches_success"] += 1; host = seed_host
            
        send_cmd(shell, "terminal length 0")
        new_ips = scan_current_switch(ip, host, shell, inventory_map, switch_inventory, stats)
        for n_ip in new_ips:
            if n_ip not in visited_ips: visited_ips.add(n_ip); queue.append(n_ip)
        if ip != SEED_IP: shell.send("exit\n"); time.sleep(1.0); curr_host = clean_shell(shell, curr_host)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    generated_files = []
    if inventory_map:
        csv_name = f"camera_inventory_{ts}.csv"
        with open(csv_name, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=inventory_map[0].keys()); writer.writeheader(); writer.writerows(inventory_map)
        generated_files.append(csv_name)
        json_name = f"camera_inventory_{ts}.json"
        with open(json_name, 'w', encoding='utf-8') as f:
            json.dump({"generated_at": datetime.now().isoformat(), "stats": stats, "inventory": inventory_map}, f, indent=2, ensure_ascii=False)
        generated_files.append(json_name)
        
        sw_csv_name = f"switch_inventory_{ts}.csv"
        with open(sw_csv_name, 'w', newline='', encoding='utf-8') as f:
            flat_rows = []
            for sw in switch_inventory:
                row = {k: v for k, v in sw.items() if k != "stack_members"}
                row["stack_members"] = "; ".join(f"Member{m['member']}:{m['serial']}" for m in sw["stack_members"])
                row["switch_links"] = "; ".join(f"[{lnk['role']}] {lnk['local_port']}->{lnk['remote_switch']}:{lnk['remote_port']}" for lnk in sw["switch_links"]) or "None"
                flat_rows.append(row)
            writer = csv.DictWriter(f, fieldnames=flat_rows[0].keys()); writer.writeheader(); writer.writerows(flat_rows)
        generated_files.append(sw_csv_name)
        sw_json_name = f"switch_inventory_{ts}.json"
        with open(sw_json_name, 'w', encoding='utf-8') as f:
            json.dump({"generated_at": datetime.now().isoformat(), "switch_count": len(switch_inventory), "switches": switch_inventory}, f, indent=2, ensure_ascii=False)
        generated_files.append(sw_json_name)
    
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
