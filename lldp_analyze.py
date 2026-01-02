import re
import sys
import argparse
from collections import defaultdict

def parse_lldp_output(file_path):
    """
    Parses 'show lldp neighbors detail' and extracts Name, IP, and Interface.
    Removes exact duplicates (same neighbor on same interface) to prevent double counting.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)

    # Split by the separator line common in Cisco LLDP output
    blocks = re.split(r'-{10,}', content)
    
    # We use a set to track unique connections to ensure we don't count the same 
    # interface line twice if the file contains duplicate text.
    seen_connections = set()
    entries = []

    for block in blocks:
        if not block.strip():
            continue

        # Extract System Name
        name_match = re.search(r'System Name:\s*(.+)', block)
        sys_name = name_match.group(1).strip() if name_match else "Unknown"

        # Extract IP Address
        ip_match = re.search(r'IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', block)
        ip_addr = ip_match.group(1).strip() if ip_match else "Unknown"

        # Extract Local Interface
        intf_match = re.search(r'Local Intf(?:erface)?:\s*(.+)', block, re.IGNORECASE)
        interface = intf_match.group(1).strip() if intf_match else "Unknown/Not Found"

        # Only process if we found meaningful data
        if sys_name != "Unknown" or ip_addr != "Unknown":
            
            # Create a unique key for this connection
            connection_key = (sys_name, ip_addr, interface)
            
            # If we haven't seen this exact link before, add it
            if connection_key not in seen_connections:
                seen_connections.add(connection_key)
                entries.append({
                    'name': sys_name,
                    'ip': ip_addr,
                    'interface': interface
                })

    return entries

def analyze_ip_duplicates(entries):
    """
    Groups by IP Address to find:
    1. IP Conflicts (Same IP, Different Switch Names)
    2. Redundant Links (Same IP, Same Switch Name, different interfaces)
    """
    # Key: IP Address, Value: List of full entry dictionaries
    ip_map = defaultdict(list)

    for entry in entries:
        ip_map[entry['ip']].append(entry)

    conflicts_found = False
    redundancy_found = False

    print(f"\n{'='*80}")
    print(f"{'DUPLICATE IP ADDRESS ANALYSIS':^80}")
    print(f"{'='*80}\n")

    # Header
    print(f"{'STATUS':<15} | {'IP ADDRESS':<15} | {'SWITCH NAME':<25} | {'LOCAL INTERFACE'}")
    print("-" * 80)

    for ip, detected_entries in ip_map.items():
        # We only care if the IP appears more than once
        if len(detected_entries) > 1:
            
            # Get all unique system names associated with this IP
            unique_names = set(e['name'] for e in detected_entries)

            # --- CASE 1: CRITICAL CONFLICT (Different Switches share IP) ---
            if len(unique_names) > 1:
                conflicts_found = True
                print(f"{'!! CONFLICT !!':<15} | {ip:<15} | {'-'*25} | {'-'*15}")
                for e in detected_entries:
                    print(f"{'':<15} | {'':<15} | {e['name']:<25} | {e['interface']}")
                print("-" * 80)

            # --- CASE 2: REDUNDANT LINK (Same Switch, multiple links) ---
            else:
                redundancy_found = True
                # Uncomment lines below to hide redundant links and ONLY show conflicts
                # continue 
                
                print(f"{'Redundant':<15} | {ip:<15} | {detected_entries[0]['name']:<25} | Multiple Interfaces")
                intfs = ", ".join([e['interface'] for e in detected_entries])
                print(f"{'':<15} | {'':<15} | {'':<25} | -> {intfs}")
                print("-" * 80)

    if not conflicts_found and not redundancy_found:
        print("\nNo duplicate IP addresses found.")
    elif not conflicts_found:
        print("\nNo IP Conflicts found (only redundant uplinks detected).")
    
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find switches sharing the same IP address.")
    parser.add_argument("filename", help="Path to the text file containing 'show lldp neighbors detail'")
    args = parser.parse_args()
    
    data = parse_lldp_output(args.filename)
    analyze_ip_duplicates(data)
