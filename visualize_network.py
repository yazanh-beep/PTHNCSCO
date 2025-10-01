#!/usr/bin/env python3
"""
Network Topology to Draw.io XML Converter
Generates a .drawio file from network_topology.json
Usage: python3 network_visualize.py [--json topology.json] [--output network.drawio]
"""
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
import argparse
import os

# Default icons for different switch types (raw GitHub URLs)
DEFAULT_ICONS = {
    'server': 'https://raw.githubusercontent.com/yazanh-beep/switch_icon/main/3850.png',
    'aggregate': 'https://raw.githubusercontent.com/yazanh-beep/switch_icon/main/3850.png',
    'access': 'https://raw.githubusercontent.com/yazanh-beep/switch_icon/main/3850.png',
    'field': 'https://raw.githubusercontent.com/yazanh-beep/switch_icon/main/IE_3000.png'
}

def load_topology(filename="network_topology.json"):
    """Load the topology JSON file"""
    with open(filename, "r") as f:
        return json.load(f)

def is_aggregate(hostname):
    """Determine if a device is an aggregate switch"""
    return "AGG" in hostname.upper()

def is_server_switch(hostname):
    """Determine if a device is a server switch"""
    return any(keyword in hostname.upper() for keyword in ["SRV", "SERVER", "SER"])

def is_field_switch(hostname):
    """Determine if a device is a field switch"""
    return any(keyword in hostname.upper() for keyword in ["IE", "IEM", "IEP", "FIELD", "INDUSTRIAL"])

def categorize_devices(devices):
    """Categorize devices into server, aggregate, access, and field switches"""
    servers = []
    aggregates = []
    access = []
    field = []
    
    for device in devices:
        hostname = device["hostname"]
        if is_server_switch(hostname):
            servers.append(device)
        elif is_aggregate(hostname):
            aggregates.append(device)
        elif is_field_switch(hostname):
            field.append(device)
        else:
            access.append(device)
    
    return servers, aggregates, access, field

def get_device_children(device, device_map):
    """Get all devices that connect to this device"""
    children = []
    for neighbor in device.get("neighbors", []):
        neighbor_ip = neighbor.get("neighbor_mgmt_ip")
        if neighbor_ip and neighbor_ip in device_map:
            children.append(device_map[neighbor_ip])
    return children

def escape_xml(text):
    """Escape special characters for XML"""
    if text is None:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def generate_drawio_xml(devices, output_file="network_topology.drawio"):
    """Generate Draw.io XML file from topology data"""
    
    print(f"Generating Draw.io XML for {len(devices)} devices...")
    
    # Categorize devices
    servers, aggregates, access, field = categorize_devices(devices)
    
    print(f"  - {len(servers)} server switches")
    print(f"  - {len(aggregates)} aggregate switches")
    print(f"  - {len(access)} access switches")
    print(f"  - {len(field)} field switches")
    
    # Combine access and field for layout purposes
    access_field = access + field
    
    # Create device map for easy lookup
    device_map = {d["management_ip"]: d for d in devices}
    
    # Layout parameters
    node_width = 220
    node_height = 90
    h_spacing = 500  # Increased from 400 to 500 for more space between access switches
    
    total_access_switches = len(access_field)
    total_width = total_access_switches * h_spacing
    canvas_width = max(5000, total_width + 400)
    canvas_height = 5000
    
    # Y positions
    server_y = 100
    agg_y = canvas_height / 2
    access_y = canvas_height - 300
    
    canvas_center_x = canvas_width / 2
    
    # Create XML structure
    mxfile = ET.Element('mxfile', host="app.diagrams.net", type="device")
    diagram = ET.SubElement(mxfile, 'diagram', id="network-topology", name="Network Topology")
    mxGraphModel = ET.SubElement(diagram, 'mxGraphModel', 
                                  dx="1434", dy="828", grid="1", gridSize="10",
                                  guides="1", tooltips="1", connect="1",
                                  arrows="1", fold="1", page="1",
                                  pageScale="1", pageWidth=str(int(canvas_width)), pageHeight=str(canvas_height),
                                  math="0", shadow="0")
    root = ET.SubElement(mxGraphModel, 'root')
    
    ET.SubElement(root, 'mxCell', id="0")
    ET.SubElement(root, 'mxCell', id="1", parent="0")
    
    cell_id = 2
    device_cells = {}
    
    # Add server switches
    print("\nCreating server switch nodes...")
    server_total_width = len(servers) * h_spacing
    server_start_x = canvas_center_x - (server_total_width / 2)
    
    for idx, srv in enumerate(servers):
        x = server_start_x + (idx * h_spacing)
        y = server_y
        
        # Single line label with spaces
        label = f"{escape_xml(srv['hostname'])} | {escape_xml(srv['management_ip'])} | SN: {escape_xml(srv.get('serial_number', 'N/A'))}"
        style = f"shape=image;html=1;verticalAlign=top;verticalLabelPosition=bottom;labelBackgroundColor=#ffffff;imageAspect=0;aspect=fixed;image={DEFAULT_ICONS['server']};fontColor=#333333;fontSize=10;fontStyle=1;"
        
        cell = ET.SubElement(root, 'mxCell', id=str(cell_id), value=label, style=style, vertex="1", parent="1")
        ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y), width=str(node_width), height=str(node_height), **{'as': 'geometry'})
        
        device_cells[srv["management_ip"]] = cell_id
        cell_id += 1
        print(f"  Added: {srv['hostname']} at ({x}, {y})")
    
    # Add aggregate switches
    print("\nCreating aggregate switch nodes...")
    agg_total_width = len(aggregates) * h_spacing
    agg_start_x = canvas_center_x - (agg_total_width / 2)
    
    for idx, agg in enumerate(aggregates):
        x = agg_start_x + (idx * h_spacing)
        y = agg_y
        
        # Single line label with spaces
        label = f"{escape_xml(agg['hostname'])} | {escape_xml(agg['management_ip'])} | SN: {escape_xml(agg.get('serial_number', 'N/A'))}"
        style = f"shape=image;html=1;verticalAlign=top;verticalLabelPosition=bottom;labelBackgroundColor=#ffffff;imageAspect=0;aspect=fixed;image={DEFAULT_ICONS['aggregate']};fontColor=#333333;fontSize=10;fontStyle=1;"
        
        cell = ET.SubElement(root, 'mxCell', id=str(cell_id), value=label, style=style, vertex="1", parent="1")
        ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y), width=str(node_width), height=str(node_height), **{'as': 'geometry'})
        
        device_cells[agg["management_ip"]] = cell_id
        cell_id += 1
        print(f"  Added: {agg['hostname']} at ({x}, {y})")
    
    # Add access/field switches
    print("\nCreating access/field switch nodes...")
    child_x_position = 100
    
    for agg_idx, agg in enumerate(aggregates):
        children = get_device_children(agg, device_map)
        agg_children = [child for child in children if child in access_field]
        
        if not agg_children:
            continue
        
        for child_idx, child in enumerate(agg_children):
            x = child_x_position
            y = access_y
            
            # Single line label with spaces
            label = f"{escape_xml(child['hostname'])} | {escape_xml(child['management_ip'])} | SN: {escape_xml(child.get('serial_number', 'N/A'))}"
            
            if is_field_switch(child['hostname']):
                icon = DEFAULT_ICONS['field']
            else:
                icon = DEFAULT_ICONS['access']
            
            style = f"shape=image;html=1;verticalAlign=top;verticalLabelPosition=bottom;labelBackgroundColor=#ffffff;imageAspect=0;aspect=fixed;image={icon};fontColor=#333333;fontSize=9;"
            
            cell = ET.SubElement(root, 'mxCell', id=str(cell_id), value=label, style=style, vertex="1", parent="1")
            ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y), width=str(node_width), height=str(node_height), **{'as': 'geometry'})
            
            device_cells[child["management_ip"]] = cell_id
            cell_id += 1
            print(f"  Added: {child['hostname'][:40]} at ({x}, {y})")
            
            child_x_position += h_spacing
            
            if child in access_field:
                access_field.remove(child)
    
    # Add remaining switches
    print("\nCreating remaining access/field switch nodes...")
    for idx, acc in enumerate(access_field):
        x = child_x_position
        y = access_y
        
        # Single line label with spaces
        label = f"{escape_xml(acc['hostname'])} | {escape_xml(acc['management_ip'])} | SN: {escape_xml(acc.get('serial_number', 'N/A'))}"
        
        if is_field_switch(acc['hostname']):
            icon = DEFAULT_ICONS['field']
        else:
            icon = DEFAULT_ICONS['access']
        
        style = f"shape=image;html=1;verticalAlign=top;verticalLabelPosition=bottom;labelBackgroundColor=#ffffff;imageAspect=0;aspect=fixed;image={icon};fontColor=#999999;fontSize=9;"
        
        cell = ET.SubElement(root, 'mxCell', id=str(cell_id), value=label, style=style, vertex="1", parent="1")
        ET.SubElement(cell, 'mxGeometry', x=str(x), y=str(y), width=str(node_width), height=str(node_height), **{'as': 'geometry'})
        
        device_cells[acc["management_ip"]] = cell_id
        cell_id += 1
        print(f"  Added: {acc['hostname'][:40]} at ({x}, {y})")
        
        child_x_position += h_spacing
    
    # Add connections
    print("\nCreating connections...")
    connections = {}
    connection_count = 0
    
    for device in devices:
        for neighbor in device.get("neighbors", []):
            neighbor_ip = neighbor.get("neighbor_mgmt_ip")
            if not neighbor_ip or neighbor_ip not in device_cells:
                continue
            
            # Create connection identifier
            conn_key = (device["management_ip"], neighbor_ip, neighbor.get('local_interface', ''), neighbor.get('remote_interface', ''))
            reverse_key = (neighbor_ip, device["management_ip"], neighbor.get('remote_interface', ''), neighbor.get('local_interface', ''))
            
            if conn_key not in connections and reverse_key not in connections:
                connections[conn_key] = True
                connection_count += 1
                
                source_id = device_cells[device["management_ip"]]
                target_id = device_cells[neighbor_ip]
                
                local_intf = neighbor.get('local_interface', 'N/A')
                remote_intf = neighbor.get('remote_interface', 'N/A')
                
                local_short = local_intf.replace('TenGigabitEthernet', 'Te').replace('GigabitEthernet', 'Gi')
                remote_short = remote_intf.replace('TenGigabitEthernet', 'Te').replace('GigabitEthernet', 'Gi')
                
                edge_label = f"{local_short} <-> {remote_short}"
                
                # Simple straight lines
                style = "endArrow=none;html=1;rounded=0;strokeWidth=2;strokeColor=#4A90E2;fontSize=8;fontColor=#333333;labelBackgroundColor=#FFFFFF;"
                
                edge = ET.SubElement(root, 'mxCell',
                                   id=str(cell_id),
                                   value=edge_label,
                                   style=style,
                                   edge="1",
                                   parent="1",
                                   source=str(source_id),
                                   target=str(target_id))
                
                ET.SubElement(edge, 'mxGeometry', relative="1", **{'as': 'geometry'})
                
                cell_id += 1
                
                if connection_count % 20 == 0:
                    print(f"  Created {connection_count} connections...")
    
    print(f"  Total connections created: {connection_count}")
    
    # Convert to XML
    xml_str = ET.tostring(mxfile, encoding='unicode')
    dom = minidom.parseString(xml_str)
    pretty_xml = dom.toprettyxml(indent="  ")
    lines = [line for line in pretty_xml.split('\n') if line.strip()]
    pretty_xml = '\n'.join(lines)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(pretty_xml)
    
    print(f"\n✅ Draw.io XML file generated: {output_file}")
    print(f"📊 Statistics:")
    print(f"   - Total devices: {len(devices)}")
    print(f"   - Server switches: {len(servers)}")
    print(f"   - Aggregate switches: {len(aggregates)}")
    print(f"   - Access switches: {len(access)}")
    print(f"   - Field switches: {len(field)}")
    print(f"   - Connections: {connection_count}")
    print(f"\n🎨 Icons:")
    print(f"   - Server/Aggregate/Access: Cisco 3850")
    print(f"   - Field: Cisco IE-3000")
    print(f"\n📖 How to use:")
    print(f"   1. Go to https://lucid.app/")
    print(f"   2. Import the file")
    print(f"   3. Edit and export as needed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert network topology JSON to Draw.io/LucidChart diagram')
    parser.add_argument('--json', default='network_topology.json', help='Input JSON file (default: network_topology.json)')
    parser.add_argument('--output', default='network_topology.drawio', help='Output Draw.io file (default: network_topology.drawio)')
    
    args = parser.parse_args()
    
    print("="*60)
    print("Network Topology to Draw.io/LucidChart Converter")
    print("="*60)
    
    try:
        devices = load_topology(args.json)
        print(f"Loaded {len(devices)} devices from {args.json}")
        generate_drawio_xml(devices, args.output)
        
    except FileNotFoundError:
        print(f"❌ Error: {args.json} not found!")
        print("Please run the discovery script first.")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
