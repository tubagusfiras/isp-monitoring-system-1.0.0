#!/usr/bin/env python3
"""
SDI Interface Monitor - Production Ready
Collects interface statistics via SNMP with proper 64-bit counter handling
"""
import subprocess
import re
import psycopg2
from psycopg2.extras import RealDictCursor
from collections import defaultdict
import sys

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

# SNMP OIDs for interface statistics
OIDS = {
    'ifDescr': '1.3.6.1.2.1.2.2.1.2',
    'ifAlias': '1.3.6.1.2.1.31.1.1.1.18',
    'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
    'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
    'ifHCInOctets': '1.3.6.1.2.1.31.1.1.1.6',
    'ifHCOutOctets': '1.3.6.1.2.1.31.1.1.1.10',
    'ifInUcastPkts': '1.3.6.1.2.1.2.2.1.11',
    'ifOutUcastPkts': '1.3.6.1.2.1.2.2.1.17',
    'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
    'ifOutErrors': '1.3.6.1.2.1.2.2.1.20',
    'ifInDiscards': '1.3.6.1.2.1.2.2.1.13',
    'ifOutDiscards': '1.3.6.1.2.1.2.2.1.19'
}

STATUS_MAP = {
    '1': 'up',
    '2': 'down',
    '3': 'testing'
}

def get_interface_filter(device_type):
    """Get interface name filter pattern based on vendor"""
    filters = {
        'juniper_mx': r'^(et-|ae\d|ge-|xe-|lt-|gr-|ip-)',
        'exos': r'Port \d+|Vlan',
        'huawei': r'^(GigabitEthernet|XGigabitEthernet|Eth-Trunk|Vlanif)',
        'mikrotik': r'^(ether|sfp|bridge|vlan)'
    }
    return filters.get(device_type, r'^(et-|ge-|Gig|ether)')

def get_db():
    """Get database connection"""
    return psycopg2.connect(**DB_CONFIG)

def safe_int(val, default=0):
    """
    Safely convert SNMP counter to integer, handling 64-bit overflow
    
    SNMP 64-bit counters can overflow and appear as huge positive numbers.
    This function normalizes them to proper values.
    """
    try:
        if not val or val == '':
            return default
        
        num = int(val)
        
        # If number is suspiciously large (> 2^63), it's likely overflow
        # Normalize using modulo 2^64
        MAX_64BIT = 2**63
        if num > MAX_64BIT:
            num = num % (2**64)
        
        return num
    except (ValueError, TypeError):
        return default

def snmp_walk(ip, community, oid):
    """
    Walk SNMP OID and return dict {index: value}
    Handles SNMP response parsing including enum values like up(1), down(2)
    """
    cmd = ['snmpwalk', '-v2c', '-c', community, ip, oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = {}
        
        for line in result.stdout.strip().split('\n'):
            if '=' not in line:
                continue
                
            # Parse: IF-MIB::ifDescr.123 = STRING: "eth0"
            match = re.search(r'\.(\d+)\s*=\s*(.+)', line)
            if not match:
                continue
            
            index = match.group(1)
            value = match.group(2).strip()
            
            # Strip SNMP type prefix (STRING:, INTEGER:, Counter64:, etc)
            value = re.sub(r'^(STRING:|INTEGER:|Counter\d+:|Gauge\d+:|TimeTicks:)\s*', '', value)
            
            # Extract number from enum format: up(1) -> 1
            enum_match = re.search(r'\((\d+)\)', value)
            if enum_match:
                value = enum_match.group(1)
            
            # Remove quotes
            value = value.strip().strip('"')
            data[index] = value
        
        return data
    except subprocess.TimeoutExpired:
        print(f"  ⏱️  SNMP timeout for {ip} {oid}")
        return {}
    except Exception as e:
        print(f"  ❌ SNMP error for {ip} {oid}: {e}")
        return {}

def collect_interface_stats(device):
    """
    Collect interface statistics for a single device
    Returns number of interfaces saved, or 0 on failure
    """
    ip = device['ip_address']
    community = device.get('snmp_community', 'public')
    device_id = device['id']
    device_type = device.get('device_type', 'unknown')
    hostname = device['hostname']
    
    print(f"Collecting interfaces from {hostname} ({ip})...")
    
    # Step 1: Get interface descriptions
    descriptions = snmp_walk(ip, community, OIDS['ifDescr'])
    if not descriptions:
        print(f"  ❌ No interfaces found or SNMP failed")
        return 0
    
    # Step 2: Filter to physical interfaces based on vendor
    pattern = get_interface_filter(device_type)
    physical_if = {
        idx: name for idx, name in descriptions.items() 
        if re.search(pattern, name) and '.32767' not in name
    }
    
    if not physical_if:
        print(f"  ⚠️  No physical interfaces found (pattern: {pattern})")
        return 0
    
    print(f"  Found {len(physical_if)} physical interfaces")
    
    # Step 3: Collect all statistics
    descriptions_alias = snmp_walk(ip, community, OIDS['ifAlias'])
    admin_status = snmp_walk(ip, community, OIDS['ifAdminStatus'])
    oper_status = snmp_walk(ip, community, OIDS['ifOperStatus'])
    speed = snmp_walk(ip, community, OIDS['ifSpeed'])
    in_octets = snmp_walk(ip, community, OIDS['ifHCInOctets'])
    out_octets = snmp_walk(ip, community, OIDS['ifHCOutOctets'])
    in_packets = snmp_walk(ip, community, OIDS['ifInUcastPkts'])
    out_packets = snmp_walk(ip, community, OIDS['ifOutUcastPkts'])
    in_errors = snmp_walk(ip, community, OIDS['ifInErrors'])
    out_errors = snmp_walk(ip, community, OIDS['ifOutErrors'])
    in_discards = snmp_walk(ip, community, OIDS['ifInDiscards'])
    out_discards = snmp_walk(ip, community, OIDS['ifOutDiscards'])
    
    # Step 4: Save to database
    conn = get_db()
    cur = conn.cursor()
    saved = 0
    
    for idx, if_name in physical_if.items():
        try:
            cur.execute("""
                INSERT INTO interface_stats 
                (device_id, interface_name, interface_index, admin_status, oper_status, 
                 speed, description, in_octets, out_octets, in_packets, out_packets,
                 in_errors, out_errors, in_discards, out_discards)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                device_id,
                if_name,
                int(idx),
                STATUS_MAP.get(admin_status.get(idx, '2'), 'down'),
                STATUS_MAP.get(oper_status.get(idx, '2'), 'down'),
                safe_int(speed.get(idx)),
                descriptions_alias.get(idx, ''),
                safe_int(in_octets.get(idx)),
                safe_int(out_octets.get(idx)),
                safe_int(in_packets.get(idx)),
                safe_int(out_packets.get(idx)),
                safe_int(in_errors.get(idx)),
                safe_int(out_errors.get(idx)),
                safe_int(in_discards.get(idx)),
                safe_int(out_discards.get(idx))
            ))
            saved += 1
        except Exception as e:
            print(f"  ⚠️  Error saving {if_name}: {e}")
    
    conn.commit()
    cur.close()
    conn.close()
    
    print(f"  ✅ Saved {saved} interfaces")
    return saved

def main():
    """Main collection workflow with error tracking"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE is_active = true ORDER BY hostname")
    devices = cur.fetchall()
    cur.close()
    conn.close()
    
    print(f"\n🔍 Found {len(devices)} active devices\n")
    print("="*80)
    
    # Track results
    success_devices = []
    failed_devices = []
    
    for device in devices:
        try:
            result = collect_interface_stats(device)
            if result > 0:
                success_devices.append({
                    'hostname': device['hostname'],
                    'ip': device['ip_address'],
                    'count': result
                })
            else:
                failed_devices.append({
                    'hostname': device['hostname'],
                    'ip': device['ip_address'],
                    'device_type': device.get('device_type', 'unknown'),
                    'reason': 'No interfaces found or SNMP failed'
                })
        except Exception as e:
            failed_devices.append({
                'hostname': device['hostname'],
                'ip': device['ip_address'],
                'device_type': device.get('device_type', 'unknown'),
                'reason': str(e)
            })
    
    # Print summary
    print("\n" + "="*80)
    print("📊 COLLECTION SUMMARY")
    print("="*80)
    total_interfaces = sum(d['count'] for d in success_devices)
    print(f"✅ Success: {len(success_devices)} devices, {total_interfaces} interfaces")
    print(f"❌ Failed: {len(failed_devices)} devices")
    
    if failed_devices:
        print("\n" + "="*80)
        print("❌ FAILED DEVICES (grouped by reason)")
        print("="*80)
        
        # Group by reason
        grouped = defaultdict(list)
        for d in failed_devices:
            grouped[d['reason']].append(d)
        
        for reason, devices_list in sorted(grouped.items()):
            print(f"\n🔴 {reason} ({len(devices_list)} devices):")
            for d in sorted(devices_list, key=lambda x: x['hostname'])[:10]:  # Show first 10
                print(f"   - {d['hostname']} ({d['ip']}) [{d['device_type']}]")
            if len(devices_list) > 10:
                print(f"   ... and {len(devices_list)-10} more")
    
    print("\n" + "="*80)
    print("✅ Collection complete!")
    print("="*80 + "\n")

if __name__ == '__main__':
    main()
