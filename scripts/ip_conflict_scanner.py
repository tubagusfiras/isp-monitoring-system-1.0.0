#!/usr/bin/env python3
import subprocess
import re
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
from pysnmp.hlapi import *
import sys

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

# SNMP OIDs
ARP_TABLE_OID = '1.3.6.1.2.1.4.22.1.2'           # ipNetToMediaPhysAddress
IP_ROUTE_DEST_OID = '1.3.6.1.2.1.4.21.1.1'       # ipRouteDest
IP_ROUTE_TYPE_OID = '1.3.6.1.2.1.4.21.1.8'       # ipRouteType

# Route Types (from RFC 1213)
ROUTE_TYPES = {
    1: 'other',
    2: 'invalid',
    3: 'direct',      # ← REAL interface assignment
    4: 'indirect'     # ← Learned route (BGP/OSPF/Static)
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def snmp_walk(target, community, oid):
    """Walk SNMP OID"""
    results = []
    try:
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((target, 161), timeout=5, retries=2),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication:
                break
            elif errorStatus:
                break
            else:
                for varBind in varBinds:
                    results.append(varBind)
        return results
    except Exception as e:
        return []

def get_route_types_from_router(device):
    """Get routing table types from router"""
    print(f"  Querying routing table from {device['hostname']}...")
    
    route_types = {}
    
    # Get route types
    type_results = snmp_walk(device['ip_address'], device['snmp_community'], IP_ROUTE_TYPE_OID)
    
    for entry in type_results:
        oid_str = str(entry[0])
        route_type_num = int(entry[1])
        
        # Extract IP from OID (last 4 octets)
        oid_parts = oid_str.split('.')
        if len(oid_parts) >= 4:
            ip = '.'.join(oid_parts[-4:])
            route_type = ROUTE_TYPES.get(route_type_num, 'unknown')
            route_types[ip] = route_type
    
    print(f"    Found {len(route_types)} routes ({sum(1 for t in route_types.values() if t == 'direct')} direct)")
    return route_types

def get_arp_from_router(device, route_types):
    """Get ARP table from router with route type context"""
    print(f"  Querying ARP table from {device['hostname']}...")
    
    arp_entries = []
    mac_results = snmp_walk(device['ip_address'], device['snmp_community'], ARP_TABLE_OID)
    
    if not mac_results:
        print(f"    No ARP entries found")
        return arp_entries
    
    for mac_entry in mac_results:
        oid_str = str(mac_entry[0])
        mac_hex = mac_entry[1]
        
        oid_parts = oid_str.split('.')
        if len(oid_parts) >= 4:
            try:
                ip = '.'.join(oid_parts[-4:])
                
                # Convert MAC
                if hasattr(mac_hex, 'prettyPrint'):
                    mac_str = mac_hex.prettyPrint()
                    if mac_str.startswith('0x'):
                        mac_bytes = mac_str[2:]
                        mac = ':'.join([mac_bytes[i:i+2] for i in range(0, len(mac_bytes), 2)]).lower()
                    else:
                        mac = ':'.join([f"{b:02x}" for b in mac_hex]).lower()
                else:
                    mac = ':'.join([f"{b:02x}" for b in mac_hex]).lower()
                
                if mac and mac != '00:00:00:00:00:00':
                    # Get route type for this IP
                    route_type = route_types.get(ip, 'unknown')
                    
                    arp_entries.append({
                        'ip': ip,
                        'mac': mac,
                        'source_device': device['hostname'],
                        'source_type': device['device_type'],
                        'route_type': route_type  # ← NEW: Route type!
                    })
            except Exception as e:
                continue
    
    print(f"    Found {len(arp_entries)} ARP entries")
    return arp_entries

def get_routers_from_db():
    """Get all active routers with SNMP"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("""
        SELECT id, hostname, ip_address, snmp_community, snmp_version, device_type
        FROM devices 
        WHERE is_active = true 
        AND snmp_community IS NOT NULL
        ORDER BY hostname
    """)
    
    routers = cur.fetchall()
    cur.close()
    conn.close()
    
    return routers

def parse_local_arp():
    """Parse local ARP table"""
    try:
        result = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=10)
        arp_entries = []
        
        for line in result.stdout.split('\n'):
            match = re.search(r'\(([0-9.]+)\)\s+at\s+([0-9a-f:]+)', line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                if mac not in ['(incomplete)', '<incomplete>']:
                    arp_entries.append({
                        'ip': ip,
                        'mac': mac,
                        'source_device': 'monitoring-server',
                        'source_type': 'local',
                        'route_type': 'direct'  # Local ARP = direct
                    })
        
        return arp_entries
    except Exception as e:
        return []

def analyze_conflict_with_route_intelligence(ip, entries):
    """
    🤖 ROUTE-AWARE CONFLICT ANALYSIS
    Key Rule: Only Local/Direct routes can conflict!
    """
    
    # Group by MAC
    unique_contexts = {}
    for entry in entries:
        mac = entry['mac']
        if mac not in unique_contexts:
            unique_contexts[mac] = []
        unique_contexts[mac].append(entry)
    
    if len(unique_contexts) == 1:
        return False, 0.0, "Single MAC - no conflict"
    
    macs = list(unique_contexts.keys())
    mac1, mac2 = macs[0], macs[1]
    contexts1 = unique_contexts[mac1]
    contexts2 = unique_contexts[mac2]
    
    # === PRIMARY RULE: Route Type Analysis ===
    
    # Get route types for both MACs
    route_types_1 = set(c.get('route_type', 'unknown') for c in contexts1)
    route_types_2 = set(c.get('route_type', 'unknown') for c in contexts2)
    
    # CRITICAL RULE: If either side has ONLY indirect/unknown routes = NOT A CONFLICT
    if 'direct' not in route_types_1 or 'direct' not in route_types_2:
        non_direct_side = 'both' if 'direct' not in route_types_1 and 'direct' not in route_types_2 else ('MAC1' if 'direct' not in route_types_1 else 'MAC2')
        return False, 0.0, f"Not a conflict - {non_direct_side} has indirect/BGP routes only"
    
    # If BOTH have 'direct' routes = POTENTIAL REAL CONFLICT
    # But still check other heuristics...
    
    # Virtual MAC patterns
    virtual_patterns = [
        'e6:5e:cc:', 'e4:5e:cc:',  # Logical tunnel
        '02:00:00:', '02:00:01:',  # Juniper internal
        'fe:54:00:',               # Virtual MAC
        '52:54:00:', '4a:5a:0d:', '48:5a:0d:',  # VM/Virtual
    ]
    
    def is_virtual_mac(mac):
        return any(mac.startswith(p) for p in virtual_patterns)
    
    if is_virtual_mac(mac1) and is_virtual_mac(mac2):
        return False, 0.2, "Both MACs virtual (likely inter-LS)"
    
    # Same source device check
    sources1 = set(c['source_device'] for c in contexts1)
    sources2 = set(c['source_device'] for c in contexts2)
    
    if sources1 == sources2 and len(sources1) == 1:
        source = list(sources1)[0]
        if source != 'monitoring-server':
            return False, 0.3, f"Same device ({source}) - inter-LS routing"
    
    # Private IP check
    private_prefixes = ['10.', '172.16.', '172.17.', '192.168.']
    if any(ip.startswith(p) for p in private_prefixes):
        return False, 0.1, "Private IP - infrastructure"
    
    # If we got here: BOTH have direct routes + different MACs = REAL CONFLICT!
    sources_info = f"{sources1} vs {sources2}"
    return True, 0.95, f"REAL CONFLICT: Both have direct routes on different devices ({sources_info})"

def detect_smart_conflicts(all_hosts):
    """Route-aware conflict detection"""
    conflicts = []
    ip_map = {}
    
    # Group by IP
    for host in all_hosts:
        ip = host['ip']
        if ip not in ip_map:
            ip_map[ip] = []
        ip_map[ip].append(host)
    
    # Analyze each IP
    for ip, entries in ip_map.items():
        # Get unique MACs
        unique_macs = {}
        for entry in entries:
            mac = entry['mac']
            if mac not in unique_macs:
                unique_macs[mac] = []
            unique_macs[mac].append(entry)
        
        # If more than one unique MAC = potential conflict
        if len(unique_macs) > 1:
            is_conflict, confidence, reason = analyze_conflict_with_route_intelligence(ip, entries)
            
            if is_conflict:
                macs = list(unique_macs.keys())
                sources = ', '.join(set(e['source_device'] for e in entries))
                route_info = ', '.join(set(f"{e['source_device']}:{e.get('route_type', 'unknown')}" for e in entries))
                
                conflicts.append({
                    'ip': ip,
                    'mac1': macs[0],
                    'mac2': macs[1] if len(macs) > 1 else 'multiple',
                    'sources': sources,
                    'route_info': route_info,
                    'type': 'duplicate_ip',
                    'severity': 'critical' if confidence > 0.8 else 'medium',
                    'confidence': confidence,
                    'reason': reason
                })
    
    return conflicts

def update_inventory(all_hosts):
    """Update IP inventory"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    updated_count = 0
    new_count = 0
    
    for host in all_hosts:
        ip = host['ip']
        mac = host.get('mac', 'unknown')
        
        if mac == 'unknown':
            continue
        
        cur.execute(
            "SELECT id FROM ip_inventory WHERE ip_address = %s AND mac_address = %s",
            (ip, mac)
        )
        existing = cur.fetchone()
        
        if existing:
            cur.execute(
                "UPDATE ip_inventory SET last_seen = CURRENT_TIMESTAMP, is_active = true WHERE id = %s",
                (existing['id'],)
            )
            updated_count += 1
        else:
            cur.execute(
                """INSERT INTO ip_inventory (ip_address, mac_address, is_active) 
                   VALUES (%s, %s, true)
                   ON CONFLICT (ip_address, mac_address) DO UPDATE 
                   SET last_seen = CURRENT_TIMESTAMP, is_active = true""",
                (ip, mac)
            )
            new_count += 1
    
    conn.commit()
    cur.close()
    conn.close()
    
    return updated_count, new_count

def log_conflicts(conflicts):
    """Log conflicts with route context"""
    if not conflicts:
        return 0
    
    conn = get_db()
    cur = conn.cursor()
    
    logged_count = 0
    
    for conflict in conflicts:
        cur.execute(
            """SELECT id FROM ip_conflicts 
               WHERE ip_address = %s AND is_resolved = false 
               AND detected_at > NOW() - INTERVAL '1 hour'""",
            (conflict['ip'],)
        )
        
        if not cur.fetchone():
            description = f"{conflict['reason']} (Confidence: {conflict['confidence']:.0%}) | Route Info: {conflict['route_info']}"
            
            cur.execute(
                """INSERT INTO ip_conflicts 
                   (ip_address, mac_address_1, mac_address_2, conflict_type, severity, description)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (conflict['ip'], conflict['mac1'], conflict['mac2'], 
                 conflict['type'], conflict['severity'], description)
            )
            logged_count += 1
    
    conn.commit()
    cur.close()
    conn.close()
    
    return logged_count

def mark_inactive_ips():
    """Mark old IPs as inactive"""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute(
        """UPDATE ip_inventory 
           SET is_active = false 
           WHERE last_seen < NOW() - INTERVAL '2 hours' AND is_active = true"""
    )
    
    inactive_count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    
    return inactive_count

def main():
    print("=" * 80)
    print("🤖 Route-Aware IP Conflict Detection (Direct/Local Routes Only)")
    print("=" * 80)
    
    all_hosts = []
    
    # Method 1: Local ARP
    print("\n📋 Method 1: Local ARP Table")
    local_arp = parse_local_arp()
    print(f"   Found {len(local_arp)} entries")
    all_hosts.extend(local_arp)
    
    # Method 2: SNMP from routers (with route type)
    print("\n📋 Method 2: SNMP Query to Routers (ARP + Routing Table)")
    routers = get_routers_from_db()
    print(f"   Found {len(routers)} devices with SNMP\n")
    
    for router in routers:
        # Get routing table first
        route_types = get_route_types_from_router(router)
        
        # Then get ARP with route context
        arp_entries = get_arp_from_router(router, route_types)
        all_hosts.extend(arp_entries)
    
    # Remove duplicates
    unique_hosts = []
    seen = set()
    for host in all_hosts:
        key = (host['ip'], host['mac'])
        if key not in seen:
            seen.add(key)
            unique_hosts.append(host)
    
    print(f"\n✅ Total unique IP-MAC pairs: {len(unique_hosts)}")
    
    # Count direct routes
    direct_count = sum(1 for h in unique_hosts if h.get('route_type') == 'direct')
    print(f"   Direct/Local routes: {direct_count}")
    print(f"   Indirect/BGP routes: {len(unique_hosts) - direct_count}")
    
    # Route-aware conflict detection
    print("\n🤖 Running Route-Aware Conflict Analysis...")
    conflicts = detect_smart_conflicts(all_hosts)
    
    if conflicts:
        print(f"\n   ⚠️  REAL CONFLICTS DETECTED: {len(conflicts)}")
        for c in conflicts:
            conf_emoji = "🔴" if c['confidence'] > 0.8 else "🟡"
            print(f"      {conf_emoji} {c['ip']}: {c['mac1']} vs {c['mac2']}")
            print(f"         Confidence: {c['confidence']:.0%} | {c['reason']}")
    else:
        print("   ✅ No real conflicts detected!")
    
    # Update inventory
    print("\n💾 Updating IP Inventory...")
    updated, new = update_inventory(unique_hosts)
    print(f"   Updated: {updated}, New: {new}")
    
    # Log conflicts
    if conflicts:
        logged = log_conflicts(conflicts)
        print(f"\n📝 Logged {logged} real conflicts")
    
    # Mark inactive
    inactive = mark_inactive_ips()
    print(f"   Marked {inactive} IPs as inactive")
    
    print("\n" + "=" * 80)
    print("✅ Route-Aware Analysis Complete!")
    print("=" * 80)

if __name__ == '__main__':
    main()
