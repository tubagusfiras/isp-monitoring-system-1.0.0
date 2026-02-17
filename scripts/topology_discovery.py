#!/usr/bin/env python3
"""
SDI Topology Discovery - LLDP/CDP neighbor discovery with DB persistence
Scans all active devices via SNMP, discovers neighbors, saves to connections table.
"""
import sys
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, nextCmd
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

# LLDP MIB OIDs
LLDP_REM_CHASSIS_ID = '1.0.8802.1.1.2.1.4.1.1.5'
LLDP_REM_PORT_ID    = '1.0.8802.1.1.2.1.4.1.1.7'
LLDP_REM_SYSNAME    = '1.0.8802.1.1.2.1.4.1.1.9'

# CDP MIB OIDs (for Cisco devices)
CDP_CACHE_DEVICE_ID   = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'   # cdpCacheDeviceId
CDP_CACHE_DEVICE_PORT = '1.3.6.1.4.1.9.9.23.1.2.1.1.7'   # cdpCacheDevicePort
CDP_CACHE_PLATFORM    = '1.3.6.1.4.1.9.9.23.1.2.1.1.8'   # cdpCachePlatform

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def snmp_walk(target, community, oid):
    """Walk SNMP OID and return results"""
    results = []
    try:
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((target, 161), timeout=5, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        ):
            if errorIndication or errorStatus:
                break
            for varBind in varBinds:
                results.append(varBind)
    except Exception:
        pass
    return results

def discover_neighbors(device):
    """Discover LLDP and CDP neighbors for a device"""
    neighbors = []
    ip = device['ip_address']
    community = device['snmp_community']
    hostname = device['hostname']
    device_id = device['id']

    # Try LLDP first
    sysnames = snmp_walk(ip, community, LLDP_REM_SYSNAME)
    port_ids = snmp_walk(ip, community, LLDP_REM_PORT_ID)

    # Build port_id lookup by OID suffix
    port_map = {}
    for p in port_ids:
        port_map[str(p[0]).split('.')[-3:]] = str(p[1])

    for sysname in sysnames:
        oid = str(sysname[0])
        neighbor_name = str(sysname[1]).strip()
        if not neighbor_name:
            continue

        oid_parts = oid.split('.')
        local_port_index = oid_parts[-2] if len(oid_parts) >= 3 else 'unknown'

        # Try to get remote port ID from matching OID
        remote_port = port_map.get(oid_parts[-3:], f"index-{oid_parts[-1]}" if len(oid_parts) >= 3 else 'unknown')

        neighbors.append({
            'local_device_id': device_id,
            'local_device': hostname,
            'remote_device': neighbor_name,
            'local_port': f"index-{local_port_index}",
            'remote_port': remote_port,
            'protocol': 'lldp'
        })

    # Try CDP (primarily Cisco)
    if not neighbors:
        cdp_devices = snmp_walk(ip, community, CDP_CACHE_DEVICE_ID)
        cdp_ports = snmp_walk(ip, community, CDP_CACHE_DEVICE_PORT)

        cdp_port_map = {}
        for p in cdp_ports:
            oid_suffix = '.'.join(str(p[0]).split('.')[-2:])
            cdp_port_map[oid_suffix] = str(p[1])

        for cdp_dev in cdp_devices:
            oid = str(cdp_dev[0])
            neighbor_name = str(cdp_dev[1]).strip()
            if not neighbor_name:
                continue

            oid_parts = oid.split('.')
            oid_suffix = '.'.join(oid_parts[-2:])
            local_if_index = oid_parts[-2] if len(oid_parts) >= 2 else 'unknown'
            remote_port = cdp_port_map.get(oid_suffix, 'unknown')

            neighbors.append({
                'local_device_id': device_id,
                'local_device': hostname,
                'remote_device': neighbor_name,
                'local_port': f"ifIndex-{local_if_index}",
                'remote_port': remote_port,
                'protocol': 'cdp'
            })

    status = f"  {hostname}: {len(neighbors)} neighbors" if neighbors else f"  {hostname}: no neighbors"
    print(status)
    return neighbors

def save_to_database(all_neighbors):
    """Match neighbor hostnames to device IDs and upsert into connections table"""
    if not all_neighbors:
        print("No neighbors to save.")
        return 0

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Build hostname → device_id lookup
    cur.execute("SELECT id, hostname FROM devices WHERE is_active = true")
    hostname_map = {}
    for row in cur.fetchall():
        hostname_map[row['hostname'].lower()] = row['id']
        # Also map without domain suffix (e.g., "switch1.example.com" → "switch1")
        short = row['hostname'].split('.')[0].lower()
        if short not in hostname_map:
            hostname_map[short] = row['id']

    saved = 0
    for n in all_neighbors:
        # Resolve remote device to ID
        remote_name = n['remote_device'].lower()
        remote_id = hostname_map.get(remote_name)
        if not remote_id:
            # Try short name
            remote_id = hostname_map.get(remote_name.split('.')[0])
        if not remote_id:
            continue  # Unknown device, skip

        local_id = n['local_device_id']

        # Normalize: always store lower ID as device_a
        if local_id > remote_id:
            local_id, remote_id = remote_id, local_id
            n['local_port'], n['remote_port'] = n['remote_port'], n['local_port']

        # Check if connection already exists
        cur.execute("""
            SELECT id FROM connections
            WHERE device_a_id = %s AND device_b_id = %s
        """, (local_id, remote_id))

        existing = cur.fetchone()
        conn_type = f"{n['protocol']}-discovered"

        if existing:
            # Update existing
            cur.execute("""
                UPDATE connections SET
                    interface_a = COALESCE(interface_a, %s),
                    interface_b = COALESCE(interface_b, %s),
                    connection_type = %s,
                    is_active = true,
                    updated_at = NOW()
                WHERE id = %s
            """, (n['local_port'], n['remote_port'], conn_type, existing['id']))
        else:
            # Insert new
            cur.execute("""
                INSERT INTO connections (device_a_id, device_b_id, interface_a, interface_b, connection_type, is_active)
                VALUES (%s, %s, %s, %s, %s, true)
            """, (local_id, remote_id, n['local_port'], n['remote_port'], conn_type))
        saved += 1

    conn.commit()
    cur.close()
    conn.close()
    return saved

def main():
    print("=" * 60)
    print("ISP Network Topology Discovery (LLDP + CDP)")
    print("=" * 60)

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, hostname, ip_address, snmp_community FROM devices WHERE is_active = true")
    devices = cur.fetchall()
    cur.close()
    conn.close()

    print(f"Scanning {len(devices)} active devices (10 parallel workers)...")

    all_neighbors = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(discover_neighbors, dev): dev for dev in devices}
        for future in as_completed(futures):
            try:
                result = future.result()
                all_neighbors.extend(result)
            except Exception as e:
                dev = futures[future]
                print(f"  {dev['hostname']}: error - {e}")

    print(f"\nDiscovery complete: {len(all_neighbors)} neighbor relationships found")

    # Save to database
    saved = save_to_database(all_neighbors)
    print(f"Saved {saved} connections to database")

    # Also save JSON for reference
    if all_neighbors:
        try:
            output_file = '/opt/isp-monitoring/data/topology.json'
            with open(output_file, 'w') as f:
                json.dump(all_neighbors, f, indent=2, default=str)
            print(f"JSON backup: {output_file}")
        except Exception:
            pass

    if not all_neighbors:
        print("\nNo neighbors discovered. Possible causes:")
        print("  - LLDP/CDP not enabled on devices")
        print("  - SNMP community strings incorrect")
        print("  - Firewall blocking SNMP")

    return len(all_neighbors)

if __name__ == '__main__':
    main()
