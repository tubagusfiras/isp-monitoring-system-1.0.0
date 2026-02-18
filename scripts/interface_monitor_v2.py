#!/usr/bin/env python3
"""
SDI Interface Monitor v2.0 - Optimized Parallel Collection
- Multi-threaded (10 workers)
- SNMP timeout 5 seconds
- Accurate speed detection (LAG, multi-vendor)
- Progress indicator
"""

import sys
import time
import re
import psycopg2
import psycopg2.extras
from pysnmp.hlapi import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm

# Database config
DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

# SNMP OIDs
OIDS = {
    'ifDescr': '1.3.6.1.2.1.2.2.1.2',
    'ifAlias': '1.3.6.1.2.1.31.1.1.1.18',
    'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
    'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
    'ifHighSpeed': '1.3.6.1.2.1.31.1.1.1.15',  # 64-bit speed in Mbps
    'ifHCInOctets': '1.3.6.1.2.1.31.1.1.1.6',
    'ifHCOutOctets': '1.3.6.1.2.1.31.1.1.1.10',
    'ifInUcastPkts': '1.3.6.1.2.1.2.2.1.11',
    'ifOutUcastPkts': '1.3.6.1.2.1.2.2.1.17',
    'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
    'ifOutErrors': '1.3.6.1.2.1.2.2.1.20',
    'ifInDiscards': '1.3.6.1.2.1.2.2.1.13',
    'ifOutDiscards': '1.3.6.1.2.1.2.2.1.19',
    'ifDisplayString': '1.3.6.1.2.1.31.1.1.1.18'
}

STATUS_MAP = {'1': 'up', '2': 'down'}

# Interface filters per vendor
INTERFACE_FILTERS = {
    'juniper_mx': r'^(ge-[0-9/]+|xe-[0-9/]+|et-[0-9/]+|ae\d+(\.\d+)?)$',
    'juniper_qfx': r'^(ge-[0-9/]+|xe-[0-9/]+|et-[0-9/]+|ae\d+(\.\d+)?)$',
    'exos': r'^.+Port\s+\d+$',
    'huawei': r'^(GigabitEthernet|XGigabitEthernet|40GE|100GE|Eth-Trunk)[0-9/]+$',
    'mikrotik': r'^(ether|sfp|bridge|vlan|bond|vrrp)[0-9a-zA-Z_\-]*$',
    'zte_olt': r'^(gpon|epon|eth|ge|10ge|uplink|onu|olt)[0-9/_\-a-zA-Z]+$',
    'cisco': r'^(GigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet)[0-9/]+$',
    'default': r'^(eth[0-9]|ens[0-9]|eno[0-9]|enp[0-9]|ge-[0-9/]+|xe-[0-9/]+|et-[0-9/]+|ae\d+)$'
}

def get_interface_filter(device_type):
    # Match any juniper_* variant (juniper_ex, juniper_srx, etc.)
    if device_type and device_type.startswith('juniper_'):
        return INTERFACE_FILTERS.get(device_type, INTERFACE_FILTERS['juniper_mx'])
    return INTERFACE_FILTERS.get(device_type, INTERFACE_FILTERS['default'])

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def safe_int(val, default=0):
    try:
        if val is None:
            return default
        if isinstance(val, int):
            return val
        val_str = str(val)
        if val_str.lower() in ('', 'none', 'null'):
            return default
        return int(val_str)
    except (ValueError, TypeError):
        return default

def snmp_walk(ip, community, oid, timeout=5, use_next=False):
    """SNMP walk - bulkCmd for modern devices, nextCmd for legacy (EXOS)"""
    result = {}
    try:
        if use_next:
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=2),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
        else:
            iterator = bulkCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=2),
                ContextData(),
                0, 50,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value = var_bind[1]
                index = oid_str.split('.')[-1]
                result[index] = str(value) if value is not None else ''
        return result
    except Exception:
        return result
def snmp_get_multi(ip, community, base_oid, indices, timeout=5):
    """Targeted SNMP GET for specific indices - much faster than walking entire table.

    Instead of walking 600+ interfaces, only fetch the 5-10 we care about.
    Uses a single SNMP GET request with multiple OIDs (up to 20 per request).
    """
    result = {}
    if not indices:
        return result

    idx_list = list(indices)
    # Process in batches of 20 OIDs per request
    for batch_start in range(0, len(idx_list), 20):
        batch = idx_list[batch_start:batch_start + 20]
        oid_objects = [ObjectType(ObjectIdentity(f'{base_oid}.{idx}')) for idx in batch]

        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, 161), timeout=timeout, retries=2),
                    ContextData(),
                    *oid_objects
                )
            )

            if error_indication or error_status:
                continue

            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value = var_bind[1]
                index = oid_str.split('.')[-1]
                result[index] = str(value) if value is not None else ''
        except Exception:
            continue

    return result

def detect_accurate_speed(device_type, interface_name, if_index, speed_data, high_speed_data):
    """
    Accurate speed detection for LAG and multi-vendor devices
    Returns speed in bits/sec
    """
    # Try ifHighSpeed first (Mbps, more reliable)
    high_speed_mbps = safe_int(high_speed_data.get(if_index))
    if high_speed_mbps > 0:
        return high_speed_mbps * 1_000_000  # Convert to bps
    
    # Fallback to ifSpeed (bps, often wrong for high-speed)
    if_speed_bps = safe_int(speed_data.get(if_index))
    if if_speed_bps > 0 and if_speed_bps < 4_294_967_295:  # Max 32-bit
        return if_speed_bps
    
    # Parse from interface name (Juniper convention — works for MX, QFX, EX, etc.)
    if device_type in ('juniper_mx', 'juniper_qfx', 'juniper_ex', 'juniper'):
        if interface_name.startswith('et-'):
            return 100_000_000_000  # 100G
        elif interface_name.startswith('xe-'):
            return 10_000_000_000   # 10G
        elif interface_name.startswith('ge-'):
            return 1_000_000_000    # 1G
        elif interface_name.startswith('ae'):
            # LAG: ifHighSpeed should aggregate, but if 0, fall through to default
            if high_speed_mbps > 0:
                return high_speed_mbps * 1_000_000
            # Fallback: return ifSpeed even if maxed (better than 0 for display)
            return if_speed_bps if 0 < if_speed_bps < 4_294_967_295 else 0

    # Juniper-style naming on unknown device type (catch-all)
    if interface_name.startswith('et-'):
        return 100_000_000_000
    elif interface_name.startswith('xe-'):
        return 10_000_000_000
    elif interface_name.startswith('ge-'):
        return 1_000_000_000

    # EXOS - numeric interfaces, use ifHighSpeed
    if device_type == 'exos':
        return high_speed_mbps * 1_000_000 if high_speed_mbps > 0 else 0
    
    # Huawei naming
    elif device_type == 'huawei':
        if '100GE' in interface_name:
            return 100_000_000_000
        elif '40GE' in interface_name:
            return 40_000_000_000
        elif 'XGigabitEthernet' in interface_name or '10GE' in interface_name:
            return 10_000_000_000
        elif 'GigabitEthernet' in interface_name:
            return 1_000_000_000
    
    # Default: use whatever we got
    return if_speed_bps if if_speed_bps > 0 else 0

def collect_interface_stats(device):
    """Collect interface statistics for a single device"""
    ip = device['ip_address']
    community = device.get('snmp_community', 'public')
    device_id = device['id']
    device_type = device.get('device_type', 'unknown')
    hostname = device['hostname']
    
    try:
        # Step 1: Get interface descriptions
        snmp_timeout = 15 if device_type == 'exos' else 5
        use_next = device_type == 'exos'
        descriptions = snmp_walk(ip, community, OIDS['ifDescr'], timeout=snmp_timeout, use_next=use_next)
        if not descriptions:
            return {'success': False, 'hostname': hostname, 'error': 'SNMP timeout'}
        
        # Step 2: Filter interfaces (physical + ae subinterfaces, skip et/xe/ge subinterfaces)
        pattern = get_interface_filter(device_type)
        physical_if = {
            idx: name for idx, name in descriptions.items()
            if re.search(pattern, name) and '.32767' not in name
        }

        if not physical_if:
            return {'success': False, 'hostname': hostname, 'error': 'No physical interfaces'}

        # Step 3: Targeted SNMP GET — only fetch data for filtered indices
        # This is MUCH faster than walking entire tables (e.g. 5 indices vs 600+)
        target_indices = set(physical_if.keys())
        descriptions_alias = snmp_get_multi(ip, community, OIDS['ifAlias'], target_indices, timeout=snmp_timeout)
        display_strings = snmp_get_multi(ip, community, OIDS['ifDisplayString'], target_indices, timeout=snmp_timeout)
        admin_status = snmp_get_multi(ip, community, OIDS['ifAdminStatus'], target_indices, timeout=snmp_timeout)
        oper_status = snmp_get_multi(ip, community, OIDS['ifOperStatus'], target_indices, timeout=snmp_timeout)
        speed = snmp_get_multi(ip, community, OIDS['ifSpeed'], target_indices, timeout=snmp_timeout)
        high_speed = snmp_get_multi(ip, community, OIDS['ifHighSpeed'], target_indices, timeout=snmp_timeout)
        in_octets = snmp_get_multi(ip, community, OIDS['ifHCInOctets'], target_indices, timeout=snmp_timeout)
        out_octets = snmp_get_multi(ip, community, OIDS['ifHCOutOctets'], target_indices, timeout=snmp_timeout)
        in_packets = snmp_get_multi(ip, community, OIDS['ifInUcastPkts'], target_indices, timeout=snmp_timeout)
        out_packets = snmp_get_multi(ip, community, OIDS['ifOutUcastPkts'], target_indices, timeout=snmp_timeout)
        in_errors = snmp_get_multi(ip, community, OIDS['ifInErrors'], target_indices, timeout=snmp_timeout)
        out_errors = snmp_get_multi(ip, community, OIDS['ifOutErrors'], target_indices, timeout=snmp_timeout)
        in_discards = snmp_get_multi(ip, community, OIDS['ifInDiscards'], target_indices, timeout=snmp_timeout)
        out_discards = snmp_get_multi(ip, community, OIDS['ifOutDiscards'], target_indices, timeout=snmp_timeout)
        
        # Step 4: Build parent ae description map for inheritance
        # ae14.xxx subinterfaces often have empty ifAlias — inherit from parent ae14
        parent_ae_desc = {}
        for idx, if_name in physical_if.items():
            if re.match(r'^ae\d+$', if_name):  # Parent ae only (no dot)
                alias = descriptions_alias.get(idx, '')
                if alias:
                    parent_ae_desc[if_name] = alias

        # Step 5: Save to database
        conn = get_db()
        cur = conn.cursor()
        saved = 0

        for idx, if_name in physical_if.items():
            try:
                # Get accurate speed
                accurate_speed = detect_accurate_speed(
                    device_type, if_name, idx, speed, high_speed
                )

                # Get description — inherit from parent ae if subinterface has none
                desc = descriptions_alias.get(idx, '')
                if not desc and '.' in if_name:
                    parent_name = if_name.split('.')[0]  # ae14.1234 → ae14
                    desc = parent_ae_desc.get(parent_name, '')

                cur.execute("""
                    INSERT INTO interface_stats
                    (device_id, interface_name, interface_index, admin_status, oper_status,
                     speed, description, in_octets, out_octets, in_packets, out_packets,
                     in_errors, out_errors, in_discards, out_discards)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    device_id, if_name, int(idx),
                    STATUS_MAP.get(admin_status.get(idx, '2'), 'down'),
                    STATUS_MAP.get(oper_status.get(idx, '2'), 'down'),
                    accurate_speed,
                    desc,
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
            except Exception:
                pass
        
        conn.commit()
        cur.close()
        conn.close()
        
        return {'success': True, 'hostname': hostname, 'interfaces': saved}
        
    except Exception as e:
        return {'success': False, 'hostname': hostname, 'error': str(e)}

def main():
    """Main collection with parallel processing"""
    start_time = time.time()
    print(f"\n🚀 SDI Interface Monitor v2.0 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Get all active devices
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM devices WHERE is_active = true ORDER BY hostname")
    devices = cur.fetchall()
    cur.close()
    conn.close()
    
    if not devices:
        print("❌ No active devices found")
        return
    
    print(f"📊 Collecting from {len(devices)} devices (10 parallel workers)...\n")
    
    # Parallel collection with progress
    success_count = 0
    failed_count = 0
    total_interfaces = 0
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(collect_interface_stats, dict(dev)): dev for dev in devices}
        with tqdm(
            total=len(devices),
            desc='  Collecting',
            unit='dev',
            bar_format='  {l_bar}{bar:40}{r_bar}',
            dynamic_ncols=True
        ) as pbar:
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                if result['success']:
                    success_count += 1
                    total_interfaces += result['interfaces']
                    tqdm.write(f"  ✅ [{i}/{len(devices)}] {result['hostname']}: {result['interfaces']} ifaces")
                else:
                    failed_count += 1
                    tqdm.write(f"  ❌ [{i}/{len(devices)}] {result['hostname']}: {result.get('error','timeout')}")
                pbar.update(1)
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 80)
    print(f"📊 COLLECTION SUMMARY")
    print(f"✅ SUCCESS: {success_count} devices, {total_interfaces} interfaces")
    print(f"❌ FAILED: {failed_count} devices")
    print(f"⏱️  Time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print("=" * 80 + "\n")

if __name__ == '__main__':
    main()
