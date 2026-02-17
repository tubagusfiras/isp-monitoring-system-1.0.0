#!/usr/bin/env python3
"""Auto-delete devices inactive > 7 days"""
import psycopg2
from datetime import datetime

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

def cleanup_inactive_devices():
    """Delete devices with 100% packet loss for 7+ days"""
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Find devices with no successful ping in 7 days
    query = """
    SELECT d.id, d.hostname, d.ip_address, MAX(lr.timestamp) as last_seen
    FROM devices d
    LEFT JOIN latency_results lr ON d.id = lr.device_id AND lr.packet_loss < 100
    GROUP BY d.id, d.hostname, d.ip_address
    HAVING MAX(lr.timestamp) < NOW() - INTERVAL '7 days' OR MAX(lr.timestamp) IS NULL
    """
    
    cur.execute(query)
    inactive = cur.fetchall()
    
    if not inactive:
        print("No inactive devices to clean up")
        cur.close()
        conn.close()
        return
    
    print(f"Found {len(inactive)} inactive devices (7+ days timeout):")
    for device_id, hostname, ip, last_seen in inactive:
        last_str = last_seen.strftime('%Y-%m-%d %H:%M') if last_seen else 'Never'
        print(f"  - #{device_id}: {hostname} ({ip}) - Last seen: {last_str}")
    
    # Delete using cascade function
    for device_id, hostname, ip, last_seen in inactive:
        cur.execute("SELECT delete_device_cascade(%s)", (device_id,))
        print(f"    ✅ Deleted device #{device_id}")
    
    conn.commit()
    print(f"\n✅ Total deleted: {len(inactive)} devices")
    
    cur.close()
    conn.close()

if __name__ == '__main__':
    try:
        cleanup_inactive_devices()
    except Exception as e:
        print(f"❌ Error: {e}")
        import sys
        sys.exit(1)
