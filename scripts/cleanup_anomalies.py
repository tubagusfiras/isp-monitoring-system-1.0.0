#!/usr/bin/env python3
"""Auto-cleanup resolved anomalies"""
import psycopg2
import sys

def get_db():
    return psycopg2.connect(
        host='localhost',
        database='isp_monitoring',
        user='super',
        password='temp123'
    )

def cleanup_resolved_anomalies():
    """Delete anomalies for devices that are now healthy"""
    conn = get_db()
    cur = conn.cursor()
    
    # Find anomalies where device is now healthy
    query = """
    DELETE FROM anomalies 
    WHERE device_id IN (
        SELECT DISTINCT d.id 
        FROM devices d
        JOIN latency_results lr ON d.id = lr.device_id
        WHERE lr.timestamp > NOW() - INTERVAL '10 minutes'
        AND lr.packet_loss < 5
        AND lr.rtt_avg < 100
    )
    AND detected_at < NOW() - INTERVAL '5 minutes'
    RETURNING id, device_id;
    """
    
    cur.execute(query)
    deleted = cur.fetchall()
    conn.commit()
    
    if deleted:
        print(f"✅ Cleaned up {len(deleted)} resolved anomalies")
        for anomaly_id, device_id in deleted:
            print(f"   - Anomaly #{anomaly_id} for device #{device_id}")
    else:
        print("No anomalies to clean up")
    
    cur.close()
    conn.close()

if __name__ == '__main__':
    try:
        cleanup_resolved_anomalies()
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
