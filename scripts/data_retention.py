#!/usr/bin/env python3
"""
SDI Data Retention - Keep raw data 30 days, aggregate older into hourly summaries
Run daily via systemd timer
"""

import psycopg2
from datetime import datetime

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

def run_retention():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    now = datetime.now()
    print(f"[{now}] Starting data retention cleanup...")

    # 1. Create hourly aggregation table if not exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS interface_stats_hourly (
            id SERIAL PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id),
            interface_name VARCHAR(100) NOT NULL,
            hour_timestamp TIMESTAMP NOT NULL,
            avg_in_octets BIGINT,
            avg_out_octets BIGINT,
            max_in_octets BIGINT,
            max_out_octets BIGINT,
            avg_speed BIGINT,
            sample_count INTEGER,
            UNIQUE(device_id, interface_name, hour_timestamp)
        );
        CREATE INDEX IF NOT EXISTS idx_hourly_device_ts
            ON interface_stats_hourly(device_id, hour_timestamp);
    """)
    conn.commit()

    # 2. Aggregate data older than 30 days into hourly buckets
    cur.execute("""
        INSERT INTO interface_stats_hourly
            (device_id, interface_name, hour_timestamp, avg_in_octets, avg_out_octets,
             max_in_octets, max_out_octets, avg_speed, sample_count)
        SELECT
            device_id, interface_name,
            date_trunc('hour', timestamp) as hour_ts,
            AVG(in_octets)::BIGINT,
            AVG(out_octets)::BIGINT,
            MAX(in_octets),
            MAX(out_octets),
            AVG(speed)::BIGINT,
            COUNT(*)
        FROM interface_stats
        WHERE timestamp < NOW() - INTERVAL '30 days'
        GROUP BY device_id, interface_name, date_trunc('hour', timestamp)
        ON CONFLICT (device_id, interface_name, hour_timestamp) DO NOTHING;
    """)
    aggregated = cur.rowcount
    conn.commit()

    # 3. Delete raw data older than 30 days (already aggregated)
    cur.execute("DELETE FROM interface_stats WHERE timestamp < NOW() - INTERVAL '30 days';")
    deleted_interface = cur.rowcount
    conn.commit()

    # 4. Delete old latency data (keep 30 days)
    cur.execute("DELETE FROM latency_results WHERE timestamp < NOW() - INTERVAL '30 days';")
    deleted_latency = cur.rowcount
    conn.commit()

    # 5. Delete old anomalies (keep 90 days)
    cur.execute("DELETE FROM anomalies WHERE detected_at < NOW() - INTERVAL '90 days';")
    deleted_anomalies = cur.rowcount
    conn.commit()

    # 6. VACUUM to reclaim space
    conn.autocommit = True
    cur.execute("VACUUM ANALYZE interface_stats;")
    cur.execute("VACUUM ANALYZE latency_results;")
    cur.execute("VACUUM ANALYZE anomalies;")

    cur.close()
    conn.close()

    print(f"  Aggregated: {aggregated} hourly records")
    print(f"  Deleted: {deleted_interface} interface_stats, {deleted_latency} latency, {deleted_anomalies} anomalies")
    print(f"  VACUUM complete. Done!")

if __name__ == '__main__':
    run_retention()
