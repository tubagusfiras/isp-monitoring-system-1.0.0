#!/usr/bin/env python3
"""
SDI Data Retention - Professional monitoring-grade retention policy
Retention:
  - interface_stats (raw)       : 90 days  → aggregate to hourly
  - interface_stats_hourly      : 1 year
  - latency_results             : 90 days
  - content_latency_results     : 90 days
  - server_metrics              : 90 days
  - anomalies                   : 180 days
  - realtime_cache              : 1 day
  - collection_jobs             : 7 days
Run daily via systemd timer at 03:00
"""
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import time

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

BATCH_SIZE = 5000  # rows per delete batch to avoid long table locks

def get_table_size(cur, table):
    cur.execute("SELECT pg_size_pretty(pg_total_relation_size(%s)), pg_total_relation_size(%s)", (table, table))
    row = cur.fetchone()
    return row[0], row[1]

def batch_delete(conn, cur, table, condition, label):
    """Delete in batches to avoid long locks"""
    total = 0
    while True:
        cur.execute(f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {condition} LIMIT {BATCH_SIZE})")
        deleted = cur.rowcount
        conn.commit()
        total += deleted
        if deleted < BATCH_SIZE:
            break
        time.sleep(0.1)  # brief pause between batches, be kind to I/O
    print(f"    [{label}] deleted {total} rows")
    return total

def run_retention():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    now = datetime.now()
    start_time = time.time()

    print(f"{'='*60}")
    print(f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] SDI Data Retention Starting...")
    print(f"{'='*60}")

    # ── 0. Ensure tables/indexes exist ──────────────────────────
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

    # ── 1. interface_stats → aggregate >90d to hourly ───────────
    print(f"\n[1/7] interface_stats (raw, keep 90 days)")
    size_before, _ = get_table_size(cur, 'interface_stats')
    t0 = time.time()

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
        WHERE timestamp < NOW() - INTERVAL '90 days'
        GROUP BY device_id, interface_name, date_trunc('hour', timestamp)
        ON CONFLICT (device_id, interface_name, hour_timestamp) DO NOTHING;
    """)
    aggregated = cur.rowcount
    conn.commit()
    print(f"    Aggregated: {aggregated} hourly records")

    deleted_iface = batch_delete(conn, cur, 'interface_stats',
        "timestamp < NOW() - INTERVAL '90 days'", 'interface_stats')
    size_after, _ = get_table_size(cur, 'interface_stats')
    print(f"    Size: {size_before} → {size_after} ({time.time()-t0:.1f}s)")

    # ── 2. interface_stats_hourly → keep 1 year ─────────────────
    print(f"\n[2/7] interface_stats_hourly (keep 1 year)")
    size_before, _ = get_table_size(cur, 'interface_stats_hourly')
    t0 = time.time()
    deleted_hourly = batch_delete(conn, cur, 'interface_stats_hourly',
        "hour_timestamp < NOW() - INTERVAL '1 year'", 'interface_stats_hourly')
    size_after, _ = get_table_size(cur, 'interface_stats_hourly')
    print(f"    Size: {size_before} → {size_after} ({time.time()-t0:.1f}s)")

    # ── 3. latency_results → keep 90 days ───────────────────────
    print(f"\n[3/7] latency_results (keep 90 days)")
    size_before, _ = get_table_size(cur, 'latency_results')
    t0 = time.time()
    deleted_latency = batch_delete(conn, cur, 'latency_results',
        "timestamp < NOW() - INTERVAL '90 days'", 'latency_results')
    size_after, _ = get_table_size(cur, 'latency_results')
    print(f"    Size: {size_before} → {size_after} ({time.time()-t0:.1f}s)")

    # ── 4. content_latency_results → keep 90 days ───────────────
    print(f"\n[4/7] content_latency_results (keep 90 days)")
    size_before, _ = get_table_size(cur, 'content_latency_results')
    t0 = time.time()
    cur.execute("DELETE FROM content_latency_results WHERE timestamp < NOW() - INTERVAL '90 days'")
    deleted_content = cur.rowcount
    conn.commit()
    size_after, _ = get_table_size(cur, 'content_latency_results')
    print(f"    Deleted: {deleted_content} rows | Size: {size_before} → {size_after} ({time.time()-t0:.1f}s)")

    # ── 5. server_metrics → keep 90 days ────────────────────────
    print(f"\n[5/7] server_metrics (keep 90 days)")
    size_before, _ = get_table_size(cur, 'server_metrics')
    t0 = time.time()
    cur.execute("DELETE FROM server_metrics WHERE timestamp < NOW() - INTERVAL '90 days'")
    deleted_server = cur.rowcount
    conn.commit()
    size_after, _ = get_table_size(cur, 'server_metrics')
    print(f"    Deleted: {deleted_server} rows | Size: {size_before} → {size_after} ({time.time()-t0:.1f}s)")

    # ── 6. anomalies → keep 180 days ────────────────────────────
    print(f"\n[6/7] anomalies (keep 180 days)")
    size_before, _ = get_table_size(cur, 'anomalies')
    t0 = time.time()
    cur.execute("DELETE FROM anomalies WHERE detected_at < NOW() - INTERVAL '180 days'")
    deleted_anomalies = cur.rowcount
    conn.commit()
    size_after, _ = get_table_size(cur, 'anomalies')
    print(f"    Deleted: {deleted_anomalies} rows | Size: {size_before} → {size_after} ({time.time()-t0:.1f}s)")

    # ── 7. realtime_cache → keep 1 day ──────────────────────────
    print(f"\n[7/7] realtime_cache & collection_jobs cleanup")
    cur.execute("DELETE FROM realtime_cache WHERE poll_timestamp < EXTRACT(EPOCH FROM NOW() - INTERVAL '1 day')")
    deleted_cache = cur.rowcount
    conn.commit()
    cur.execute("DELETE FROM collection_jobs WHERE started_at < NOW() - INTERVAL '7 days'")
    deleted_jobs = cur.rowcount
    conn.commit()
    print(f"    realtime_cache: {deleted_cache} rows | collection_jobs: {deleted_jobs} rows")

    # ── VACUUM ANALYZE ───────────────────────────────────────────
    print(f"\n[VACUUM] Running VACUUM ANALYZE on all affected tables...")
    conn.autocommit = True
    tables_to_vacuum = [
        'interface_stats', 'interface_stats_hourly',
        'latency_results', 'content_latency_results',
        'server_metrics', 'anomalies', 'realtime_cache', 'collection_jobs'
    ]
    for tbl in tables_to_vacuum:
        t0 = time.time()
        cur.execute(f"VACUUM ANALYZE {tbl};")
        print(f"    VACUUM {tbl} ({time.time()-t0:.1f}s)")

    cur.close()
    conn.close()

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[DONE] Total duration: {elapsed:.1f}s")
    print(f"  interface_stats deleted : {deleted_iface} rows ({aggregated} aggregated to hourly)")
    print(f"  interface_stats_hourly  : {deleted_hourly} rows (>1yr)")
    print(f"  latency_results deleted : {deleted_latency} rows")
    print(f"  content_latency deleted : {deleted_content} rows")
    print(f"  server_metrics deleted  : {deleted_server} rows")
    print(f"  anomalies deleted       : {deleted_anomalies} rows")
    print(f"  realtime_cache deleted  : {deleted_cache} rows")
    print(f"  collection_jobs deleted : {deleted_jobs} rows")
    print(f"{'='*60}")

if __name__ == '__main__':
    run_retention()
