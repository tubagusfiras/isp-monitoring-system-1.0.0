#!/usr/bin/env python3
"""
SDI Content Latency Monitor
Continuous ping to external targets (DNS, CDN, websites)
SmokePing-style monitoring for content provider latency
"""
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def ping_target(host, count=5):
    """Ping a target host and return latency stats"""
    try:
        cmd = ['ping', '-c', str(count), '-W', '2', host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            output = result.stdout

            loss_match = re.search(r'(\d+)% packet loss', output)
            packet_loss = float(loss_match.group(1)) if loss_match else 100.0

            rtt_match = re.search(
                r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
                output
            )

            if rtt_match and packet_loss < 100:
                return {
                    'success': True,
                    'rtt_min': float(rtt_match.group(1)),
                    'rtt_avg': float(rtt_match.group(2)),
                    'rtt_max': float(rtt_match.group(3)),
                    'packet_loss': packet_loss
                }

        return {'success': False, 'packet_loss': 100.0}

    except Exception as e:
        return {'success': False, 'packet_loss': 100.0, 'error': str(e)}

def ping_and_save(target):
    """Ping a single target and save results to DB"""
    target_id = target['id']
    host = target['target_host']
    name = target['target_name']

    print(f"  -> Pinging {name} ({host})...", end=' ', flush=True)
    result = ping_target(host)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO content_latency_results
               (target_id, rtt_avg, rtt_min, rtt_max, packet_loss)
               VALUES (%s, %s, %s, %s, %s)""",
            (target_id,
             result.get('rtt_avg'),
             result.get('rtt_min'),
             result.get('rtt_max'),
             result.get('packet_loss', 100.0))
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"DB error: {e}")
        return

    if result['success']:
        print(f"OK  RTT: {result['rtt_avg']:.2f}ms  Loss: {result['packet_loss']:.0f}%")
    else:
        print(f"FAIL  Loss: 100%")

def monitor_cycle():
    """Run one monitoring cycle for all active targets"""
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, target_name, target_host FROM content_targets WHERE is_active = true")
    targets = cur.fetchall()
    cur.close()
    conn.close()

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Monitoring {len(targets)} content targets...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(ping_and_save, t): t for t in targets}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                t = futures[f]
                print(f"  !! Error for {t['target_name']}: {e}")

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Cycle complete.\n")

if __name__ == '__main__':
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Content Latency Monitor starting...")
    while True:
        try:
            monitor_cycle()
            time.sleep(60)
        except KeyboardInterrupt:
            print(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] Stopped by user.")
            break
        except Exception as e:
            print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] ERROR: {e}")
            time.sleep(60)
