#!/usr/bin/env python3
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import re
import time
import redis
from datetime import datetime
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def ping_device(ip_address, count=5):
    """Ping device and return latency stats"""
    try:
        cmd = ['ping', '-c', str(count), '-W', '2', ip_address]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            output = result.stdout
            loss_match = re.search(r'(\d+)% packet loss', output)
            packet_loss = float(loss_match.group(1)) if loss_match else 100.0
            rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
            if rtt_match and packet_loss < 100:
                return {
                    'success': True,
                    'rtt_min': float(rtt_match.group(1)),
                    'rtt_avg': float(rtt_match.group(2)),
                    'rtt_max': float(rtt_match.group(3)),
                    'packet_loss': packet_loss
                }
        return {'success': False, 'packet_loss': 100.0, 'error': 'timeout'}
    except Exception as e:
        return {'success': False, 'packet_loss': 100.0, 'error': str(e)}

def detect_anomaly(device_id, current_rtt, current_loss):
    """Detect anomaly with realistic thresholds"""
    key = f"latency_history:{device_id}"
    history = r.lrange(key, 0, 19)
    if len(history) < 10:
        r.lpush(key, f"{current_rtt}:{current_loss}")
        r.ltrim(key, 0, 49)
        return None

    rtts = []
    losses = []
    for item in history:
        rtt, loss = item.split(':')
        rtts.append(float(rtt))
        losses.append(float(loss))

    avg_rtt = statistics.mean(rtts)
    std_rtt = statistics.stdev(rtts) if len(rtts) > 1 else 0
    avg_loss = statistics.mean(losses)

    r.lpush(key, f"{current_rtt}:{current_loss}")
    r.ltrim(key, 0, 49)

    jitter = abs(current_rtt - avg_rtt)
    anomaly = None

    if current_loss >= 100:
        anomaly = {'type': 'timeout', 'severity': 'critical',
                   'description': f'Device unreachable: 100% packet loss'}
    elif current_loss > 5.0:
        anomaly = {'type': 'packet_loss', 'severity': 'critical',
                   'description': f'Critical packet loss: {current_loss:.1f}% (threshold: 5%)'}
    elif avg_rtt > 0 and current_rtt > (avg_rtt * 7):
        anomaly = {'type': 'latency_spike', 'severity': 'high',
                   'description': f'Severe latency spike: {current_rtt:.2f}ms (7x baseline: {avg_rtt:.2f}ms)'}
    elif std_rtt > 0 and jitter > (std_rtt * 5) and jitter > 10:
        anomaly = {'type': 'jitter', 'severity': 'medium',
                   'description': f'High jitter: {jitter:.2f}ms variance (baseline: {avg_rtt:.2f}ms ± {std_rtt:.2f}ms)'}

    return anomaly

def save_latency_result(device_id, ip, result):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO latency_results (device_id, target_ip, rtt_avg, rtt_min, rtt_max, packet_loss)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (device_id, ip, result.get('rtt_avg'), result.get('rtt_min'),
             result.get('rtt_max'), result.get('packet_loss'))
        )
        conn.commit()
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ DB INSERT ERROR {ip}: {e}", flush=True)
    finally:
        cur.close()
        conn.close()

def save_anomaly(device_id, anomaly):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO anomalies (device_id, anomaly_type, severity, description)
               VALUES (%s, %s, %s, %s)""",
            (device_id, anomaly['type'], anomaly['severity'], anomaly['description'])
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

def process_device(device):
    """Process single device — ping + save + anomaly check"""
    result = ping_device(device['ip_address'])

    if result['success']:
        save_latency_result(device['id'], device['ip_address'], result)
        anomaly = detect_anomaly(device['id'], result['rtt_avg'], result['packet_loss'])
        if anomaly:
            save_anomaly(device['id'], anomaly)
        return {'hostname': device['hostname'], 'status': 'ok',
                'rtt': result['rtt_avg'], 'loss': result['packet_loss']}
    else:
        save_latency_result(device['id'], device['ip_address'], {'packet_loss': 100.0})
        save_anomaly(device['id'], {
            'type': 'timeout', 'severity': 'critical',
            'description': f"Device unreachable: {result.get('error', 'timeout')}"
        })
        return {'hostname': device['hostname'], 'status': 'failed',
                'error': result.get('error', 'timeout')}

def monitor_devices():
    """Main monitoring loop — parallel ping dengan 20 workers"""
    start = time.time()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting latency monitor cycle...")

    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT id, hostname, ip_address FROM devices WHERE is_active = true")
        devices = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    total = len(devices)
    success = 0
    failed = 0

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Pinging {total} devices (20 parallel workers)...")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(process_device, dict(dev)): dev for dev in devices}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result['status'] == 'ok':
                    success += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

    elapsed = time.time() - start
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Cycle done: ✅ {success} up, ❌ {failed} down | ⏱️ {elapsed:.1f}s\n")

if __name__ == '__main__':
    while True:
        try:
            monitor_devices()
            time.sleep(60)
        except KeyboardInterrupt:
            print(f"\n[{datetime.now()}] Monitor stopped.")
            break
        except Exception as e:
            print(f"[{datetime.now()}] ERROR: {e}")
            time.sleep(60)
