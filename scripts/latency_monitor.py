#!/usr/bin/env python3
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import re
import time
import redis
from datetime import datetime
import statistics

# Database config
DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

# Redis config
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def ping_device(ip_address, count=5):
    """Ping device and return latency stats"""
    try:
        cmd = ['ping', '-c', str(count), '-W', '2', ip_address]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            # Parse ping output
            output = result.stdout
            
            # Extract packet loss
            loss_match = re.search(r'(\d+)% packet loss', output)
            packet_loss = float(loss_match.group(1)) if loss_match else 100.0
            
            # Extract RTT stats
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
    
    # Get last 20 measurements
    history = r.lrange(key, 0, 19)
    if len(history) < 10:
        # Need at least 10 measurements for reliable baseline
        r.lpush(key, f"{current_rtt}:{current_loss}")
        r.ltrim(key, 0, 49)
        return None
    
    # Parse history
    rtts = []
    losses = []
    for item in history:
        rtt, loss = item.split(':')
        rtts.append(float(rtt))
        losses.append(float(loss))
    
    # Calculate baseline
    avg_rtt = statistics.mean(rtts)
    std_rtt = statistics.stdev(rtts) if len(rtts) > 1 else 0
    avg_loss = statistics.mean(losses)
    
    # Store current measurement
    r.lpush(key, f"{current_rtt}:{current_loss}")
    r.ltrim(key, 0, 49)
    
    # Calculate jitter (variance from baseline)
    jitter = abs(current_rtt - avg_rtt)
    
    anomaly = None

    # RULE 1: CRITICAL - Total timeout (100% loss) - must be checked before general packet loss
    if current_loss >= 100:
        anomaly = {
            'type': 'timeout',
            'severity': 'critical',
            'description': f'Device unreachable: 100% packet loss'
        }

    # RULE 2: CRITICAL - Packet loss > 5%
    elif current_loss > 5.0:
        anomaly = {
            'type': 'packet_loss',
            'severity': 'critical',
            'description': f'Critical packet loss: {current_loss:.1f}% (threshold: 5%)'
        }

    # RULE 3: HIGH - Latency spike > 7x baseline
    elif avg_rtt > 0 and current_rtt > (avg_rtt * 7):
        anomaly = {
            'type': 'latency_spike',
            'severity': 'high',
            'description': f'Severe latency spike: {current_rtt:.2f}ms (7x baseline: {avg_rtt:.2f}ms)'
        }

    # RULE 4: MEDIUM - Jitter > 5x stddev (only if significant)
    elif std_rtt > 0 and jitter > (std_rtt * 5) and jitter > 10:
        anomaly = {
            'type': 'jitter',
            'severity': 'medium',
            'description': f'High jitter detected: {jitter:.2f}ms variance (baseline: {avg_rtt:.2f}ms ± {std_rtt:.2f}ms)'
        }

    return anomaly

def save_latency_result(device_id, ip, result):
    """Save latency result to database"""
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
    finally:
        cur.close()
        conn.close()

def save_anomaly(device_id, anomaly):
    """Save anomaly to database"""
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

def monitor_devices():
    """Main monitoring loop"""
    print(f"[{datetime.now()}] Starting latency monitor...")
    
    conn = get_db()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Get active devices
        cur.execute("SELECT id, hostname, ip_address FROM devices WHERE is_active = true")
        devices = cur.fetchall()
        
        print(f"[{datetime.now()}] Monitoring {len(devices)} devices...")
        
        for device in devices:
            print(f"  → Pinging {device['hostname']} ({device['ip_address']})...", end=' ')
            
            result = ping_device(device['ip_address'])
            
            if result['success']:
                print(f"✓ RTT: {result['rtt_avg']:.2f}ms, Loss: {result['packet_loss']:.1f}%")
                
                # Save result
                save_latency_result(device['id'], device['ip_address'], result)
                
                # Check for anomalies
                anomaly = detect_anomaly(device['id'], result['rtt_avg'], result['packet_loss'])
                
                if anomaly:
                    print(f"    ⚠️  ANOMALY: {anomaly['description']}")
                    save_anomaly(device['id'], anomaly)
            else:
                print(f"✗ FAILED: {result.get('error', 'unknown')}")
                save_latency_result(device['id'], device['ip_address'], {'packet_loss': 100.0})
                
                # Timeout anomaly
                anomaly = {
                    'type': 'timeout',
                    'severity': 'critical',
                    'description': f"Device unreachable: {result.get('error', 'timeout')}"
                }
                save_anomaly(device['id'], anomaly)
        
        print(f"[{datetime.now()}] Monitoring cycle completed.\n")
        
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    while True:
        try:
            monitor_devices()
            time.sleep(60)  # Run every 60 seconds
        except KeyboardInterrupt:
            print(f"\n[{datetime.now()}] Monitor stopped by user.")
            break
        except Exception as e:
            print(f"[{datetime.now()}] ERROR: {e}")
            time.sleep(60)
