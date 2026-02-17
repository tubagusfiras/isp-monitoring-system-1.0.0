#!/usr/bin/env python3
"""Server performance metrics collector"""
import psutil
import psycopg2
from datetime import datetime
import time
import socket

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)

def collect_metrics():
    """Collect system metrics"""
    
    # CPU
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # Memory
    mem = psutil.virtual_memory()
    mem_percent = mem.percent
    mem_used_gb = mem.used / (1024**3)
    mem_total_gb = mem.total / (1024**3)
    
    # Disk
    disk = psutil.disk_usage('/')
    disk_percent = disk.percent
    disk_used_gb = disk.used / (1024**3)
    disk_total_gb = disk.total / (1024**3)
    
    # Network
    net_io = psutil.net_io_counters()
    net_sent_mb = net_io.bytes_sent / (1024**2)
    net_recv_mb = net_io.bytes_recv / (1024**2)
    
    # System load
    load_1, load_5, load_15 = psutil.getloadavg()
    
    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    
    return {
        'cpu_percent': cpu_percent,
        'mem_percent': mem_percent,
        'mem_used_gb': mem_used_gb,
        'mem_total_gb': mem_total_gb,
        'disk_percent': disk_percent,
        'disk_used_gb': disk_used_gb,
        'disk_total_gb': disk_total_gb,
        'net_sent_mb': net_sent_mb,
        'net_recv_mb': net_recv_mb,
        'load_1': load_1,
        'load_5': load_5,
        'load_15': load_15,
        'uptime_seconds': uptime_seconds
    }

def save_metrics():
    """Save metrics to database"""
    conn = get_db()
    cur = conn.cursor()
    
    # Create table if not exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS server_metrics (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT NOW(),
            hostname VARCHAR(255),
            cpu_percent FLOAT,
            mem_percent FLOAT,
            mem_used_gb FLOAT,
            mem_total_gb FLOAT,
            disk_percent FLOAT,
            disk_used_gb FLOAT,
            disk_total_gb FLOAT,
            net_sent_mb FLOAT,
            net_recv_mb FLOAT,
            load_1 FLOAT,
            load_5 FLOAT,
            load_15 FLOAT,
            uptime_seconds BIGINT
        )
    """)
    
    metrics = collect_metrics()
    hostname = socket.gethostname()
    
    cur.execute("""
        INSERT INTO server_metrics 
        (hostname, cpu_percent, mem_percent, mem_used_gb, mem_total_gb,
         disk_percent, disk_used_gb, disk_total_gb, net_sent_mb, net_recv_mb,
         load_1, load_5, load_15, uptime_seconds)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        hostname,
        metrics['cpu_percent'],
        metrics['mem_percent'],
        metrics['mem_used_gb'],
        metrics['mem_total_gb'],
        metrics['disk_percent'],
        metrics['disk_used_gb'],
        metrics['disk_total_gb'],
        metrics['net_sent_mb'],
        metrics['net_recv_mb'],
        metrics['load_1'],
        metrics['load_5'],
        metrics['load_15'],
        metrics['uptime_seconds']
    ))
    
    conn.commit()
    cur.close()
    conn.close()
    
    print(f"✅ Metrics saved: CPU {metrics['cpu_percent']:.1f}%, MEM {metrics['mem_percent']:.1f}%, DISK {metrics['disk_percent']:.1f}%")

if __name__ == '__main__':
    try:
        save_metrics()
    except Exception as e:
        print(f"❌ Error: {e}")
        import sys
        sys.exit(1)
