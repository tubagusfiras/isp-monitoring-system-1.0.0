#!/usr/bin/env python3
"""
SDI Monitoring System - Automated Auditor
Tests API endpoints, DB health, SNMP reachability, and UI consistency
"""
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import json
from datetime import datetime

BASE_URL = "http://localhost:5000"
DB_CONFIG = {'host':'localhost','database':'isp_monitoring','user':'super','password':'temp123'}

results = []
session = requests.Session()

def check(name, passed, detail=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append({'name': name, 'passed': passed, 'detail': detail})
    print(f"  {status} | {name}" + (f" — {detail}" if detail else ""))

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ── 1. API Health ──────────────────────────────────────────
section("1. API HEALTH CHECK")
try:
    r = session.post(f"{BASE_URL}/api/auth/login", json={"username":"admin","password":"admin123"})
    check("Login endpoint", r.status_code == 200, f"status={r.status_code}")
except Exception as e:
    check("Login endpoint", False, str(e))

endpoints = [
    ("/api/devices/status", "Devices status"),
    ("/api/anomalies", "Anomalies"),
    ("/api/ip-conflicts", "IP Conflicts"),
    ("/api/collection/status", "Collection status"),
    ("/api/collection/errors", "Collection errors"),
    ("/api/server-metrics/latest", "Server metrics"),
    ("/api/sites/summary", "Site summary"),
    ("/api/auth/me", "Auth me"),
]
for path, name in endpoints:
    try:
        r = session.get(f"{BASE_URL}{path}")
        d = r.json()
        check(name, r.status_code == 200 and d.get('success'), f"status={r.status_code}")
    except Exception as e:
        check(name, False, str(e))

# ── 2. Database Health ─────────────────────────────────────
section("2. DATABASE HEALTH")
try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT COUNT(*) as c FROM devices WHERE is_active=true")
    count = cur.fetchone()['c']
    check("Active devices", count > 0, f"{count} devices")
    
    cur.execute("SELECT COUNT(*) as c FROM latency_results WHERE timestamp > NOW() - INTERVAL '10 minutes'")
    count = cur.fetchone()['c']
    check("Recent latency data (<10min)", count > 0, f"{count} records")
    
    cur.execute("SELECT COUNT(*) as c FROM interface_stats WHERE timestamp > NOW() - INTERVAL '3 hours'")
    count = cur.fetchone()['c']
    check("Recent interface data (<3h)", count > 0, f"{count} records")
    
    cur.execute("SELECT COUNT(*) as c FROM anomalies WHERE resolved_at IS NULL")
    count = cur.fetchone()['c']
    check("Anomalies table accessible", True, f"{count} active anomalies")
    
    cur.execute("SELECT COUNT(*) as c FROM ip_inventory WHERE is_active=true")
    count = cur.fetchone()['c']
    check("IP inventory populated", count > 0, f"{count} IPs")
    
    cur.execute("SELECT COUNT(*) as c FROM ip_inventory WHERE subnet IS NOT NULL")
    count = cur.fetchone()['c']
    check("IP inventory has subnet data", count > 0, f"{count} with subnet")

    cur.close()
    conn.close()
except Exception as e:
    check("Database connection", False, str(e))

# ── 3. Systemd Services ────────────────────────────────────
section("3. SYSTEMD SERVICES")
services = [
    ("sdi-api", "API Server"),
    ("sdi-latency", "Latency Monitor"),
    ("sdi-interface-collect.timer", "Interface Collection Timer"),
    ("sdi-ip-scanner.timer", "IP Scanner Timer"),
    ("sdi-retention.timer", "Data Retention Timer"),
    ("sdi-server-metrics.timer", "Server Metrics Timer"),
]
for svc, name in services:
    try:
        r = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True)
        active = r.stdout.strip() == 'active'
        check(name, active, r.stdout.strip())
    except Exception as e:
        check(name, False, str(e))

# ── 4. SNMP Reachability ───────────────────────────────────
section("4. SNMP REACHABILITY (Failed Devices)")
try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT ce.hostname, COALESCE(d.ip_address::text, ce.ip_address, '?') as ip_address, ce.error_message
        FROM collection_errors ce
        LEFT JOIN devices d ON d.hostname = ce.hostname
        WHERE ce.job_id = (SELECT MAX(id) FROM collection_jobs)
    """)
    failed = cur.fetchall()
    cur.close()
    conn.close()
    
    if not failed:
        check("No failed devices in last collection", True)
    else:
        for dev in failed:
            ip = dev['ip_address']
            err = dev['error_message']
            ping = subprocess.run(['ping','-c1','-W2',ip], capture_output=True)
            reachable = ping.returncode == 0
            check(f"{dev['hostname']} ({ip})", reachable, f"ping={'ok' if reachable else 'fail'}, snmp={err}")
except Exception as e:
    check("SNMP check", False, str(e))

# ── 5. Data Freshness ──────────────────────────────────────
section("5. DATA FRESHNESS")
try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute("SELECT EXTRACT(EPOCH FROM (NOW() - MAX(timestamp)))::int as age FROM latency_results")
    age = cur.fetchone()['age'] or 99999
    check("Latency data fresh (<5min)", age < 300, f"{age}s ago")
    
    cur.execute("SELECT EXTRACT(EPOCH FROM (NOW() - MAX(timestamp)))::int as age FROM interface_stats")
    age = cur.fetchone()['age'] or 99999
    check("Interface data fresh (<3h)", age < 10800, f"{age//60}min ago")
    
    cur.execute("SELECT EXTRACT(EPOCH FROM (NOW() - MAX(timestamp)))::int as age FROM server_metrics")
    age = cur.fetchone()['age'] or 99999
    check("Server metrics fresh (<2min)", age < 120, f"{age}s ago")
    
    cur.close()
    conn.close()
except Exception as e:
    check("Data freshness", False, str(e))

# ── Summary ────────────────────────────────────────────────
section("AUDIT SUMMARY")
total = len(results)
passed = sum(1 for r in results if r['passed'])
failed = total - passed
print(f"\n  Total checks : {total}")
print(f"  ✅ Passed    : {passed}")
print(f"  ❌ Failed    : {failed}")
print(f"  Score        : {passed/total*100:.1f}%")

if failed > 0:
    print(f"\n  Issues to fix:")
    for r in results:
        if not r['passed']:
            print(f"  → {r['name']}: {r['detail']}")

print(f"\n  Audit completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*60)
