#!/usr/bin/env python3
"""
SDI Monitoring System - API Server
Production-ready Flask API with all endpoints
"""
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import bcrypt
import os
from datetime import datetime, timedelta


# Rate limiting for realtime endpoints
from time import time
realtime_rate_limit = {}  # {device_id-interface_name: last_request_time}
REALTIME_MIN_INTERVAL = 3  # seconds

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sdi-monitoring-secret-change-in-production')
app.permanent_session_lifetime = timedelta(hours=12)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE"]}}, supports_credentials=True)

# --- Authentication ---
# Default admin credentials (change password on first login!)
DEFAULT_USERS = {
    'admin': bcrypt.hashpw(b'sdi@2026', bcrypt.gensalt()).decode()
}

def get_users():
    """Get users from DB, fallback to default"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT username, password_hash FROM auth_users WHERE is_active = true")
        users = {row['username']: row['password_hash'] for row in cur.fetchall()}
        cur.close()
        conn.close()
        return users if users else DEFAULT_USERS
    except Exception:
        return DEFAULT_USERS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('authenticated'):
            return f(*args, **kwargs)
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    return decorated

# Protect all /api/ endpoints except auth
@app.before_request
def check_auth():
    # Skip auth for login/status/logout endpoints
    if request.path.startswith('/api/auth/'):
        return None
    if request.path.startswith('/api/') and not session.get('authenticated'):
        return jsonify({'success': False, 'error': 'Authentication required'}), 401

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '').encode()

    users = get_users()
    stored_hash = users.get(username)

    if stored_hash and bcrypt.checkpw(password, stored_hash.encode()):
        session.permanent = True
        session['authenticated'] = True
        session['username'] = username
        return jsonify({'success': True, 'username': username})

    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if session.get('authenticated'):
        return jsonify({'success': True, 'authenticated': True, 'username': session.get('username')})
    return jsonify({'success': True, 'authenticated': False})

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def auth_change_password():
    data = request.get_json()
    new_password = data.get('new_password', '').encode()
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password min 6 characters'}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        new_hash = bcrypt.hashpw(new_password, bcrypt.gensalt()).decode()
        cur.execute("""
            INSERT INTO auth_users (username, password_hash) VALUES (%s, %s)
            ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
        """, (session['username'], new_hash))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

DB_CONFIG = {
    'host': 'localhost',
    'database': 'isp_monitoring',
    'user': 'super',
    'password': 'temp123'
}

def get_db():
    """Get database connection"""
    return psycopg2.connect(**DB_CONFIG)

# ============================================================================
# DEVICES ENDPOINTS
# ============================================================================

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all devices"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        location = request.args.get("location")
        if location:
            cur.execute("SELECT * FROM devices WHERE TRIM(location) ILIKE %s AND is_active=true ORDER BY hostname", (location,))
        else:
            cur.execute("SELECT * FROM devices ORDER BY id")
        devices = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': devices})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices', methods=['POST'])
def add_device():
    """Add new device"""
    try:
        data = request.json
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            INSERT INTO devices (hostname, ip_address, device_type, snmp_community, location, role)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (data['hostname'], data['ip_address'], data['device_type'], 
              data.get('snmp_community', 'public'), data.get('location'), data.get('role')))
        device = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': device})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>', methods=['PUT'])
def update_device(device_id):
    """Update device"""
    try:
        data = request.json
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE devices SET 
                hostname = %s, ip_address = %s, device_type = %s,
                snmp_community = %s, location = %s, role = %s, is_active = %s,
                device_category = %s
            WHERE id = %s
            RETURNING *
        """, (data['hostname'], data['ip_address'], data['device_type'],
              data.get('snmp_community'), data.get('location'), data.get('role'),
              data.get('is_active', True), data.get('device_category', 'access'), device_id))
        device = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': device})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    """Delete device"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM devices WHERE id = %s", (device_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# STATS ENDPOINT
# ============================================================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT COUNT(*) as total FROM devices WHERE is_active = true")
        total = cur.fetchone()['total']
        cur.execute("""
            SELECT COUNT(*) as healthy
            FROM latency_results lr
            JOIN (SELECT device_id, MAX(timestamp) as max_ts
                  FROM latency_results GROUP BY device_id) latest
            ON lr.device_id = latest.device_id AND lr.timestamp = latest.max_ts
            JOIN devices d ON d.id = lr.device_id AND d.is_active = true
            WHERE lr.packet_loss < 5 AND lr.rtt_avg < 100
            AND lr.timestamp > NOW() - INTERVAL '10 minutes'
        """)
        healthy = cur.fetchone()['healthy']
        
        cur.execute("SELECT COUNT(DISTINCT device_id) as up FROM latency_results WHERE timestamp > NOW() - INTERVAL '5 minutes' AND packet_loss < 100")
        up = cur.fetchone()['up']
        
        cur.execute("SELECT COUNT(*) as anomalies FROM anomalies WHERE detected_at > NOW() - INTERVAL '24 hours'")
        anomalies = cur.fetchone()['anomalies']
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True, 
            'total_devices': total, 
            'devices_up': up,
            'healthy_devices': healthy, 
            'recent_anomalies': anomalies
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# LATENCY ENDPOINTS
# ============================================================================

@app.route('/api/latency/latest', methods=['GET'])
def get_latest_latency():
    """Get latest latency results"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT DISTINCT ON (device_id) * FROM latency_results
            ORDER BY device_id, timestamp DESC
        """)
        results = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/latency/device/<int:device_id>', methods=['GET'])
def get_device_latency(device_id):
    """Get latency history for specific device"""
    try:
        hours = int(request.args.get('hours', 24))
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT * FROM latency_results
            WHERE device_id = %s AND timestamp > NOW() - make_interval(hours := %s)
            ORDER BY timestamp DESC
        """, (device_id, hours))
        results = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# ANOMALIES ENDPOINT
# ============================================================================

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """Get anomalies"""
    try:
        limit = int(request.args.get('limit', 50))
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT a.*, d.hostname, d.ip_address
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            ORDER BY a.detected_at DESC
            LIMIT %s
        """, (limit,))
        anomalies = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': anomalies})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# TOPOLOGY ENDPOINTS
# ============================================================================

@app.route('/api/connections', methods=['GET'])
def get_connections():
    """Get network connections with device names"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT c.*,
                   da.hostname as device_a_name,
                   db.hostname as device_b_name
            FROM connections c
            LEFT JOIN devices da ON c.device_a_id = da.id
            LEFT JOIN devices db ON c.device_b_id = db.id
            ORDER BY c.id
        """)
        connections = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': connections})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connections', methods=['POST'])
def add_connection():
    """Add new connection"""
    try:
        data = request.json
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            INSERT INTO connections (device_a_id, device_b_id, interface_a, interface_b,
                                     connection_type, bandwidth, description, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (data.get('device_a_id') or data.get('source_device_id'),
              data.get('device_b_id') or data.get('target_device_id'),
              data.get('interface_a'), data.get('interface_b'),
              data.get('connection_type', 'physical'), data.get('bandwidth'),
              data.get('description'), data.get('is_active', True)))
        connection = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': connection})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connections/<int:conn_id>', methods=['DELETE'])
def delete_connection(conn_id):
    """Delete connection"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM connections WHERE id = %s", (conn_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/topology/graph', methods=['GET'])
def get_topology_graph():
    """Get topology graph data with device names resolved"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM devices WHERE is_active = true")
        devices = cur.fetchall()
        cur.execute("""
            SELECT c.*,
                   da.hostname as device_a_name,
                   db.hostname as device_b_name
            FROM connections c
            LEFT JOIN devices da ON c.device_a_id = da.id
            LEFT JOIN devices db ON c.device_b_id = db.id
        """)
        connections = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'devices': devices, 'connections': connections})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/topology/discover', methods=['POST'])
def run_topology_discovery():
    """Run LLDP/CDP topology discovery"""
    try:
        result = subprocess.run(
            ['/opt/isp-monitoring/venv/bin/python3', '/opt/isp-monitoring/scripts/topology_discovery.py'],
            capture_output=True,
            text=True,
            timeout=600
        )
        output = result.stdout[-1000:] if result.stdout else ''
        return jsonify({
            'success': True,
            'message': output.strip().split('\n')[-1] if output.strip() else 'Discovery completed',
            'output': output
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Discovery timeout (10 min limit)'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# IP CONFLICTS ENDPOINTS
# ============================================================================

@app.route('/api/ip-inventory', methods=['GET'])
def get_ip_inventory():
    """Get IP inventory"""
    try:
        limit = int(request.args.get('limit', 100))
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        query = "SELECT * FROM ip_inventory"
        if active_only:
            query += " WHERE is_active = true"
        query += " ORDER BY last_seen DESC LIMIT %s"
        
        cur.execute(query, (limit,))
        inventory = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'data': inventory})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ip-conflicts', methods=['GET'])
def get_ip_conflicts():
    """Get IP conflicts"""
    try:
        limit = int(request.args.get('limit', 50))
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT * FROM ip_conflicts
            WHERE is_resolved = false
            ORDER BY detected_at DESC
            LIMIT %s
        """, (limit,))
        conflicts = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': conflicts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ip-conflicts/<int:conflict_id>/resolve', methods=['POST'])
def resolve_conflict(conflict_id):
    """Resolve IP conflict"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE ip_conflicts SET is_resolved = true, resolved_at = NOW()
            WHERE id = %s
        """, (conflict_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ip-stats', methods=['GET'])
def get_ip_stats():
    """Get IP statistics"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT COUNT(DISTINCT ip_address) as total_ips FROM ip_inventory")
        stats = cur.fetchone()
        total_ips = stats['total_ips'] if stats else 0
        
        cur.execute("SELECT COUNT(DISTINCT ip_address) as active_ips FROM ip_inventory WHERE is_active = true")
        stats = cur.fetchone()
        active_ips = stats['active_ips'] if stats else 0
        
        cur.execute("SELECT COUNT(DISTINCT mac_address) as unique_macs FROM ip_inventory WHERE is_active = true")
        stats = cur.fetchone()
        unique_macs = stats['unique_macs'] if stats else 0
        
        cur.execute("SELECT COUNT(DISTINCT ip_address) as recent_ips FROM ip_inventory WHERE last_seen > NOW() - INTERVAL '24 hours'")
        stats = cur.fetchone()
        recent_ips = stats['recent_ips'] if stats else 0
        
        cur.execute("SELECT COUNT(*) as total_conflicts FROM ip_conflicts WHERE is_resolved = false")
        stats = cur.fetchone()
        total_conflicts = stats['total_conflicts'] if stats else 0
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'total_ips': total_ips,
            'active_ips': active_ips,
            'unique_macs': unique_macs,
            'recent_ips': recent_ips,
            'total_conflicts': total_conflicts,
            'active_conflicts': total_conflicts,
            'critical_conflicts': 0
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<int:device_id>/cascade-delete', methods=['POST'])
@login_required
def cascade_delete_device(device_id):
    """Delete device with all related data"""
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Use cascade delete function
        cur.execute("SELECT delete_device_cascade(%s)", (device_id,))
        conn.commit()
        
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Device deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/anomalies/<int:anomaly_id>', methods=['DELETE'])
@login_required
def delete_anomaly(anomaly_id):
    """Delete anomaly record"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM anomalies WHERE id = %s", (anomaly_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Anomaly deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add to api.py

@app.route('/api/server-metrics/latest', methods=['GET'])
@login_required
def get_latest_server_metrics():
    """Get latest server metrics"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get latest metrics
        cur.execute("""
            SELECT * FROM server_metrics 
            ORDER BY timestamp DESC 
            LIMIT 1
        """)
        latest = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not latest:
            return jsonify({'success': False, 'error': 'No metrics available'})
        
        return jsonify({
            'success': True,
            'data': dict(latest)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/server-metrics/history', methods=['GET'])
@login_required
def get_server_metrics_history():
    """Get server metrics history"""
    try:
        hours = request.args.get('hours', 1, type=int)
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT * FROM server_metrics 
            WHERE timestamp > NOW() - INTERVAL '%s hours'
            ORDER BY timestamp ASC
        """, (hours,))
        
        metrics = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'data': [dict(m) for m in metrics]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/run-scanner', methods=['POST'])
def run_scanner():
    """Run IP conflict scanner"""
    try:
        result = subprocess.run(
            ['python3', '/opt/isp-monitoring/scripts/ip_conflict_scanner.py'],
            capture_output=True,
            text=True,
            timeout=300
        )
        return jsonify({
            'success': True,
            'message': 'Scanner executed successfully',
            'output': result.stdout[-500:] if result.stdout else ''
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Scanner timeout (5 min limit)'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# INTERFACE ENDPOINTS (NEW)
# ============================================================================

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get interface statistics (latest snapshot)"""
    try:
        device_id = request.args.get('device_id')
        limit = int(request.args.get('limit', 100))
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        if device_id:
            query = """
                SELECT DISTINCT ON (interface_name) *
                FROM interface_stats
                WHERE device_id = %s
                ORDER BY interface_name, timestamp DESC
                LIMIT %s
            """
            cur.execute(query, (device_id, limit))
        else:
            query = """
                SELECT DISTINCT ON (device_id, interface_name) 
                    s.*, d.hostname
                FROM interface_stats s
                JOIN devices d ON s.device_id = d.id
                ORDER BY device_id, interface_name, timestamp DESC
                LIMIT %s
            """
            cur.execute(query, (limit,))
        
        interfaces = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'data': interfaces})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/interfaces/bandwidth', methods=['GET'])
def get_interface_bandwidth():
    """
    Calculate real-time bandwidth from counter deltas
    Returns Mbps instead of total counters - like Cacti
    """
    try:
        device_id = request.args.get('device_id')
        if not device_id:
            return jsonify({'success': False, 'error': 'device_id required'}), 400
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get latest 2 snapshots per interface for delta calculation
        # Use 30 min window to ensure we get 2+ snapshots (collection takes ~8-10 min)
        query = """
            WITH ranked AS (
                SELECT *,
                    ROW_NUMBER() OVER (PARTITION BY interface_name ORDER BY timestamp DESC) as rn
                FROM interface_stats
                WHERE device_id = %s AND timestamp > NOW() - INTERVAL '3 hours'
            )
            SELECT * FROM ranked WHERE rn <= 2 ORDER BY interface_name, timestamp DESC
        """
        cur.execute(query, (device_id,))
        results = cur.fetchall()
        cur.close()
        conn.close()

        # Calculate bandwidth per interface
        bandwidth_data = {}

        i = 0
        while i < len(results):
            if i + 1 >= len(results):
                break

            current = results[i]
            previous = results[i+1]

            # Skip if not same interface
            if current['interface_name'] != previous['interface_name']:
                i += 1
                continue

            # Calculate time difference in seconds
            time_diff = (current['timestamp'] - previous['timestamp']).total_seconds()

            # Skip if interval is too short (<30s) or too long (>4 hours)
            if time_diff <= 30 or time_diff > 14400:
                i += 2
                continue

            # Calculate byte deltas (handle 64-bit counter wraps vs resets)
            MAX_COUNTER_64 = 2**64
            RESET_THRESHOLD = 2**48  # counters below this after negative delta = reset, not wrap
            in_delta = current['in_octets'] - previous['in_octets']
            out_delta = current['out_octets'] - previous['out_octets']

            # Detect counter reset vs wrap
            if in_delta < 0:
                if current['in_octets'] < RESET_THRESHOLD:
                    i += 2; continue  # counter reset — skip
                in_delta += MAX_COUNTER_64
            if out_delta < 0:
                if current['out_octets'] < RESET_THRESHOLD:
                    i += 2; continue  # counter reset — skip
                out_delta += MAX_COUNTER_64

            # If delta is unreasonably large after wrap calc, skip
            max_bytes = (current['speed'] or 100_000_000_000) / 8 * time_diff * 1.1
            if in_delta > max_bytes or out_delta > max_bytes:
                i += 2
                continue

            # Convert to Mbps: (bytes * 8 bits/byte) / seconds / 1,000,000
            in_mbps = (in_delta * 8) / time_diff / 1000000
            out_mbps = (out_delta * 8) / time_diff / 1000000

            # Get speed, fix 32-bit overflow (4294967295 bps = ~4295 Mbps)
            raw_speed = current['speed'] or 0
            if raw_speed == 4294967295:
                speed_mbps = 0  # Unknown — let frontend show N/A
            else:
                speed_mbps = round(raw_speed / 1000000, 0)

            # Cap bandwidth to interface speed if speed is known
            if speed_mbps > 0:
                in_mbps = min(in_mbps, speed_mbps)
                out_mbps = min(out_mbps, speed_mbps)

            bandwidth_data[current['interface_name']] = {
                'interface_name': current['interface_name'],
                'description': current.get('description', ''),
                'admin_status': current['admin_status'],
                'oper_status': current['oper_status'],
                'speed_mbps': speed_mbps,
                'in_mbps': round(in_mbps, 2),
                'out_mbps': round(out_mbps, 2),
                'in_errors': current['in_errors'],
                'out_errors': current['out_errors'],
                'timestamp': current['timestamp'].isoformat(),
                'interval_seconds': int(time_diff)
            }

            i += 2  # Skip to next interface pair
        
        return jsonify({
            'success': True,
            'data': list(bandwidth_data.values())
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Tambahkan ini ke api.py setelah endpoint /api/devices yang existing

@app.route('/api/devices/status', methods=['GET'])
def get_devices_status():
    """Get all devices with their UP/DOWN and SNMP status"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        import datetime
        # Get devices with latest collection + latency timestamps (optimized)
        query = """
            WITH latest_latency AS (
                SELECT DISTINCT ON (device_id)
                    device_id, timestamp, packet_loss, rtt_avg
                FROM latency_results
                ORDER BY device_id, timestamp DESC
            ),
            latest_collection AS (
                SELECT device_id,
                    MAX(timestamp) as last_collection,
                    COUNT(DISTINCT interface_name) as interface_count
                FROM interface_stats
                GROUP BY device_id
            )
            SELECT
                d.id, d.hostname, d.ip_address, d.device_type, d.device_category,
                d.is_active, d.snmp_community,
                lc.last_collection,
                COALESCE(lc.interface_count, 0) as interface_count,
                ll.timestamp as last_latency,
                ll.packet_loss as latest_packet_loss,
                ll.rtt_avg as latest_rtt
            FROM devices d
            LEFT JOIN latest_collection lc ON d.id = lc.device_id
            LEFT JOIN latest_latency ll ON d.id = ll.device_id
            WHERE d.is_active = true
            ORDER BY d.hostname
        """
        cur.execute(query)
        devices = cur.fetchall()

        # Add status indicators
        result = []
        for dev in devices:
            now = datetime.datetime.utcnow()
            last_latency = dev['last_latency']
            last_collection = dev['last_collection']

            latency_age = int((now - last_latency).total_seconds()) if last_latency else None
            collection_age = int((now - last_collection).total_seconds()) if last_collection else None

            # last_seen = sumber paling fresh
            candidates = [x for x in [latency_age, collection_age] if x is not None]
            last_seen = min(candidates) if candidates else None

            # ping_status dari latency (real-time)
            ping_status = 'unknown'
            if last_latency and latency_age is not None and latency_age <= 300:
                loss = float(dev['latest_packet_loss']) if dev['latest_packet_loss'] is not None else None
                if loss is not None:
                    if loss == 0: ping_status = 'up'
                    elif loss < 100: ping_status = 'warning'
                    else: ping_status = 'down'

            # snmp_status dari interface collection
            snmp_status = 'unknown'
            if collection_age is not None:
                if collection_age < 7800: snmp_status = 'ok'
                elif collection_age < 14400: snmp_status = 'warning'
                else: snmp_status = 'error'

            result.append({
                'id': dev['id'],
                'hostname': dev['hostname'],
                'ip_address': dev['ip_address'],
                'device_type': dev['device_type'],
                'category': dev['device_category'],
                'is_active': dev['is_active'],
                'interface_count': dev['interface_count'] or 0,
                'last_collection': last_collection.isoformat() if last_collection else None,
                'last_latency': last_latency.isoformat() if last_latency else None,
                'last_seen_seconds': last_seen,
                'ping_status': ping_status,
                'snmp_status': snmp_status,
                'latest_rtt': float(dev['latest_rtt']) if dev['latest_rtt'] else None,
                'latest_packet_loss': float(dev['latest_packet_loss']) if dev['latest_packet_loss'] is not None else None
            })
        return jsonify({'success': True, 'data': result})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<int:device_id>/collect', methods=['POST'])
def trigger_device_collection(device_id):
    """Trigger manual collection for a single device"""
    try:
        import subprocess
        import sys
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get device info
        cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
        device = cur.fetchone()
        cur.close()
        conn.close()
        
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        
        # Run collection in background
        script_path = '/opt/isp-monitoring/scripts/interface_monitor.py'
        python_path = sys.executable
        
        # Execute in background using parameterized query via -c
        safe_device_id = int(device_id)
        subprocess.Popen(
            [python_path, '-c',
             f'import sys; sys.path.insert(0, "/opt/isp-monitoring/scripts"); '
             f'from interface_monitor import collect_interface_stats; '
             f'import psycopg2, psycopg2.extras; '
             f'conn = psycopg2.connect(host="localhost", database="isp_monitoring", user="super", password="temp123"); '
             f'cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor); '
             f'cur.execute("SELECT * FROM devices WHERE id = %s", ({safe_device_id},)); '
             f'dev = cur.fetchone(); cur.close(); conn.close(); '
             f'collect_interface_stats(dict(dev)) if dev else None'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        
        return jsonify({
            'success': True, 
            'message': f'Collection started for {device["hostname"]}'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/devices/<int:device_id>/test-snmp', methods=['GET'])
def test_device_snmp(device_id):
    """Test SNMP connectivity for a device"""
    try:
        import subprocess
        
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT * FROM devices WHERE id = %s", (device_id,))
        device = cur.fetchone()
        cur.close()
        conn.close()
        
        if not device:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
        
        # Quick SNMP test (sysDescr)
        cmd = [
            'snmpget', '-v2c', '-c', device['snmp_community'],
            '-t', '5', device['ip_address'], '1.3.6.1.2.1.1.1.0'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'status': 'ok',
                'message': 'SNMP accessible',
                'response': result.stdout.strip()
            })
        else:
            return jsonify({
                'success': True,
                'status': 'error',
                'message': 'SNMP timeout or authentication failed',
                'error': result.stderr.strip()
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



# ============================================================================
# CONTENT LATENCY MONITOR ENDPOINTS
# ============================================================================

@app.route('/api/content-targets', methods=['GET'])
def get_content_targets():
    """List all content targets"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM content_targets ORDER BY id")
        targets = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': targets})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/content-targets', methods=['POST'])
def add_content_target():
    """Add new content target"""
    try:
        data = request.json
        name = data.get('target_name', '').strip()
        host = data.get('target_host', '').strip()
        ttype = data.get('target_type', 'custom').strip()
        if not name or not host:
            return jsonify({'success': False, 'error': 'target_name and target_host required'}), 400
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO content_targets (target_name, target_host, target_type) VALUES (%s, %s, %s) RETURNING *",
            (name, host, ttype)
        )
        target = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': target})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/content-targets/<int:target_id>', methods=['PUT'])
def update_content_target(target_id):
    """Update content target (toggle active, rename)"""
    try:
        data = request.json
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            """UPDATE content_targets SET
                target_name = COALESCE(%s, target_name),
                target_host = COALESCE(%s, target_host),
                target_type = COALESCE(%s, target_type),
                is_active = COALESCE(%s, is_active)
            WHERE id = %s RETURNING *""",
            (data.get('target_name'), data.get('target_host'),
             data.get('target_type'), data.get('is_active'), target_id)
        )
        target = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if not target:
            return jsonify({'success': False, 'error': 'Target not found'}), 404
        return jsonify({'success': True, 'data': target})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/content-targets/<int:target_id>', methods=['DELETE'])
def delete_content_target(target_id):
    """Delete content target (cascade deletes results)"""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM content_targets WHERE id = %s", (target_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/content-targets/latency/latest', methods=['GET'])
def get_content_latency_latest():
    """Latest latency for ALL targets (dashboard cards)"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT t.*, r.rtt_avg, r.rtt_min, r.rtt_max, r.packet_loss, r.timestamp as last_check
            FROM content_targets t
            LEFT JOIN LATERAL (
                SELECT rtt_avg, rtt_min, rtt_max, packet_loss, timestamp
                FROM content_latency_results
                WHERE target_id = t.id
                ORDER BY timestamp DESC LIMIT 1
            ) r ON true
            ORDER BY t.id
        """)
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/content-targets/<int:target_id>/latency', methods=['GET'])
def get_content_target_latency(target_id):
    """Historical latency for 1 target"""
    try:
        hours = int(request.args.get('hours', 4))
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT rtt_avg, rtt_min, rtt_max, packet_loss, timestamp
            FROM content_latency_results
            WHERE target_id = %s AND timestamp > NOW() - make_interval(hours := %s)
            ORDER BY timestamp ASC
        """, (target_id, hours))
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/content-targets/latency/all', methods=['GET'])
def get_content_latency_all():
    """Historical latency ALL targets (overlay chart)"""
    try:
        hours = int(request.args.get('hours', 4))
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT r.target_id, t.target_name, r.rtt_avg, r.packet_loss, r.timestamp
            FROM content_latency_results r
            JOIN content_targets t ON r.target_id = t.id
            WHERE r.timestamp > NOW() - make_interval(hours := %s)
            ORDER BY r.timestamp ASC
        """, (hours,))
        data = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/notifications/critical', methods=['GET'])
@login_required
def get_critical_notifications():
    """Get critical issues for notification bell"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        notifications = []
        
        # 1. Devices with high packet loss (5-99%)
        cur.execute("""
            SELECT DISTINCT d.hostname, d.ip_address, lr.packet_loss, 
                   lr.timestamp, 'high_loss' as issue_type
            FROM devices d
            JOIN latency_results lr ON d.id = lr.device_id
            WHERE lr.timestamp > NOW() - INTERVAL '30 minutes'
            AND lr.packet_loss BETWEEN 5 AND 99
            ORDER BY lr.packet_loss DESC
            LIMIT 10
        """)
        high_loss = cur.fetchall()
        notifications.extend([{**dict(item), 'severity': 'warning'} for item in high_loss])
        
        # 2. Devices currently down (100% loss)
        cur.execute("""
            SELECT DISTINCT d.hostname, d.ip_address, 
                   lr.timestamp, 'device_down' as issue_type
            FROM devices d
            JOIN latency_results lr ON d.id = lr.device_id
            WHERE lr.timestamp > NOW() - INTERVAL '30 minutes'
            AND lr.packet_loss = 100
            ORDER BY lr.timestamp DESC
            LIMIT 10
        """)
        down = cur.fetchall()
        notifications.extend([{**dict(item), 'severity': 'critical'} for item in down])
        
        # 3. Interfaces with errors (from last hour)
        cur.execute("""
            SELECT d.hostname, i.interface_name, 
                   (i.in_errors + i.out_errors) as total_errors,
                   i.timestamp, 'interface_errors' as issue_type
            FROM interface_stats i
            JOIN devices d ON i.device_id = d.id
            WHERE i.timestamp > NOW() - INTERVAL '1 hour'
            AND (i.in_errors + i.out_errors) > 100
            ORDER BY total_errors DESC
            LIMIT 10
        """)
        errors = cur.fetchall()
        notifications.extend([{**dict(item), 'severity': 'warning'} for item in errors])
        
        cur.close()
        conn.close()
        
        # Group by severity
        critical_count = len([n for n in notifications if n['severity'] == 'critical'])
        warning_count = len([n for n in notifications if n['severity'] == 'warning'])
        
        return jsonify({
            'success': True,
            'total': len(notifications),
            'critical_count': critical_count,
            'warning_count': warning_count,
            'notifications': notifications[:20]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# SERVER STARTUP
# ============================================================================


@app.route('/api/interfaces/history', methods=['GET'])
def get_interface_history():
    """Get bandwidth/error/packet history for a specific interface.
    Query params: device_id, interface_name, hours, metrics (bandwidth|errors|packets|all)
    """
    try:
        device_id = request.args.get('device_id')
        interface_name = request.args.get('interface_name')
        hours = float(request.args.get('hours', 1))
        metrics = request.args.get('metrics', 'bandwidth')  # bandwidth|errors|packets|all

        if not device_id or not interface_name:
            return jsonify({'success': False, 'error': 'device_id and interface_name required'}), 400

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        seconds = int(hours * 3600)
        query = """
            SELECT timestamp, in_octets, out_octets, speed,
                   in_errors, out_errors, in_discards, out_discards,
                   in_packets, out_packets
            FROM interface_stats
            WHERE device_id = %s AND interface_name = %s
                AND timestamp > NOW() - make_interval(secs := %s)
            ORDER BY timestamp ASC
        """
        cur.execute(query, (device_id, interface_name, seconds))
        snapshots = cur.fetchall()
        cur.close()
        conn.close()

        if len(snapshots) < 2:
            return jsonify({'success': True, 'data': [], 'speed': 0})

        # Get speed from latest snapshot
        raw_speed = snapshots[-1]['speed'] or 0
        if raw_speed == 4294967295:
            speed_mbps = 0
        else:
            speed_mbps = round(raw_speed / 1000000, 0)

        MAX_COUNTER_64 = 2**64
        RESET_THRESHOLD = 2**48

        def safe_delta(curr_val, prev_val):
            """Calculate counter delta with wrap/reset detection. Returns None on reset."""
            delta = curr_val - prev_val
            if delta < 0:
                if curr_val < RESET_THRESHOLD:
                    return None  # counter reset
                delta += MAX_COUNTER_64
            return delta

        history = []
        for i in range(1, len(snapshots)):
            prev = snapshots[i-1]
            curr = snapshots[i]

            time_diff = (curr['timestamp'] - prev['timestamp']).total_seconds()
            if time_diff <= 0:
                continue

            in_delta = safe_delta(curr['in_octets'], prev['in_octets'])
            out_delta = safe_delta(curr['out_octets'], prev['out_octets'])

            if in_delta is None or out_delta is None:
                continue

            # Skip unreasonable deltas (use interface speed or 800Gbps default)
            iface_speed = curr['speed'] or 800_000_000_000
            max_reasonable = iface_speed / 8 * time_diff * 1.1
            if in_delta > max_reasonable or out_delta > max_reasonable:
                continue

            in_mbps = round((in_delta * 8) / time_diff / 1000000, 2)
            out_mbps = round((out_delta * 8) / time_diff / 1000000, 2)

            point = {'timestamp': curr['timestamp'].isoformat(), 'in_mbps': in_mbps, 'out_mbps': out_mbps}

            # Add error/discard rates if requested
            if metrics in ('errors', 'all'):
                ie = safe_delta(curr['in_errors'] or 0, prev['in_errors'] or 0)
                oe = safe_delta(curr['out_errors'] or 0, prev['out_errors'] or 0)
                id_ = safe_delta(curr['in_discards'] or 0, prev['in_discards'] or 0)
                od = safe_delta(curr['out_discards'] or 0, prev['out_discards'] or 0)
                point['in_errors_rate'] = round((ie or 0) / time_diff, 2)
                point['out_errors_rate'] = round((oe or 0) / time_diff, 2)
                point['in_discards_rate'] = round((id_ or 0) / time_diff, 2)
                point['out_discards_rate'] = round((od or 0) / time_diff, 2)

            # Add packet rates if requested
            if metrics in ('packets', 'all'):
                ip = safe_delta(curr['in_packets'] or 0, prev['in_packets'] or 0)
                op = safe_delta(curr['out_packets'] or 0, prev['out_packets'] or 0)
                point['in_pps'] = round((ip or 0) / time_diff, 0)
                point['out_pps'] = round((op or 0) / time_diff, 0)

            history.append(point)

        return jsonify({'success': True, 'data': history, 'speed_mbps': speed_mbps})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route('/api/interfaces/rrd-history', methods=['GET'])
def get_rrd_history():
    """Get RRD historical data for an interface
    Query params:
      - device_id, interface_name (required)
      - timerange: 1h|6h|24h|7d|30d|1y (default: 24h)
      - start_ts, end_ts: unix timestamps for custom range
    """
    try:
        device_id = request.args.get('device_id')
        interface_name = request.args.get('interface_name')
        timerange = request.args.get('timerange', '24h')
        start_ts = request.args.get('start_ts')
        end_ts = request.args.get('end_ts')

        if not device_id or not interface_name:
            return jsonify({'success': False, 'error': 'device_id and interface_name required'}), 400

        import sys
        sys.path.insert(0, '/opt/isp-monitoring')
        from scripts.rrd_manager import fetch_rrd, fetch_rrd_custom, get_rrd_path
        import os

        # Check RRD file exists
        rrd_path = get_rrd_path(int(device_id), interface_name)
        if not os.path.exists(rrd_path):
            return jsonify({'success': False, 'error': 'No RRD data yet for this interface', 'data': []})

        # Fetch data
        if start_ts and end_ts:
            points = fetch_rrd_custom(int(device_id), interface_name, float(start_ts), float(end_ts))
        else:
            points = fetch_rrd(int(device_id), interface_name, timerange)

        # Get interface speed from DB for utilization calc
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""SELECT speed FROM interface_stats
            WHERE device_id=%s AND interface_name=%s
            ORDER BY timestamp DESC LIMIT 1""", (device_id, interface_name))
        row = cur.fetchone()
        cur.close(); conn.close()

        raw_speed = (row['speed'] or 0) if row else 0
        speed_mbps = 0 if raw_speed == 4294967295 else round(raw_speed / 1_000_000, 0)

        return jsonify({
            'success': True,
            'data': points,
            'speed_mbps': speed_mbps,
            'timerange': timerange,
            'points': len(points)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/interfaces/top-talkers', methods=['GET'])
def get_top_talkers():
    """Get top bandwidth consumers across all devices"""
    try:
        limit = int(request.args.get('limit', 20))
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get latest 2 snapshots per (device, interface) within 30min
        query = """
            WITH ranked AS (
                SELECT s.*, d.hostname,
                    ROW_NUMBER() OVER (PARTITION BY s.device_id, s.interface_name ORDER BY s.timestamp DESC) as rn
                FROM interface_stats s
                JOIN devices d ON s.device_id = d.id
                WHERE s.timestamp > NOW() - INTERVAL '30 minutes'
                  AND s.oper_status = 'up'
            )
            SELECT * FROM ranked WHERE rn <= 2
            ORDER BY device_id, interface_name, timestamp DESC
        """
        cur.execute(query)
        results = cur.fetchall()
        cur.close()
        conn.close()

        MAX_COUNTER_64 = 2**64
        RESET_THRESHOLD = 2**48
        talkers = []

        i = 0
        while i < len(results):
            if i + 1 >= len(results):
                break
            current = results[i]
            previous = results[i+1]

            if current['device_id'] != previous['device_id'] or \
               current['interface_name'] != previous['interface_name']:
                i += 1
                continue

            time_diff = (current['timestamp'] - previous['timestamp']).total_seconds()
            if time_diff <= 30 or time_diff > 1800:
                i += 2
                continue

            in_delta = current['in_octets'] - previous['in_octets']
            out_delta = current['out_octets'] - previous['out_octets']

            # Handle wrap/reset
            if in_delta < 0:
                if current['in_octets'] < RESET_THRESHOLD:
                    i += 2; continue
                in_delta += MAX_COUNTER_64
            if out_delta < 0:
                if current['out_octets'] < RESET_THRESHOLD:
                    i += 2; continue
                out_delta += MAX_COUNTER_64

            max_bytes = (current['speed'] or 100_000_000_000) / 8 * time_diff * 1.1
            if in_delta > max_bytes or out_delta > max_bytes:
                i += 2
                continue

            in_mbps = round((in_delta * 8) / time_diff / 1000000, 2)
            out_mbps = round((out_delta * 8) / time_diff / 1000000, 2)
            total_mbps = in_mbps + out_mbps

            raw_speed = current['speed'] or 0
            speed_mbps = 0 if raw_speed == 4294967295 else round(raw_speed / 1000000, 0)
            util = round((max(in_mbps, out_mbps) / speed_mbps * 100), 1) if speed_mbps > 0 else 0

            talkers.append({
                'hostname': current['hostname'],
                'device_id': current['device_id'],
                'interface_name': current['interface_name'],
                'description': current.get('description', ''),
                'speed_mbps': speed_mbps,
                'in_mbps': in_mbps,
                'out_mbps': out_mbps,
                'total_mbps': round(total_mbps, 2),
                'utilization': util
            })
            i += 2

        # Sort by total bandwidth descending
        talkers.sort(key=lambda x: x['total_mbps'], reverse=True)

        return jsonify({'success': True, 'data': talkers[:limit]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/interfaces/sparklines', methods=['GET'])
def get_interface_sparklines():
    """Get mini sparkline data (last ~7 snapshots per interface) for a device"""
    try:
        device_id = request.args.get('device_id')
        if not device_id:
            return jsonify({'success': False, 'error': 'device_id required'}), 400

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = """
            WITH ranked AS (
                SELECT interface_name, in_octets, out_octets, speed, timestamp,
                    ROW_NUMBER() OVER (PARTITION BY interface_name ORDER BY timestamp DESC) as rn
                FROM interface_stats
                WHERE device_id = %s AND timestamp > NOW() - INTERVAL '5 hours'
            )
            SELECT * FROM ranked WHERE rn <= 7
            ORDER BY interface_name, timestamp ASC
        """
        cur.execute(query, (device_id,))
        results = cur.fetchall()
        cur.close()
        conn.close()

        MAX_COUNTER_64 = 2**64
        RESET_THRESHOLD = 2**48

        # Group by interface
        iface_data = {}
        for row in results:
            name = row['interface_name']
            if name not in iface_data:
                iface_data[name] = []
            iface_data[name].append(row)

        sparklines = {}
        for name, snapshots in iface_data.items():
            points = []
            for i in range(1, len(snapshots)):
                prev = snapshots[i-1]
                curr = snapshots[i]
                time_diff = (curr['timestamp'] - prev['timestamp']).total_seconds()
                if time_diff <= 0:
                    continue

                in_delta = curr['in_octets'] - prev['in_octets']
                out_delta = curr['out_octets'] - prev['out_octets']

                if in_delta < 0:
                    if curr['in_octets'] < RESET_THRESHOLD:
                        continue
                    in_delta += MAX_COUNTER_64
                if out_delta < 0:
                    if curr['out_octets'] < RESET_THRESHOLD:
                        continue
                    out_delta += MAX_COUNTER_64

                max_bytes = (curr['speed'] or 100_000_000_000) / 8 * time_diff * 1.1
                if in_delta > max_bytes or out_delta > max_bytes:
                    continue

                in_mbps = round((in_delta * 8) / time_diff / 1000000, 2)
                out_mbps = round((out_delta * 8) / time_diff / 1000000, 2)
                points.append({'in': in_mbps, 'out': out_mbps})

            if points:
                sparklines[name] = points

        return jsonify({'success': True, 'data': sparklines})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# EVENTS CHECK (lightweight polling for smart refresh)
# ============================================================================

@app.route('/api/events/check', methods=['GET'])
def events_check():
    """Lightweight endpoint for smart refresh - returns change indicators"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM devices) as device_count,
                (SELECT MAX(updated_at) FROM devices) as last_device_update,
                (SELECT MAX(detected_at) FROM anomalies) as last_anomaly
        """)
        row = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({
            'success': True,
            'device_count': row['device_count'],
            'last_device_update': row['last_device_update'].isoformat() if row['last_device_update'] else None,
            'last_anomaly': row['last_anomaly'].isoformat() if row['last_anomaly'] else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# REALTIME INTERFACE POLL (live SNMP for single interface)
# ============================================================================

@app.route('/api/interfaces/realtime-poll', methods=['GET'])
def realtime_interface_poll():
    """Live SNMP poll for a single interface - returns instant bandwidth in Mbps"""
    try:
        device_id = request.args.get('device_id')
        interface_name = request.args.get('interface_name')
        if not device_id or not interface_name:
            return jsonify({'success': False, 'error': 'device_id and interface_name required'}), 400

        import time as _time
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get device info + interface index
        cur.execute("SELECT ip_address, snmp_community FROM devices WHERE id = %s", (device_id,))
        device = cur.fetchone()
        if not device:
            cur.close(); conn.close()
            return jsonify({'success': False, 'error': 'Device not found'}), 404

        cur.execute("""
            SELECT interface_index FROM interface_stats
            WHERE device_id = %s AND interface_name = %s
            ORDER BY timestamp DESC LIMIT 1
        """, (device_id, interface_name))
        idx_row = cur.fetchone()
        if not idx_row or not idx_row['interface_index']:
            cur.close(); conn.close()
            return jsonify({'success': False, 'error': 'Interface index not found'}), 404

        iface_idx = idx_row['interface_index']
        ip = device['ip_address']
        community = device['snmp_community'] or 'public'

        # SNMP GET ifHCInOctets + ifHCOutOctets
        from pysnmp.hlapi import (SnmpEngine, CommunityData, UdpTransportTarget,
                                  ContextData, ObjectType, ObjectIdentity, getCmd)

        oid_in = f'1.3.6.1.2.1.31.1.1.1.6.{iface_idx}'   # ifHCInOctets
        oid_out = f'1.3.6.1.2.1.31.1.1.1.10.{iface_idx}'  # ifHCOutOctets

        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=3, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid_in)),
                ObjectType(ObjectIdentity(oid_out))
            )
        )

        if error_indication:
            cur.close(); conn.close()
            return jsonify({'success': False, 'error': f'SNMP error: {error_indication}'}), 500
        if error_status:
            cur.close(); conn.close()
            return jsonify({'success': False, 'error': f'SNMP error: {error_status.prettyPrint()}'}), 500

        now_ts = _time.time()
        in_octets = int(var_binds[0][1])
        out_octets = int(var_binds[1][1])

        # Get previous reading from realtime_cache
        cur.execute("""
            SELECT poll_timestamp, in_octets, out_octets FROM realtime_cache
            WHERE device_id = %s AND interface_name = %s
        """, (device_id, interface_name))
        prev = cur.fetchone()

        # Store current reading
        cur.execute("""
            INSERT INTO realtime_cache (device_id, interface_name, poll_timestamp, in_octets, out_octets)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (device_id, interface_name) DO UPDATE SET
                poll_timestamp = EXCLUDED.poll_timestamp,
                in_octets = EXCLUDED.in_octets,
                out_octets = EXCLUDED.out_octets
        """, (device_id, interface_name, now_ts, in_octets, out_octets))
        conn.commit()
        cur.close()
        conn.close()

        if not prev:
            return jsonify({
                'success': True,
                'data': {'in_mbps': 0, 'out_mbps': 0, 'interval_seconds': 0,
                         'timestamp': now_ts, 'first_poll': True}
            })

        # Calculate delta
        interval = now_ts - prev['poll_timestamp']
        if interval < 1:
            return jsonify({
                'success': True,
                'data': {'in_mbps': 0, 'out_mbps': 0, 'interval_seconds': round(interval, 1),
                         'timestamp': now_ts, 'first_poll': False}
            })

        MAX_COUNTER_64 = 2**64
        in_delta = in_octets - prev['in_octets']
        out_delta = out_octets - prev['out_octets']
        if in_delta < 0:
            in_delta += MAX_COUNTER_64
        if out_delta < 0:
            out_delta += MAX_COUNTER_64

        in_mbps = round((in_delta * 8) / interval / 1000000, 3)
        out_mbps = round((out_delta * 8) / interval / 1000000, 3)

        return jsonify({
            'success': True,
            'data': {
                'in_mbps': in_mbps, 'out_mbps': out_mbps,
                'interval_seconds': round(interval, 1),
                'timestamp': now_ts, 'first_poll': False
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# REALTIME CONTENT PING (live ping for single target)
# ============================================================================

@app.route('/api/content-targets/<int:target_id>/realtime-ping', methods=['GET'])
def realtime_content_ping(target_id):
    """Single ping to a content target - returns instant RTT"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT target_host FROM content_targets WHERE id = %s", (target_id,))
        target = cur.fetchone()
        cur.close()
        conn.close()

        if not target:
            return jsonify({'success': False, 'error': 'Target not found'}), 404

        import re
        host = target['target_host']
        # Validate host to prevent command injection
        if not re.match(r'^[a-zA-Z0-9._:-]+$', host):
            return jsonify({'success': False, 'error': 'Invalid host format'}), 400

        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', host],
            capture_output=True, text=True, timeout=5
        )

        import time as _time
        now_ts = _time.time()

        if result.returncode == 0:
            # Parse rtt from ping output: rtt min/avg/max/mdev = 1.234/1.234/1.234/0.000 ms
            rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', result.stdout)
            if rtt_match:
                return jsonify({
                    'success': True,
                    'data': {
                        'rtt_min': float(rtt_match.group(1)),
                        'rtt_avg': float(rtt_match.group(2)),
                        'rtt_max': float(rtt_match.group(3)),
                        'packet_loss': 0,
                        'timestamp': now_ts
                    }
                })

        # Packet loss or timeout
        return jsonify({
            'success': True,
            'data': {
                'rtt_min': 0, 'rtt_avg': 0, 'rtt_max': 0,
                'packet_loss': 100,
                'timestamp': now_ts
            }
        })
    except subprocess.TimeoutExpired:
        import time as _time
        return jsonify({
            'success': True,
            'data': {
                'rtt_min': 0, 'rtt_avg': 0, 'rtt_max': 0,
                'packet_loss': 100,
                'timestamp': _time.time()
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# Add to api.py

import os
from dotenv import load_dotenv
from groq import Groq

# Load environment variables
load_dotenv('/opt/isp-monitoring/.env')

# Initialize Groq client
groq_client = Groq(api_key=os.getenv('GROQ_API_KEY'))

@app.route('/api/ai/chat', methods=['POST'])
@login_required
def ai_chat():
    """AI Assistant chat endpoint"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        
        if not user_message:
            return jsonify({'success': False, 'error': 'Message required'}), 400
        
        # Build context with monitoring data
        context = build_monitoring_context()
        
        # System prompt (Indonesian)
        system_prompt = f"""Kamu adalah AI Assistant untuk sistem monitoring jaringan ISP.
        
ATURAN PENTING:
- Jawab HANYA dalam Bahasa Indonesia
- Fokus pada pertanyaan monitoring: device status, latency, anomali, interface
- Jika pertanyaan di luar monitoring, arahkan user untuk bertanya tentang monitoring
- Gunakan data real-time yang tersedia di context
- Jawab singkat dan jelas

CONTEXT DATA SAAT INI:
{context}

Bantu user memahami status jaringan mereka."""

        # Call Groq API
        # Build message history for context
        history = data.get('history', [])
        groq_messages = [{"role": "system", "content": system_prompt}]
        # Add last 8 messages from history (exclude current message)
        for h in history[-9:-1]:
            if h.get('role') in ('user', 'assistant') and h.get('content'):
                groq_messages.append({
                    "role": h['role'],
                    "content": str(h['content'])[:500]  # limit per message
                })
        groq_messages.append({"role": "user", "content": user_message})

        completion = groq_client.chat.completions.create(
            model="meta-llama/llama-4-maverick-17b-128e-instruct",
            messages=groq_messages,
            temperature=0.7,
            max_tokens=1000
        )
        
        assistant_reply = completion.choices[0].message.content
        
        return jsonify({
            'success': True,
            'reply': assistant_reply
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def build_monitoring_context():
    """Build FULL context from all monitoring data"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # 1. Device Summary
        cur.execute("SELECT COUNT(*) as total FROM devices")
        total_devices = cur.fetchone()['total']
        
        cur.execute("""
            SELECT COUNT(*) as healthy
            FROM latency_results lr
            JOIN (SELECT device_id, MAX(timestamp) as max_ts
                  FROM latency_results
                  GROUP BY device_id) latest
            ON lr.device_id = latest.device_id AND lr.timestamp = latest.max_ts
            JOIN devices d ON d.id = lr.device_id AND d.is_active = true
            WHERE lr.packet_loss < 5 AND lr.rtt_avg < 100
            AND lr.timestamp > NOW() - INTERVAL '10 minutes'
        """)
        healthy = cur.fetchone()['healthy']

        # 3. Devices with issues
        cur.execute("""
            SELECT d.hostname, d.ip_address, d.device_type, lr.packet_loss, lr.rtt_avg, lr.timestamp
            FROM devices d
            JOIN latency_results lr ON d.id = lr.device_id
            JOIN (SELECT device_id, MAX(timestamp) as max_ts 
                  FROM latency_results GROUP BY device_id) latest
            ON lr.device_id = latest.device_id AND lr.timestamp = latest.max_ts
            WHERE lr.packet_loss > 5 OR lr.rtt_avg > 100
            ORDER BY lr.packet_loss DESC
            LIMIT 10
        """)
        problem_devices = cur.fetchall()

        # 4. All active anomalies
        cur.execute("""
            SELECT a.anomaly_type, a.description, a.severity, a.detected_at,
                   d.hostname, d.ip_address
            FROM anomalies a
            JOIN devices d ON a.device_id = d.id
            ORDER BY a.detected_at DESC
            LIMIT 10
        """)
        anomalies = cur.fetchall()

        # 5. Interface errors
        cur.execute("""
            SELECT DISTINCT ON (d.hostname, i.interface_name)
                   d.hostname, i.interface_name, i.in_errors, i.out_errors,
                   i.in_discards, i.out_discards, i.oper_status
            FROM interface_stats i
            JOIN devices d ON i.device_id = d.id
            WHERE i.timestamp > NOW() - INTERVAL '1 hour'
            AND (i.in_errors + i.out_errors > 100 OR i.oper_status = 'down')
            ORDER BY d.hostname, i.interface_name, (i.in_errors + i.out_errors) DESC
            LIMIT 10
        """)
        interface_issues = cur.fetchall()

        # 6. IP Conflicts
        cur.execute("""
            SELECT ip_address, COUNT(*) as conflict_count
            FROM ip_inventory
            GROUP BY ip_address
            HAVING COUNT(*) > 1
            LIMIT 5
        """)
        ip_conflicts = cur.fetchall()

        # 7. Content Monitor status
        cur.execute("""
            SELECT ct.target_name, ct.target_host, ct.target_type,
                   clr.packet_loss, clr.rtt_avg, clr.timestamp
            FROM content_targets ct
            LEFT JOIN content_latency_results clr ON ct.id = clr.target_id
            JOIN (SELECT target_id, MAX(timestamp) as max_ts 
                  FROM content_latency_results GROUP BY target_id) latest
            ON clr.target_id = latest.target_id AND clr.timestamp = latest.max_ts
            ORDER BY clr.packet_loss DESC
            LIMIT 10
        """)
        content_status = cur.fetchall()

        # 8. Server Performance
        cur.execute("""
            SELECT cpu_percent, mem_percent, disk_percent, 
                   load_1, load_5, uptime_seconds
            FROM server_metrics
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        server_perf = cur.fetchone()

        # 9. Average latency
        cur.execute("""
            SELECT AVG(rtt_avg)::numeric(10,2) as avg_rtt,
                   AVG(packet_loss)::numeric(10,2) as avg_loss
            FROM latency_results
            WHERE timestamp > NOW() - INTERVAL '30 minutes'
        """)
        avg_stats = cur.fetchone()

        cur.close()
        conn.close()

        # Build comprehensive context
        context = f"""
=== RINGKASAN JARINGAN ===
Total Perangkat: {total_devices}
Perangkat Sehat: {healthy}
Perangkat Bermasalah: {len(problem_devices)}
Rata-rata RTT: {avg_stats['avg_rtt'] if avg_stats else 'N/A'} ms
Rata-rata Packet Loss: {avg_stats['avg_loss'] if avg_stats else 'N/A'}%

=== ANOMALI AKTIF ({len(anomalies)}) ===
"""
        for a in anomalies:
            context += "- [" + str(a["severity"]) + "] " + str(a["hostname"]) + " (" + str(a["ip_address"]) + "): " + str(a["description"]) + " (Terdeteksi: " + str(a["detected_at"]) + ")\n"

        for d in problem_devices:
            context += f"- {d['hostname']} ({d['ip_address']}) [{d['device_type']}]: Loss {d['packet_loss']}%, RTT {d['rtt_avg']}ms\n"

        for i in interface_issues:
            context += f"- {i['hostname']} {i['interface_name']}: In-Err {i['in_errors']}, Out-Err {i['out_errors']}, Status: {i['oper_status']}\n"

        for ip in ip_conflicts:
            context += f"- IP {ip['ip_address']}: {ip['conflict_count']} konflik\n"

        for c in content_status:
            status = "✅ OK" if c['packet_loss'] == 0 else f"⚠️ Loss {c['packet_loss']}%"
            context += f"- {c['target_name']} ({c['target_host']}) [{c['target_type']}]: {status}, RTT {c['rtt_avg']}ms\n"

        if server_perf:
            uptime_days = int(server_perf['uptime_seconds'] / 86400)
            context += f"""
=== PERFORMA SERVER ===
CPU: {server_perf['cpu_percent']}%
Memory: {server_perf['mem_percent']}%
Disk: {server_perf['disk_percent']}%
Load: {server_perf['load_1']} (1m), {server_perf['load_5']} (5m)
Uptime: {uptime_days} hari
"""

        return context

    except Exception as e:
        return f"Error loading context: {str(e)}"



@app.route('/api/collection/trigger', methods=['POST'])
def trigger_collection():
    """Trigger manual interface collection"""
    try:
        # Cek apakah collection sedang berjalan
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM collection_jobs WHERE status='running' ORDER BY started_at DESC LIMIT 1")
        running = cur.fetchone()
        if running:
            cur.close(); conn.close()
            return jsonify({'success': False, 'error': 'Collection already running', 'job_id': running['id']})

        # Insert job baru
        cur.execute("INSERT INTO collection_jobs (status, triggered_by) VALUES ('running', 'manual') RETURNING id")
        job_id = cur.fetchone()['id']
        conn.commit()
        cur.close(); conn.close()


        # Clear log file sebelum collection baru
        open('/tmp/interface_cron.log', 'w').close()

        # Jalankan collection di background
        import threading, os

        def run_collection(job_id):
            import time, re
            start = time.time()
            proc = None
            try:
                log_file = open('/tmp/interface_cron.log', 'a')
                proc = subprocess.Popen(
                    ['/opt/isp-monitoring/venv/bin/python3', '/opt/isp-monitoring/scripts/interface_monitor_v2.py'],
                    stdout=log_file, stderr=log_file, text=True
                )
                # Simpan PID agar bisa di-cancel
                with open('/tmp/interface_collect.pid', 'w') as pf:
                    pf.write(str(proc.pid))

                proc.wait()
                log_file.close()
                elapsed = time.time() - start

                if proc.returncode == -15:  # SIGTERM = cancelled
                    final_status = 'cancelled'
                    success = failed = interfaces = 0
                else:
                    final_status = 'completed'
                    success = 0; failed = 0; interfaces = 0
                    with open('/tmp/interface_cron.log', 'r') as lf:
                        for line in lf.readlines():
                            if 'SUCCESS:' in line:
                                m = re.search(r'SUCCESS: (\d+) devices, (\d+)', line)
                                if m: success, interfaces = int(m.group(1)), int(m.group(2))
                            if 'FAILED:' in line:
                                m = re.search(r'FAILED: (\d+)', line)
                                if m: failed = int(m.group(1))

                conn2 = get_db()
                cur2 = conn2.cursor()
                cur2.execute("""UPDATE collection_jobs SET status=%s, finished_at=NOW(),
                    success_count=%s, failed_count=%s, total_interfaces=%s,
                    total_devices=%s, duration_seconds=%s WHERE id=%s""",
                    (final_status, success, failed, interfaces, success+failed, elapsed, job_id))
                conn2.commit(); cur2.close(); conn2.close()

            except Exception as e:
                conn2 = get_db()
                cur2 = conn2.cursor()
                cur2.execute("UPDATE collection_jobs SET status='failed', finished_at=NOW() WHERE id=%s", (job_id,))
                conn2.commit(); cur2.close(); conn2.close()
            finally:
                try: os.remove('/tmp/interface_collect.pid')
                except: pass

        t = threading.Thread(target=run_collection, args=(job_id,), daemon=True)
        t.start()
        return jsonify({'success': True, 'job_id': job_id, 'message': 'Collection started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/collection/status', methods=['GET'])
def collection_status():
    """Get collection status dengan dead process detection"""
    try:
        import os
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""SELECT * FROM collection_jobs ORDER BY started_at DESC LIMIT 1""")
        latest = cur.fetchone()

        # Dead process detection: status 'running' tapi PID file tidak ada
        # dan sudah lebih dari 35 menit → mark sebagai failed
        if latest and latest['status'] == 'running':
            pid_exists = os.path.exists('/tmp/interface_collect.pid')
            if not pid_exists:
                from datetime import datetime, timezone
                started = latest['started_at']
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                if elapsed > 120:  # 2 menit tanpa PID file = dead process
                    cur.execute("""UPDATE collection_jobs SET status='failed', finished_at=NOW()
                        WHERE id=%s""", (latest['id'],))
                    conn.commit()
                    latest['status'] = 'failed'
                    latest['finished_at'] = datetime.now(timezone.utc)

        # Progress dari log file
        progress = {'current': 0, 'total': 0, 'percent': 0, 'last_device': ''}
        if latest and latest['status'] == 'running':
            try:
                import re
                with open('/tmp/interface_cron.log', 'r') as f:
                    lines_log = f.readlines()
                for line in reversed(lines_log):
                    m = re.search(r'(\d+)/(\d+)', line)
                    if m:
                        cur_val = int(m.group(1))
                        tot_val = int(m.group(2))
                        if tot_val > 10:
                            progress['current'] = cur_val
                            progress['total'] = tot_val
                            progress['percent'] = round(cur_val / tot_val * 100, 1)
                            progress['last_device'] = line.strip()
                            break
            except: pass

        cur.close(); conn.close()
        return jsonify({'success': True, 'job': dict(latest) if latest else None, 'progress': progress})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/collection/errors', methods=['GET'])
def get_collection_errors():
    """Get failed devices from last collection"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT ce.hostname, ce.ip_address, ce.error_message, ce.collected_at,
                   d.device_type, d.location
            FROM collection_errors ce
            LEFT JOIN devices d ON d.hostname = ce.hostname
            WHERE ce.job_id = (SELECT MAX(id) FROM collection_jobs)
            ORDER BY ce.hostname
        """)
        errors = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({'success': True, 'data': errors, 'count': len(errors)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/collection/cancel', methods=['POST'])
def cancel_collection():
    """Cancel collection yang sedang berjalan"""
    try:
        import os, signal
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""SELECT id FROM collection_jobs WHERE status='running' ORDER BY started_at DESC LIMIT 1""")
        running = cur.fetchone()

        if not running:
            cur.close(); conn.close()
            return jsonify({'success': False, 'error': 'No collection running'})

        job_id = running['id']
        killed = False

        # Kill via PID file
        pid_file = '/tmp/interface_collect.pid'
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as pf:
                    pid = int(pf.read().strip())
                os.kill(pid, signal.SIGTERM)
                killed = True
            except (ProcessLookupError, ValueError):
                pass
            finally:
                try: os.remove(pid_file)
                except: pass

        # Fallback: pkill by script name
        if not killed:
            import subprocess
            subprocess.run(['pkill', '-f', 'interface_monitor_v2.py'], capture_output=True)

        # Update DB
        cur.execute("""UPDATE collection_jobs SET status='cancelled', finished_at=NOW() WHERE id=%s""", (job_id,))
        conn.commit()
        cur.close(); conn.close()

        # Cleanup lock file
        try: os.remove('/tmp/interface_collect.lock')
        except: pass

        return jsonify({'success': True, 'message': 'Collection cancelled'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 SDI Monitoring API Server Starting...")
    print("📡 Endpoints loaded:")
    print("   - Devices: GET, POST, PUT, DELETE")
    print("   - Stats: Dashboard statistics")
    print("   - Latency: Latest & device history")
    print("   - Anomalies: Event tracking")
    print("   - Topology: Connections & graph")
    print("   - IP Conflicts: Inventory & conflicts")
    print("   - Interfaces: Stats, bandwidth (Mbps), history")
    print("   - Content Targets: CRUD, latency monitoring")
    print("\n✅ Ready on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

@app.route('/api/sites/summary', methods=['GET'])
@login_required
def get_sites_summary():
    """Get per-site summary for dashboard"""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Aggregate per site (normalize location casing)
        cur.execute("""
            SELECT
                COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown') as location,
                COUNT(DISTINCT d.id) as total_devices,
                COUNT(DISTINCT CASE WHEN d.role = 'core' THEN d.id END) as core_devices,
                COUNT(DISTINCT CASE WHEN d.role = 'edge' THEN d.id END) as edge_devices,
                COUNT(DISTINCT CASE WHEN d.role = 'peering' THEN d.id END) as peering_devices,
                COUNT(DISTINCT CASE WHEN d.role = 'customer_handoff' THEN d.id END) as handoff_devices,
                COUNT(DISTINCT CASE WHEN d.role IS NULL OR d.role = '' THEN d.id END) as other_devices,
                COUNT(DISTINCT ist.interface_name) as total_interfaces,
                MAX(ist.timestamp) as last_poll
            FROM devices d
            LEFT JOIN interface_stats ist ON ist.device_id = d.id
                AND ist.timestamp > NOW() - INTERVAL '3 hours'
            WHERE d.is_active = true
            GROUP BY COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown')
            ORDER BY location
        """)
        sites = cur.fetchall()

        # Get latency health per site
        cur.execute("""
            SELECT
                COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown') as location,
                COUNT(DISTINCT d.id) as devices_reachable,
                AVG(lr.rtt_avg) as avg_latency,
                AVG(lr.packet_loss) as avg_loss,
                COUNT(DISTINCT CASE WHEN lr.packet_loss >= 100 THEN d.id END) as devices_down
            FROM devices d
            JOIN (
                SELECT device_id, MAX(timestamp) as max_ts
                FROM latency_results
                WHERE timestamp > NOW() - INTERVAL '10 minutes'
                GROUP BY device_id
            ) latest ON latest.device_id = d.id
            JOIN latency_results lr ON lr.device_id = d.id AND lr.timestamp = latest.max_ts
            WHERE d.is_active = true
            GROUP BY COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown')
        """)
        latency_data = {row['location']: row for row in cur.fetchall()}

        # Get top bandwidth interfaces per site (last collection)
        cur.execute("""
            SELECT
                COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown') as location,
                SUM(rc.in_octets + rc.out_octets) as total_bps
            FROM realtime_cache rc
            JOIN devices d ON d.id = rc.device_id
            WHERE d.is_active = true
            GROUP BY COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown')
        """)
        bw_data = {row['location']: row for row in cur.fetchall()}

        # Get anomaly count per site (last 24h)
        cur.execute("""
            SELECT
                COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown') as location,
                COUNT(*) as anomaly_count
            FROM anomalies a
            JOIN devices d ON d.id = a.device_id
            WHERE a.detected_at > NOW() - INTERVAL '24 hours'
            AND d.is_active = true
            GROUP BY COALESCE(NULLIF(TRIM(d.location), ''), 'Unknown')
        """)
        anomaly_data = {row['location']: row for row in cur.fetchall()}

        # Merge all data
        result = []
        for site in sites:
            loc = site['location']
            lat = latency_data.get(loc, {})
            bw = bw_data.get(loc, {})
            anom = anomaly_data.get(loc, {})

            # Determine health status
            devices_down = lat.get('devices_down', 0) or 0
            avg_loss = float(lat.get('avg_loss', 0) or 0)
            avg_latency = float(lat.get('avg_latency', 0) or 0)
            anomalies = int(anom.get('anomaly_count', 0) or 0)

            if devices_down > 0 or avg_loss >= 50:
                health = 'critical'
            elif avg_loss >= 10 or avg_latency >= 100 or anomalies > 5:
                health = 'warning'
            elif lat.get('devices_reachable', 0):
                health = 'healthy'
            else:
                health = 'unknown'

            result.append({
                'location': loc,
                'total_devices': site['total_devices'],
                'core_devices': site['core_devices'],
                'edge_devices': site['edge_devices'],
                'peering_devices': site['peering_devices'],
                'handoff_devices': site['handoff_devices'],
                'other_devices': site['other_devices'],
                'total_interfaces': site['total_interfaces'],
                'last_poll': site['last_poll'].isoformat() if site['last_poll'] else None,
                'devices_reachable': int(lat.get('devices_reachable', 0) or 0),
                'devices_down': int(devices_down),
                'avg_latency': round(avg_latency, 1),
                'avg_loss': round(avg_loss, 1),
                'total_bps': int(bw.get('total_bps', 0) or 0),
                'anomaly_count': anomalies,
                'health': health
            })

        cur.close()
        conn.close()
        return jsonify({'success': True, 'sites': result, 'total_sites': len(result)})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/search', methods=['GET'])
@login_required
def global_search():
    """Global search across devices, interfaces, IP inventory, anomalies"""
    try:
        q = request.args.get('q', '').strip()
        if len(q) < 2:
            return jsonify({'success': True, 'results': [], 'total': 0})

        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        pattern = f'%{q}%'
        results = []

        # Search devices
        cur.execute("""
            SELECT id, hostname, ip_address::text as ip, device_type, location, role, is_active
            FROM devices
            WHERE hostname ILIKE %s OR ip_address::text ILIKE %s OR location ILIKE %s
            ORDER BY is_active DESC, hostname
            LIMIT 10
        """, (pattern, pattern, pattern))
        for row in cur.fetchall():
            results.append({
                'type': 'device',
                'icon': '🖥️',
                'title': row['hostname'],
                'subtitle': f"{row['ip']} • {row['location'] or '-'} • {row['role'] or '-'}",
                'meta': row['device_type'],
                'id': row['id'],
                'active': row['is_active']
            })

        # Search interfaces
        cur.execute("""
            SELECT DISTINCT ON (i.interface_name, i.device_id)
                i.device_id, i.interface_name, i.description, i.oper_status,
                d.hostname, d.location
            FROM interface_stats i
            JOIN devices d ON d.id = i.device_id
            WHERE i.interface_name ILIKE %s OR i.description ILIKE %s
            ORDER BY i.interface_name, i.device_id, i.timestamp DESC
            LIMIT 10
        """, (pattern, pattern))
        for row in cur.fetchall():
            results.append({
                'type': 'interface',
                'icon': '🔌',
                'title': row['interface_name'],
                'subtitle': f"{row['hostname']} • {row['location'] or '-'}",
                'meta': row['description'] or row['oper_status'],
                'device_id': row['device_id'],
                'interface_name': row['interface_name']
            })

        # Search IP inventory
        cur.execute("""
            SELECT ip.ip_address::text as ip, ip.mac_address, ip.hostname as inv_hostname,
                   d.hostname as device_hostname, d.id as device_id
            FROM ip_inventory ip
            LEFT JOIN devices d ON d.id = ip.device_id
            WHERE ip.ip_address::text ILIKE %s OR ip.hostname ILIKE %s OR ip.mac_address ILIKE %s
            LIMIT 8
        """, (pattern, pattern, pattern))
        for row in cur.fetchall():
            results.append({
                'type': 'ip',
                'icon': '🌐',
                'title': row['ip'],
                'subtitle': f"{row['inv_hostname'] or '-'} • {row['device_hostname'] or '-'}",
                'meta': row['mac_address'] or '',
                'device_id': row['device_id']
            })

        # Search anomalies
        cur.execute("""
            SELECT a.id, a.anomaly_type, a.description, a.severity, a.detected_at,
                   d.hostname, d.id as device_id
            FROM anomalies a
            JOIN devices d ON d.id = a.device_id
            WHERE a.description ILIKE %s OR a.anomaly_type ILIKE %s OR d.hostname ILIKE %s
            ORDER BY a.detected_at DESC
            LIMIT 8
        """, (pattern, pattern, pattern))
        for row in cur.fetchall():
            results.append({
                'type': 'anomaly',
                'icon': '⚠️',
                'title': row['anomaly_type'],
                'subtitle': f"{row['hostname']} • {row['detected_at'].strftime('%Y-%m-%d %H:%M')}",
                'meta': row['description'][:80] + ('...' if len(row['message']) > 80 else ''),
                'severity': row['severity'],
                'device_id': row['device_id']
            })

        cur.close()
        conn.close()
        return jsonify({'success': True, 'results': results, 'total': len(results), 'query': q})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
