#!/usr/bin/env python3
"""
RRD Manager — Create, update, and fetch RRD data per interface
RRA Structure:
  - 5min resolution  → 1 day   (288 points)
  - 30min resolution → 1 week  (336 points)
  - 2hr resolution   → 1 month (360 points)
  - 1day resolution  → 1 year  (365 points)
"""
import rrdtool
import os
import time
from pathlib import Path
from datetime import timezone

RRD_DIR = '/opt/isp-monitoring/rrd'

def get_rrd_path(device_id, interface_name):
    """Get RRD file path for a device/interface pair"""
    # Sanitize interface name for filename
    safe_name = interface_name.replace('/', '_').replace('.', '_').replace(' ', '_')
    device_dir = os.path.join(RRD_DIR, str(device_id))
    os.makedirs(device_dir, exist_ok=True)
    return os.path.join(device_dir, f"{safe_name}.rrd")

def create_rrd(device_id, interface_name, step=7200):
    """Create RRD file for an interface
    Step 7200s = 2 hours (matches collection interval)
    """
    path = get_rrd_path(device_id, interface_name)
    if os.path.exists(path):
        return path

    heartbeat = step * 3  # 3x step = 6 jam max gap

    rrdtool.create(
        path,
        '--step', str(step),
        '--start', '0',

        # Data Sources — GAUGE karena kita pre-calculate bps
        f'DS:in_bps:GAUGE:{heartbeat}:0:U',
        f'DS:out_bps:GAUGE:{heartbeat}:0:U',
        f'DS:in_errors:GAUGE:{heartbeat}:0:U',
        f'DS:out_errors:GAUGE:{heartbeat}:0:U',

        # RRA: 2hr resolution → 1 week (84 points)
        'RRA:AVERAGE:0.5:1:84',
        'RRA:MAX:0.5:1:84',

        # RRA: 6hr resolution → 1 month (120 points)
        'RRA:AVERAGE:0.5:3:120',
        'RRA:MAX:0.5:3:120',

        # RRA: 1day resolution → 1 year (365 points)
        'RRA:AVERAGE:0.5:12:365',
        'RRA:MAX:0.5:12:365',
    )
    return path

def update_rrd(device_id, interface_name, timestamp, in_octets, out_octets, in_errors=0, out_errors=0):
    """Update RRD with new data point"""
    try:
        path = get_rrd_path(device_id, interface_name)
        if not os.path.exists(path):
            create_rrd(device_id, interface_name)

        # Pakai time.time() style — avoid utcnow().timestamp() bug
        if hasattr(timestamp, 'timestamp'):
            # datetime object — convert properly
            if timestamp.tzinfo is None:
                # naive datetime — assume UTC, use time.time() offset trick
                import calendar
                ts = calendar.timegm(timestamp.timetuple())
            else:
                ts = int(timestamp.timestamp())
        else:
            ts = int(timestamp)
        rrdtool.update(
            path,
            f"{ts}:{in_octets}:{out_octets}:{in_errors}:{out_errors}"
        )
        return True
    except Exception as e:
        print(f"RRD update error {device_id}/{interface_name}: {e}")
        return False

def fetch_rrd(device_id, interface_name, timerange='24h'):
    """
    Fetch RRD data for a timerange
    Returns list of {timestamp, in_mbps, out_mbps}
    """
    path = get_rrd_path(device_id, interface_name)
    if not os.path.exists(path):
        return []

    # Timerange mapping
    timerange_map = {
        '1h':   ('-1h',  'AVERAGE', 1),
        '6h':   ('-6h',  'AVERAGE', 1),
        '24h':  ('-1d',  'AVERAGE', 6),
        '7d':   ('-1w',  'AVERAGE', 6),
        '30d':  ('-1month', 'AVERAGE', 24),
        '1y':   ('-1y',  'AVERAGE', 288),
    }

    start, cf, _ = timerange_map.get(timerange, ('-1d', 'AVERAGE', 6))

    try:
        result = rrdtool.fetch(path, cf, '--start', start)
        start_ts, end_ts, step = result[0]
        ds_names = result[1]
        rows = result[2]

        in_idx = ds_names.index('in_bps')
        out_idx = ds_names.index('out_bps')

        points = []
        ts = start_ts
        for row in rows:
            if row[in_idx] is not None and row[out_idx] is not None:
                # Convert bytes/sec to Mbps
                in_mbps = round(row[in_idx] / 1_000_000, 3)
                out_mbps = round(row[out_idx] / 1_000_000, 3)
                points.append({'ts': ts * 1000, 'in': in_mbps, 'out': out_mbps})
            else:
                # Include null for gaps — Chart.js will show gap in line
                points.append({'ts': ts * 1000, 'in': None, 'out': None})
            ts += step

        # Trim leading/trailing nulls (no data at boundaries)
        while points and points[0]['in'] is None:
            points.pop(0)
        while points and points[-1]['in'] is None:
            points.pop()

        return points
    except Exception as e:
        print(f"RRD fetch error {device_id}/{interface_name}: {e}")
        return []

def fetch_rrd_custom(device_id, interface_name, start_ts, end_ts):
    """Fetch RRD data for custom date range"""
    path = get_rrd_path(device_id, interface_name)
    if not os.path.exists(path):
        return []
    try:
        result = rrdtool.fetch(
            path, 'AVERAGE',
            '--start', str(int(start_ts)),
            '--end', str(int(end_ts))
        )
        start_r, end_r, step = result[0]
        ds_names = result[1]
        rows = result[2]

        in_idx = ds_names.index('in_bps')
        out_idx = ds_names.index('out_bps')

        points = []
        ts = start_r
        for row in rows:
            if row[in_idx] is not None and row[out_idx] is not None:
                in_mbps = round(row[in_idx] / 1_000_000, 3)
                out_mbps = round(row[out_idx] / 1_000_000, 3)
                points.append({'ts': ts * 1000, 'in': in_mbps, 'out': out_mbps})
            else:
                points.append({'ts': ts * 1000, 'in': None, 'out': None})
            ts += step

        # Trim leading/trailing nulls
        while points and points[0]['in'] is None:
            points.pop(0)
        while points and points[-1]['in'] is None:
            points.pop()

        return points
    except Exception as e:
        print(f"RRD fetch custom error: {e}")
        return []

def get_rrd_stats(device_id, interface_name):
    """Get RRD file info/stats"""
    path = get_rrd_path(device_id, interface_name)
    if not os.path.exists(path):
        return None
    try:
        info = rrdtool.info(path)
        return {
            'path': path,
            'size': os.path.getsize(path),
            'last_update': info.get('last_update', 0)
        }
    except:
        return None

if __name__ == '__main__':
    # Test
    print("Testing RRD manager...")
    path = create_rrd(999, 'test-interface')
    print(f"✅ Created: {path}")
    import datetime
    update_rrd(999, 'test-interface', datetime.datetime.now(), 1000000, 500000)
    print("✅ Updated")
    import shutil
    shutil.rmtree('/opt/isp-monitoring/rrd/999', ignore_errors=True)
    print("✅ RRD manager OK")
