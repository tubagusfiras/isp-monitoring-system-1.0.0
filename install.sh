#!/bin/bash
# ============================================================
# SDI Monitoring System - Installer v1.0.0
# Supported OS: Ubuntu 20.04+, Debian 11+, Kali Linux 2023+
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       SDI Monitoring System - Installer v1.0.0       ║"
echo "║   Supported: Ubuntu 20.04+, Debian 11+, Kali 2023+  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Check OS
echo -e "${BLUE}🔍 Checking OS compatibility...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
    echo -e "${GREEN}✅ Detected: $PRETTY_NAME${NC}"
    
    case $OS in
        ubuntu)
            if (( $(echo "$OS_VERSION < 20.04" | bc -l) )); then
                echo -e "${RED}❌ Ubuntu 20.04+ required${NC}"
                exit 1
            fi
            ;;
        debian)
            if (( $(echo "$OS_VERSION < 11" | bc -l) )); then
                echo -e "${RED}❌ Debian 11+ required${NC}"
                exit 1
            fi
            ;;
        kali)
            echo -e "${GREEN}✅ Kali Linux detected${NC}"
            ;;
        *)
            echo -e "${YELLOW}⚠️  Unsupported OS: $OS - continuing anyway...${NC}"
            ;;
    esac
else
    echo -e "${RED}❌ Cannot detect OS${NC}"
    exit 1
fi

# ============================================================
# USER INPUT
# ============================================================
echo ""
echo -e "${CYAN}📋 Configuration Setup${NC}"
echo "────────────────────────────────────────"

# DB credentials
read -p "🗄️  Database name [isp_monitoring]: " DB_NAME
DB_NAME=${DB_NAME:-isp_monitoring}

read -p "👤 Database username [sdi_user]: " DB_USER
DB_USER=${DB_USER:-sdi_user}

while true; do
    read -s -p "🔑 Database password: " DB_PASS
    echo ""
    read -s -p "🔑 Confirm password: " DB_PASS2
    echo ""
    if [ "$DB_PASS" = "$DB_PASS2" ]; then
        break
    fi
    echo -e "${RED}❌ Passwords don't match, try again${NC}"
done

# Admin credentials
read -p "👤 Admin username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

while true; do
    read -s -p "🔑 Admin password (min 6 chars): " ADMIN_PASS
    echo ""
    if [ ${#ADMIN_PASS} -ge 6 ]; then
        break
    fi
    echo -e "${RED}❌ Password too short (min 6 chars)${NC}"
done

# Groq API Key
read -p "🤖 Groq API Key (gsk_...): " GROQ_KEY

echo ""
echo -e "${YELLOW}📋 Summary:${NC}"
echo "  DB Name: $DB_NAME"
echo "  DB User: $DB_USER"
echo "  Admin User: $ADMIN_USER"
echo "  Groq API: ${GROQ_KEY:0:10}..."
echo ""
read -p "▶️  Continue installation? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ]; then
    echo -e "${RED}❌ Installation cancelled${NC}"
    exit 1
fi

# ============================================================
# INSTALL DEPENDENCIES
# ============================================================
echo ""
echo -e "${BLUE}📦 Installing dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    postgresql postgresql-contrib \
    nginx \
    git \
    curl \
    snmp snmpd \
    bc \
    libpq-dev python3-dev

echo -e "${GREEN}✅ Dependencies installed${NC}"

# ============================================================
# SETUP POSTGRESQL
# ============================================================
echo ""
echo -e "${BLUE}🗄️  Setting up PostgreSQL...${NC}"

# Start PostgreSQL
systemctl start postgresql
systemctl enable postgresql

# Create DB user & database
sudo -u postgres psql << EOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
    END IF;
END
\$\$;

CREATE DATABASE $DB_NAME OWNER $DB_USER;
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
EOF

echo -e "${GREEN}✅ PostgreSQL configured${NC}"

# ============================================================
# COPY FILES
# ============================================================
echo ""
echo -e "${BLUE}📁 Installing application files...${NC}"

INSTALL_DIR="/opt/isp-monitoring"
mkdir -p $INSTALL_DIR

# Copy all files
cp -r . $INSTALL_DIR/
chmod +x $INSTALL_DIR/scripts/*.py

echo -e "${GREEN}✅ Files installed to $INSTALL_DIR${NC}"

# ============================================================
# SETUP PYTHON VENV
# ============================================================
echo ""
echo -e "${BLUE}🐍 Setting up Python environment...${NC}"

python3 -m venv $INSTALL_DIR/venv
$INSTALL_DIR/venv/bin/pip install --quiet --upgrade pip
$INSTALL_DIR/venv/bin/pip install --quiet \
    flask \
    flask-cors \
    gunicorn \
    psycopg2-binary \
    bcrypt \
    python-dotenv \
    groq \
    psutil \
    pysnmp \
    requests

echo -e "${GREEN}✅ Python environment ready${NC}"

# ============================================================
# SETUP ENV FILE
# ============================================================
echo ""
echo -e "${BLUE}⚙️  Creating configuration...${NC}"

cat > $INSTALL_DIR/.env << EOF
GROQ_API_KEY=$GROQ_KEY
DB_HOST=localhost
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASS
EOF

chmod 600 $INSTALL_DIR/.env

# Update DB config in api.py
sed -i "s/'database': 'isp_monitoring'/'database': '$DB_NAME'/g" $INSTALL_DIR/scripts/api.py
sed -i "s/'user': 'super'/'user': '$DB_USER'/g" $INSTALL_DIR/scripts/api.py
sed -i "s/'password': 'temp123'/'password': '$DB_PASS'/g" $INSTALL_DIR/scripts/api.py

# Update all other scripts
for script in $INSTALL_DIR/scripts/*.py; do
    sed -i "s/'database': 'isp_monitoring'/'database': '$DB_NAME'/g" $script
    sed -i "s/'user': 'super'/'user': '$DB_USER'/g" $script
    sed -i "s/'password': 'temp123'/'password': '$DB_PASS'/g" $script
done

echo -e "${GREEN}✅ Configuration created${NC}"

# ============================================================
# INITIALIZE DATABASE
# ============================================================
echo ""
echo -e "${BLUE}🗄️  Initializing database schema...${NC}"

# Run API once to create tables
cd $INSTALL_DIR
PGPASSWORD=$DB_PASS $INSTALL_DIR/venv/bin/python3 -c "
import psycopg2
conn = psycopg2.connect(host='localhost', database='$DB_NAME', user='$DB_USER', password='$DB_PASS')
cur = conn.cursor()

# Create all tables
cur.execute('''
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL UNIQUE,
    device_type VARCHAR(100),
    snmp_community VARCHAR(100) DEFAULT '"'"'public'"'"',
    snmp_version VARCHAR(10) DEFAULT '"'"'2c'"'"',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS latency_results (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT NOW(),
    rtt_min FLOAT,
    rtt_avg FLOAT,
    rtt_max FLOAT,
    packet_loss FLOAT DEFAULT 0,
    packets_sent INTEGER DEFAULT 5,
    packets_recv INTEGER DEFAULT 5
);

CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    anomaly_type VARCHAR(100),
    severity VARCHAR(50) DEFAULT '"'"'warning'"'"',
    description TEXT,
    detected_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS interface_stats (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    interface_name VARCHAR(100),
    interface_index INTEGER,
    oper_status VARCHAR(20),
    admin_status VARCHAR(20),
    in_octets BIGINT DEFAULT 0,
    out_octets BIGINT DEFAULT 0,
    in_errors BIGINT DEFAULT 0,
    out_errors BIGINT DEFAULT 0,
    in_discards BIGINT DEFAULT 0,
    out_discards BIGINT DEFAULT 0,
    speed BIGINT,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_inventory (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    device_id INTEGER REFERENCES devices(id),
    subnet VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    last_seen TIMESTAMP DEFAULT NOW(),
    first_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(ip_address, mac_address)
);

CREATE TABLE IF NOT EXISTS content_targets (
    id SERIAL PRIMARY KEY,
    target_name VARCHAR(255) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_type VARCHAR(50) DEFAULT '"'"'custom'"'"',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS content_latency_results (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES content_targets(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT NOW(),
    rtt_min FLOAT,
    rtt_avg FLOAT,
    rtt_max FLOAT,
    packet_loss FLOAT DEFAULT 0
);

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
);

CREATE TABLE IF NOT EXISTS auth_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);
''')
conn.commit()
cur.close()
conn.close()
print('Tables created successfully')
"

# Create admin user
PGPASSWORD=$DB_PASS $INSTALL_DIR/venv/bin/python3 -c "
import psycopg2
import bcrypt

conn = psycopg2.connect(host='localhost', database='$DB_NAME', user='$DB_USER', password='$DB_PASS')
cur = conn.cursor()

password_hash = bcrypt.hashpw('$ADMIN_PASS'.encode(), bcrypt.gensalt()).decode()
cur.execute('''
    INSERT INTO auth_users (username, password_hash) 
    VALUES (%s, %s)
    ON CONFLICT (username) DO UPDATE SET password_hash = %s
''', ('$ADMIN_USER', password_hash, password_hash))

conn.commit()
cur.close()
conn.close()
print('Admin user created: $ADMIN_USER')
"

echo -e "${GREEN}✅ Database initialized${NC}"

# ============================================================
# SETUP NGINX
# ============================================================
echo ""
echo -e "${BLUE}🌐 Configuring Nginx...${NC}"

# Remove default nginx config
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/sdi-monitoring << EOF
server {
    listen 80 default_server;
    server_name _;
    root /opt/isp-monitoring/web;
    index index.html;

    # Disable cache for development
    add_header Cache-Control "no-store, no-cache, must-revalidate";

    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;
        if (\$request_method = 'OPTIONS') {
            return 204;
        }
    }
}
EOF

ln -sf /etc/nginx/sites-available/sdi-monitoring /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx
systemctl enable nginx

echo -e "${GREEN}✅ Nginx configured${NC}"

# ============================================================
# SETUP SYSTEMD SERVICES
# ============================================================
echo ""
echo -e "${BLUE}⚙️  Setting up services...${NC}"

# API Service
cat > /etc/systemd/system/sdi-api.service << EOF
[Unit]
Description=SDI Monitoring API Service
After=network.target postgresql.service

[Service]
Type=notify
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 6 --timeout 120 --access-logfile /tmp/flask_api.log --error-logfile /tmp/flask_api_error.log --capture-output --log-level warning scripts.api:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Latency Monitor
cat > /etc/systemd/system/sdi-latency.service << EOF
[Unit]
Description=SDI Latency Monitor
After=network.target postgresql.service sdi-api.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/latency_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Content Latency Monitor
cat > /etc/systemd/system/sdi-content-latency.service << EOF
[Unit]
Description=SDI Content Latency Monitor
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/content_latency_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Interface Collect Timer
cat > /etc/systemd/system/sdi-interface-collect.service << EOF
[Unit]
Description=SDI Interface Collection
After=network.target postgresql.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/interface_monitor_v2.py
EOF

cat > /etc/systemd/system/sdi-interface-collect.timer << EOF
[Unit]
Description=SDI Interface Collection Timer

[Timer]
OnBootSec=60sec
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

# Anomaly Cleanup Timer
cat > /etc/systemd/system/sdi-anomaly-cleanup.service << EOF
[Unit]
Description=SDI Anomaly Cleanup
After=postgresql.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/cleanup_anomalies.py
EOF

cat > /etc/systemd/system/sdi-anomaly-cleanup.timer << EOF
[Unit]
Description=Run anomaly cleanup every 10 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF

# Cleanup Inactive Devices Timer
cat > /etc/systemd/system/sdi-cleanup-inactive.service << EOF
[Unit]
Description=SDI Cleanup Inactive Devices
After=postgresql.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/cleanup_inactive_devices.py
EOF

cat > /etc/systemd/system/sdi-cleanup-inactive.timer << EOF
[Unit]
Description=Run inactive device cleanup daily

[Timer]
OnBootSec=5min
OnCalendar=daily

[Install]
WantedBy=timers.target
EOF

# Server Metrics Timer
cat > /etc/systemd/system/sdi-server-metrics.service << EOF
[Unit]
Description=SDI Server Metrics Collector
After=network.target postgresql.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/server_metrics_monitor.py
EOF

cat > /etc/systemd/system/sdi-server-metrics.timer << EOF
[Unit]
Description=Collect server metrics every minute

[Timer]
OnBootSec=30sec
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF

# Data Retention Timer
cat > /etc/systemd/system/sdi-retention.service << EOF
[Unit]
Description=SDI Data Retention
After=postgresql.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/isp-monitoring
Environment="PATH=/opt/isp-monitoring/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/isp-monitoring/venv/bin/python3 /opt/isp-monitoring/scripts/data_retention.py
EOF

cat > /etc/systemd/system/sdi-retention.timer << EOF
[Unit]
Description=SDI Data Retention Timer - Daily at 3AM

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Reload & enable all
systemctl daemon-reload

systemctl enable --now sdi-api.service
systemctl enable --now sdi-latency.service
systemctl enable --now sdi-content-latency.service
systemctl enable --now sdi-interface-collect.timer
systemctl enable --now sdi-anomaly-cleanup.timer
systemctl enable --now sdi-cleanup-inactive.timer
systemctl enable --now sdi-server-metrics.timer
systemctl enable --now sdi-retention.timer

echo -e "${GREEN}✅ All services configured${NC}"

# ============================================================
# FIREWALL
# ============================================================
echo ""
echo -e "${BLUE}🔒 Configuring firewall...${NC}"

if command -v ufw &> /dev/null; then
    ufw allow 80/tcp
    ufw allow 22/tcp
    echo -e "${GREEN}✅ UFW firewall configured${NC}"
else
    echo -e "${YELLOW}⚠️  UFW not found - skipping firewall setup${NC}"
fi

# ============================================================
# FINAL CHECK
# ============================================================
echo ""
echo -e "${BLUE}🔍 Running final checks...${NC}"
sleep 3

# Check services
SERVICES=("sdi-api" "sdi-latency" "sdi-content-latency")
ALL_OK=true
for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $svc; then
        echo -e "${GREEN}  ✅ $svc - running${NC}"
    else
        echo -e "${RED}  ❌ $svc - failed${NC}"
        ALL_OK=false
    fi
done

# Check nginx
if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}  ✅ nginx - running${NC}"
else
    echo -e "${RED}  ❌ nginx - failed${NC}"
    ALL_OK=false
fi

# Get IP
IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
if [ "$ALL_OK" = true ]; then
echo -e "${CYAN}║${NC} ${GREEN}🎉 Installation Complete!${NC}                              ${CYAN}║${NC}"
else
echo -e "${CYAN}║${NC} ${YELLOW}⚠️  Installation done with warnings${NC}                   ${CYAN}║${NC}"
fi
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  🌐 Access: ${GREEN}http://$IP${NC}"
echo -e "${CYAN}║${NC}  👤 Username: ${GREEN}$ADMIN_USER${NC}"
echo -e "${CYAN}║${NC}  🔑 Password: ${GREEN}[your chosen password]${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
