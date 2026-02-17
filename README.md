# ISP Monitoring System v1.0.0

Sistem monitoring jaringan ISP berbasis web yang komprehensif.

## Fitur
- 📊 **Dashboard** - Performance monitor server (CPU, Memory, Disk, Network)
- 🖥️ **Device Monitoring** - Real-time device status & latency
- 🗺️ **Topology** - Network topology map
- 🔍 **IP Conflicts** - Deteksi konflik IP
- 📡 **Interfaces** - SNMP interface monitoring
- ⚠️ **Anomalies** - Deteksi & manajemen anomali
- 🌐 **Content Monitor** - Monitoring konten dengan realtime ping
- 🤖 **AI Assistant** - AI berbasis Groq untuk analisis jaringan
- 🔔 **Notification Bell** - Alert critical issues

## Requirements
- Ubuntu 20.04/22.04
- Python 3.10+
- PostgreSQL 14+
- Nginx

## Installation
```bash
git clone https://github.com/tubagusfiras/isp-monitoring-system-1.0.0
cd isp-monitoring-system-1.0.0
chmod +x install.sh
sudo ./install.sh
```

## Configuration
Copy `.env.example` to `.env` and fill in your credentials:
```bash
cp .env.example .env
nano .env
```

## Credits
Built with ❤️ by SDI Team
