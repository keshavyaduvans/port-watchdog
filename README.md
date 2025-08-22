# port-watchdog
Port Watchdog is a lightweight, production-ready Python tool for monitoring IP addresses and detecting changes in open ports. It uses Nmap for scanning, keeps a historical record, and alerts you when something changes.  🔐 Designed for security monitoring, sysadmins, and network engineers who need visibility into exposed services.

---<img width="1536" height="1024" alt="ChatGPT Image Aug 22, 2025, 11_56_00 PM" src="https://github.com/user-attachments/assets/f87ec48c-d9ad-47a6-a09c-b40c5a6d71c5" />


# IP Port Monitoring Tool

A production-ready Python tool for monitoring IP addresses and detecting port changes.

## ✨ Features

* Automated **Nmap** scanning at configurable intervals
* Change detection (new/closed ports)
* **Email alerts** for immediate changes
* Weekly summary reports
* Comprehensive logging and audit trails
* Modular design for easy extension
* Docker and systemd service deployment options

## 📦 Requirements

* Python 3.8+
* **Nmapinstalled
* Python package:

  ```
  schedule>=1.2.0
  ```

  (all other dependencies are standard library)

## ⚙️ Configuration

Main configuration file: `config.json`
Example:

```json
{
  "scan_interval_minutes": 60,
  "default_port_range": "1-1000",
  "immediate_alerts": true,
  "weekly_summary_day": "monday",
  "weekly_summary_time": "09:00",
  "log_level": "INFO",
  "log_file": "port_monitor.log",
  "data_directory": "data",
  "ip_list_file": "ip_list.txt",
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "your-email@gmail.com",
    "to_emails": ["admin@company.com", "security@company.com"]
  }
}
```

* IP list file: `ip_list.txt` (one IP per line, `#` for comments)
* See `supporting_files.md` for sample configs, Docker setup, and bonus dashboard.

## 🚀 Installation

### 1. Clone repository

```bash
git clone https://github.com/yourusername/ip-port-monitor.git
cd ip-port-monitor
```

### 2. Install dependencies

```bash
sudo apt install python3 python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure

* Edit `config.json` with your settings
* Add target IPs to `ip_list.txt`

### 4. Run

Single scan:

```bash
python3 ip_port_monitor.py --scan-once
```

Continuous monitoring:

```bash
python3 ip_port_monitor.py --config config.json
```

## 🐳 Docker Deployment

```bash
docker-compose up -d
```

(see `docker-compose.yml` and `Dockerfile`)

## 🔧 Service Deployment (Linux)

Systemd unit file example is included in `config_and_setup.md`.

## 📊 Optional Dashboard

A simple Flask dashboard is provided (`ip_port_monitor.py`) for real-time monitoring.

## 🛡 Security Best Practices

* Run under a dedicated user
* Protect `config.json` (chmod 600)
* Use app-specific passwords for email
* Deploy from a secured monitoring network

## 📈 Monitoring & Alerts

* Immediate email alerts for changes
* Weekly summaries`      
* Full audit logs in CSV and JSON


