# Supporting Files for IP Port Monitoring Tool

## 📋 requirements.txt
```txt
schedule>=1.2.0
# All other dependencies are Python standard library:
# json, csv, logging, smtplib, subprocess, datetime, pathlib, argparse, time, os, sys, typing
```

## 📝 sample_ip_list.txt
```txt
# Production Web Servers
192.168.1.100
192.168.1.101
192.168.1.102

# Database Servers  
192.168.2.50
192.168.2.51

# Load Balancers
10.0.1.10
10.0.1.11

# DMZ Servers
203.0.113.10
203.0.113.20

# Development Environment
172.16.0.100
172.16.0.101

# Comments are ignored (lines starting with #)
# Empty lines are also ignored
```

## ⚙️ config_production.json
```json
{
  "scan_interval_minutes": 30,
  "default_port_range": "22,80,443,3306,5432,6379,8080,8443,9090",
  "immediate_alerts": true,
  "weekly_summary_day": "monday",
  "weekly_summary_time": "08:00",
  "log_level": "INFO",
  "log_file": "/var/log/port-monitor/port_monitor.log",
  "data_directory": "/var/lib/port-monitor/data",
  "ip_list_file": "/etc/port-monitor/ip_list.txt",
  
  "email": {
    "smtp_server": "smtp.company.com",
    "smtp_port": 587,
    "username": "monitoring@company.com",
    "password": "secure-app-password",
    "from_email": "Port Monitor <monitoring@company.com>",
    "to_emails": [
      "security-team@company.com",
      "network-ops@company.com",
      "soc@company.com"
    ]
  }
}
```

## ⚙️ config_development.json
```json
{
  "scan_interval_minutes": 120,
  "default_port_range": "22,80,443,3000,8000,8080",
  "immediate_alerts": false,
  "weekly_summary_day": "friday",
  "weekly_summary_time": "17:00",
  "log_level": "DEBUG",
  "log_file": "dev_port_monitor.log",
  "data_directory": "dev_data",
  "ip_list_file": "dev_ip_list.txt",
  
  "email": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "dev-alerts@company.com",
    "password": "dev-app-password",
    "from_email": "Dev Port Monitor <dev-alerts@company.com>",
    "to_emails": ["dev-team@company.com"]
  }
}
```

## 🐳 Dockerfile
```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash monitor

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY port_monitor.py .
COPY config.json .
COPY ip_list.txt .

# Create data directory
RUN mkdir -p data logs && chown -R monitor:monitor /app

# Switch to non-root user
USER monitor

# Health check
HEALTHCHECK --interval=300s --timeout=30s --start-period=60s --retries=3 \
    CMD python3 -c "import json; import os; \
        from datetime import datetime, timedelta; \
        try: \
            with open('data/current_results.json') as f: data = json.load(f); \
            last_scan = datetime.fromisoformat(data['timestamp']); \
            exit(0 if datetime.now() - last_scan < timedelta(hours=2) else 1) \
        except: exit(1)"

# Run the application
CMD ["python3", "port_monitor.py", "--config", "config.json"]
```

## 🐳 docker-compose.yml
```yaml
version: '3.8'

services:
  port-monitor:
    build: .
    container_name: port-monitor
    restart: unless-stopped
    
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
    
    environment:
      - TZ=UTC
      - PYTHONUNBUFFERED=1
    
    networks:
      - monitoring
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.1'
          memory: 128M
    
    # Health check
    healthcheck:
      test: ["CMD", "python3", "-c", "import requests; requests.get('http://localhost:8080/health')"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 30s

networks:
  monitoring:
    driver: bridge
```

## 📊 monitoring_dashboard.py (Bonus Web Interface)
```python
#!/usr/bin/env python3
"""
Simple web dashboard for monitoring tool
Run with: python monitoring_dashboard.py
"""

from flask import Flask, render_template, jsonify, request
import json
import csv
from datetime import datetime, timedelta
from pathlib import Path

app = Flask(__name__)

class DashboardAPI:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
    
    def get_current_status(self):
        """Get current scan status"""
        try:
            with open(self.data_dir / 'current_results.json') as f:
                data = json.load(f)
            
            total_ips = len(data['results'])
            total_ports = sum(len(ports) for ports in data['results'].values())
            
            return {
                'status': 'healthy',
                'last_scan': data['timestamp'],
                'total_ips': total_ips,
                'total_open_ports': total_ports,
                'results': data['results']
            }
        except FileNotFoundError:
            return {'status': 'no_data', 'message': 'No scan data available'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def get_recent_changes(self, days=7):
        """Get recent port changes"""
        try:
            with open(self.data_dir / 'port_changes.json') as f:
                changes = json.load(f)
            
            cutoff = datetime.now() - timedelta(days=days)
            recent = [
                c for c in changes 
                if datetime.fromisoformat(c['timestamp']) >= cutoff
            ]
            
            return recent
        except FileNotFoundError:
            return []
        except Exception:
            return []

dashboard_api = DashboardAPI()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    return jsonify(dashboard_api.get_current_status())

@app.route('/api/changes')
def api_changes():
    days = request.args.get('days', 7, type=int)
    return jsonify(dashboard_api.get_recent_changes(days))

@app.route('/health')
def health():
    status = dashboard_api.get_current_status()
    if status['status'] == 'healthy':
        return 'OK', 200
    else:
        return 'UNHEALTHY', 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
```

## 🎯 usage_examples.py
```python
#!/usr/bin/env python3
"""
Usage examples and testing for the IP Port Monitoring Tool
"""

import json
import time
from port_monitor import IPPortMonitor, NetworkScanner, DataManager, EmailAlerter

def test_scanner():
    """Test the network scanner component"""
    config = {
        'default_port_range': '22,80,443'
    