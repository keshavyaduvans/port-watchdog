# IP Port Monitoring Tool - Configuration and Setup

## Configuration File (config.json)

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

## IP List File (ip_list.txt)

```
192.168.1.1
192.168.1.100
10.0.0.1
203.0.113.1
198.51.100.1
# Add your IP addresses here, one per line
# Comments starting with # are ignored
```

## Installation and Setup Instructions

### Prerequisites

1. **Python 3.8+** installed
2. **Nmap** installed on the system
3. **Email account** with app-specific password (for Gmail)

### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap python3 python3-pip python3-venv
```

**CentOS/RHEL:**
```bash
sudo yum install nmap python3 python3-pip
# or for newer versions:
sudo dnf install nmap python3 python3-pip
```

### Step 2: Create Project Directory

```bash
mkdir ip-port-monitor
cd ip-port-monitor
```

### Step 3: Create Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# venv\Scripts\activate     # On Windows
```

### Step 4: Install Python Dependencies

```bash
pip install schedule
```

Note: The tool uses only standard library modules except for `schedule`. All other dependencies (`json`, `csv`, `logging`, `smtplib`, `subprocess`, etc.) are built-in.

### Step 5: Setup Configuration Files

1. **Create config.json:**
   - Copy the configuration example above
   - Update email settings with your SMTP details
   - Adjust scan intervals and port ranges as needed

2. **Create ip_list.txt:**
   - Add IP addresses you want to monitor, one per line
   - Use # for comments

3. **Set up email authentication:**
   - For Gmail: Enable 2FA and create an app-specific password
   - For other providers: Use appropriate SMTP settings

### Step 6: Test the Installation

```bash
# Test single scan
python3 port_monitor.py --scan-once

# Test configuration
python3 port_monitor.py --config config.json --scan-once
```

### Step 7: Set up as a System Service (Production Deployment)

**Create systemd service file:**
```bash
sudo nano /etc/systemd/system/port-monitor.service
```

**Service configuration:**
```ini
[Unit]
Description=IP Port Monitor Service
After=network.target

[Service]
Type=simple
User=monitor
Group=monitor
WorkingDirectory=/opt/port-monitor
Environment=PATH=/opt/port-monitor/venv/bin
ExecStart=/opt/port-monitor/venv/bin/python port_monitor.py --config config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start the service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable port-monitor.service
sudo systemctl start port-monitor.service
```

### Step 8: Monitoring and Maintenance

**Check service status:**
```bash
sudo systemctl status port-monitor.service
```

**View logs:**
```bash
# Service logs
sudo journalctl -u port-monitor.service -f

# Application logs
tail -f /opt/port-monitor/port_monitor.log
```

**Log rotation setup:**
```bash
sudo nano /etc/logrotate.d/port-monitor
```

```
/opt/port-monitor/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 monitor monitor
    postrotate
        systemctl reload port-monitor.service > /dev/null 2>&1 || true
    endscript
}
```

## Security Best Practices

1. **Run with dedicated user:**
   ```bash
   sudo useradd -r -s /bin/false monitor
   sudo chown -R monitor:monitor /opt/port-monitor
   ```

2. **Set proper file permissions:**
   ```bash
   chmod 600 config.json  # Protect email credentials
   chmod 644 port_monitor.py
   chmod 644 ip_list.txt
   ```

3. **Use app-specific passwords:**
   - Never use your main email password
   - Use OAuth2 when possible

4. **Network security:**
   - Run scans from a dedicated monitoring network
   - Consider firewall rules for scan traffic

## Customization Options

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `scan_interval_minutes` | Minutes between scans | 60 |
| `default_port_range` | Default port range to scan | "1-1000" |
| `immediate_alerts` | Send alerts for immediate changes | true |
| `weekly_summary_day` | Day for weekly summary | "monday" |
| `weekly_summary_time` | Time for weekly summary | "09:00" |
| `log_level` | Logging level (DEBUG/INFO/WARNING/ERROR) | "INFO" |

### Extending the Tool

The tool is designed with modularity in mind:

1. **Add new notification channels:**
   - Extend the `EmailAlerter` class
   - Add Slack/Teams integration

2. **Database integration:**
   - Replace file-based storage in `DataManager`
   - Add PostgreSQL/MySQL support

3. **Web dashboard:**
   - Create Flask/FastAPI wrapper
   - Add real-time monitoring interface

4. **Advanced scanning:**
   - Add service detection
   - Integrate vulnerability scanning

## Troubleshooting

### Common Issues

1. **"nmap: command not found"**
   - Install nmap: `sudo apt install nmap`

2. **Email authentication failed**
   - Check SMTP settings
   - Use app-specific password for Gmail
   - Test with telnet: `telnet smtp.gmail.com 587`

3. **Permission denied errors**
   - Check file permissions
   - Ensure proper user/group ownership

4. **High CPU usage**
   - Reduce scan frequency
   - Limit port ranges
   - Use TCP SYN scan only (-sS flag)

### Performance Optimization

1. **For large IP ranges:**
   - Use parallel scanning (implement threading)
   - Consider network segmentation
   - Use faster scan techniques

2. **For production environments:**
   - Implement connection pooling for emails
   - Use database instead of file storage
   - Add caching for scan results

## Monitoring and Alerting

The tool provides comprehensive monitoring with:

- **Immediate alerts** for port changes
- **Weekly summaries** with trend analysis  
- **Audit logs** for compliance
- **Error handling** with retry mechanisms
- **Health monitoring** with uptime tracking

This ensures 90%+ visibility uptime as required for production security monitoring environments.