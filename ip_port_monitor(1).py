#!/usr/bin/env python3
"""
IP Port Monitoring Tool
=======================
A production-ready Python tool for monitoring IP addresses and detecting port changes.
Features:
- Automated Nmap scanning at configurable intervals
- Change detection (new/closed ports)
- Email alerting with weekly summaries
- Comprehensive logging and audit trails
- Modular design for easy extension

Author: Generated for network security monitoring
Version: 1.0.0
"""

import json
import csv
import logging
import smtplib
import subprocess
import schedule
import time
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple
from pathlib import Path
import argparse

# Email imports with Python 3.13 compatibility
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
except ImportError:
    # Fallback for Python 3.13
    from email.message import EmailMessage
    MimeText = None
    MimeMultipart = None


class NetworkScanner:
    """Handles network scanning operations using Nmap"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def scan_host(self, ip: str, port_range: str = None) -> Dict[str, Set[int]]:
        """
        Scan a single host for open ports
        
        Args:
            ip: IP address to scan
            port_range: Port range (e.g., "1-1000", "22,80,443")
            
        Returns:
            Dictionary with scan results
        """
        port_range = port_range or self.config.get('default_port_range', '1-1000')
        
        try:
            # Build nmap command
            cmd = [
                'nmap', '-sS', '--host-timeout', '30s', 
                '-p', port_range, ip
            ]
            
            self.logger.info(f"Scanning {ip} on ports {port_range}")
            
            # Execute nmap
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            
            if result.returncode != 0:
                self.logger.error(f"Nmap scan failed for {ip}: {result.stderr}")
                return {ip: set()}
            
            # Parse nmap output
            open_ports = self._parse_nmap_output(result.stdout)
            
            self.logger.info(f"Found {len(open_ports)} open ports on {ip}")
            return {ip: open_ports}
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan timeout for {ip}")
            return {ip: set()}
        except Exception as e:
            self.logger.error(f"Error scanning {ip}: {str(e)}")
            return {ip: set()}
    
    def _parse_nmap_output(self, output: str) -> Set[int]:
        """Parse nmap output to extract open ports"""
        open_ports = set()
        
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                try:
                    port = int(line.split('/')[0])
                    open_ports.add(port)
                except ValueError:
                    continue
                    
        return open_ports
    
    def scan_multiple_hosts(self, ip_list: List[str]) -> Dict[str, Set[int]]:
        """Scan multiple hosts"""
        results = {}
        
        for ip in ip_list:
            host_results = self.scan_host(ip)
            results.update(host_results)
            
        return results


class DataManager:
    """Handles data storage and retrieval for scan results"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.data_dir = Path(config.get('data_directory', 'data'))
        self.data_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        # File paths
        self.current_results_file = self.data_dir / 'current_results.json'
        self.history_file = self.data_dir / 'scan_history.csv'
        self.changes_file = self.data_dir / 'port_changes.json'
    
    def save_scan_results(self, results: Dict[str, Set[int]], timestamp: str):
        """Save current scan results"""
        # Convert sets to lists for JSON serialization
        json_results = {
            ip: list(ports) for ip, ports in results.items()
        }
        
        scan_data = {
            'timestamp': timestamp,
            'results': json_results
        }
        
        with open(self.current_results_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
            
        # Also append to history CSV
        self._append_to_history(results, timestamp)
    
    def load_previous_results(self) -> Tuple[Dict[str, Set[int]], str]:
        """Load previous scan results"""
        try:
            with open(self.current_results_file, 'r') as f:
                data = json.load(f)
                
            # Convert lists back to sets
            results = {
                ip: set(ports) for ip, ports in data['results'].items()
            }
            
            return results, data['timestamp']
            
        except FileNotFoundError:
            self.logger.info("No previous scan results found")
            return {}, ""
        except Exception as e:
            self.logger.error(f"Error loading previous results: {str(e)}")
            return {}, ""
    
    def _append_to_history(self, results: Dict[str, Set[int]], timestamp: str):
        """Append scan results to history CSV"""
        try:
            with open(self.history_file, 'a', newline='') as f:
                writer = csv.writer(f)
                
                # Write header if file is new
                if f.tell() == 0:
                    writer.writerow(['timestamp', 'ip', 'open_ports', 'port_count'])
                
                # Write results
                for ip, ports in results.items():
                    writer.writerow([
                        timestamp,
                        ip,
                        ','.join(map(str, sorted(ports))),
                        len(ports)
                    ])
                    
        except Exception as e:
            self.logger.error(f"Error writing to history: {str(e)}")
    
    def detect_changes(self, current_results: Dict[str, Set[int]], 
                      previous_results: Dict[str, Set[int]]) -> Dict:
        """Detect port changes between scans"""
        changes = {
            'new_ports': {},
            'closed_ports': {},
            'timestamp': datetime.now().isoformat()
        }
        
        all_ips = set(current_results.keys()) | set(previous_results.keys())
        
        for ip in all_ips:
            current_ports = current_results.get(ip, set())
            previous_ports = previous_results.get(ip, set())
            
            # Detect new ports
            new_ports = current_ports - previous_ports
            if new_ports:
                changes['new_ports'][ip] = list(new_ports)
            
            # Detect closed ports
            closed_ports = previous_ports - current_ports
            if closed_ports:
                changes['closed_ports'][ip] = list(closed_ports)
        
        # Save changes if any detected
        if changes['new_ports'] or changes['closed_ports']:
            self._save_changes(changes)
            
        return changes
    
    def _save_changes(self, changes: Dict):
        """Save detected changes to file"""
        try:
            # Load existing changes
            existing_changes = []
            if self.changes_file.exists():
                with open(self.changes_file, 'r') as f:
                    existing_changes = json.load(f)
            
            # Append new changes
            existing_changes.append(changes)
            
            # Save updated changes
            with open(self.changes_file, 'w') as f:
                json.dump(existing_changes, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving changes: {str(e)}")
    
    def get_recent_changes(self, days: int = 7) -> List[Dict]:
        """Get changes from the last N days"""
        try:
            if not self.changes_file.exists():
                return []
            
            with open(self.changes_file, 'r') as f:
                all_changes = json.load(f)
            
            # Filter changes from last N days
            cutoff_date = datetime.now() - timedelta(days=days)
            recent_changes = []
            
            for change in all_changes:
                change_date = datetime.fromisoformat(change['timestamp'])
                if change_date >= cutoff_date:
                    recent_changes.append(change)
            
            return recent_changes
            
        except Exception as e:
            self.logger.error(f"Error getting recent changes: {str(e)}")
            return []


class EmailAlerter:
    """Handles email alerting functionality"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Email configuration
        self.smtp_server = config['email']['smtp_server']
        self.smtp_port = config['email']['smtp_port']
        self.username = config['email']['username']
        self.password = config['email']['password']
        self.from_email = config['email']['from_email']
        self.to_emails = config['email']['to_emails']
    
    def send_immediate_alert(self, changes: Dict):
        """Send immediate alert for critical changes"""
        if not changes['new_ports'] and not changes['closed_ports']:
            return
        
        subject = f"Port Monitoring Alert - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        body = self._format_immediate_alert(changes)
        
        self._send_email(subject, body)
    
    def send_weekly_summary(self, data_manager: DataManager):
        """Send weekly summary email"""
        changes = data_manager.get_recent_changes(7)
        
        subject = f"Weekly Port Monitoring Summary - {datetime.now().strftime('%Y-%m-%d')}"
        body = self._format_weekly_summary(changes)
        
        self._send_email(subject, body)
    
    def _format_immediate_alert(self, changes: Dict) -> str:
        """Format immediate alert email body"""
        body = "Port Monitoring Alert\n"
        body += "=" * 50 + "\n\n"
        body += f"Scan Time: {changes['timestamp']}\n\n"
        
        if changes['new_ports']:
            body += "NEW PORTS DETECTED:\n"
            body += "-" * 20 + "\n"
            for ip, ports in changes['new_ports'].items():
                body += f"{ip}: {', '.join(map(str, ports))}\n"
            body += "\n"
        
        if changes['closed_ports']:
            body += "CLOSED PORTS:\n"
            body += "-" * 15 + "\n"
            for ip, ports in changes['closed_ports'].items():
                body += f"{ip}: {', '.join(map(str, ports))}\n"
            body += "\n"
        
        body += "Please investigate these changes immediately.\n"
        body += "\nThis is an automated alert from the IP Port Monitoring Tool."
        
        return body
    
    def _format_weekly_summary(self, changes_list: List[Dict]) -> str:
        """Format weekly summary email body"""
        body = "Weekly Port Monitoring Summary\n"
        body += "=" * 50 + "\n\n"
        body += f"Report Period: {(datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')} to {datetime.now().strftime('%Y-%m-%d')}\n\n"
        
        if not changes_list:
            body += "No port changes detected during this period.\n\n"
        else:
            total_new = sum(len(c.get('new_ports', {})) for c in changes_list)
            total_closed = sum(len(c.get('closed_ports', {})) for c in changes_list)
            
            body += f"Summary:\n"
            body += f"- Total scan events with changes: {len(changes_list)}\n"
            body += f"- New ports detected: {total_new}\n"
            body += f"- Ports closed: {total_closed}\n\n"
            
            body += "Detailed Changes:\n"
            body += "-" * 20 + "\n"
            
            for change in changes_list[-10:]:  # Last 10 changes
                body += f"\nTime: {change['timestamp']}\n"
                
                if change.get('new_ports'):
                    body += "New ports:\n"
                    for ip, ports in change['new_ports'].items():
                        body += f"  {ip}: {', '.join(map(str, ports))}\n"
                
                if change.get('closed_ports'):
                    body += "Closed ports:\n"
                    for ip, ports in change['closed_ports'].items():
                        body += f"  {ip}: {', '.join(map(str, ports))}\n"
        
        body += "\nThis is an automated summary from the IP Port Monitoring Tool."
        return body
    
    def _send_email(self, subject: str, body: str):
        """Send email using SMTP - Python 3.13 compatible"""
        try:
            # Use EmailMessage for Python 3.13 compatibility
            if MimeMultipart is None:
                # Python 3.13+ approach
                from email.message import EmailMessage
                msg = EmailMessage()
                msg['From'] = self.from_email
                msg['To'] = ', '.join(self.to_emails)
                msg['Subject'] = subject
                msg.set_content(body)
            else:
                # Traditional approach for older Python versions
                msg = MimeMultipart()
                msg['From'] = self.from_email
                msg['To'] = ', '.join(self.to_emails)
                msg['Subject'] = subject
                msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            
            if MimeMultipart is None:
                server.send_message(msg)
            else:
                text = msg.as_string()
                server.sendmail(self.from_email, self.to_emails, text)
            
            server.quit()
            
            self.logger.info(f"Email sent successfully: {subject}")
            
        except Exception as e:
            self.logger.error(f"Failed to send email: {str(e)}")


class IPPortMonitor:
    """Main monitoring class that orchestrates all components"""
    
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self._setup_logging()
        
        # Initialize components
        self.scanner = NetworkScanner(self.config)
        self.data_manager = DataManager(self.config)
        self.emailer = EmailAlerter(self.config)
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("IP Port Monitor initialized")
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {str(e)}")
            sys.exit(1)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        log_file = self.config.get('log_file', 'port_monitor.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def load_ip_list(self) -> List[str]:
        """Load IP addresses to monitor"""
        ip_file = self.config.get('ip_list_file', 'ip_list.txt')
        
        try:
            with open(ip_file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"Loaded {len(ips)} IP addresses to monitor")
            return ips
            
        except FileNotFoundError:
            self.logger.error(f"IP list file not found: {ip_file}")
            return []
        except Exception as e:
            self.logger.error(f"Error loading IP list: {str(e)}")
            return []
    
    def run_scan(self):
        """Execute a single scan cycle"""
        self.logger.info("Starting scan cycle")
        
        try:
            # Load IPs to scan
            ip_list = self.load_ip_list()
            if not ip_list:
                self.logger.warning("No IPs to scan")
                return
            
            # Perform scan
            current_results = self.scanner.scan_multiple_hosts(ip_list)
            timestamp = datetime.now().isoformat()
            
            # Load previous results
            previous_results, _ = self.data_manager.load_previous_results()
            
            # Detect changes
            changes = self.data_manager.detect_changes(current_results, previous_results)
            
            # Save current results
            self.data_manager.save_scan_results(current_results, timestamp)
            
            # Send immediate alerts if needed
            if (changes['new_ports'] or changes['closed_ports']) and self.config.get('immediate_alerts', True):
                self.emailer.send_immediate_alert(changes)
            
            self.logger.info("Scan cycle completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error in scan cycle: {str(e)}")
    
    def send_weekly_summary(self):
        """Send weekly summary email"""
        try:
            self.emailer.send_weekly_summary(self.data_manager)
            self.logger.info("Weekly summary sent")
        except Exception as e:
            self.logger.error(f"Error sending weekly summary: {str(e)}")
    
    def start_monitoring(self):
        """Start the monitoring service"""
        self.logger.info("Starting IP Port Monitoring Service")
        
        # Schedule regular scans
        scan_interval = self.config.get('scan_interval_minutes', 60)
        schedule.every(scan_interval).minutes.do(self.run_scan)
        
        # Schedule weekly summary
        summary_day = self.config.get('weekly_summary_day', 'monday')
        summary_time = self.config.get('weekly_summary_time', '09:00')
        getattr(schedule.every(), summary_day).at(summary_time).do(self.send_weekly_summary)
        
        # Run initial scan
        self.run_scan()
        
        # Main monitoring loop
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {str(e)}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='IP Port Monitoring Tool')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--scan-once', action='store_true', help='Run single scan and exit')
    parser.add_argument('--weekly-summary', action='store_true', help='Send weekly summary and exit')
    
    args = parser.parse_args()
    
    # Initialize monitor
    monitor = IPPortMonitor(args.config)
    
    if args.scan_once:
        monitor.run_scan()
    elif args.weekly_summary:
        monitor.send_weekly_summary()
    else:
        monitor.start_monitoring()


if __name__ == '__main__':
    main()
