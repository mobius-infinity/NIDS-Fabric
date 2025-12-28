import os
import csv
import json
import psutil
from datetime import datetime
from threading import Lock
from pathlib import Path

class SystemLogger:
    """Manage system logs (API calls, user logins, system metrics)"""
    
    def __init__(self, base_folder):
        self.base_folder = base_folder
        self.logs_folder = os.path.join(base_folder, 'storage', 'system_logs')
        os.makedirs(self.logs_folder, exist_ok=True)
        
        self.api_log_file = os.path.join(self.logs_folder, 'api_calls.csv')
        self.login_log_file = os.path.join(self.logs_folder, 'user_logins.csv')
        self.system_log_file = os.path.join(self.logs_folder, 'system_metrics.csv')
        
        self.lock = Lock()
        self._init_csv_files()
    
    def _init_csv_files(self):
        """Initialize CSV files with headers if they don't exist"""
        # API Calls CSV
        if not os.path.exists(self.api_log_file):
            with open(self.api_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'method', 'endpoint', 'username', 'ip_address', 'status_code', 'response_time_ms'])
        
        # User Logins CSV
        if not os.path.exists(self.login_log_file):
            with open(self.login_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'username', 'ip_address', 'status', 'details'])
        
        # System Metrics CSV
        if not os.path.exists(self.system_log_file):
            with open(self.system_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'metric_type', 'value', 'unit', 'status'])
    
    def log_api_call(self, method, endpoint, username, ip_address, status_code=200, response_time_ms=0):
        """Log API call"""
        with self.lock:
            try:
                with open(self.api_log_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().isoformat(),
                        method,
                        endpoint,
                        username or 'anonymous',
                        ip_address,
                        status_code,
                        response_time_ms
                    ])
            except Exception as e:
                print(f"[SystemLogger] Error logging API call: {e}")
    
    def log_user_login(self, username, ip_address, status='success', details=''):
        """Log user login/logout"""
        with self.lock:
            try:
                with open(self.login_log_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().isoformat(),
                        username,
                        ip_address,
                        status,
                        details
                    ])
            except Exception as e:
                print(f"[SystemLogger] Error logging user login: {e}")
    
    def log_system_metric(self, metric_type, value, unit='', status='normal'):
        """Log system metric (CPU, Memory, Disk, etc.)"""
        with self.lock:
            try:
                with open(self.system_log_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().isoformat(),
                        metric_type,
                        value,
                        unit,
                        status
                    ])
            except Exception as e:
                print(f"[SystemLogger] Error logging system metric: {e}")
    
    def get_api_logs(self, limit=100):
        """Get API call logs"""
        try:
            logs = []
            if os.path.exists(self.api_log_file):
                with open(self.api_log_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        logs.append(row)
            return logs[-limit:][::-1]  # Return last 'limit' entries in reverse order (newest first)
        except Exception as e:
            print(f"[SystemLogger] Error reading API logs: {e}")
            return []
    
    def get_login_logs(self, limit=100):
        """Get user login logs"""
        try:
            logs = []
            if os.path.exists(self.login_log_file):
                with open(self.login_log_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        logs.append(row)
            return logs[-limit:][::-1]  # Return last 'limit' entries in reverse order
        except Exception as e:
            print(f"[SystemLogger] Error reading login logs: {e}")
            return []
    
    def get_system_logs(self, limit=100):
        """Get system metric logs"""
        try:
            logs = []
            if os.path.exists(self.system_log_file):
                with open(self.system_log_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        logs.append(row)
            return logs[-limit:][::-1]  # Return last 'limit' entries in reverse order
        except Exception as e:
            print(f"[SystemLogger] Error reading system logs: {e}")
            return []
    
    def get_current_system_metrics(self):
        """Get current system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_info = psutil.virtual_memory()
            disk_info = psutil.disk_usage('/')
            
            return {
                'cpu_percent': round(cpu_percent, 2),
                'memory_percent': round(memory_info.percent, 2),
                'memory_used_gb': round(memory_info.used / (1024**3), 2),
                'memory_total_gb': round(memory_info.total / (1024**3), 2),
                'disk_percent': round(disk_info.percent, 2),
                'disk_used_gb': round(disk_info.used / (1024**3), 2),
                'disk_total_gb': round(disk_info.total / (1024**3), 2),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"[SystemLogger] Error getting system metrics: {e}")
            return {}

# Global instance
system_logger = None

def init_system_logger(base_folder):
    global system_logger
    system_logger = SystemLogger(base_folder)
    return system_logger

def get_system_logger():
    return system_logger
