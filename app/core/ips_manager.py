"""
IPS/IDS Rules Manager
- Quản lý threat intelligence rules từ các public sources
- Hỗ trợ quét flows để phát hiện threat
"""

import os
import pandas as pd
import uuid
from datetime import datetime
import requests
import io

# Sample IPS Rules được tổng hợp từ các public sources
SAMPLE_IPS_RULES = [
    {
        'rule_id': 'SID-2000001',
        'rule_name': 'Suspicious SSH Brute Force Attempt',
        'source': 'Suricata',
        'protocol': 'TCP',
        'port': '22',
        'severity': 'High',
        'category': 'Authentication Attack',
        'description': 'Detects excessive SSH login attempts from a single source',
        'rule_content': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Suspicious SSH Brute Force"; flow:to_server,established; content:"SSH"; depth:4; sid:2000001;)',
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0',
        'false_positive_rate': 0.02
    },
    {
        'rule_id': 'SID-2000002',
        'rule_name': 'SQL Injection Attack Detection',
        'source': 'OWASP CRS',
        'protocol': 'TCP',
        'port': '80,443',
        'severity': 'Critical',
        'category': 'Web Attack',
        'description': 'Detects SQL injection patterns in HTTP requests',
        'rule_content': 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SQL Injection Attack"; uricontent:"/";  pcre:"/union|select|insert|update|delete|drop|create/i"; sid:2000002;)',
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0',
        'false_positive_rate': 0.01
    },
    {
        'rule_id': 'SID-2000003',
        'rule_name': 'Port Scanning Activity Detected',
        'source': 'Snort',
        'protocol': 'TCP',
        'port': 'any',
        'severity': 'Medium',
        'category': 'Reconnaissance',
        'description': 'Detects port scanning attempts using SYN packets',
        'rule_content': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Port Scanning"; flags:S; flow:stateless; threshold: type by_src, track by_src, count 20, seconds 60; sid:2000003;)',
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0',
        'false_positive_rate': 0.05
    },
    {
        'rule_id': 'SID-2000004',
        'rule_name': 'Malware C2 Communication Pattern',
        'source': 'Alien Vault OTX',
        'protocol': 'TCP',
        'port': 'any',
        'severity': 'Critical',
        'category': 'Malware',
        'description': 'Detects known malware command and control server communication',
        'rule_content': 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Malware C2 Communication"; http_header; content:"User-Agent|3a|" http_header; content:"WinHTTP"; sid:2000004;)',
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0',
        'false_positive_rate': 0.001
    },
    {
        'rule_id': 'SID-2000005',
        'rule_name': 'DNS Tunneling Detection',
        'source': 'Snort',
        'protocol': 'UDP',
        'port': '53',
        'severity': 'High',
        'category': 'Data Exfiltration',
        'description': 'Detects DNS query patterns consistent with DNS tunneling attacks',
        'rule_content': 'alert dns $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DNS Tunneling"; dns_query; content:"."; distance:50; within:100; sid:2000005;)',
        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0',
        'false_positive_rate': 0.03
    },
]

class IPSRulesManager:
    """Quản lý IPS/IDS Rules"""
    
    def __init__(self, app=None):
        self.app = app
        self.rules_path = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Khởi tạo IPS Manager với Flask app"""
        self.app = app
        base_folder = app.config.get('BASE_FOLDER', '.')
        ips_folder = os.path.join(base_folder, 'storage', 'ips')
        os.makedirs(ips_folder, exist_ok=True)
        self.rules_path = os.path.join(ips_folder, 'ips_rules.csv')
        
        # Tạo rules database nếu chưa tồn tại
        if not os.path.exists(self.rules_path):
            self.initialize_rules_database()
    
    def initialize_rules_database(self):
        """Tạo database rules từ sample data"""
        try:
            df = pd.DataFrame(SAMPLE_IPS_RULES)
            os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
            df.to_csv(self.rules_path, sep='#', index=False)
            print(f"[IPS Manager] Initialized rules database at {self.rules_path}")
        except Exception as e:
            print(f"[IPS Manager] Error initializing rules: {e}")
    
    def get_all_rules(self, limit=None, offset=0):
        """Lấy danh sách tất cả rules"""
        try:
            if not os.path.exists(self.rules_path):
                return []
            
            df = pd.read_csv(self.rules_path, sep='#')
            
            # Sorting theo last_updated (mới nhất trước)
            df['last_updated'] = pd.to_datetime(df['last_updated'], errors='coerce')
            df = df.sort_values(by='last_updated', ascending=False)
            
            if limit:
                df = df.iloc[offset:offset+limit]
            
            return df.to_dict('records')
        except Exception as e:
            print(f"[IPS Manager] Error reading rules: {e}")
            return []
    
    def get_rule_by_id(self, rule_id):
        """Lấy chi tiết rule theo ID"""
        try:
            if not os.path.exists(self.rules_path):
                return None
            
            df = pd.read_csv(self.rules_path, sep='#')
            record = df[df['rule_id'] == rule_id]
            
            if not record.empty:
                return record.iloc[0].to_dict()
            return None
        except Exception as e:
            print(f"[IPS Manager] Error reading rule: {e}")
            return None
    
    def search_rules(self, keyword):
        """Tìm kiếm rules theo keyword"""
        try:
            if not os.path.exists(self.rules_path):
                return []
            
            df = pd.read_csv(self.rules_path, sep='#')
            
            # Tìm kiếm trong các cột chính
            mask = (
                df['rule_name'].str.contains(keyword, case=False, na=False) |
                df['description'].str.contains(keyword, case=False, na=False) |
                df['category'].str.contains(keyword, case=False, na=False)
            )
            
            return df[mask].to_dict('records')
        except Exception as e:
            print(f"[IPS Manager] Error searching rules: {e}")
            return []
    
    def add_rule(self, rule_data):
        """Thêm rule mới"""
        try:
            if not os.path.exists(self.rules_path):
                df = pd.DataFrame([rule_data])
            else:
                df = pd.read_csv(self.rules_path, sep='#')
                df = pd.concat([df, pd.DataFrame([rule_data])], ignore_index=True)
            
            df.to_csv(self.rules_path, sep='#', index=False)
            return True
        except Exception as e:
            print(f"[IPS Manager] Error adding rule: {e}")
            return False
    
    def get_rules_by_severity(self, severity):
        """Lấy rules theo mức độ nghiêm trọng"""
        try:
            if not os.path.exists(self.rules_path):
                return []
            
            df = pd.read_csv(self.rules_path, sep='#')
            return df[df['severity'] == severity].to_dict('records')
        except Exception as e:
            print(f"[IPS Manager] Error filtering by severity: {e}")
            return []
    
    def get_rules_by_category(self, category):
        """Lấy rules theo loại threat"""
        try:
            if not os.path.exists(self.rules_path):
                return []
            
            df = pd.read_csv(self.rules_path, sep='#')
            return df[df['category'] == category].to_dict('records')
        except Exception as e:
            print(f"[IPS Manager] Error filtering by category: {e}")
            return []
    
    def get_statistics(self):
        """Lấy thống kê về rules"""
        try:
            if not os.path.exists(self.rules_path):
                return {
                    'total_rules': 0,
                    'critical_rules': 0,
                    'high_rules': 0,
                    'medium_rules': 0,
                    'low_rules': 0,
                    'categories': []
                }
            
            df = pd.read_csv(self.rules_path, sep='#')
            
            return {
                'total_rules': len(df),
                'critical_rules': len(df[df['severity'] == 'Critical']),
                'high_rules': len(df[df['severity'] == 'High']),
                'medium_rules': len(df[df['severity'] == 'Medium']),
                'low_rules': len(df[df['severity'] == 'Low']),
                'categories': df['category'].unique().tolist()
            }
        except Exception as e:
            print(f"[IPS Manager] Error getting statistics: {e}")
            return {}
    
    def import_rules_from_file(self, file_obj):
        """Import rules từ file CSV"""
        try:
            # Đọc file từ file object
            df_new = pd.read_csv(file_obj, sep='#')
            
            # Validate cột bắt buộc
            required_cols = ['rule_id', 'rule_name', 'severity', 'category']
            missing_cols = [col for col in required_cols if col not in df_new.columns]
            
            if missing_cols:
                return {
                    'success': False,
                    'message': f"Missing required columns: {', '.join(missing_cols)}"
                }
            
            # Đọc rules hiện tại
            if os.path.exists(self.rules_path):
                df_existing = pd.read_csv(self.rules_path, sep='#')
            else:
                df_existing = pd.DataFrame()
            
            # Thêm timestamp và các cột mặc định nếu thiếu
            if 'last_updated' not in df_new.columns:
                df_new['last_updated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if 'version' not in df_new.columns:
                df_new['version'] = '1.0'
            if 'false_positive_rate' not in df_new.columns:
                df_new['false_positive_rate'] = 0.0
            if 'source' not in df_new.columns:
                df_new['source'] = 'Custom'
            
            # Hợp nhất - loại bỏ duplicates theo rule_id
            if not df_existing.empty:
                df_combined = pd.concat([df_existing, df_new], ignore_index=True)
                df_combined = df_combined.drop_duplicates(subset=['rule_id'], keep='last')
            else:
                df_combined = df_new
            
            # Lưu
            df_combined.to_csv(self.rules_path, sep='#', index=False)
            
            return {
                'success': True,
                'message': f"Imported {len(df_new)} rules successfully",
                'imported_count': len(df_new)
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Error importing rules: {str(e)}"
            }
    
    def import_rules_from_url(self, url):
        """Import rules từ URL (CSV file)"""
        try:
            # Tải file từ URL
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Đọc CSV từ content
            file_obj = io.StringIO(response.text)
            return self.import_rules_from_file(file_obj)
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'message': f"Error downloading from URL: {str(e)}"
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Error importing rules: {str(e)}"
            }
    
    def delete_rule(self, rule_id):
        """Xóa rule theo ID"""
        try:
            if not os.path.exists(self.rules_path):
                return False
            
            df = pd.read_csv(self.rules_path, sep='#')
            df = df[df['rule_id'] != rule_id]
            df.to_csv(self.rules_path, sep='#', index=False)
            return True
        except Exception as e:
            print(f"[IPS Manager] Error deleting rule: {e}")
            return False


# Global instance
ips_manager = IPSRulesManager()
