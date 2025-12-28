"""
IPS/IDS Rules Manager
- Quản lý threat intelligence rules từ các public sources
- Hỗ trợ quét flows để phát hiện threat
- Hỗ trợ import Snort/Suricata rules format
"""

import os
import pandas as pd
import uuid
import re
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
        self.sources_path = None
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Khởi tạo IPS Manager với Flask app"""
        self.app = app
        base_folder = app.config.get('BASE_FOLDER', '.')
        ips_folder = os.path.join(base_folder, 'storage', 'ips')
        os.makedirs(ips_folder, exist_ok=True)
        self.rules_path = os.path.join(ips_folder, 'ips_rules.csv')
        self.sources_path = os.path.join(ips_folder, 'ips_sources.csv')
        
        # Tạo rules database nếu chưa tồn tại
        if not os.path.exists(self.rules_path):
            self.initialize_rules_database()
        
        # Tạo sources database nếu chưa tồn tại
        if not os.path.exists(self.sources_path):
            self.initialize_sources_database()
    
    def initialize_rules_database(self):
        """Tạo database rules từ sample data"""
        try:
            df = pd.DataFrame(SAMPLE_IPS_RULES)
            os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
            df.to_csv(self.rules_path, sep='#', index=False)
            print(f"[IPS Manager] Initialized rules database at {self.rules_path}")
        except Exception as e:
            print(f"[IPS Manager] Error initializing rules: {e}")
    
    def initialize_sources_database(self):
        """Tạo sources database trống"""
        try:
            columns = ['id', 'name', 'url', 'interval_minutes', 'last_update', 'last_status', 
                       'rules_count', 'enabled', 'created_at', 'error_message']
            df = pd.DataFrame(columns=columns)
            os.makedirs(os.path.dirname(self.sources_path), exist_ok=True)
            df.to_csv(self.sources_path, sep='#', index=False)
            print(f"[IPS Manager] Initialized sources database at {self.sources_path}")
        except Exception as e:
            print(f"[IPS Manager] Error initializing sources: {e}")
    
    # ============= SOURCES MANAGEMENT =============
    
    def get_all_sources(self):
        """Lấy danh sách tất cả sources"""
        try:
            if not os.path.exists(self.sources_path):
                return []
            
            df = pd.read_csv(self.sources_path, sep='#')
            if df.empty:
                return []
            
            # Convert to list of dicts
            sources = df.to_dict('records')
            
            # Check if any source needs update
            for source in sources:
                source['needs_update'] = self._check_source_needs_update(source)
            
            return sources
        except Exception as e:
            print(f"[IPS Manager] Error reading sources: {e}")
            return []
    
    def _check_source_needs_update(self, source):
        """Kiểm tra source có cần update không"""
        try:
            if not source.get('enabled', True):
                return False
            
            last_update = source.get('last_update')
            if not last_update or pd.isna(last_update):
                return True
            
            interval = int(source.get('interval_minutes', 10))
            last_update_dt = pd.to_datetime(last_update)
            next_update = last_update_dt + pd.Timedelta(minutes=interval)
            
            return datetime.now() >= next_update
        except:
            return True
    
    def add_source(self, name, url, interval_minutes=10):
        """Thêm nguồn IDS rules mới"""
        try:
            source_id = str(uuid.uuid4())[:8]
            
            new_source = {
                'id': source_id,
                'name': name,
                'url': url,
                'interval_minutes': interval_minutes,
                'last_update': None,
                'last_status': 'pending',
                'rules_count': 0,
                'enabled': True,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error_message': ''
            }
            
            if os.path.exists(self.sources_path):
                df = pd.read_csv(self.sources_path, sep='#')
                # Check duplicate URL
                if not df.empty and url in df['url'].values:
                    return {'success': False, 'message': 'Source URL already exists'}
                df = pd.concat([df, pd.DataFrame([new_source])], ignore_index=True)
            else:
                df = pd.DataFrame([new_source])
            
            df.to_csv(self.sources_path, sep='#', index=False)
            
            return {
                'success': True, 
                'message': 'Source added successfully',
                'source_id': source_id
            }
        except Exception as e:
            return {'success': False, 'message': f'Error adding source: {str(e)}'}
    
    def update_source(self, source_id, **kwargs):
        """Cập nhật thông tin source"""
        try:
            if not os.path.exists(self.sources_path):
                return {'success': False, 'message': 'Sources database not found'}
            
            df = pd.read_csv(self.sources_path, sep='#')
            idx = df[df['id'] == source_id].index
            
            if idx.empty:
                return {'success': False, 'message': 'Source not found'}
            
            # Update allowed fields (including url now)
            allowed_fields = ['name', 'url', 'interval_minutes', 'enabled']
            for field in allowed_fields:
                if field in kwargs:
                    df.loc[idx, field] = kwargs[field]
            
            df.to_csv(self.sources_path, sep='#', index=False)
            return {'success': True, 'message': 'Source updated successfully'}
        except Exception as e:
            return {'success': False, 'message': f'Error updating source: {str(e)}'}
    
    def get_source_by_id(self, source_id):
        """Lấy chi tiết source theo ID"""
        try:
            if not os.path.exists(self.sources_path):
                return None
            
            df = pd.read_csv(self.sources_path, sep='#')
            record = df[df['id'] == source_id]
            
            if record.empty:
                return None
            
            source = record.iloc[0].to_dict()
            source['needs_update'] = self._check_source_needs_update(source)
            
            # Clean NaN values
            for key, value in source.items():
                if pd.isna(value):
                    source[key] = None
            
            return source
        except Exception as e:
            print(f"[IPS Manager] Error getting source: {e}")
            return None
    
    def delete_source(self, source_id):
        """Xóa source và tất cả rules của source đó"""
        try:
            if not os.path.exists(self.sources_path):
                return {'success': False, 'message': 'Sources database not found'}
            
            df = pd.read_csv(self.sources_path, sep='#')
            original_len = len(df)
            df = df[df['id'] != source_id]
            
            if len(df) == original_len:
                return {'success': False, 'message': 'Source not found'}
            
            df.to_csv(self.sources_path, sep='#', index=False)
            
            # Xóa tất cả rules của source này
            rules_deleted = 0
            if os.path.exists(self.rules_path):
                df_rules = pd.read_csv(self.rules_path, sep='#')
                original_rules = len(df_rules)
                
                # Check if source_id column exists
                if 'source_id' in df_rules.columns:
                    # Convert source_id to string for proper comparison
                    df_rules['source_id'] = df_rules['source_id'].astype(str).str.strip()
                    source_id_str = str(source_id).strip()
                    
                    print(f"[IPS Manager] Deleting rules with source_id: '{source_id_str}'")
                    print(f"[IPS Manager] Unique source_ids in rules: {df_rules['source_id'].unique()[:10]}")
                    
                    # Filter out rules with matching source_id
                    df_rules = df_rules[df_rules['source_id'] != source_id_str]
                    rules_deleted = original_rules - len(df_rules)
                    
                    print(f"[IPS Manager] Rules deleted: {rules_deleted}")
                    
                    df_rules.to_csv(self.rules_path, sep='#', index=False)
            
            return {
                'success': True, 
                'message': f'Source deleted successfully. Removed {rules_deleted} associated rules.'
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {'success': False, 'message': f'Error deleting source: {str(e)}'}
    
    def refresh_source(self, source_id):
        """Refresh rules từ source - tải và import rules"""
        try:
            if not os.path.exists(self.sources_path):
                return {'success': False, 'message': 'Sources database not found'}
            
            df = pd.read_csv(self.sources_path, sep='#')
            idx = df[df['id'] == source_id].index
            
            if idx.empty:
                return {'success': False, 'message': 'Source not found'}
            
            source = df.loc[idx[0]].to_dict()
            url = source['url']
            source_name = source.get('name', 'Unknown')
            
            print(f"[IPS Manager] Refreshing source: {source_name} from {url}")
            
            # Import rules từ URL
            result = self.import_rules_from_url(url, source_id=source_id)
            
            # Update source status
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if result.get('success'):
                df.loc[idx, 'last_update'] = now
                df.loc[idx, 'last_status'] = 'success'
                df.loc[idx, 'rules_count'] = result.get('imported_count', 0)
                df.loc[idx, 'error_message'] = ''
            else:
                df.loc[idx, 'last_update'] = now
                df.loc[idx, 'last_status'] = 'error'
                df.loc[idx, 'error_message'] = result.get('message', 'Unknown error')
            
            df.to_csv(self.sources_path, sep='#', index=False)
            
            return result
        except Exception as e:
            return {'success': False, 'message': f'Error refreshing source: {str(e)}'}
    
    def refresh_all_sources(self):
        """Refresh tất cả sources cần update"""
        try:
            sources = self.get_all_sources()
            updated = 0
            errors = 0
            
            for source in sources:
                if source.get('enabled', True) and source.get('needs_update', False):
                    result = self.refresh_source(source['id'])
                    if result.get('success'):
                        updated += 1
                    else:
                        errors += 1
            
            return {
                'success': True,
                'updated': updated,
                'errors': errors
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    # ============= END SOURCES MANAGEMENT =============

    def get_all_rules(self, limit=None, offset=0):
        """Lấy danh sách tất cả rules"""
        try:
            if not os.path.exists(self.rules_path):
                return []
            
            df = pd.read_csv(self.rules_path, sep='#')
            
            # Replace NaN with empty string for JSON serialization
            df = df.fillna('')
            
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
            # Replace NaN with empty string
            df = df.fillna('')
            
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
            # Replace NaN with empty string
            df = df.fillna('')
            
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
    
    def import_rules_from_file(self, file_obj, source_id=None):
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
            
            # Thêm source_id nếu có
            if source_id:
                df_new['source_id'] = source_id
                # Xóa rules cũ của source này
                if not df_existing.empty and 'source_id' in df_existing.columns:
                    df_existing = df_existing[df_existing['source_id'] != source_id]
            
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
    
    def import_rules_from_url(self, url, source_id=None):
        """Import rules từ URL (CSV file hoặc Snort/Suricata .rules)"""
        try:
            # Tải file từ URL
            response = requests.get(url, timeout=60)
            response.raise_for_status()
            
            # Kiểm tra nếu là Snort/Suricata rules format (dựa trên URL hoặc content)
            if url.endswith('.rules') or 'alert ' in response.text[:1000]:
                return self.import_snort_rules(response.text, source_id=source_id)
            
            # Nếu không, xử lý như CSV
            file_obj = io.StringIO(response.text)
            return self.import_rules_from_file(file_obj, source_id=source_id)
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
    
    def parse_snort_rule(self, rule_line):
        """Parse một dòng Snort/Suricata rule"""
        try:
            # Format: action protocol src_ip src_port -> dst_ip dst_port (options)
            # Ví dụ: alert tcp any any -> any any (msg:"ET SHELLCODE..."; sid:2009285; rev:2;)
            
            # Bỏ qua dòng comment hoặc trống
            rule_line = rule_line.strip()
            if not rule_line or rule_line.startswith('#'):
                return None
            
            # Regex để parse rule
            # action protocol src dst (options)
            header_pattern = r'^(alert|drop|pass|reject|log)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*)\)$'
            match = re.match(header_pattern, rule_line, re.DOTALL)
            
            if not match:
                return None
            
            action, protocol, src_ip, src_port, dst_ip, dst_port, options = match.groups()
            
            # Parse options
            options_dict = {}
            
            # Extract msg
            msg_match = re.search(r'msg\s*:\s*"([^"]+)"', options)
            msg = msg_match.group(1) if msg_match else 'Unknown Rule'
            
            # Extract sid
            sid_match = re.search(r'sid\s*:\s*(\d+)', options)
            sid = sid_match.group(1) if sid_match else str(uuid.uuid4())[:8]
            
            # Extract classtype (category)
            classtype_match = re.search(r'classtype\s*:\s*([^;]+)', options)
            classtype = classtype_match.group(1).strip() if classtype_match else 'Unknown'
            
            # Extract rev (version)
            rev_match = re.search(r'rev\s*:\s*(\d+)', options)
            rev = rev_match.group(1) if rev_match else '1'
            
            # Extract metadata for extra info
            metadata_match = re.search(r'metadata\s*:\s*([^;]+)', options)
            metadata = metadata_match.group(1).strip() if metadata_match else ''
            
            # Extract JA3/JA3S fingerprint from Suricata rules
            # Format: ja3.hash; content:"hash_value"; (or ja3.string)
            ja3_match = re.search(r'ja3\.hash\s*;\s*content\s*:\s*"([^"]+)"', options, re.IGNORECASE)
            ja3_hash = ja3_match.group(1).strip() if ja3_match else ''
            
            ja3s_match = re.search(r'ja3s\.hash\s*;\s*content\s*:\s*"([^"]+)"', options, re.IGNORECASE)
            ja3s_hash = ja3s_match.group(1).strip() if ja3s_match else ''
            
            # Extract SNI from tls.sni content
            sni_match = re.search(r'tls\.sni\s*;\s*content\s*:\s*"([^"]+)"', options, re.IGNORECASE)
            sni = sni_match.group(1).strip() if sni_match else ''
            
            # Alternative JA3 format: ja3_hash:"hash_value"
            if not ja3_hash:
                ja3_alt = re.search(r'ja3_hash\s*:\s*"?([a-fA-F0-9]{32})"?', options)
                ja3_hash = ja3_alt.group(1).strip() if ja3_alt else ''
            
            if not ja3s_hash:
                ja3s_alt = re.search(r'ja3s_hash\s*:\s*"?([a-fA-F0-9]{32})"?', options)
                ja3s_hash = ja3s_alt.group(1).strip() if ja3s_alt else ''
            
            # Map classtype to severity
            severity_map = {
                'shellcode-detect': 'Critical',
                'attempted-admin': 'Critical',
                'attempted-user': 'High',
                'trojan-activity': 'Critical',
                'successful-admin': 'Critical',
                'successful-user': 'High',
                'web-application-attack': 'High',
                'attempted-dos': 'High',
                'attempted-recon': 'Medium',
                'bad-unknown': 'Medium',
                'suspicious-login': 'Medium',
                'policy-violation': 'Low',
                'misc-activity': 'Low',
                'not-suspicious': 'Low',
                'network-scan': 'Medium',
                'denial-of-service': 'High',
                'misc-attack': 'Medium',
                'protocol-command-decode': 'Medium',
            }
            
            # Determine severity from metadata or classtype
            severity = 'Medium'  # Default
            if 'signature_severity' in metadata.lower():
                if 'major' in metadata.lower() or 'critical' in metadata.lower():
                    severity = 'Critical'
                elif 'minor' in metadata.lower():
                    severity = 'Low'
            elif classtype.lower() in severity_map:
                severity = severity_map[classtype.lower()]
            
            # Determine port
            port = dst_port if dst_port != 'any' else (src_port if src_port != 'any' else 'any')
            
            return {
                'rule_id': f'SID-{sid}',
                'rule_name': msg,
                'source': 'Snort/Suricata',
                'protocol': protocol.upper(),
                'port': port,
                'severity': severity,
                'category': classtype.replace('-', ' ').title(),
                'description': f'{action.upper()} rule: {msg}',
                'rule_content': rule_line,
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'version': rev,
                'false_positive_rate': 0.0,
                # TLS Fingerprint fields
                'ja3': ja3_hash,
                'ja3s': ja3s_hash,
                'sni': sni,
            }
        except Exception as e:
            print(f"[IPS Manager] Error parsing rule: {e}")
            return None
    
    def import_snort_rules(self, rules_text, source_id=None):
        """Import rules từ Snort/Suricata format"""
        try:
            lines = rules_text.split('\n')
            parsed_rules = []
            skipped = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Skip commented rules (bắt đầu bằng #)
                if line.startswith('#'):
                    skipped += 1
                    continue
                
                rule = self.parse_snort_rule(line)
                if rule:
                    # Thêm source_id nếu có
                    if source_id:
                        rule['source_id'] = source_id
                    parsed_rules.append(rule)
                else:
                    skipped += 1
            
            if not parsed_rules:
                return {
                    'success': False,
                    'message': f"No valid rules found. Skipped {skipped} lines."
                }
            
            # Chuyển thành DataFrame
            df_new = pd.DataFrame(parsed_rules)
            
            # Đọc rules hiện tại
            if os.path.exists(self.rules_path):
                df_existing = pd.read_csv(self.rules_path, sep='#')
            else:
                df_existing = pd.DataFrame()
            
            # Nếu có source_id, xóa rules cũ của source này trước
            if source_id and not df_existing.empty and 'source_id' in df_existing.columns:
                df_existing = df_existing[df_existing['source_id'] != source_id]
            
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
                'message': f"Imported {len(parsed_rules)} Snort/Suricata rules successfully. Skipped {skipped} commented/invalid lines.",
                'imported_count': len(parsed_rules),
                'skipped_count': skipped
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Error importing Snort rules: {str(e)}"
            }
    
    def add_ja3_rule(self, rule_name, category, ja3='', ja3s='', sni='', severity='High', description=''):
        """
        Add a JA3/JA3S/SNI fingerprint rule.
        
        Args:
            rule_name: Name of the rule
            category: Category (e.g., C2/Malware, Trojan Activity)
            ja3: JA3 client fingerprint (32-char MD5)
            ja3s: JA3S server fingerprint (32-char MD5)
            sni: Server Name Indication
            severity: Severity level (Critical, High, Medium, Low)
            description: Description of the rule
        
        Returns:
            dict with success status and rule_id
        """
        try:
            # Generate unique rule ID
            rule_id = f"JA3-{uuid.uuid4().hex[:8].upper()}"
            
            # Build rule content description
            content_parts = []
            if ja3:
                content_parts.append(f"JA3={ja3}")
            if ja3s:
                content_parts.append(f"JA3S={ja3s}")
            if sni:
                content_parts.append(f"SNI={sni}")
            rule_content = '; '.join(content_parts)
            
            # Determine match type for description
            match_type = 'JA3' if ja3 else ('JA3S' if ja3s else 'SNI')
            
            new_rule = {
                'rule_id': rule_id,
                'rule_name': rule_name,
                'source': 'Manual (TLS Fingerprint)',
                'protocol': 'TCP',
                'port': '443',  # TLS typically on 443
                'severity': severity,
                'category': category,
                'description': description or f'{match_type} Fingerprint Rule: {rule_name}',
                'rule_content': rule_content,
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'version': '1.0',
                'false_positive_rate': 0.0,
                'ja3': ja3,
                'ja3s': ja3s,
                'sni': sni
            }
            
            # Load existing rules
            if os.path.exists(self.rules_path):
                df = pd.read_csv(self.rules_path, sep='#')
            else:
                df = pd.DataFrame()
            
            # Append new rule
            df_new = pd.DataFrame([new_rule])
            df = pd.concat([df, df_new], ignore_index=True)
            
            # Save
            df.to_csv(self.rules_path, sep='#', index=False)
            
            print(f"[IPS Manager] Added JA3 rule: {rule_id} - {rule_name}")
            
            return {
                'success': True,
                'message': f"JA3 rule added successfully: {rule_id}",
                'rule_id': rule_id
            }
            
        except Exception as e:
            print(f"[IPS Manager] Error adding JA3 rule: {e}")
            return {
                'success': False,
                'message': f"Error adding rule: {str(e)}"
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
