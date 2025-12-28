"""
IPS Engine - Signature-based Intrusion Prevention System
Matches network flows against Snort/Suricata rules for hybrid ML+IPS detection
"""

import os
import re
import pandas as pd
from datetime import datetime


class IPSEngine:
    """
    Signature-based IPS engine that matches flows against loaded rules.
    Used in hybrid mode with ML models for confidence-based detection.
    """
    
    def __init__(self, rules_path=None):
        self.rules = []
        self.rules_path = rules_path
        self.loaded = False
        self.last_load_time = None
        self.rules_count = 0
        
        # Protocol mapping
        self.proto_map = {
            'tcp': 6,
            'udp': 17,
            'icmp': 1,
            'ip': 0,
            'any': None
        }
        
    def init_app(self, app):
        """Initialize with Flask app context"""
        ips_folder = os.path.join(app.config.get('BASE_FOLDER', '.'), 'storage', 'ips')
        self.rules_path = os.path.join(ips_folder, 'ips_rules.csv')
        self.load_rules()
        
    def load_rules(self):
        """Load rules from CSV database"""
        try:
            if not self.rules_path or not os.path.exists(self.rules_path):
                print("[IPS Engine] No rules file found")
                self.rules = []
                self.loaded = False
                return False
            
            df = pd.read_csv(self.rules_path, sep='#', low_memory=False)
            self.rules = df.to_dict('records')
            self.rules_count = len(self.rules)
            self.loaded = True
            self.last_load_time = datetime.now()
            print(f"[IPS Engine] Loaded {self.rules_count} rules")
            return True
        except Exception as e:
            print(f"[IPS Engine] Error loading rules: {e}")
            self.rules = []
            self.loaded = False
            return False
    
    def reload_if_needed(self, interval_seconds=300):
        """Reload rules if older than interval"""
        if not self.last_load_time:
            return self.load_rules()
        
        elapsed = (datetime.now() - self.last_load_time).total_seconds()
        if elapsed > interval_seconds:
            return self.load_rules()
        return True
    
    def _proto_to_num(self, proto_str):
        """Convert protocol string to number"""
        if proto_str is None:
            return None
        proto_lower = str(proto_str).lower().strip()
        return self.proto_map.get(proto_lower, None)
    
    def _parse_ports(self, port_str):
        """Parse port specification (can be single, range, or list)"""
        if port_str is None or str(port_str).lower() in ['any', 'nan', '']:
            return None
        
        ports = set()
        port_str = str(port_str)
        
        # Handle comma-separated
        for part in port_str.split(','):
            part = part.strip()
            if ':' in part:
                # Range like 1:1024
                try:
                    start, end = part.split(':')
                    ports.update(range(int(start), int(end) + 1))
                except:
                    pass
            elif '-' in part:
                # Range like 1-1024
                try:
                    start, end = part.split('-')
                    ports.update(range(int(start), int(end) + 1))
                except:
                    pass
            else:
                try:
                    ports.add(int(part))
                except:
                    pass
        
        return ports if ports else None
    
    def match_flow(self, flow_data):
        """
        Match a single flow against all rules.
        
        Args:
            flow_data: dict with flow information (IPV4_SRC_ADDR, L4_SRC_PORT, etc.)
            
        Returns:
            dict with match result:
            - matched: bool
            - rule_id: str or None
            - rule_name: str or None  
            - severity: str or None
            - category: str or None
            - match_type: str or None (port, ja3, ja3s, etc.)
        """
        if not self.rules:
            return {
                'matched': False,
                'rule_id': None,
                'rule_name': None,
                'severity': None,
                'category': None,
                'match_type': None
            }
        
        flow_proto = flow_data.get('PROTOCOL')
        flow_src_port = flow_data.get('L4_SRC_PORT')
        flow_dst_port = flow_data.get('L4_DST_PORT')
        flow_src_ip = flow_data.get('IPV4_SRC_ADDR', '')
        flow_dst_ip = flow_data.get('IPV4_DST_ADDR', '')
        
        # TLS Fingerprint fields
        flow_ja3 = str(flow_data.get('JA3C_HASH', '')).strip()
        flow_ja3s = str(flow_data.get('JA3S_HASH', '')).strip()
        flow_sni = str(flow_data.get('SSL_SERVER_NAME', '')).strip()
        
        for rule in self.rules:
            match_result = self._check_rule_match(
                flow_proto, flow_src_port, flow_dst_port, 
                flow_src_ip, flow_dst_ip, 
                flow_ja3, flow_ja3s, flow_sni, rule
            )
            if match_result['matched']:
                return {
                    'matched': True,
                    'rule_id': rule.get('rule_id'),
                    'rule_name': rule.get('rule_name'),
                    'severity': rule.get('severity'),
                    'category': rule.get('category'),
                    'match_type': match_result['match_type']
                }
        
        return {
            'matched': False,
            'rule_id': None,
            'rule_name': None,
            'severity': None,
            'category': None,
            'match_type': None
        }
    
    def _check_rule_match(self, flow_proto, flow_src_port, flow_dst_port, 
                          flow_src_ip, flow_dst_ip, flow_ja3, flow_ja3s, flow_sni, rule):
        """
        Check if flow matches a specific rule.
        
        TLS FINGERPRINT ONLY MATCHING:
        - JA3 Client Hash - malicious client TLS fingerprint
        - JA3S Server Hash - malicious server TLS fingerprint  
        - SNI (Server Name Indication) - malicious domain names
        
        NO PORT-BASED MATCHING to reduce false positives.
        """
        try:
            # TLS Fingerprint fields from rule
            rule_ja3 = str(rule.get('ja3', '')).strip().lower()
            rule_ja3s = str(rule.get('ja3s', '')).strip().lower()
            rule_sni = str(rule.get('sni', '')).strip().lower()
            
            # === PRIORITY 1: JA3 CLIENT FINGERPRINT ===
            # Matches malicious client TLS handshake patterns
            if rule_ja3 and rule_ja3 not in ['', 'nan', 'none']:
                if flow_ja3 and flow_ja3.lower() == rule_ja3:
                    return {'matched': True, 'match_type': 'JA3'}
            
            # === PRIORITY 2: JA3S SERVER FINGERPRINT ===
            # Matches malicious server TLS handshake patterns
            if rule_ja3s and rule_ja3s not in ['', 'nan', 'none']:
                if flow_ja3s and flow_ja3s.lower() == rule_ja3s:
                    return {'matched': True, 'match_type': 'JA3S'}
            
            # === PRIORITY 3: SNI (SERVER NAME INDICATION) ===
            # Matches malicious domain names in TLS handshake
            if rule_sni and rule_sni not in ['', 'nan', 'none']:
                if flow_sni:
                    # Support both exact match and partial match (subdomain)
                    flow_sni_lower = flow_sni.lower()
                    if rule_sni == flow_sni_lower or flow_sni_lower.endswith('.' + rule_sni):
                        return {'matched': True, 'match_type': 'SNI'}
            
            # No match - rule doesn't have TLS fingerprint indicators
            # or flow doesn't match any TLS fingerprint
            return {'matched': False, 'match_type': None}
            
        except Exception as e:
            # On error, don't match
            return {'matched': False, 'match_type': None}
    
    def match_flows_batch(self, flows_df):
        """
        Match multiple flows against rules (batch processing).
        
        Args:
            flows_df: DataFrame with flow data
            
        Returns:
            list of match results (same length as flows_df)
        """
        results = []
        for idx, row in flows_df.iterrows():
            result = self.match_flow(row.to_dict())
            results.append(result)
        return results
    
    def get_statistics(self):
        """Get IPS engine statistics"""
        return {
            'loaded': self.loaded,
            'rules_count': self.rules_count,
            'last_load_time': self.last_load_time.isoformat() if self.last_load_time else None
        }


# Global instance
ips_engine = IPSEngine()
