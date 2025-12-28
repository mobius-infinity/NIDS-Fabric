import threading
import os
import pandas as pd

# Locks
HISTORY_LOCK = threading.Lock()
CONFIG_LOCK = threading.Lock()
PCAP_METADATA_LOCK = threading.Lock()
IPS_RULES_LOCK = threading.Lock()

# Shared Data
FILE_STATUS = {}
FILE_SIZES = {}
REALTIME_HISTORY = { 'timestamps': [], 'cpu': [], 'ram': [], 'flows_per_sec': [] }
GLOBAL_THREAT_STATS = { 'total_attacks': 0, 'total_safe': 0 }
SYSTEM_CONFIG = {
    'detection_mode': 'voting', 
    'voting_threshold': 2
}

# PCAP Metadata Cache (loaded on startup)
PCAP_METADATA = {}

# IPS Rules Cache (loaded on startup)
IPS_RULES = {}


def load_pcap_metadata_from_csv(app):
    """Load PCAP metadata from CSV into memory cache on startup"""
    try:
        pcap_info_folder = app.config.get('PCAP_INFO_FOLDER')
        pcap_metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
        evidence_folder = app.config.get('EVIDENCE_FOLDER')
        
        if not os.path.exists(pcap_metadata_path):
            print("[System] No PCAP metadata file found (first startup)")
            return
        
        df = pd.read_csv(pcap_metadata_path, sep='#')
        
        with PCAP_METADATA_LOCK:
            PCAP_METADATA.clear()
            for _, row in df.iterrows():
                pcap_id = row['pcap_id']
                pcap_name = row['pcap_name']
                is_threat = bool(row.get('is_threat', False))
                
                # Check if PCAP file exists (only for threat files, safe files are deleted)
                file_exists = False
                if is_threat:
                    pcap_path = os.path.join(evidence_folder, pcap_name)
                    file_exists = os.path.exists(pcap_path)
                else:
                    file_exists = False  # Safe files are deleted after processing
                
                metadata_dict = row.to_dict()
                metadata_dict['exists'] = file_exists
                PCAP_METADATA[pcap_id] = metadata_dict
        
        print(f"[System] PCAP metadata loaded: {len(PCAP_METADATA)} records")
    except Exception as e:
        print(f"[System] Error loading PCAP metadata: {e}")


def load_ips_rules_from_csv(app):
    """Load IPS rules from CSV into memory cache on startup"""
    try:
        ips_folder = app.config.get('IPS_FOLDER', os.path.join(app.config['BASE_FOLDER'], 'storage', 'ips'))
        ips_rules_path = os.path.join(ips_folder, 'ips_rules.csv')
        
        if not os.path.exists(ips_rules_path):
            print("[System] No IPS rules file found (first startup)")
            return
        
        df = pd.read_csv(ips_rules_path, sep='#', low_memory=False)
        
        with IPS_RULES_LOCK:
            IPS_RULES.clear()
            for _, row in df.iterrows():
                rule_id = row['rule_id']
                IPS_RULES[rule_id] = row.to_dict()
        
        print(f"[System] IPS rules loaded: {len(IPS_RULES)} rules")
    except Exception as e:
        print(f"[System] Error loading IPS rules: {e}")
