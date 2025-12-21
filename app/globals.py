import threading

# Locks
HISTORY_LOCK = threading.Lock()
CONFIG_LOCK = threading.Lock()

# Shared Data
FILE_STATUS = {}
FILE_SIZES = {}
REALTIME_HISTORY = { 'timestamps': [], 'cpu': [], 'ram': [], 'flows_per_sec': [] }
GLOBAL_THREAT_STATS = { 'total_attacks': 0, 'total_safe': 0 }
SYSTEM_CONFIG = {
    'detection_mode': 'voting', 
    'voting_threshold': 2
}
