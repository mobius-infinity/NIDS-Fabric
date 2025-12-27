import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-nids-2025'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Paths
    BASE_FOLDER = BASE_DIR
    NPROBE_PATH = "/usr/bin/nprobe"
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'temp_uploads')
    INCOMING_FOLDER = os.path.join(BASE_DIR, 'storage', 'incoming_pcaps')
    EVIDENCE_FOLDER = os.path.join(BASE_DIR, 'storage', 'evidence_pcaps')
    PROCESSED_FOLDER = os.path.join(BASE_DIR, 'storage', 'processed_pcaps')
    LOGS_FOLDER = os.path.join(BASE_DIR, 'storage', 'model_logs')
    PCAP_INFO_FOLDER = os.path.join(BASE_DIR, 'storage', 'info_pcaps')
    IPS_FOLDER = os.path.join(BASE_DIR, 'storage', 'ips')
    AVATAR_FOLDER = os.path.join(BASE_DIR, 'app', 'static', 'avatars')
    ML_ASSETS_DIR = os.path.join(BASE_DIR, 'ml_assets')
    
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 * 1024  # 10GB Upload limit
    JSON_SORT_KEYS = False
