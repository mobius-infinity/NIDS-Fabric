import os
import threading
from app import create_app, db
from app.models import User, SystemSettings
from app.globals import SYSTEM_CONFIG
from app.core.worker import thread_system_stats, thread_pcap_worker
from werkzeug.security import generate_password_hash

app = create_app()

def init_db_data(app):
    """Khởi tạo dữ liệu ban đầu giống hệt app4.py"""
    with app.app_context():
        # db.drop_all() # Bỏ comment nếu muốn reset sạch DB mỗi lần chạy
        db.create_all()
        
        # Tạo Admin
        if not User.query.filter_by(username='admin').first():
            print("[System] Creating default admin account...")
            hashed_pw = generate_password_hash('admin', method='pbkdf2:sha256')
            admin = User(
                username='admin', 
                password=hashed_pw, 
                full_name='System Admin',
                avatar_file='admin_default.png'
            )
            db.session.add(admin)
            db.session.commit()
        
        # Load Config
        setting = SystemSettings.query.first()
        if setting:
            SYSTEM_CONFIG['detection_mode'] = setting.detection_mode
            SYSTEM_CONFIG['voting_threshold'] = setting.voting_threshold
            print(f"[System] Config Loaded: Mode={setting.detection_mode}")
        else:
            new_setting = SystemSettings(detection_mode='voting', voting_threshold=2)
            db.session.add(new_setting)
            db.session.commit()

def create_folders(app):
    folders = [
        app.config['UPLOAD_FOLDER'],
        app.config['INCOMING_FOLDER'],
        app.config['EVIDENCE_FOLDER'],
        app.config['PROCESSED_FOLDER'],
        os.path.join(app.config['PROCESSED_FOLDER'], 'benign'),
        app.config['LOGS_FOLDER'],
        app.config['AVATAR_FOLDER']
    ]
    for f in folders:
        os.makedirs(f, exist_ok=True)

if __name__ == '__main__':
    create_folders(app)
    init_db_data(app)
    
    # --- KHỞI CHẠY THREAD ---
    # Vì debug=False, chúng ta không cần kiểm tra WERKZEUG_RUN_MAIN nữa.
    # Code sẽ chỉ chạy 1 lần duy nhất, đảm bảo FILE_STATUS hoạt động đúng.
    print("[System] Starting Background Threads...")
    threading.Thread(target=thread_system_stats, daemon=True).start()
    threading.Thread(target=thread_pcap_worker, args=(app,), daemon=True).start()
    
    print(f"[NIDS] Server running on port 5000 (Production Mode)...")
    
    # --- QUAN TRỌNG: Đặt debug=False giống hệt app4.py ---
    app.run(host='0.0.0.0', port=5000, debug=False)
