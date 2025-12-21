import os
import glob
import pandas as pd
import numpy as np
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app import db
from app.models import User, SystemSettings

# Import các biến toàn cục (Global States)
from app.globals import (
    HISTORY_LOCK, REALTIME_HISTORY, GLOBAL_THREAT_STATS,
    SYSTEM_CONFIG, CONFIG_LOCK, FILE_STATUS, FILE_SIZES
)

api_bp = Blueprint('api', __name__)

# --- USER & SETTINGS API ---

@api_bp.route('/user-info')
@login_required
def get_user_info():
    try:
        return jsonify({
            "username": current_user.username,
            "full_name": current_user.full_name,
            "avatar": current_user.avatar_file,
            "config_mode": SYSTEM_CONFIG.get('detection_mode'),
            "config_threshold": SYSTEM_CONFIG.get('voting_threshold', 2)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    try:
        new_name = request.form.get('full_name')
        if new_name: 
            current_user.full_name = new_name
            
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file.filename != '':
                # Lấy đường dẫn AVATAR_FOLDER từ config
                avatar_folder = current_app.config['AVATAR_FOLDER']
                filename = secure_filename(f"{current_user.id}_{file.filename}")
                file.save(os.path.join(avatar_folder, filename))
                current_user.avatar_file = filename
        
        db.session.add(current_user)
        db.session.commit()
        return jsonify({"status": "success", "message": "Profile updated!"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@api_bp.route('/update-settings', methods=['POST'])
@login_required
def update_settings():
    data = request.json
    try:
        setting = SystemSettings.query.first()
        if not setting: 
            setting = SystemSettings()
            db.session.add(setting)
        
        if 'detection_mode' in data: 
            setting.detection_mode = data['detection_mode']
        if 'voting_threshold' in data: 
            setting.voting_threshold = int(data['voting_threshold'])
        
        db.session.commit()
        
        # Cập nhật biến Global trong RAM để Worker đọc được ngay
        with CONFIG_LOCK:
            if 'detection_mode' in data: 
                SYSTEM_CONFIG['detection_mode'] = data['detection_mode']
            if 'voting_threshold' in data: 
                SYSTEM_CONFIG['voting_threshold'] = int(data['voting_threshold'])
                
        return jsonify({"status": "success"})
    except Exception as e: 
        return jsonify({"status": "error", "message": str(e)}), 500

@api_bp.route('/reset-stats', methods=['POST'])
@login_required
def reset_stats():
    with HISTORY_LOCK:
        GLOBAL_THREAT_STATS['total_attacks'] = 0
        GLOBAL_THREAT_STATS['total_safe'] = 0
    return jsonify({"status": "success"})

# --- DASHBOARD DATA API ---

@api_bp.route('/general-dashboard')
@login_required
def general_dashboard_stats():
    with HISTORY_LOCK:
        sys_stats = { 
            "cpu_history": list(REALTIME_HISTORY['cpu']), 
            "ram_history": list(REALTIME_HISTORY['ram']), 
            "flow_history": list(REALTIME_HISTORY['flows_per_sec']), 
            "labels": list(REALTIME_HISTORY['timestamps']), 
            "latest_cpu": REALTIME_HISTORY['cpu'][-1] if REALTIME_HISTORY['cpu'] else 0, 
            "latest_ram": REALTIME_HISTORY['ram'][-1] if REALTIME_HISTORY['ram'] else 0 
        }
        sec_stats = { 
            "total_attacks": GLOBAL_THREAT_STATS['total_attacks'], 
            "total_safe": GLOBAL_THREAT_STATS['total_safe'] 
        }
    
    processed_folder = current_app.config['PROCESSED_FOLDER']
    evidence_folder = current_app.config['EVIDENCE_FOLDER']
    
    # Đếm file an toàn (trong benign) và nguy hiểm
    safe_cnt = len(glob.glob(os.path.join(processed_folder, 'benign', '*')))
    threat_cnt = len(glob.glob(os.path.join(evidence_folder, '*')))
    
    return jsonify({ 
        "system": sys_stats, 
        "storage": {"safe": safe_cnt, "threats": threat_cnt, "total": safe_cnt + threat_cnt}, 
        "security": sec_stats 
    })

@api_bp.route('/incoming-files')
@login_required
def get_incoming_files():
    files = []
    incoming_folder = current_app.config['INCOMING_FOLDER']
    
    if os.path.exists(incoming_folder):
        for f in glob.glob(os.path.join(incoming_folder, "*.pcap*")):
            bn = os.path.basename(f)
            # Cập nhật size nếu chưa có hoặc cập nhật mới
            sz = FILE_SIZES.get(bn, round(os.path.getsize(f)/(1024*1024), 2))
            FILE_SIZES[bn] = sz
            files.append({
                "name": bn, 
                "size_mb": sz, 
                "status": FILE_STATUS.get(bn, 'Pending')
            })
            
    # Thêm các file đang xử lý nhưng đã bị move khỏi folder incoming (để hiển thị trạng thái Done/Error)
    for f_name, status in FILE_STATUS.items():
        if ('Done' in status or 'Error' in status) and not any(x['name'] == f_name for x in files):
            files.append({
                "name": f_name, 
                "size_mb": FILE_SIZES.get(f_name, 0), 
                "status": status
            })
            
    return jsonify({"files": sorted(files, key=lambda x: x['name'])})

# --- LOGS & DETAILS API ---

@api_bp.route('/get_flows')
@login_required
def get_flows():
    model = request.args.get('model', 'Random Forest')
    task = request.args.get('task', 'binary')
    logs_folder = current_app.config['LOGS_FOLDER']
    
    path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
    
    if not os.path.exists(path): 
        return jsonify({"flows": []})
    
    try:
        df = pd.read_csv(path)
        # Clean column names (remove %)
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        if request.args.get('filename'): 
            df = df[df['file_scaned'] == request.args.get('filename')]
            
        # Trả về 100 dòng mới nhất
        return jsonify({
            "flows": df.sort_values(by='time_scaned', ascending=False)
                       .head(100)
                       .fillna('')
                       .to_dict('records')
        })
    except Exception as e: 
        return jsonify({"error": str(e)})

@api_bp.route('/flow-details/<flow_id>')
@login_required
def get_details(flow_id):
    model = request.args.get('model', 'Random Forest')
    task = request.args.get('task', 'binary')
    logs_folder = current_app.config['LOGS_FOLDER']
    
    path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
    
    try:
        df = pd.read_csv(path)
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        # Tìm dòng có id khớp (chuyển về string để so sánh an toàn)
        rec = df[df['id'].astype(str).str.strip() == str(flow_id).strip()]
        
        if not rec.empty:
            return jsonify(rec.iloc[0].replace({np.nan: None}).to_dict())
        else:
            return jsonify({"error": "Not found"}), 404
    except Exception: 
        return jsonify({"error": "Error processing log file"}), 500
