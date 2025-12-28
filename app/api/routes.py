import os
import glob
import pandas as pd
import numpy as np
from flask import Blueprint, jsonify, request, current_app, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from datetime import datetime

from app import db
from app.models import User, SystemSettings

# Import các biến toàn cục (Global States)
from app.globals import (
    HISTORY_LOCK, REALTIME_HISTORY, GLOBAL_THREAT_STATS,
    SYSTEM_CONFIG, CONFIG_LOCK, FILE_STATUS, FILE_SIZES,
    PCAP_METADATA, PCAP_METADATA_LOCK
)

# Import IPS Manager
from app.core.ips_manager import ips_manager

api_bp = Blueprint('api', __name__)

# --- WELL-KNOWN ENDPOINTS ---

@api_bp.route('/.well-known/appspecific/com.chrome.devtools.json')
def chrome_devtools():
    """Suppress Chrome DevTools metadata request"""
    return jsonify({}), 200

# --- USER & SETTINGS API ---

@api_bp.route('/user-info')
@login_required
def get_user_info():
    try:
        return jsonify({
            "username": current_user.username,
            "full_name": current_user.full_name,
            "avatar": current_user.avatar_file,
            "theme": current_user.theme_preference,
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
        
        # Handle theme preference
        theme = request.form.get('theme')
        if theme in ['light', 'dark']:
            current_user.theme_preference = theme
        
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

@api_bp.route('/pcap-details/<pcap_id>')
@login_required
def get_pcap_details(pcap_id):
    """Get detailed information about a PCAP file using pcap_id or filename (fallback)"""
    evidence_folder = current_app.config['EVIDENCE_FOLDER']
    
    try:
        pcap_info = None
        
        # Try to get from cache using pcap_id first (fast - in-memory)
        with PCAP_METADATA_LOCK:
            if pcap_id in PCAP_METADATA:
                pcap_info = PCAP_METADATA[pcap_id].copy()
        
        # If not found, check if pcap_id is actually a filename - search by filename in cache
        if pcap_info is None:
            with PCAP_METADATA_LOCK:
                for pid, metadata in PCAP_METADATA.items():
                    if metadata.get('pcap_name') == pcap_id:
                        pcap_info = metadata.copy()
                        break
        
        # Fallback to CSV if not in cache
        if pcap_info is None:
            pcap_info_folder = current_app.config.get('PCAP_INFO_FOLDER', os.path.join(current_app.config['BASE_FOLDER'], 'storage', 'info_pcaps'))
            pcap_metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
            
            if not os.path.exists(pcap_metadata_path):
                return jsonify({"error": "No PCAP metadata found"}), 404
            
            df_metadata = pd.read_csv(pcap_metadata_path, sep='#')
            
            # Try to find by pcap_id first
            record = df_metadata[df_metadata['pcap_id'] == pcap_id]
            
            # If not found, try to find by pcap_name (filename)
            if record.empty:
                record = df_metadata[df_metadata['pcap_name'] == pcap_id]
            
            if record.empty:
                return jsonify({"error": "PCAP not found in metadata"}), 404
            
            pcap_info = record.iloc[0].to_dict()
        
        is_threat = bool(pcap_info.get('is_threat', False))
        pcap_filename = pcap_info.get('pcap_name', '')
        
        # Check if file exists from cache metadata (already checked on startup)
        # If 'exists' column missing (backward compatibility), check file directly
        if 'exists' in pcap_info:
            pcap_file_exists = pcap_info.get('exists', False)
        else:
            # Fallback: check file existence directly
            pcap_file_exists = False
            if is_threat and pcap_filename:
                pcap_path = os.path.join(evidence_folder, pcap_filename)
                pcap_file_exists = os.path.exists(pcap_path)
        
        return jsonify({
            "pcap_id": pcap_info.get('pcap_id', ''),
            "name": pcap_info.get('pcap_name'),
            "size_mb": pcap_info.get('size_mb', 0),
            "size_bytes": int(pcap_info.get('size_mb', 0) * 1024 * 1024),
            "upload_date": pcap_info.get('analysis_date', 'N/A'),
            "status": 'Done (Threat Found)' if is_threat else 'Done (Safe)',
            "total_flows": int(pcap_info.get('total_flows', 0)),
            "threat_flows": int(pcap_info.get('threat_flows', 0)),
            "safe_flows": int(pcap_info.get('safe_flows', 0)),
            "is_threat": is_threat,
            "pcap_exists": pcap_file_exists
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/incoming-files')
@login_required
def get_incoming_files():
    filename = request.args.get('file')
    incoming_folder = current_app.config['INCOMING_FOLDER']
    
    # If specific file requested by pcap_id, return details
    if filename:
        # Try to get from cache using pcap_id
        with PCAP_METADATA_LOCK:
            if filename in PCAP_METADATA:
                pcap_info = PCAP_METADATA[filename]
                return jsonify({
                    "status": "success",
                    "file": {
                        "pcap_id": pcap_info.get('pcap_id', ''),
                        "name": pcap_info.get('pcap_name'),
                        "size_mb": pcap_info.get('size_mb', 0),
                        "size_bytes": int(pcap_info.get('size_mb', 0) * 1024 * 1024),
                        "status": FILE_STATUS.get(pcap_info.get('pcap_name', ''), 'Done'),
                        "upload_date": pcap_info.get('analysis_date', 'N/A'),
                        "total_flows": int(pcap_info.get('total_flows', 0)),
                        "threat_flows": int(pcap_info.get('threat_flows', 0)),
                        "safe_flows": int(pcap_info.get('safe_flows', 0))
                    }
                })
        
        # Fallback to filesystem for pending files
        safe_filename = secure_filename(filename)
        filepath = os.path.join(incoming_folder, safe_filename)
        if os.path.exists(filepath):
            try:
                return jsonify({
                    "status": "success",
                    "file": {
                        "pcap_id": "pending",
                        "name": safe_filename,
                        "size_mb": round(os.path.getsize(filepath)/(1024*1024), 2),
                        "size_bytes": os.path.getsize(filepath),
                        "status": FILE_STATUS.get(safe_filename, 'Pending'),
                        "upload_date": datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
                        "total_flows": 0,
                        "threat_flows": 0,
                        "safe_flows": 0
                    }
                })
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
        else:
            return jsonify({"status": "error", "message": "File not found"}), 404
    
    # Get filter/search/sort parameters
    search = request.args.get('search', '').strip().lower()
    filter_name = request.args.get('filter_name', '').strip().lower()
    filter_status = request.args.get('filter_status', '').strip().lower()
    filter_threat = request.args.get('filter_threat', '').strip().lower()  # 'threat', 'safe', or empty
    sort_by = request.args.get('sort_by', 'upload_date').strip().lower()  # name, size, status, upload_date, flows
    sort_order = request.args.get('sort_order', 'desc').strip().lower()  # asc or desc
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 100))
    
    # Debug logging
    if search or filter_name or filter_status or filter_threat:
        print(f"[PCAP Filter] search='{search}', name='{filter_name}', status='{filter_status}', threat='{filter_threat}'", flush=True)
    
    # Otherwise return list of all files (combining incoming folder + cache)
    files = []
    
    # Add files from incoming folder
    if os.path.exists(incoming_folder):
        for f in glob.glob(os.path.join(incoming_folder, "*.pcap*")):
            bn = os.path.basename(f)
            sz = FILE_SIZES.get(bn, round(os.path.getsize(f)/(1024*1024), 2))
            FILE_SIZES[bn] = sz
            files.append({
                "pcap_id": "pending",  # New files don't have ID yet
                "name": bn, 
                "size_mb": sz, 
                "status": FILE_STATUS.get(bn, 'Pending'),
                "upload_date": datetime.fromtimestamp(os.path.getctime(f)).strftime('%Y-%m-%d %H:%M:%S'),
                "total_flows": 0,
                "threat_flows": 0,
                "safe_flows": 0,
                "is_threat": False
            })
    
    # Add processed files from cache (Done/Error status)
    with PCAP_METADATA_LOCK:
        for pcap_id, metadata in PCAP_METADATA.items():
            # Don't add if already in list from incoming folder (check by pcap_id for uniqueness)
            if not any(x['pcap_id'] == pcap_id for x in files):
                files.append({
                    "pcap_id": pcap_id,
                    "name": metadata.get('pcap_name', ''),
                    "size_mb": metadata.get('size_mb', 0),
                    "status": FILE_STATUS.get(metadata.get('pcap_name', ''), 'Done'),
                    "upload_date": metadata.get('analysis_date', 'N/A'),
                    "total_flows": int(metadata.get('total_flows', 0)),
                    "threat_flows": int(metadata.get('threat_flows', 0)),
                    "safe_flows": int(metadata.get('safe_flows', 0)),
                    "is_threat": bool(metadata.get('is_threat', False))
                })
    
    # Add files from FILE_STATUS that were processed but moved
    for f_name, status in FILE_STATUS.items():
        if ('Done' in status or 'Error' in status) and not any(x['name'] == f_name for x in files):
            files.append({
                "pcap_id": "",  
                "name": f_name, 
                "size_mb": FILE_SIZES.get(f_name, 0), 
                "status": status,
                "upload_date": "N/A",
                "total_flows": 0,
                "threat_flows": 0,
                "safe_flows": 0,
                "is_threat": False
            })
    
    # Apply filters
    filtered_files = []
    for f in files:
        # Global search
        if search:
            if search not in f['name'].lower() and search not in f['status'].lower():
                continue
        
        # Filter by name
        if filter_name and filter_name not in f['name'].lower():
            continue
        
        # Filter by status
        if filter_status:
            status_match = filter_status in f['status'].lower()
            if not status_match:
                continue
        
        # Filter by threat level
        if filter_threat:
            if filter_threat == 'threat' and not f['is_threat']:
                continue
            elif filter_threat == 'safe' and f['is_threat']:
                continue
        
        filtered_files.append(f)
    
    # Debug log after filtering
    if search or filter_name or filter_status or filter_threat:
        print(f"[PCAP Filter] Before: {len(files)} files, After: {len(filtered_files)} files", flush=True)
    
    # Apply sorting
    sort_key_map = {
        'name': lambda x: x['name'].lower(),
        'size': lambda x: x['size_mb'],
        'status': lambda x: x['status'].lower(),
        'upload_date': lambda x: x['upload_date'],
        'flows': lambda x: x['total_flows']
    }
    
    sort_func = sort_key_map.get(sort_by, sort_key_map['upload_date'])
    filtered_files.sort(key=sort_func, reverse=(sort_order == 'desc'))
    
    # Pagination
    total = len(filtered_files)
    paginated_files = filtered_files[offset:offset+limit]
    
    return jsonify({
        "files": paginated_files,
        "total": total,
        "offset": offset,
        "limit": limit
    })


@api_bp.route('/delete-pcap/<pcap_id>', methods=['DELETE'])
@login_required
def delete_pcap(pcap_id):
    """Delete PCAP file from cache and CSV metadata"""
    try:
        pcap_info_folder = current_app.config.get('PCAP_INFO_FOLDER', os.path.join(current_app.config['BASE_FOLDER'], 'storage', 'info_pcaps'))
        evidence_folder = current_app.config['EVIDENCE_FOLDER']
        pcap_metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
        
        # Get info from cache
        pcap_info = None
        with PCAP_METADATA_LOCK:
            if pcap_id in PCAP_METADATA:
                pcap_info = PCAP_METADATA[pcap_id].copy()
                del PCAP_METADATA[pcap_id]
        
        if pcap_info is None:
            return jsonify({"status": "error", "message": "PCAP not found"}), 404
        
        pcap_filename = pcap_info.get('pcap_name', '')
        
        # Delete physical file if it exists (threat files)
        if pcap_info.get('is_threat', False) and pcap_filename:
            pcap_path = os.path.join(evidence_folder, pcap_filename)
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
        
        # Update CSV - remove the record
        if os.path.exists(pcap_metadata_path):
            try:
                df = pd.read_csv(pcap_metadata_path, sep='#')
                df = df[df['pcap_id'] != pcap_id]
                df.to_csv(pcap_metadata_path, index=False, sep='#')
            except Exception as e:
                print(f"[Error] Failed to update CSV: {e}")
        
        return jsonify({
            "status": "success",
            "message": f"PCAP {pcap_filename} deleted successfully"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route('/clear_logs', methods=['POST'])
@login_required
def clear_logs():
    try:
        model = request.args.get('model', 'Random Forest')
        task = request.args.get('task', 'binary')
        logs_folder = current_app.config['LOGS_FOLDER']
        
        # Get filter parameters
        search = request.args.get('search', '').strip().lower()
        filter_time = request.args.get('filter_time', '').strip().lower()
        filter_file = request.args.get('filter_file', '').strip().lower()
        filter_srcip = request.args.get('filter_srcip', '').strip().lower()
        filter_srcport = request.args.get('filter_srcport', '').strip().lower()
        filter_dstip = request.args.get('filter_dstip', '').strip().lower()
        filter_dstport = request.args.get('filter_dstport', '').strip().lower()
        filter_prediction = request.args.get('filter_prediction', '').strip().lower()
        
        path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
        
        if not os.path.exists(path):
            return jsonify({"status": "error", "message": "Log file not found"}), 404
        
        df = pd.read_csv(path, sep='#')
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        original_count = len(df)
        
        # Apply filters to identify rows to delete
        if search:
            mask = df.astype(str).apply(lambda x: x.str.contains(search, case=False, na=False).any(), axis=1)
            df = df[~mask]  # Keep rows that DON'T match
        
        if filter_time and 'time_scaned' in df.columns:
            mask = df['time_scaned'].astype(str).str.contains(filter_time, case=False, na=False)
            df = df[~mask]
        
        if filter_file and 'file_scaned' in df.columns:
            mask = df['file_scaned'].astype(str).str.contains(filter_file, case=False, na=False)
            df = df[~mask]
        
        if filter_srcip and 'IPV4_SRC_ADDR' in df.columns:
            mask = df['IPV4_SRC_ADDR'].astype(str).str.contains(filter_srcip, case=False, na=False)
            df = df[~mask]
        
        if filter_srcport and 'L4_SRC_PORT' in df.columns:
            mask = df['L4_SRC_PORT'].astype(str).str.contains(filter_srcport, case=False, na=False)
            df = df[~mask]
        
        if filter_dstip and 'IPV4_DST_ADDR' in df.columns:
            mask = df['IPV4_DST_ADDR'].astype(str).str.contains(filter_dstip, case=False, na=False)
            df = df[~mask]
        
        if filter_dstport and 'L4_DST_PORT' in df.columns:
            mask = df['L4_DST_PORT'].astype(str).str.contains(filter_dstport, case=False, na=False)
            df = df[~mask]
        
        if filter_prediction and 'result' in df.columns:
            mask = df['result'].astype(str).str.contains(filter_prediction, case=False, na=False)
            df = df[~mask]
        
        deleted_count = original_count - len(df)
        
        # Save filtered dataframe back to file
        if len(df) > 0:
            df.to_csv(path, index=False, sep='#')
        else:
            # If all rows deleted, clear the file (keep header)
            df_empty = pd.DataFrame(columns=df.columns)
            df_empty.to_csv(path, index=False, sep='#')
        
        return jsonify({
            "status": "success",
            "deleted": deleted_count,
            "remaining": len(df)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route('/clear_all_logs', methods=['POST'])
@login_required
def clear_all_logs():
    """Clear all logs for a specific model or all models"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        all_models = request.args.get('all_models', 'false').lower() == 'true'
        total_deleted = 0
        
        if all_models:
            # Clear all logs from all models
            models = ['Random Forest', 'LightGBM', 'DNN']
            tasks = ['binary', 'multiclass']
            
            for model in models:
                for task in tasks:
                    path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
                    
                    if os.path.exists(path):
                        try:
                            df = pd.read_csv(path, sep='#')
                            total_deleted += len(df)
                            
                            # Clear the file by creating an empty dataframe with same columns
                            df_empty = pd.DataFrame(columns=df.columns)
                            df_empty.to_csv(path, index=False, sep='#')
                        except Exception as e:
                            print(f"Error clearing {model} {task}: {str(e)}")
                            continue
        else:
            # Clear specific model
            model = request.args.get('model', 'Random Forest')
            task = request.args.get('task', 'binary')
            path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
            
            if not os.path.exists(path):
                return jsonify({"status": "error", "message": "Log file not found"}), 404
            
            df = pd.read_csv(path, sep='#')
            total_deleted = len(df)
            
            # Clear the file by creating an empty dataframe with same columns
            df.columns = [str(c).replace('%', '').strip() for c in df.columns]
            df_empty = pd.DataFrame(columns=df.columns)
            df_empty.to_csv(path, index=False, sep='#')
        
        return jsonify({
            "status": "success",
            "deleted": total_deleted
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route('/upload_pcap', methods=['POST'])
@login_required
def upload_pcap():
    try:
        if 'pcap' not in request.files:
            return jsonify({"status": "error", "message": "No file provided"}), 400

        file = request.files['pcap']
        if file.filename == '':
            return jsonify({"status": "error", "message": "Empty filename"}), 400

        incoming_folder = current_app.config['INCOMING_FOLDER']
        original_filename = secure_filename(file.filename)
        
        # Generate unique pcap_id for new uploads
        import uuid
        pcap_id = uuid.uuid4().hex
        
        # Rename file with pcap_id: {pcap_id}_{original_filename}
        base, ext = os.path.splitext(original_filename)
        filename = f"{pcap_id}_{original_filename}"

        # Avoid overwrite: if exists, append counter
        dest_path = os.path.join(incoming_folder, filename)
        counter = 1
        while os.path.exists(dest_path):
            filename = f"{pcap_id}_{base}_{counter}{ext}"
            dest_path = os.path.join(incoming_folder, filename)
            counter += 1

        os.makedirs(incoming_folder, exist_ok=True)
        file.save(dest_path)

        # Update global state
        FILE_STATUS[filename] = 'Pending'
        FILE_SIZES[filename] = round(os.path.getsize(dest_path)/(1024*1024), 2)

        return jsonify({"status": "success", "name": filename, "pcap_id": pcap_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- FLOWS SUMMARY API ---

@api_bp.route('/flows-summary')
@login_required
def flows_summary():
    """Aggregate flows from all logs into unique flow entries"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        
        # Read all log files
        all_flows = []
        for log_file in glob.glob(os.path.join(logs_folder, "*.csv")):
            try:
                df = pd.read_csv(log_file, sep='#')
                df.columns = [str(c).replace('%', '').strip() for c in df.columns]
                
                # Filter only threat flows
                if 'result' in df.columns:
                    threat_mask = ~df['result'].astype(str).str.lower().isin(['safe', 'benign', '0', 'clean'])
                    df = df[threat_mask]
                
                all_flows.append(df)
            except Exception as e:
                print(f"Error reading {log_file}: {e}")
                continue
        
        if not all_flows:
            return jsonify({
                "total_flows": 0,
                "attack_flows": 0,
                "top_src_ips": [],
                "top_dst_ips": [],
                "protocol_dist": [],
                "attack_details": []
            })
        
        # Combine all flows
        combined_df = pd.concat(all_flows, ignore_index=True)
        
        # Create unique flows (group by src, dst, srcport, dstport, protocol)
        if 'IPV4_SRC_ADDR' in combined_df.columns and 'IPV4_DST_ADDR' in combined_df.columns:
            flow_cols = ['IPV4_SRC_ADDR', 'L4_SRC_PORT', 'IPV4_DST_ADDR', 'L4_DST_PORT', 'PROTOCOL']
            existing_cols = [c for c in flow_cols if c in combined_df.columns]
            
            if existing_cols:
                unique_flows = combined_df.drop_duplicates(subset=existing_cols)
            else:
                unique_flows = combined_df.drop_duplicates()
        else:
            unique_flows = combined_df.drop_duplicates()
        
        # Calculate stats
        total_flows = len(unique_flows)
        attack_flows = len(unique_flows[unique_flows['result'].astype(str).str.lower().apply(
            lambda x: x not in ['safe', 'benign', '0', 'clean'])])
        
        # Top Source IPs
        if 'IPV4_SRC_ADDR' in combined_df.columns:
            top_src = combined_df['IPV4_SRC_ADDR'].value_counts().head(10).to_dict()
            top_src_ips = [{"ip": k, "count": int(v)} for k, v in top_src.items()]
        else:
            top_src_ips = []
        
        # Top Destination IPs
        if 'IPV4_DST_ADDR' in combined_df.columns:
            top_dst = combined_df['IPV4_DST_ADDR'].value_counts().head(10).to_dict()
            top_dst_ips = [{"ip": k, "count": int(v)} for k, v in top_dst.items()]
        else:
            top_dst_ips = []
        
        # Protocol Distribution
        if 'PROTOCOL' in combined_df.columns:
            proto_dist = combined_df['PROTOCOL'].value_counts().to_dict()
            protocol_dist = [{"protocol": str(k), "count": int(v)} for k, v in proto_dist.items()][:10]
        else:
            protocol_dist = []
        
        # Attack Details (latest 10 attack flows)
        attack_details = []
        if 'result' in combined_df.columns:
            attack_mask = ~combined_df['result'].astype(str).str.lower().isin(['safe', 'benign', '0', 'clean'])
            attack_df = combined_df[attack_mask].head(10)
            
            for idx, row in attack_df.iterrows():
                attack_details.append({
                    "src_ip": str(row.get('IPV4_SRC_ADDR', '-')),
                    "dst_ip": str(row.get('IPV4_DST_ADDR', '-')),
                    "src_port": str(row.get('L4_SRC_PORT', '-')),
                    "dst_port": str(row.get('L4_DST_PORT', '-')),
                    "protocol": str(row.get('PROTOCOL', '-')),
                    "result": str(row.get('result', '-')),
                    "file": str(row.get('file_scaned', '-'))
                })
        
        return jsonify({
            "total_flows": total_flows,
            "attack_flows": attack_flows,
            "top_src_ips": top_src_ips,
            "top_dst_ips": top_dst_ips,
            "protocol_dist": protocol_dist,
            "attack_details": attack_details
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- LOGS & DETAILS API ---

@api_bp.route('/get_flows')
@login_required
def get_flows():
    model = request.args.get('model', 'Random Forest')
    task = request.args.get('task', 'binary')
    logs_folder = current_app.config['LOGS_FOLDER']
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))
    
    # Get filter parameters
    search = request.args.get('search', '').strip().lower()
    filter_time = request.args.get('filter_time', '').strip().lower()
    filter_file = request.args.get('filter_file', '').strip().lower()
    filter_srcip = request.args.get('filter_srcip', '').strip().lower()
    filter_srcport = request.args.get('filter_srcport', '').strip().lower()
    filter_dstip = request.args.get('filter_dstip', '').strip().lower()
    filter_dstport = request.args.get('filter_dstport', '').strip().lower()
    filter_prediction = request.args.get('filter_prediction', '').strip().lower()
    
    # Get sort parameters
    sort_by = request.args.get('sort_by', 'time').strip().lower()
    sort_order = request.args.get('sort_order', 'desc').strip().lower()
    
    path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
    
    if not os.path.exists(path): 
        return jsonify({"flows": [], "total": 0})
    
    try:
        df = pd.read_csv(path, sep='#')
        # Clean column names (remove %)
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        # Apply filters
        if search:
            # Global search across all columns (case-insensitive)
            mask = df.astype(str).apply(lambda x: x.str.contains(search, case=False, na=False).any(), axis=1)
            df = df[mask]
        
        if filter_time and 'time_scaned' in df.columns:
            df = df[df['time_scaned'].astype(str).str.contains(filter_time, case=False, na=False)]
        
        if filter_file and 'file_scaned' in df.columns:
            df = df[df['file_scaned'].astype(str).str.contains(filter_file, case=False, na=False)]
        
        if filter_srcip and 'IPV4_SRC_ADDR' in df.columns:
            df = df[df['IPV4_SRC_ADDR'].astype(str).str.contains(filter_srcip, case=False, na=False)]
        
        if filter_srcport and 'L4_SRC_PORT' in df.columns:
            df = df[df['L4_SRC_PORT'].astype(str).str.contains(filter_srcport, case=False, na=False)]
        
        if filter_dstip and 'IPV4_DST_ADDR' in df.columns:
            df = df[df['IPV4_DST_ADDR'].astype(str).str.contains(filter_dstip, case=False, na=False)]
        
        if filter_dstport and 'L4_DST_PORT' in df.columns:
            df = df[df['L4_DST_PORT'].astype(str).str.contains(filter_dstport, case=False, na=False)]
        
        if filter_prediction and 'result' in df.columns:
            df = df[df['result'].astype(str).str.contains(filter_prediction, case=False, na=False)]
        
        # ============== APPLY SORTING ==============
        # Map frontend column names to DataFrame column names
        sort_column_map = {
            'time': 'time_scaned',
            'file': 'file_scaned',
            'srcip': 'IPV4_SRC_ADDR',
            'srcport': 'L4_SRC_PORT',
            'dstip': 'IPV4_DST_ADDR',
            'dstport': 'L4_DST_PORT',
            'prediction': 'result'
        }
        
        # Get actual column name from mapping
        sort_col = sort_column_map.get(sort_by, 'time_scaned')
        
        # Check if column exists in dataframe
        if sort_col not in df.columns:
            sort_col = 'time_scaned'
        
        # Determine ascending based on sort_order
        ascending = (sort_order == 'asc')
        
        # Try to sort numerically for ports and numeric columns
        if sort_col in ['L4_SRC_PORT', 'L4_DST_PORT', 'FLOW_START_MILLISECONDS']:
            try:
                df[sort_col] = pd.to_numeric(df[sort_col], errors='coerce')
                df = df.sort_values(by=sort_col, ascending=ascending, na_position='last')
            except:
                df = df.sort_values(by=sort_col, ascending=ascending)
        else:
            # String sorting for other columns
            df = df.sort_values(by=sort_col, ascending=ascending)

        total = len(df)

        # Apply pagination
        flows = df.iloc[offset:offset+limit].fillna('').to_dict('records')
        # Attach sequence number for UI (1-based, relative to full sorted list)
        for i, rec in enumerate(flows):
            rec['seq'] = int(offset + i + 1)
        
        return jsonify({
            "flows": flows,
            "total": total,
            "offset": offset,
            "limit": limit
        })
    except Exception as e: 
        return jsonify({"error": str(e)})


@api_bp.route('/get_consensus_logs')
@login_required
def get_consensus_logs():
    """
    API để lấy kết quả tổng hợp từ voting/consensus của tất cả models.
    File: Consensus_Voting.csv
    """
    logs_folder = current_app.config['LOGS_FOLDER']
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))
    
    # Get filter parameters
    search = request.args.get('search', '').strip().lower()
    filter_time = request.args.get('filter_time', '').strip().lower()
    filter_file = request.args.get('filter_file', '').strip().lower()
    filter_srcip = request.args.get('filter_srcip', '').strip().lower()
    filter_srcport = request.args.get('filter_srcport', '').strip().lower()
    filter_dstip = request.args.get('filter_dstip', '').strip().lower()
    filter_dstport = request.args.get('filter_dstport', '').strip().lower()
    filter_result = request.args.get('filter_result', '').strip().lower()
    filter_votes = request.args.get('filter_votes', '').strip()
    
    # Get sort parameters
    sort_by = request.args.get('sort_by', 'time').strip().lower()
    sort_order = request.args.get('sort_order', 'desc').strip().lower()
    
    path = os.path.join(logs_folder, "Consensus_Voting.csv")
    
    if not os.path.exists(path): 
        return jsonify({"flows": [], "total": 0})
    
    try:
        df = pd.read_csv(path, sep='#')
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        # Apply filters
        if search:
            mask = df.astype(str).apply(lambda x: x.str.contains(search, case=False, na=False).any(), axis=1)
            df = df[mask]
        
        if filter_time and 'time_scaned' in df.columns:
            df = df[df['time_scaned'].astype(str).str.contains(filter_time, case=False, na=False)]
        
        if filter_file and 'file_scaned' in df.columns:
            df = df[df['file_scaned'].astype(str).str.contains(filter_file, case=False, na=False)]
        
        if filter_srcip and 'IPV4_SRC_ADDR' in df.columns:
            df = df[df['IPV4_SRC_ADDR'].astype(str).str.contains(filter_srcip, case=False, na=False)]
        
        if filter_srcport and 'L4_SRC_PORT' in df.columns:
            df = df[df['L4_SRC_PORT'].astype(str).str.contains(filter_srcport, case=False, na=False)]
        
        if filter_dstip and 'IPV4_DST_ADDR' in df.columns:
            df = df[df['IPV4_DST_ADDR'].astype(str).str.contains(filter_dstip, case=False, na=False)]
        
        if filter_dstport and 'L4_DST_PORT' in df.columns:
            df = df[df['L4_DST_PORT'].astype(str).str.contains(filter_dstport, case=False, na=False)]
        
        if filter_result and 'result' in df.columns:
            df = df[df['result'].astype(str).str.contains(filter_result, case=False, na=False)]
        
        if filter_votes and 'votes' in df.columns:
            try:
                min_votes = int(filter_votes)
                df = df[pd.to_numeric(df['votes'], errors='coerce') >= min_votes]
            except:
                pass
        
        # Sort
        sort_column_map = {
            'time': 'time_scaned',
            'file': 'file_scaned',
            'srcip': 'IPV4_SRC_ADDR',
            'srcport': 'L4_SRC_PORT',
            'dstip': 'IPV4_DST_ADDR',
            'dstport': 'L4_DST_PORT',
            'result': 'result',
            'votes': 'votes',
            'confidence': 'confidence',
            'source': 'detection_source'
        }
        
        sort_col = sort_column_map.get(sort_by, 'time_scaned')
        if sort_col not in df.columns:
            sort_col = 'time_scaned'
        
        ascending = (sort_order == 'asc')
        
        if sort_col == 'votes':
            try:
                df['votes'] = pd.to_numeric(df['votes'], errors='coerce')
                df = df.sort_values(by=sort_col, ascending=ascending, na_position='last')
            except:
                df = df.sort_values(by=sort_col, ascending=ascending)
        else:
            df = df.sort_values(by=sort_col, ascending=ascending)

        total = len(df)
        flows = df.iloc[offset:offset+limit].fillna('').to_dict('records')
        
        for i, rec in enumerate(flows):
            rec['seq'] = int(offset + i + 1)
        
        return jsonify({
            "flows": flows,
            "total": total,
            "offset": offset,
            "limit": limit
        })
    except Exception as e: 
        return jsonify({"error": str(e)})


@api_bp.route('/clear_consensus_logs', methods=['POST'])
@login_required
def clear_consensus_logs():
    """Clear consensus/voting logs"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        path = os.path.join(logs_folder, "Consensus_Voting.csv")
        
        if not os.path.exists(path):
            return jsonify({"status": "error", "message": "Log file not found"}), 404
        
        df = pd.read_csv(path, sep='#')
        total_deleted = len(df)
        
        # Clear file but keep header
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        df_empty = pd.DataFrame(columns=df.columns)
        df_empty.to_csv(path, index=False, sep='#')
        
        return jsonify({
            "status": "success",
            "deleted": total_deleted
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route('/consensus-details/<flow_id>')
@login_required
def get_consensus_details(flow_id):
    """Get detailed information about a specific consensus voting log entry"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        path = os.path.join(logs_folder, "Consensus_Voting.csv")
        
        if not os.path.exists(path):
            return jsonify({"error": "Consensus log file not found"}), 404
        
        df = pd.read_csv(path, sep='#')
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        # Find the record by ID
        rec = df[df['id'].astype(str).str.strip() == str(flow_id).strip()]
        
        if rec.empty:
            return jsonify({"error": "Flow not found"}), 404
        
        return jsonify(rec.iloc[0].replace({np.nan: None}).to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/top-flows')
@login_required
def get_top_flows():
    """Get top 5 flows by traffic (IN_BYTES + OUT_BYTES)"""
    model = request.args.get('model', 'Random Forest')
    task = request.args.get('task', 'binary')
    logs_folder = current_app.config['LOGS_FOLDER']
    
    path = os.path.join(logs_folder, f"{model.replace(' ', '_')}_{task}.csv")
    
    if not os.path.exists(path):
        return jsonify({"flows": []})
    
    try:
        df = pd.read_csv(path, sep='#')
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        # Calculate total traffic
        df['IN_BYTES'] = pd.to_numeric(df['IN_BYTES'], errors='coerce').fillna(0)
        df['OUT_BYTES'] = pd.to_numeric(df['OUT_BYTES'], errors='coerce').fillna(0)
        df['total_traffic'] = df['IN_BYTES'] + df['OUT_BYTES']
        
        # Get top 5 by traffic
        top5 = df.nlargest(5, 'total_traffic')[['IPV4_SRC_ADDR', 'L4_SRC_PORT', 'IPV4_DST_ADDR', 'L4_DST_PORT', 'PROTOCOL', 'IN_BYTES', 'OUT_BYTES', 'total_traffic']].fillna('')
        
        return jsonify({"flows": top5.to_dict('records')})
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
        df = pd.read_csv(path, sep='#')
        df.columns = [str(c).replace('%', '').strip() for c in df.columns]
        
        # Tìm dòng có id khớp (chuyển về string để so sánh an toàn)
        rec = df[df['id'].astype(str).str.strip() == str(flow_id).strip()]
        
        if not rec.empty:
            return jsonify(rec.iloc[0].replace({np.nan: None}).to_dict())
        else:
            return jsonify({"error": "Not found"}), 404
    except Exception: 
        return jsonify({"error": "Error processing log file"}), 500


@api_bp.route('/delete-file', methods=['POST'])
@login_required
def delete_file():
    try:
        filename = request.args.get('file')
        if not filename:
            return jsonify({"status": "error", "message": "No filename provided"}), 400
        
        incoming_folder = current_app.config['INCOMING_FOLDER']
        filepath = os.path.join(incoming_folder, secure_filename(filename))
        
        if os.path.exists(filepath):
            os.remove(filepath)
            # Clean up from file status tracking
            if filename in FILE_STATUS:
                del FILE_STATUS[filename]
            if filename in FILE_SIZES:
                del FILE_SIZES[filename]
            
            return jsonify({"status": "success", "message": "File deleted"})
        else:
            return jsonify({"status": "error", "message": "File not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route('/download-file')
@login_required
def download_file():
    try:
        filename = request.args.get('file')
        if not filename:
            return jsonify({"status": "error", "message": "No filename provided"}), 400
        
        incoming_folder = current_app.config['INCOMING_FOLDER']
        evidence_folder = current_app.config['EVIDENCE_FOLDER']
        
        # Secure the filename
        safe_filename = secure_filename(filename)
        
        # Try incoming folder first (pending files)
        filepath = os.path.join(incoming_folder, safe_filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        # Try evidence folder (threat files)
        filepath = os.path.join(evidence_folder, safe_filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        
        # File not found in either location
        return jsonify({"status": "error", "message": "File not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- IPS/IDS RULES API ---

@api_bp.route('/ips-rules')
@login_required
def get_ips_rules():
    """Get IPS rules with pagination and search"""
    try:
        # Initialize IPS manager với app context
        ips_manager.init_app(current_app)
        
        offset = request.args.get('offset', 0, type=int)
        limit = request.args.get('limit', 50, type=int)
        search = request.args.get('search', '').strip()
        severity_filter = request.args.get('severity', '').strip()
        category_filter = request.args.get('category', '').strip()
        
        # Get all rules first for filtering
        all_rules = ips_manager.get_all_rules(limit=99999, offset=0)
        
        # Apply search filter
        if search:
            search_lower = search.lower()
            all_rules = [r for r in all_rules if (
                search_lower in str(r.get('rule_id', '')).lower() or
                search_lower in str(r.get('rule_name', '')).lower() or
                search_lower in str(r.get('category', '')).lower() or
                search_lower in str(r.get('source', '')).lower()
            )]
        
        # Apply severity filter
        if severity_filter:
            all_rules = [r for r in all_rules if r.get('severity', '').lower() == severity_filter.lower()]
        
        # Apply category filter
        if category_filter:
            all_rules = [r for r in all_rules if r.get('category', '').lower() == category_filter.lower()]
        
        total_filtered = len(all_rules)
        
        # Apply pagination
        rules = all_rules[offset:offset + limit]
        
        stats = ips_manager.get_statistics()
        
        return jsonify({
            "rules": rules,
            "total_rules": total_filtered,
            "total_all": stats.get('total_rules', 0),
            "statistics": stats,
            "offset": offset,
            "limit": limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-rules/<rule_id>')
@login_required
def get_ips_rule_details(rule_id):
    """Get detailed information about a specific IPS rule"""
    try:
        ips_manager.init_app(current_app)
        rule = ips_manager.get_rule_by_id(rule_id)
        
        if not rule:
            return jsonify({"error": "Rule not found"}), 404
        
        return jsonify(rule)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-rules/search', methods=['POST'])
@login_required
def search_ips_rules():
    """Search IPS rules by keyword"""
    try:
        ips_manager.init_app(current_app)
        keyword = request.json.get('keyword', '')
        
        rules = ips_manager.search_rules(keyword)
        
        return jsonify({
            "rules": rules,
            "count": len(rules)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-statistics')
@login_required
def get_ips_statistics():
    """Get IPS rules statistics"""
    try:
        ips_manager.init_app(current_app)
        stats = ips_manager.get_statistics()
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-rules/severity/<severity>')
@login_required
def get_ips_rules_by_severity(severity):
    """Get IPS rules filtered by severity"""
    try:
        ips_manager.init_app(current_app)
        rules = ips_manager.get_rules_by_severity(severity)
        
        return jsonify({
            "rules": rules,
            "severity": severity,
            "count": len(rules)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-rules/category/<category>')
@login_required
def get_ips_rules_by_category(category):
    """Get IPS rules filtered by category"""
    try:
        ips_manager.init_app(current_app)
        rules = ips_manager.get_rules_by_category(category)
        
        return jsonify({
            "rules": rules,
            "category": category,
            "count": len(rules)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-rules/import-file', methods=['POST'])
@login_required
def import_ips_rules_from_file():
    """Import IPS rules from uploaded CSV or Snort/Suricata .rules file"""
    try:
        ips_manager.init_app(current_app)
        
        if 'file' not in request.files:
            return jsonify({"success": False, "message": "No file provided"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "message": "Empty filename"}), 400
        
        # Hỗ trợ cả CSV và .rules file
        if file.filename.endswith('.csv'):
            # Import từ CSV file
            result = ips_manager.import_rules_from_file(file.stream)
        elif file.filename.endswith('.rules'):
            # Import từ Snort/Suricata .rules file
            rules_text = file.stream.read().decode('utf-8', errors='ignore')
            result = ips_manager.import_snort_rules(rules_text)
        else:
            return jsonify({"success": False, "message": "Supported formats: .csv, .rules"}), 400
        
        return jsonify(result), 200 if result.get('success') else 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@api_bp.route('/ips-rules/import-url', methods=['POST'])
@login_required
def import_ips_rules_from_url():
    """Import IPS rules from URL"""
    try:
        ips_manager.init_app(current_app)
        
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"success": False, "message": "URL not provided"}), 400
        
        # Validate URL
        if not url.startswith('http://') and not url.startswith('https://'):
            return jsonify({"success": False, "message": "Invalid URL (must start with http:// or https://)"}), 400
        
        # Import từ URL
        result = ips_manager.import_rules_from_url(url)
        
        return jsonify(result), 200 if result.get('success') else 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@api_bp.route('/ips-rules/add-ja3', methods=['POST'])
@login_required
def add_ja3_rule():
    """Add a JA3/TLS fingerprint rule"""
    try:
        ips_manager.init_app(current_app)
        data = request.get_json()
        
        rule_name = data.get('rule_name', '').strip()
        category = data.get('category', 'C2/Malware')
        ja3 = data.get('ja3', '').strip().lower()
        ja3s = data.get('ja3s', '').strip().lower()
        sni = data.get('sni', '').strip().lower()
        severity = data.get('severity', 'High')
        description = data.get('description', '')
        
        if not rule_name:
            return jsonify({"status": "error", "message": "Rule name is required"}), 400
        
        if not ja3 and not ja3s and not sni:
            return jsonify({"status": "error", "message": "At least one of JA3, JA3S, or SNI is required"}), 400
        
        # Validate JA3/JA3S format
        import re
        md5_pattern = re.compile(r'^[a-f0-9]{32}$')
        if ja3 and not md5_pattern.match(ja3):
            return jsonify({"status": "error", "message": "JA3 must be a 32-character MD5 hash"}), 400
        if ja3s and not md5_pattern.match(ja3s):
            return jsonify({"status": "error", "message": "JA3S must be a 32-character MD5 hash"}), 400
        
        result = ips_manager.add_ja3_rule(
            rule_name=rule_name,
            category=category,
            ja3=ja3,
            ja3s=ja3s,
            sni=sni,
            severity=severity,
            description=description
        )
        
        if result.get('success'):
            return jsonify({"status": "success", "message": result.get('message'), "rule_id": result.get('rule_id')}), 200
        else:
            return jsonify({"status": "error", "message": result.get('message')}), 400
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@api_bp.route('/ips-rules/<rule_id>', methods=['DELETE'])
@login_required
def delete_ips_rule(rule_id):
    """Delete an IPS rule"""
    try:
        ips_manager.init_app(current_app)
        success = ips_manager.delete_rule(rule_id)
        
        if success:
            return jsonify({"success": True, "message": "Rule deleted successfully"}), 200
        else:
            return jsonify({"success": False, "message": "Rule not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ============= IPS SOURCES API =============

@api_bp.route('/ips-sources')
@login_required
def get_ips_sources():
    """Get all IPS rule sources"""
    try:
        ips_manager.init_app(current_app)
        sources = ips_manager.get_all_sources()
        
        # Clean NaN values for JSON serialization
        for source in sources:
            for key, value in source.items():
                if pd.isna(value):
                    source[key] = None
        
        return jsonify({"sources": sources})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-sources', methods=['POST'])
@login_required
def add_ips_source():
    """Add a new IPS rule source"""
    try:
        ips_manager.init_app(current_app)
        
        data = request.json
        if not data:
            return jsonify({"success": False, "message": "No data provided"}), 400
        
        name = data.get('name', 'Unnamed Source')
        url = data.get('url')
        interval = data.get('interval_minutes', 10)
        
        if not url:
            return jsonify({"success": False, "message": "URL is required"}), 400
        
        result = ips_manager.add_source(name, url, interval)
        
        # Nếu thêm thành công và có auto_refresh, refresh ngay
        if result.get('success') and data.get('auto_refresh', True):
            source_id = result.get('source_id')
            if source_id:
                refresh_result = ips_manager.refresh_source(source_id)
                result['refresh_result'] = refresh_result
        
        return jsonify(result), 200 if result.get('success') else 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@api_bp.route('/ips-sources/<source_id>')
@login_required
def get_ips_source_details(source_id):
    """Get details of a specific IPS source"""
    try:
        ips_manager.init_app(current_app)
        source = ips_manager.get_source_by_id(source_id)
        
        if not source:
            return jsonify({"error": "Source not found"}), 404
        
        return jsonify(source)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/ips-sources/<source_id>', methods=['PUT'])
@login_required
def update_ips_source(source_id):
    """Update an IPS source settings"""
    try:
        ips_manager.init_app(current_app)
        
        data = request.json
        if not data:
            return jsonify({"success": False, "message": "No data provided"}), 400
        
        result = ips_manager.update_source(source_id, **data)
        return jsonify(result), 200 if result.get('success') else 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@api_bp.route('/ips-sources/<source_id>', methods=['DELETE'])
@login_required
def delete_ips_source(source_id):
    """Delete an IPS source"""
    try:
        ips_manager.init_app(current_app)
        result = ips_manager.delete_source(source_id)
        return jsonify(result), 200 if result.get('success') else 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@api_bp.route('/ips-sources/<source_id>/refresh', methods=['POST'])
@login_required
def refresh_ips_source(source_id):
    """Manually refresh rules from a source"""
    try:
        ips_manager.init_app(current_app)
        result = ips_manager.refresh_source(source_id)
        return jsonify(result), 200 if result.get('success') else 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@api_bp.route('/ips-sources/refresh-all', methods=['POST'])
@login_required
def refresh_all_ips_sources():
    """Refresh all sources that need update"""
    try:
        ips_manager.init_app(current_app)
        result = ips_manager.refresh_all_sources()
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# --- IPS LOGS API ---

@api_bp.route('/ips-logs')
@login_required
def get_ips_logs():
    """Get IPS detection logs with pagination and filtering"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        log_path = os.path.join(logs_folder, 'IPS_Detections.csv')
        
        offset = request.args.get('offset', 0, type=int)
        limit = request.args.get('limit', 50, type=int)
        search = request.args.get('search', '').strip()
        severity_filter = request.args.get('severity', '').strip()
        sort_by = request.args.get('sort_by', 'time').strip()
        sort_order = request.args.get('sort_order', 'desc').strip()
        
        if not os.path.exists(log_path):
            return jsonify({
                "logs": [],
                "total": 0,
                "statistics": {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium_low": 0
                }
            })
        
        df = pd.read_csv(log_path, sep='#')
        df.columns = [str(c).strip() for c in df.columns]
        
        # Calculate statistics before filtering
        stats = {
            "total": len(df),
            "critical": len(df[df['severity'].str.lower() == 'critical']) if 'severity' in df.columns else 0,
            "high": len(df[df['severity'].str.lower() == 'high']) if 'severity' in df.columns else 0,
            "medium_low": len(df[df['severity'].str.lower().isin(['medium', 'low'])]) if 'severity' in df.columns else 0
        }
        
        # Apply search filter
        if search:
            search_lower = search.lower()
            mask = df.astype(str).apply(lambda x: x.str.contains(search_lower, case=False, na=False).any(), axis=1)
            df = df[mask]
        
        # Apply severity filter
        if severity_filter:
            df = df[df['severity'].str.lower() == severity_filter.lower()]
        
        # Sort
        sort_column_map = {
            'time': 'timestamp',
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip',
            'rule_name': 'rule_name',
            'severity': 'severity'
        }
        sort_col = sort_column_map.get(sort_by, 'timestamp')
        if sort_col in df.columns:
            ascending = (sort_order == 'asc')
            df = df.sort_values(by=sort_col, ascending=ascending, na_position='last')
        
        total_filtered = len(df)
        
        # Apply pagination
        logs = df.iloc[offset:offset + limit].fillna('').to_dict('records')
        
        return jsonify({
            "logs": logs,
            "total": total_filtered,
            "statistics": stats,
            "offset": offset,
            "limit": limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/ips-logs/<log_id>')
@login_required
def get_ips_log_details(log_id):
    """Get detailed information about a specific IPS log entry"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        log_path = os.path.join(logs_folder, 'IPS_Detections.csv')
        
        if not os.path.exists(log_path):
            return jsonify({"error": "Log file not found"}), 404
        
        df = pd.read_csv(log_path, sep='#')
        df.columns = [str(c).strip() for c in df.columns]
        
        rec = df[df['id'].astype(str).str.strip() == str(log_id).strip()]
        
        if rec.empty:
            return jsonify({"error": "Log entry not found"}), 404
        
        return jsonify(rec.iloc[0].replace({np.nan: None}).to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route('/ips-logs/clear', methods=['POST'])
@login_required
def clear_ips_logs():
    """Clear IPS detection logs"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        log_path = os.path.join(logs_folder, 'IPS_Detections.csv')
        
        if not os.path.exists(log_path):
            return jsonify({"status": "success", "deleted": 0})
        
        df = pd.read_csv(log_path, sep='#')
        total_deleted = len(df)
        
        # Clear file but keep header
        df_empty = pd.DataFrame(columns=df.columns)
        df_empty.to_csv(log_path, index=False, sep='#')
        
        return jsonify({
            "status": "success",
            "deleted": total_deleted
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --- LOG SUMMARY API ---

@api_bp.route('/logs/summary')
@login_required
def get_logs_summary():
    """Get summary of all logs"""
    try:
        logs_folder = current_app.config['LOGS_FOLDER']
        summary = {}
        
        # Model Logs
        model_logs = [
            'DNN_binary.csv', 'DNN_multiclass.csv',
            'LightGBM_binary.csv', 'LightGBM_multiclass.csv',
            'Random_Forest_binary.csv', 'Random_Forest_multiclass.csv'
        ]
        
        for log_file in model_logs:
            log_path = os.path.join(logs_folder, log_file)
            count = 0
            last_updated = 'Never'
            if os.path.exists(log_path):
                try:
                    df = pd.read_csv(log_path, sep='#')
                    count = len(df)
                    if count > 0 and 'timestamp' in df.columns:
                        last_updated = str(df['timestamp'].iloc[-1])
                except:
                    pass
            
            summary[log_file] = {
                'type': 'Model Log',
                'count': count,
                'last_updated': last_updated,
                'status': 'OK' if count > 0 else 'Empty'
            }
        
        # Consensus Voting Logs
        consensus_path = os.path.join(logs_folder, 'Consensus_Voting.csv')
        count = 0
        last_updated = 'Never'
        if os.path.exists(consensus_path):
            try:
                df = pd.read_csv(consensus_path, sep='#')
                count = len(df)
                if count > 0 and 'timestamp' in df.columns:
                    last_updated = str(df['timestamp'].iloc[-1])
            except:
                pass
        
        summary['Consensus_Voting.csv'] = {
            'type': 'Consensus Voting',
            'count': count,
            'last_updated': last_updated,
            'status': 'OK' if count > 0 else 'Empty'
        }
        
        # IPS Logs
        ips_path = os.path.join(logs_folder, 'IPS_Detections.csv')
        count = 0
        last_updated = 'Never'
        if os.path.exists(ips_path):
            try:
                df = pd.read_csv(ips_path, sep='#')
                count = len(df)
                if count > 0 and 'timestamp' in df.columns:
                    last_updated = str(df['timestamp'].iloc[-1])
            except:
                pass
        
        summary['IPS_Detections.csv'] = {
            'type': 'IPS Logs',
            'count': count,
            'last_updated': last_updated,
            'status': 'OK' if count > 0 else 'Empty'
        }
        
        # Calculate total
        total_entries = sum([s['count'] for s in summary.values()])
        
        return jsonify({
            'status': 'success',
            'summary': summary,
            'total_entries': total_entries
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/logs/delete', methods=['POST'])
@login_required
def delete_logs():
    """Delete logs - support bulk deletion"""
    try:
        data = request.get_json()
        log_files = data.get('log_files', [])
        
        if not log_files:
            return jsonify({'status': 'error', 'message': 'No logs selected'}), 400
        
        logs_folder = current_app.config['LOGS_FOLDER']
        deleted_count = 0
        deleted_logs = []
        
        for log_file in log_files:
            # Validate filename to prevent path traversal
            if '..' in log_file or '/' in log_file:
                continue
            
            log_path = os.path.join(logs_folder, log_file)
            
            if os.path.exists(log_path) and log_path.startswith(logs_folder):
                try:
                    df = pd.read_csv(log_path, sep='#')
                    count = len(df)
                    
                    # Clear file but keep header
                    df_empty = pd.DataFrame(columns=df.columns)
                    df_empty.to_csv(log_path, index=False, sep='#')
                    
                    deleted_count += count
                    deleted_logs.append({
                        'file': log_file,
                        'entries': count
                    })
                except:
                    pass
        
        return jsonify({
            'status': 'success',
            'message': f'Deleted {deleted_count} entries from {len(deleted_logs)} logs',
            'deleted_logs': deleted_logs,
            'total_deleted': deleted_count
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# --- SYSTEM LOGS ENDPOINTS ---

@api_bp.route('/system-logs/api-calls')
@login_required
def get_api_logs():
    """Get API call logs"""
    try:
        from app.core.system_logger import get_system_logger
        logger = get_system_logger()
        
        limit = request.args.get('limit', 100, type=int)
        logs = logger.get_api_logs(limit=limit)
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'total': len(logs)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/system-logs/logins')
@login_required
def get_login_logs():
    """Get user login logs"""
    try:
        from app.core.system_logger import get_system_logger
        logger = get_system_logger()
        
        limit = request.args.get('limit', 100, type=int)
        logs = logger.get_login_logs(limit=limit)
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'total': len(logs)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/system-logs/system-metrics')
@login_required
def get_system_metrics():
    """Get system metrics logs and current metrics"""
    try:
        from app.core.system_logger import get_system_logger
        logger = get_system_logger()
        
        limit = request.args.get('limit', 100, type=int)
        logs = logger.get_system_logs(limit=limit)
        current_metrics = logger.get_current_system_metrics()
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'current_metrics': current_metrics,
            'total': len(logs)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/delete-evidence-pcap', methods=['POST'])
@login_required
def delete_evidence_pcap():
    """Delete evidence PCAP file with password verification (force delete)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        filename = data.get('filename')
        password = data.get('password')
        
        # Validate required fields
        if not filename:
            return jsonify({'status': 'error', 'message': 'Filename is required'}), 400
        
        if not password:
            return jsonify({'status': 'error', 'message': 'Password verification required to delete evidence'}), 403
        
        # Verify password against current user
        user = User.query.get(current_user.id)
        if not user or not check_password_hash(user.password, password):
            return jsonify({'status': 'error', 'message': 'Invalid password'}), 403
        
        # Secure filename to prevent path traversal
        safe_filename = secure_filename(filename)
        if not safe_filename:
            return jsonify({'status': 'error', 'message': 'Invalid filename'}), 400
        
        evidence_folder = current_app.config['EVIDENCE_FOLDER']
        filepath = os.path.join(evidence_folder, safe_filename)
        
        # Verify file exists and is within evidence folder
        if not os.path.exists(filepath):
            return jsonify({'status': 'error', 'message': 'Evidence file not found'}), 404
        
        if not filepath.startswith(evidence_folder):
            return jsonify({'status': 'error', 'message': 'Access denied'}), 403
        
        # Delete the file
        os.remove(filepath)
        
        # Update PCAP metadata to mark as deleted
        with PCAP_METADATA_LOCK:
            for pcap_id, metadata in PCAP_METADATA.items():
                if metadata.get('pcap_name') == safe_filename:
                    metadata['pcap_exists'] = False
                    break
        
        return jsonify({
            'status': 'success',
            'message': f'Evidence file "{safe_filename}" deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
