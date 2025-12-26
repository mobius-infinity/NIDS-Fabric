import os
import glob
import pandas as pd
import numpy as np
from flask import Blueprint, jsonify, request, current_app, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime

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

@api_bp.route('/incoming-files')
@login_required
def get_incoming_files():
    filename = request.args.get('file')
    incoming_folder = current_app.config['INCOMING_FOLDER']
    
    # If specific file requested, return details
    if filename:
        filepath = os.path.join(incoming_folder, secure_filename(filename))
        if os.path.exists(filepath):
            try:
                return jsonify({
                    "status": "success",
                    "file": {
                        "name": filename,
                        "size_mb": round(os.path.getsize(filepath)/(1024*1024), 2),
                        "size_bytes": os.path.getsize(filepath),
                        "status": FILE_STATUS.get(filename, 'Pending'),
                        "upload_date": datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S'),
                        "total_flows": 0,
                        "threat_flows": 0,
                        "safe_flows": 0
                    }
                })
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
        else:
            # Try to get from FILE_STATUS if file was processed
            if filename in FILE_STATUS:
                return jsonify({
                    "status": "success",
                    "file": {
                        "name": filename,
                        "size_mb": FILE_SIZES.get(filename, 0),
                        "size_bytes": FILE_SIZES.get(filename, 0) * 1024 * 1024,
                        "status": FILE_STATUS.get(filename, 'Unknown'),
                        "upload_date": "N/A",
                        "total_flows": 0,
                        "threat_flows": 0,
                        "safe_flows": 0
                    }
                })
            return jsonify({"status": "error", "message": "File not found"}), 404
    
    # Otherwise return list of all files
    files = []
    if os.path.exists(incoming_folder):
        for f in glob.glob(os.path.join(incoming_folder, "*.pcap*")):
            bn = os.path.basename(f)
            # Cập nhật size nếu chưa có hoặc cập nhật mới
            sz = FILE_SIZES.get(bn, round(os.path.getsize(f)/(1024*1024), 2))
            FILE_SIZES[bn] = sz
            files.append({
                "name": bn, 
                "size_mb": sz, 
                "status": FILE_STATUS.get(bn, 'Pending'),
                "upload_date": datetime.fromtimestamp(os.path.getctime(f)).strftime('%Y-%m-%d %H:%M:%S')
            })
            
    # Thêm các file đang xử lý nhưng đã bị move khỏi folder incoming (để hiển thị trạng thái Done/Error)
    for f_name, status in FILE_STATUS.items():
        if ('Done' in status or 'Error' in status) and not any(x['name'] == f_name for x in files):
            files.append({
                "name": f_name, 
                "size_mb": FILE_SIZES.get(f_name, 0), 
                "status": status,
                "upload_date": "N/A"
            })
            
    return jsonify({"files": sorted(files, key=lambda x: x['name'])})


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
        filename = secure_filename(file.filename)

        # Avoid overwrite: if exists, append counter
        dest_path = os.path.join(incoming_folder, filename)
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(dest_path):
            filename = f"{base}_{counter}{ext}"
            dest_path = os.path.join(incoming_folder, filename)
            counter += 1

        os.makedirs(incoming_folder, exist_ok=True)
        file.save(dest_path)

        # Update global state
        FILE_STATUS[filename] = 'Pending'
        FILE_SIZES[filename] = round(os.path.getsize(dest_path)/(1024*1024), 2)

        return jsonify({"status": "success", "name": filename})
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
        filepath = os.path.join(incoming_folder, secure_filename(filename))
        
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({"status": "error", "message": "File not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
