import os

# Disable CUDA/GPU logging since GPU is not used
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow logs
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU

import glob
import time
import shutil
import uuid
import traceback
import pandas as pd
import numpy as np
from datetime import datetime

# Suppress TensorFlow warnings
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=FutureWarning)

# Import các biến Global
from app.globals import (
    HISTORY_LOCK, CONFIG_LOCK, REALTIME_HISTORY, 
    FILE_STATUS, FILE_SIZES, GLOBAL_THREAT_STATS, SYSTEM_CONFIG,
    PCAP_METADATA, PCAP_METADATA_LOCK
)
# Import ML Logic
from app.core.pcap_utils import convert_pcap_to_csv, FEATURES_DNN_RF, LIGHTGBM_23_FEATURES
from app.core.ml_engine import model_cache, get_binary_prediction_vector, predict_logic_full_str
from app.core.ips_engine import ips_engine

def update_model_log(app, model_name, task, df_results):
    """
    Hàm ghi log, cần nhận biến 'app' để biết LOGS_FOLDER nằm ở đâu.
    OPTIMIZED: Uses mode='a' for faster appending
    """
    try:
        log_path = os.path.join(app.config['LOGS_FOLDER'], f"{model_name.replace(' ', '_')}_{task}.csv")
        
        # Xóa các cột trống/NaN trước concat để tránh FutureWarning
        df_results = df_results.dropna(axis=1, how='all')
        
        # If file exists, append directly (faster than read-concat-write)
        if os.path.exists(log_path):
            # Read to check row count and columns
            df_old = pd.read_csv(log_path, sep='#', low_memory=False)
            
            # Align columns
            for col in df_results.columns:
                if col not in df_old.columns:
                    df_old[col] = None
            
            df_old_aligned = df_old[df_results.columns].dropna(axis=1, how='all')
            df_results_clean = df_results.dropna(axis=1, how='all')
            combined = pd.concat([df_old_aligned, df_results_clean], ignore_index=True)
            
            # Keep only last 10000 rows
            if len(combined) > 10000:
                combined = combined.tail(10000)
        else:
            combined = df_results
            
        if 'time_scaned' in combined.columns: 
            combined = combined.sort_values(by='time_scaned')
            
        combined.to_csv(log_path, index=False, sep='#')
    except Exception as e: 
        print(f"[Log Error] Cannot write log: {e}")

def update_consensus_log(app, df_raw, votes, final_decisions, threshold, mode, filename, timestamp, 
                         detection_sources=None, ips_matches=None):
    """
    Ghi log kết quả consensus/voting từ tất cả models.
    File: Consensus_Voting.csv
    
    Args:
        detection_sources: list of source types ('ML_HIGH_THREAT', 'ML_IPS_CONFIRMED', etc.)
        ips_matches: list of IPS match results (rule_id, rule_name for each flow)
    """
    try:
        log_path = os.path.join(app.config['LOGS_FOLDER'], "Consensus_Voting.csv")
        
        # Tạo DataFrame với kết quả tổng hợp
        df_consensus = df_raw.copy()
        df_consensus['id'] = [uuid.uuid4().hex for _ in range(len(df_consensus))]
        df_consensus['time_scaned'] = timestamp
        df_consensus['file_scaned'] = filename
        df_consensus['votes'] = votes
        df_consensus['threshold'] = threshold
        df_consensus['detection_mode'] = mode
        
        # Kết quả cuối cùng dựa trên voting
        df_consensus['result'] = ['attack' if d == 1 else 'benign' for d in final_decisions]
        df_consensus['confidence'] = [f"{v}/{6}" for v in votes]  # 6 models total
        
        # Thêm thông tin Hybrid detection
        if detection_sources is not None:
            df_consensus['detection_source'] = detection_sources
        else:
            df_consensus['detection_source'] = 'ML_ONLY'
            
        if ips_matches is not None:
            df_consensus['ips_matched'] = [m.get('matched', False) if m else False for m in ips_matches]
            df_consensus['ips_rule_id'] = [m.get('rule_id', '') if m else '' for m in ips_matches]
            df_consensus['ips_rule_name'] = [m.get('rule_name', '') if m else '' for m in ips_matches]
        else:
            df_consensus['ips_matched'] = False
            df_consensus['ips_rule_id'] = ''
            df_consensus['ips_rule_name'] = ''
        
        # Chọn các cột quan trọng để lưu
        important_cols = ['id', 'time_scaned', 'file_scaned', 'IPV4_SRC_ADDR', 'L4_SRC_PORT', 
                         'IPV4_DST_ADDR', 'L4_DST_PORT', 'PROTOCOL', 'votes', 'threshold',
                         'detection_mode', 'result', 'confidence', 'detection_source',
                         'ips_matched', 'ips_rule_id', 'ips_rule_name']
        
        # Chỉ giữ các cột tồn tại
        existing_cols = [c for c in important_cols if c in df_consensus.columns]
        df_consensus = df_consensus[existing_cols].dropna(axis=1, how='all')
        
        # Đọc cũ -> Nối mới -> Giữ 10000 dòng
        if os.path.exists(log_path):
            df_old = pd.read_csv(log_path, sep='#')
            for col in df_consensus.columns:
                if col not in df_old.columns:
                    df_old[col] = None
            df_old_aligned = df_old[df_consensus.columns].dropna(axis=1, how='all')
            df_consensus_clean = df_consensus.dropna(axis=1, how='all')
            combined = pd.concat([df_old_aligned, df_consensus_clean], ignore_index=True)
        else:
            combined = df_consensus
            
        if 'time_scaned' in combined.columns: 
            combined = combined.sort_values(by='time_scaned')
            
        combined.tail(10000).to_csv(log_path, index=False, sep='#')
    except Exception as e: 
        print(f"[Consensus Log Error] Cannot write log: {e}")


def update_ips_log(app, df_raw, ips_matches, filename, timestamp):
    """
    Ghi log các detections từ IPS Engine.
    File: IPS_Detections.csv
    
    Chỉ ghi những flow mà IPS đã match (ips_matches[i]['matched'] == True)
    """
    try:
        log_path = os.path.join(app.config['LOGS_FOLDER'], "IPS_Detections.csv")
        
        # Filter only matched flows
        matched_indices = [i for i, m in enumerate(ips_matches) if m.get('matched', False)]
        
        if not matched_indices:
            return  # No IPS matches to log
        
        # Create log entries only for matched flows
        log_entries = []
        for i in matched_indices:
            flow = df_raw.iloc[i]
            match = ips_matches[i]
            
            entry = {
                'id': uuid.uuid4().hex,
                'timestamp': timestamp,
                'file_scaned': filename,
                'src_ip': flow.get('IPV4_SRC_ADDR', ''),
                'src_port': flow.get('L4_SRC_PORT', ''),
                'dst_ip': flow.get('IPV4_DST_ADDR', ''),
                'dst_port': flow.get('L4_DST_PORT', ''),
                'protocol': flow.get('PROTOCOL', ''),
                'rule_id': match.get('rule_id', ''),
                'rule_name': match.get('rule_name', ''),
                'severity': match.get('severity', ''),
                'category': match.get('category', ''),
                'match_type': match.get('match_type', ''),  # JA3, JA3S, SNI, PORT
                'ja3_hash': flow.get('JA3C_HASH', ''),
                'ja3s_hash': flow.get('JA3S_HASH', ''),
                'sni': flow.get('SSL_SERVER_NAME', ''),
                'in_bytes': flow.get('IN_BYTES', 0),
                'out_bytes': flow.get('OUT_BYTES', 0),
            }
            log_entries.append(entry)
        
        df_new = pd.DataFrame(log_entries)
        
        # Append to existing or create new
        if os.path.exists(log_path):
            df_old = pd.read_csv(log_path, sep='#')
            combined = pd.concat([df_old, df_new], ignore_index=True)
        else:
            combined = df_new
        
        # Keep last 10000 entries
        combined.tail(10000).to_csv(log_path, index=False, sep='#')
        
        print(f"[IPS Log] Logged {len(log_entries)} IPS detections")
    except Exception as e:
        print(f"[IPS Log Error] Cannot write log: {e}")


def save_pcap_metadata(app, pcap_filename, pcap_size_mb, total_flows, threat_flows, safe_flows, is_threat, timestamp):
    """
    Lưu thông tin PCAP metadata vào CSV tại storage/info_pcaps/metadata_pcaps.csv
    và cập nhật cache với flag 'exists'
    """
    try:
        pcap_info_folder = app.config.get('PCAP_INFO_FOLDER', os.path.join(app.config['BASE_FOLDER'], 'storage', 'info_pcaps'))
        evidence_folder = app.config.get('EVIDENCE_FOLDER', os.path.join(app.config['BASE_FOLDER'], 'storage', 'evidence_pcaps'))
        incoming_folder = app.config.get('INCOMING_FOLDER', os.path.join(app.config['BASE_FOLDER'], 'storage', 'incoming_pcaps'))
        processed_folder = app.config.get('PROCESSED_FOLDER', os.path.join(app.config['BASE_FOLDER'], 'storage', 'processed_pcaps'))
        os.makedirs(pcap_info_folder, exist_ok=True)
        pcap_metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
        
        # Extract pcap_id from filename if format is {pcap_id}_{original_name}
        pcap_id = None
        if '_' in pcap_filename:
            parts = pcap_filename.split('_', 1)
            if len(parts[0]) == 32:  # UUID hex is 32 chars
                try:
                    int(parts[0], 16)  # Validate it's hex
                    pcap_id = parts[0]
                except:
                    pass
        
        # Generate new ID if not found in filename
        if not pcap_id:
            pcap_id = uuid.uuid4().hex
        
        # Check if file exists - check multiple folders
        file_exists = False
        if is_threat:
            # For threat files, check in evidence_folder first
            pcap_path = os.path.join(evidence_folder, pcap_filename)
            file_exists = os.path.exists(pcap_path)
            # If not found in evidence_folder, check incoming_folder (file might not be moved yet)
            if not file_exists:
                pcap_path = os.path.join(incoming_folder, pcap_filename)
                file_exists = os.path.exists(pcap_path)
        else:
            # Safe files are deleted, so always False
            file_exists = False
        
        new_record = pd.DataFrame({
            'pcap_id': [pcap_id],
            'pcap_name': [pcap_filename],
            'size_mb': [pcap_size_mb],
            'total_flows': [total_flows],
            'threat_flows': [threat_flows],
            'safe_flows': [safe_flows],
            'is_threat': [is_threat],
            'analysis_date': [timestamp],
            'exists': [file_exists]
        })
        
        if os.path.exists(pcap_metadata_path):
            df_old = pd.read_csv(pcap_metadata_path, sep='#')
            # Ensure old records have 'exists' column (for backward compatibility)
            if 'exists' not in df_old.columns:
                # For old records, check file existence
                for idx, row in df_old.iterrows():
                    is_threat_old = bool(row.get('is_threat', False))
                    pcap_name = row.get('pcap_name', '')
                    file_exists_old = False
                    if is_threat_old and pcap_name:
                        pcap_path = os.path.join(evidence_folder, pcap_name)
                        file_exists_old = os.path.exists(pcap_path)
                    df_old.loc[idx, 'exists'] = file_exists_old
            combined = pd.concat([df_old, new_record], ignore_index=True)
        else:
            combined = new_record
        
        # Giữ lại 5000 records gần nhất
        combined.tail(5000).to_csv(pcap_metadata_path, index=False, sep='#')
        
        # Cập nhật cache PCAP_METADATA với metadata mới (thêm flag exists)
        metadata_dict = new_record.iloc[0].to_dict()
        metadata_dict['exists'] = file_exists
        with PCAP_METADATA_LOCK:
            # Use pcap_id as key to avoid conflicts with duplicate filenames
            PCAP_METADATA[pcap_id] = metadata_dict
        
        return pcap_id
    except Exception as e:
        print(f"[PCAP Metadata Error] Cannot save metadata: {e}")
        return uuid.uuid4().hex


def hybrid_detection(df_raw, votes, threshold, use_ips=True):
    """
    Hybrid ML + IPS detection (Low Level / Fast Mode) - OPTIMIZED VERSION
    
    Logic:
    - HIGH CONFIDENCE Threat (≥5/6 votes): ALERT ngay, skip IPS
    - MEDIUM (votes >= threshold nhưng < 5): IPS verify
        - IPS match → ALERT (confirmed)
        - IPS no match → SUSPICIOUS
    - LOW Benign (< threshold): IPS check for false negative
        - IPS match → ALERT (false negative caught)
        - IPS no match → ALLOW (verified benign)
    
    Returns:
        final_decisions: numpy array of 0/1
        detection_sources: list of detection source strings
        ips_matches: list of IPS match results
    """
    n_flows = len(df_raw)
    final_decisions = np.zeros(n_flows, dtype=int)
    detection_sources = [''] * n_flows
    ips_matches = [{'matched': False, 'rule_id': None, 'rule_name': None}] * n_flows
    
    # Reload IPS rules if needed (every 5 minutes)
    if use_ips:
        ips_engine.reload_if_needed(interval_seconds=300)
    
    # Use numpy vectorized operations for classification
    high_threat_mask = votes >= 5
    medium_mask = (votes >= threshold) & (votes < 5)
    low_mask = votes < threshold
    
    # HIGH CONFIDENCE THREAT - Alert immediately, skip IPS
    final_decisions[high_threat_mask] = 1
    for i in np.where(high_threat_mask)[0]:
        detection_sources[i] = 'ML_HIGH_THREAT'
    
    # Get indices that need IPS check (medium + low confidence)
    ips_check_indices = np.where(medium_mask | low_mask)[0]
    
    if use_ips and ips_engine.loaded and len(ips_check_indices) > 0:
        # Batch IPS matching - only for flows that need it
        for i in ips_check_indices:
            flow_data = df_raw.iloc[i].to_dict()
            ips_result = ips_engine.match_flow(flow_data)
            ips_matches[i] = ips_result
            
            if medium_mask[i]:
                # MEDIUM CONFIDENCE
                if ips_result['matched']:
                    final_decisions[i] = 1
                    detection_sources[i] = 'ML_IPS_CONFIRMED'
                else:
                    final_decisions[i] = 1
                    detection_sources[i] = 'ML_UNCONFIRMED'
            else:
                # LOW CONFIDENCE (Benign)
                if ips_result['matched']:
                    final_decisions[i] = 1
                    detection_sources[i] = 'IPS_FALSE_NEGATIVE'
                else:
                    final_decisions[i] = 0
                    detection_sources[i] = 'VERIFIED_BENIGN'
    else:
        # No IPS - handle medium and low confidence with ML only
        for i in np.where(medium_mask)[0]:
            final_decisions[i] = 1
            detection_sources[i] = 'ML_ONLY'
        for i in np.where(low_mask)[0]:
            final_decisions[i] = 0
            detection_sources[i] = 'ML_BENIGN'
    
    return final_decisions, detection_sources, ips_matches


def thread_system_stats():
    """Giống hệt app4.py"""
    while True:
        try:
            import psutil
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
        except:
            import random
            cpu = random.randint(5, 15)
            ram = random.randint(30, 40)
            
        with HISTORY_LOCK:
            REALTIME_HISTORY['timestamps'].append(datetime.now().strftime('%H:%M:%S'))
            REALTIME_HISTORY['cpu'].append(cpu)
            REALTIME_HISTORY['ram'].append(ram)
            REALTIME_HISTORY['flows_per_sec'].append(0)
            
            if len(REALTIME_HISTORY['timestamps']) > 60:
                for k in REALTIME_HISTORY: 
                    if REALTIME_HISTORY[k]: REALTIME_HISTORY[k].pop(0)
        time.sleep(2)

def thread_pcap_worker(app):
    """
    Worker chính. Nhận biến 'app' từ run.py để truy cập config.
    """
    MODELS_CONFIG_LIST = [
        ('Random Forest', 'rf', 'binary', FEATURES_DNN_RF), 
        ('Random Forest', 'rf', 'multiclass', FEATURES_DNN_RF),
        ('LightGBM', 'lightgbm', 'binary', LIGHTGBM_23_FEATURES), 
        ('LightGBM', 'lightgbm', 'multiclass', LIGHTGBM_23_FEATURES),
        ('DNN', 'dnn', 'binary', FEATURES_DNN_RF), 
        ('DNN', 'dnn', 'multiclass', FEATURES_DNN_RF)
    ]

    print("[Worker] PCAP Analysis Thread Started...")
    
    while True:
        # Sử dụng app_context để truy cập config an toàn
        with app.app_context():
            try:
                incoming_dir = app.config['INCOMING_FOLDER']
                # Quét file
                if os.path.exists(incoming_dir):
                    files = sorted(glob.glob(os.path.join(incoming_dir, "*.pcap*")))
                    
                    # Cập nhật size
                    for f in files: 
                        FILE_SIZES[os.path.basename(f)] = round(os.path.getsize(f)/(1024*1024), 2)
                    
                    for pcap in files:
                        fname = os.path.basename(pcap)
                        
                        # Bỏ qua nếu đang xử lý hoặc đã xong
                        if FILE_STATUS.get(fname) in ['Analyzing', 'Error', 'Done (Safe)', 'Done (Threat Found)']: 
                            continue
                        
                        # Lấy config (Thread-safe)
                        with CONFIG_LOCK: 
                            current_thresh = SYSTEM_CONFIG.get('voting_threshold', 2)
                            current_mode = SYSTEM_CONFIG.get('detection_mode', 'voting')
                            ips_enabled = SYSTEM_CONFIG.get('ips_enabled', True)
                        
                        print(f"[Worker] Analyzing: {fname} | Mode: {current_mode} | Thresh: {current_thresh}")
                        FILE_STATUS[fname] = 'Analyzing'
                        
                        # Tạo thư mục tạm
                        tmp_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"auto_{uuid.uuid4().hex[:8]}")
                        os.makedirs(tmp_dir, exist_ok=True)
                        
                        try:
                            # 1. Convert PCAP -> CSV
                            csv_path = convert_pcap_to_csv(pcap, tmp_dir)
                            if not csv_path: 
                                FILE_STATUS[fname] = 'Error'
                                continue
                                
                            df_raw = pd.read_csv(csv_path, sep='#')
                            if df_raw.empty: 
                                FILE_STATUS[fname] = 'Error'
                                continue
                            
                            # Cập nhật biểu đồ flow
                            with HISTORY_LOCK: 
                                if REALTIME_HISTORY['flows_per_sec']: 
                                    REALTIME_HISTORY['flows_per_sec'][-1] += len(df_raw)

                            # 2. Logic Dự đoán & Voting + Hybrid IPS Detection
                            votes = np.zeros(len(df_raw), dtype=int)
                            detection_sources = []
                            ips_matches = []
                            
                            if current_mode == 'rf_only':
                                model, scaler, _, _ = model_cache.get_model('DNN', 'binary')
                                if model: 
                                    final_decisions = get_binary_prediction_vector(df_raw, model, scaler, 'dnn', FEATURES_DNN_RF)
                                    votes = final_decisions.astype(int)  # DNN only = 0 or 1 vote
                                    detection_sources = ['DNN_ONLY'] * len(df_raw)
                                    ips_matches = [{'matched': False, 'rule_id': None, 'rule_name': None}] * len(df_raw)
                                else:
                                    final_decisions = np.zeros(len(df_raw))
                                    detection_sources = ['NO_MODEL'] * len(df_raw)
                                    ips_matches = [{'matched': False, 'rule_id': None, 'rule_name': None}] * len(df_raw)
                            else:
                                # Voting mode: Use all 6 models (3 binary + 3 multiclass)
                                for name, mtype, task, feats in MODELS_CONFIG_LIST:
                                    model, scaler, _, _ = model_cache.get_model(name, task)
                                    if model:
                                        vec = get_binary_prediction_vector(df_raw, model, scaler, mtype, feats)
                                        if len(vec) == len(votes): 
                                            votes += vec # Get flows vote from each model for each loop
                                
                                # Hybrid Detection: ML voting + IPS verification
                                final_decisions, detection_sources, ips_matches = hybrid_detection(
                                    df_raw, votes, current_thresh, use_ips=ips_enabled
                                )

                            # 3. Thống kê
                            n_threats = np.sum(final_decisions)
                            n_safe = len(final_decisions) - n_threats
                            
                            with HISTORY_LOCK: 
                                GLOBAL_THREAT_STATS['total_attacks'] += int(n_threats)
                                GLOBAL_THREAT_STATS['total_safe'] += int(n_safe)

                            is_threat = n_threats > 0
                            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # 4. Ghi Consensus Log với Hybrid Detection results
                            update_consensus_log(app, df_raw, votes, final_decisions, current_thresh, 
                                               current_mode, fname, ts, detection_sources, ips_matches)
                            
                            # 4.1 Ghi IPS Detection Log (chỉ những flow IPS matched)
                            update_ips_log(app, df_raw, ips_matches, fname, ts)
                            
                            # 5. Ghi Log chi tiết cho từng model
                            for name, mtype, task, feats in MODELS_CONFIG_LIST:
                                model, scaler, encoder, _ = model_cache.get_model(name, task)
                                if model:
                                    df_log = df_raw.copy()
                                    df_log['result'] = predict_logic_full_str(df_log, model, scaler, encoder, mtype, task, feats)
                                    df_log['id'] = [uuid.uuid4().hex for _ in range(len(df_log))]
                                    df_log['time_scaned'] = ts
                                    df_log['file_scaned'] = fname
                                    
                                    # GHI LOG TẠI ĐÂY
                                    update_model_log(app, name, task, df_log)

                            # 5. Lưu metadata PCAP vào CSV
                            pcap_size_mb = FILE_SIZES.get(fname, 0)
                            pcap_id = save_pcap_metadata(app, fname, pcap_size_mb, 
                                                        int(len(df_raw)), int(n_threats), 
                                                        int(n_safe), is_threat, ts)
                            
                            # 6. Di chuyển file (Chỉ lưu PCAP nếu có threat, nếu không thì xóa)
                            if os.path.exists(pcap):
                                if is_threat:
                                    # Lưu PCAP vào evidence folder nếu có threat
                                    os.makedirs(app.config['EVIDENCE_FOLDER'], exist_ok=True)
                                    shutil.move(pcap, os.path.join(app.config['EVIDENCE_FOLDER'], fname))
                                    FILE_STATUS[fname] = 'Done (Threat Found)'
                                else:
                                    # Xóa PCAP nếu an toàn (chỉ lưu metadata)
                                    os.remove(pcap)
                                    FILE_STATUS[fname] = 'Done (Safe)'
                            else:
                                # Nếu file đã bị thread khác move rồi thì coi như xong
                                if 'Done' not in FILE_STATUS.get(fname, ''):
                                    FILE_STATUS[fname] = 'Error (File Missing)'

                        except Exception as e: 
                            print(f"[Worker Error] Processing {fname}: {e}")
                            traceback.print_exc()
                            FILE_STATUS[fname] = 'Error'
                        finally:
                            shutil.rmtree(tmp_dir, ignore_errors=True)
                            
                time.sleep(2)
            except Exception as e: 
                # print(f"[Worker Loop Error] {e}") 
                time.sleep(5)
