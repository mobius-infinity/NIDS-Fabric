import os
import glob
import time
import shutil
import uuid
import traceback
import pandas as pd
import numpy as np
from datetime import datetime

# Import các biến Global
from app.globals import (
    HISTORY_LOCK, CONFIG_LOCK, REALTIME_HISTORY, 
    FILE_STATUS, FILE_SIZES, GLOBAL_THREAT_STATS, SYSTEM_CONFIG
)
# Import ML Logic
from app.core.pcap_utils import convert_pcap_to_csv, FEATURES_DNN_RF, LIGHTGBM_23_FEATURES
from app.core.ml_engine import model_cache, get_binary_prediction_vector, predict_logic_full_str

def update_model_log(app, model_name, task, df_results):
    """
    Hàm ghi log, cần nhận biến 'app' để biết LOGS_FOLDER nằm ở đâu.
    """
    try:
        log_path = os.path.join(app.config['LOGS_FOLDER'], f"{model_name.replace(' ', '_')}_{task}.csv")
        
        # Logic giống app4.py: Đọc cũ -> Nối mới -> Giữ 10000 dòng
        if os.path.exists(log_path):
            combined = pd.concat([pd.read_csv(log_path), df_results], ignore_index=True)
        else:
            combined = df_results
            
        if 'time_scaned' in combined.columns: 
            combined = combined.sort_values(by='time_scaned')
            
        combined.tail(10000).to_csv(log_path, index=False)
        # Debug log để biết là đã ghi file
        # print(f"[Log] Saved result to {log_path}") 
    except Exception as e: 
        print(f"[Log Error] Cannot write log: {e}")

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
                                
                            df_raw = pd.read_csv(csv_path)
                            if df_raw.empty: 
                                FILE_STATUS[fname] = 'Error'
                                continue
                            
                            # Cập nhật biểu đồ flow
                            with HISTORY_LOCK: 
                                if REALTIME_HISTORY['flows_per_sec']: 
                                    REALTIME_HISTORY['flows_per_sec'][-1] += len(df_raw)

                            # 2. Logic Dự đoán & Voting (Giống hệt app4.py)
                            final_decisions = np.zeros(len(df_raw))
                            
                            if current_mode == 'rf_only':
                                model, scaler, _, _ = model_cache.get_model('Random Forest', 'binary')
                                if model: 
                                    final_decisions = get_binary_prediction_vector(df_raw, model, scaler, 'rf', FEATURES_DNN_RF)
                            else:
                                votes = np.zeros(len(df_raw), dtype=int)
                                for name, mtype, task, feats in MODELS_CONFIG_LIST:
                                    model, scaler, _, _ = model_cache.get_model(name, task)
                                    if model:
                                        vec = get_binary_prediction_vector(df_raw, model, scaler, mtype, feats)
                                        if len(vec) == len(votes): 
                                            votes += vec
                                final_decisions = (votes >= current_thresh).astype(int)

                            # 3. Thống kê
                            n_threats = np.sum(final_decisions)
                            n_safe = len(final_decisions) - n_threats
                            
                            with HISTORY_LOCK: 
                                GLOBAL_THREAT_STATS['total_attacks'] += int(n_threats)
                                GLOBAL_THREAT_STATS['total_safe'] += int(n_safe)

                            is_threat = n_threats > 0
                            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # 4. Ghi Log chi tiết (SỬA: Gọi hàm update_model_log với biến app)
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

                            # 5. Di chuyển file (SỬA: Thêm kiểm tra tồn tại để tránh lỗi File Missing)
                            dest_folder = app.config['EVIDENCE_FOLDER'] if is_threat else os.path.join(app.config['PROCESSED_FOLDER'], 'benign')
                            os.makedirs(dest_folder, exist_ok=True)
                            
                            if os.path.exists(pcap):
                                shutil.move(pcap, os.path.join(dest_folder, fname))
                                FILE_STATUS[fname] = 'Done (Threat Found)' if is_threat else 'Done (Safe)'
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
