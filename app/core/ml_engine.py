import os
import joblib
import numpy as np
import lightgbm as lgb
from flask import current_app

# Định nghĩa các đường dẫn tương đối giống hệt app4.py
# Nhưng sẽ được nối với ML_ASSETS_DIR trong config
REL_MODEL_PATHS = {
    'rf_binary': 'RF/binary/rf_binary_model.joblib',
    'rf_multiclass': 'RF/multiclass/rf_multiclass_model.joblib',
    'lightgbm_binary': 'LightGBM/binary/lightgbm_binary_model.txt',
    'lightgbm_multiclass': 'LightGBM/multiclass/lightgbm_multiclass_model.txt',
    'dnn_binary': 'DNN/binary/dnn_binary_model.keras',
    'dnn_multiclass': 'DNN/multiclass/dnn_multiclass_model.keras',
    'rf_encoder': 'RF/multiclass/label_encoder.joblib',
    'dnn_encoder': 'DNN/multiclass/label_encoder.joblib',
    'dnn_scaler': 'DNN/standard_scaler.joblib',
}

class ModelCache:
    def __init__(self): 
        self.models = {}
        self.scalers = {}
        self.encoders = {}

    def _get_abs_path(self, key):
        """Hàm nội bộ để lấy đường dẫn tuyệt đối từ Config"""
        base_dir = current_app.config['ML_ASSETS_DIR']
        rel_path = REL_MODEL_PATHS.get(key)
        if not rel_path: 
            return None
        return os.path.join(base_dir, rel_path)

    def get_model(self, model_name, task):
        key = f"{model_name}_{task}"
        
        # 1. Kiểm tra Cache RAM
        if key in self.models: 
            return self.models[key], self.scalers.get(key), self.encoders.get(key), self.models[key+"_type"]
        
        try:
            path = ""
            encoder_path = None
            scaler_path = None
            model_type = ""
            
            # 2. Xác định key đường dẫn dựa trên tên Model (Logic của app4.py)
            if "Random Forest" in model_name: 
                model_type = "rf"
                path = self._get_abs_path(f'rf_{task}')
                if task == 'multiclass':
                    encoder_path = self._get_abs_path('rf_encoder')
            
            elif "LightGBM" in model_name: 
                model_type = "lightgbm"
                path = self._get_abs_path(f'lightgbm_{task}')
            
            elif "DNN" in model_name: 
                model_type = "dnn"
                path = self._get_abs_path(f'dnn_{task}')
                scaler_path = self._get_abs_path('dnn_scaler')
                if task == 'multiclass':
                    encoder_path = self._get_abs_path('dnn_encoder')

            # 3. Kiểm tra file tồn tại
            if not path or not os.path.exists(path):
                print(f"[Model Warning] File not found: {path}") # <--- DEBUG QUAN TRỌNG
                return None, None, None, None

            print(f"[Model System] Loading model from: {path}") # <--- DEBUG

            # 4. Load Model
            if model_type == 'dnn': 
                import tensorflow as tf
                model = tf.keras.models.load_model(path)
            elif model_type == 'lightgbm': 
                model = lgb.Booster(model_file=path)
            else: 
                model = joblib.load(path)

            # 5. Load Scaler & Encoder (Nếu có)
            encoder = None
            if encoder_path and os.path.exists(encoder_path):
                encoder = joblib.load(encoder_path)
            
            scaler = None
            if scaler_path and os.path.exists(scaler_path):
                scaler = joblib.load(scaler_path)

            # 6. Lưu vào Cache
            self.models[key] = model
            self.models[key+"_type"] = model_type
            self.scalers[key] = scaler
            self.encoders[key] = encoder
            
            return model, scaler, encoder, model_type
            
        except Exception as e: 
            print(f"[Model Error] Failed to load {key}: {e}")
            return None, None, None, None

# Singleton instance
model_cache = ModelCache()

# --- CÁC HÀM PREDICT (Giữ nguyên logic app4.py) ---

def get_binary_prediction_vector(df, model, scaler, model_type, feat_cols):
    actual_cols = [c.lstrip('%') for c in feat_cols]
    for c in actual_cols: 
        if c not in df.columns: df[c] = 0
    
    X = df[actual_cols].fillna(0).values.astype(np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
    
    if scaler: 
        X = scaler.transform(X)
    
    try:
        if model_type == 'rf':
            preds = model.predict(X)
            if preds.dtype.kind in {'U', 'S', 'O'}: 
                return np.array([1 if str(p).lower() in ['attack', '1', 'malware', 'dos'] else 0 for p in preds.flatten()])
            return preds.flatten().astype(int)
            
        elif model_type in ['lightgbm', 'dnn']:
            probs = model.predict(X) if model_type == 'lightgbm' else model.predict(X, verbose=0)
            if probs.ndim > 1 and probs.shape[1] > 1: 
                return np.array([0 if c == 0 else 1 for c in np.argmax(probs, axis=1)])
            return np.array([1 if p >= 0.5 else 0 for p in probs.flatten()])
            
    except Exception as e:
        print(f"[Predict Error] {e}")
        return np.zeros(len(df), dtype=int)
    
    return np.zeros(len(df), dtype=int)

def predict_logic_full_str(df, model, scaler, encoder, model_type, task, feat_cols):
    actual_cols = [c.lstrip('%') for c in feat_cols]
    for c in actual_cols: 
        if c not in df.columns: df[c] = 0
        
    X = df[actual_cols].fillna(0).values.astype(np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
    
    if scaler: 
        X = scaler.transform(X)
        
    preds = []
    try:
        if model_type == 'rf':
            raw_preds = model.predict(X)
            if task == 'binary': 
                preds = ['attack' if int(p) == 1 else 'benign' for p in raw_preds.flatten()]
            elif encoder: 
                preds = encoder.inverse_transform(raw_preds)
            else:
                preds = raw_preds
                
        elif model_type in ['lightgbm', 'dnn']:
            probs = model.predict(X) if model_type == 'lightgbm' else model.predict(X, verbose=0)
            if task == 'binary': 
                preds = ['attack' if p >= 0.5 else 'benign' for p in probs.flatten()]
            else: 
                indices = np.argmax(probs, axis=1)
                preds = encoder.inverse_transform(indices) if encoder else indices
    except Exception as e:
        print(f"[Predict String Error] {e}")
        return ["Error"] * len(df)
            
    return [str(p) for p in preds]
