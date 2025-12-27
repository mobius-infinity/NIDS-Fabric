# PCAP Metadata Storage Reorganization

## 📋 Tóm tắt thay đổi

### Vị trí lưu trữ metadata PCAP
```
CŨ:  storage/model_logs/pcap_metadata.csv
MỚI: storage/info_pcaps/metadata_pcaps.csv ✨
```

---

## 🎯 Các thay đổi chi tiết

### 1. Cấu trúc thư mục mới

```
storage/
├── ips/                     (IPS rules)
├── info_pcaps/              ← THÊMỚI
│   └── metadata_pcaps.csv   ← Lưu metadata PCAP
├── model_logs/              (Model logs)
├── incoming_pcaps/          (PCAP chưa scan)
├── evidence_pcaps/          (PCAP có threat)
├── processed_pcaps/         (PCAP an toàn)
└── temp_uploads/            (Temp files)
```

### 2. File được cập nhật

#### **config.py**
```python
✅ Thêm: PCAP_INFO_FOLDER = os.path.join(BASE_DIR, 'storage', 'info_pcaps')
```

#### **app/core/worker.py - save_pcap_metadata()**
```python
✅ Cập nhật path:
   CŨ: os.path.join(app.config['LOGS_FOLDER'], 'pcap_metadata.csv')
   MỚI: os.path.join(pcap_info_folder, 'metadata_pcaps.csv')

✅ Thêm fallback:
   pcap_info_folder = app.config.get('PCAP_INFO_FOLDER', ...)
   os.makedirs(pcap_info_folder, exist_ok=True)
```

#### **app/api/routes.py - get_pcap_details()**
```python
✅ Cập nhật để đọc từ:
   CŨ: logs_folder + 'pcap_metadata.csv'
   MỚI: pcap_info_folder + 'metadata_pcaps.csv'
```

---

## 🔄 Workflow PCAP Processing

```
1. User Upload PCAP
   ↓
   storage/incoming_pcaps/

2. Worker Process
   ├─ Convert PCAP → NetFlow
   ├─ Run ML predictions
   ├─ Count threats vs safe flows
   ↓

3. Save Metadata
   └─ storage/info_pcaps/metadata_pcaps.csv ← NEW

4. File Management
   ├─ If THREAT:
   │  └─ Move to storage/evidence_pcaps/
   │
   └─ If SAFE:
      └─ Delete (only metadata kept)
```

---

## 📊 CSV Schema (metadata_pcaps.csv)

```
Column          | Type      | Example
────────────────┼───────────┼──────────────────────────
pcap_id         | String    | a1b2c3d4e5f6...
pcap_name       | String    | malware_traffic.pcap
size_mb         | Float     | 2.5
total_flows     | Int       | 1024
threat_flows    | Int       | 45
safe_flows      | Int       | 979
is_threat       | Boolean   | True / False
analysis_date   | DateTime  | 2025-12-27 10:30:00
```

---

## 🚀 Workflow Timing

### Load on Startup
```
App Start
  ↓
config.PCAP_INFO_FOLDER loads from config.py
  ↓
Ready to read/write: storage/info_pcaps/metadata_pcaps.csv
```

### Scan Process
```
1. PCAP uploaded to incoming_pcaps/
2. Worker picks up file
3. Converts PCAP → NetFlow
4. Runs ML predictions
5. save_pcap_metadata() writes to metadata_pcaps.csv
6. If threat: moves PCAP to evidence_pcaps/
   If safe: deletes PCAP (metadata remains)
```

### Read Process
```
Frontend requests: /api/pcap-details/filename.pcap
  ↓
routes.get_pcap_details() reads from:
  storage/info_pcaps/metadata_pcaps.csv
  ↓
Returns: threat status, flow counts, file location
```

---

## ✅ Benefits

| Aspect | Trước | Sau |
|--------|-------|-----|
| **Organization** | PCAP metadata mixed with model logs | Separate folder for PCAP info |
| **Clarity** | Unclear what each CSV contains | Clear: info_pcaps = PCAP metadata |
| **Scalability** | Hard to manage many log files | Easy to backup/archive PCAP metadata separately |
| **Maintenance** | PCAP metadata lost if model_logs cleaned | PCAP metadata independent |
| **Naming** | Generic pcap_metadata.csv | Clear metadata_pcaps.csv |

---

## 📝 File Locations Summary

| Data Type | Location | Purpose |
|-----------|----------|---------|
| PCAP Files (with threats) | `storage/evidence_pcaps/` | Saved for investigation |
| PCAP Files (safe) | Deleted | Only metadata kept |
| PCAP Metadata | `storage/info_pcaps/metadata_pcaps.csv` | **NEW** - All PCAP info |
| Model Logs | `storage/model_logs/` | ML predictions |
| IPS Rules | `storage/ips/ips_rules.csv` | Threat intelligence |

---

## 🔐 Configuration

```python
# config.py
class Config:
    PCAP_INFO_FOLDER = os.path.join(BASE_DIR, 'storage', 'info_pcaps')
```

Usage in code:
```python
# In worker.py
pcap_info_folder = app.config.get('PCAP_INFO_FOLDER', 
                                   os.path.join(app.config['BASE_FOLDER'], 
                                               'storage', 'info_pcaps'))
pcap_metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
```

---

## 📈 Data Retention

- **PCAP Files**: Only threat files kept in evidence_pcaps/
- **PCAP Metadata**: Last 5000 records kept in metadata_pcaps.csv
- **Model Logs**: Last 10000 records per model per task

---

## 🔄 Backward Compatibility

If old `pcap_metadata.csv` exists in `model_logs/`:
1. System will still work with new path
2. Migrate old data manually (optional):
   ```bash
   mv storage/model_logs/pcap_metadata.csv \
      storage/info_pcaps/metadata_pcaps.csv
   ```

---

## ✨ Example Flow

```
1️⃣ Upload: synscan.pcapng
   storage/incoming_pcaps/synscan.pcapng

2️⃣ Process:
   - Extract 1024 flows
   - Detect 45 threat flows
   - Mark as_threat = True
   - timestamp: 2025-12-27 10:30:00

3️⃣ Save Metadata:
   storage/info_pcaps/metadata_pcaps.csv
   
   Row added:
   {
     "pcap_id": "abc123def456...",
     "pcap_name": "synscan.pcapng",
     "size_mb": 2.5,
     "total_flows": 1024,
     "threat_flows": 45,
     "safe_flows": 979,
     "is_threat": true,
     "analysis_date": "2025-12-27 10:30:00"
   }

4️⃣ File Management:
   mv storage/incoming_pcaps/synscan.pcapng \
      storage/evidence_pcaps/synscan.pcapng

5️⃣ Display:
   Frontend shows:
   - File: synscan.pcapng ✅ Threat Found
   - Size: 2.5 MB
   - Flows: 1024 total, 45 threat, 979 safe
   - Date: 2025-12-27 10:30:00
   - [Download PCAP] button ✅
```

---

## 🧪 Testing

**Manual Test:**
1. Start app: `python3 run.py`
2. Upload PCAP file
3. Wait for scan to complete
4. Check: `storage/info_pcaps/metadata_pcaps.csv` exists
5. Verify content has correct data
6. Click file in dashboard → details show correctly

**Automated Check:**
```bash
# Verify folder exists
ls -la storage/info_pcaps/

# Verify CSV created and readable
head storage/info_pcaps/metadata_pcaps.csv

# Check data format
python3 -c "import pandas as pd; df = pd.read_csv('storage/info_pcaps/metadata_pcaps.csv', sep='#'); print(df.head())"
```

---

## 📞 Summary

**What Changed:**
- PCAP metadata moved to dedicated folder: `storage/info_pcaps/`
- New file name: `metadata_pcaps.csv` (clearer naming)
- Config updated: Added `PCAP_INFO_FOLDER`
- Code updated: worker.py & routes.py point to new location

**Why:**
- Better organization (separate from model logs)
- Clearer naming convention
- Easier to backup/archive PCAP info separately
- Scalable for large deployments

**Impact:**
- ✅ Minimal - all paths configured
- ✅ Backward compatible if migration needed
- ✅ No API changes - transparent to frontend

**Status:** ✅ Ready for testing

