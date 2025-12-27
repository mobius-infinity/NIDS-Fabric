# PCAP Storage Architecture - Visual Guide

## Complete Storage Structure

```
storage/
│
├── 📂 ips/                          (IPS/IDS Rules Database)
│   └── ips_rules.csv               • All threat intelligence rules
│                                   • Imported via URL or file
│
├── 📂 info_pcaps/ ← NEW             (PCAP Information & Metadata)
│   └── metadata_pcaps.csv           • All PCAP scan results
│                                   • Flow counts & threat classification
│                                   • Analysis timestamps
│
├── 📂 incoming_pcaps/               (Temporary - PCAP Uploads)
│   └── *.pcap, *.pcapng            • Newly uploaded files waiting to be processed
│                                   • Cleaned up after scan completes
│
├── 📂 evidence_pcaps/               (Archived - Threat PCAPs)
│   └── *.pcap, *.pcapng            • PCAP files with detected threats
│                                   • Kept for forensics & investigation
│                                   • Reference in metadata_pcaps.csv
│
├── 📂 processed_pcaps/              (Safe Files Archive)
│   └── benign/
│       └── *.pcap, *.pcapng        • Original: Safe PCAP files
│                                   • Current: Metadata only
│                                   • Actual files deleted to save space
│
├── 📂 model_logs/                   (ML Model Results)
│   ├── Random_Forest_binary.csv
│   ├── Random_Forest_multiclass.csv
│   ├── LightGBM_binary.csv
│   ├── LightGBM_multiclass.csv
│   ├── DNN_binary.csv
│   ├── DNN_multiclass.csv           • Flow-level predictions
│   │                                • Feature vectors
│   │                                • Confidence scores
│   │
│   └── (OLD: pcap_metadata.csv)    ← DEPRECATED, moved to info_pcaps/
│
└── 📂 temp_uploads/                 (Temporary Files)
    └── *.tmp, *.work               • Temporary processing files
                                    • Auto-cleaned
```

---

## PCAP Processing Flow with Storage

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER UPLOADS PCAP FILE                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
         ┌─────────────────────────────────────┐
         │   storage/incoming_pcaps/           │
         │   (PCAP file queued for processing) │
         └────────────┬────────────────────────┘
                      │
         ┌────────────▼─────────────────────────┐
         │  WORKER PROCESS (worker.py)          │
         │  1. Convert PCAP → NetFlow (nprobe)  │
         │  2. Extract features                 │
         │  3. Run ML predictions (6 models)    │
         │  4. Count threat vs safe flows       │
         │  5. Generate statistics              │
         └─────────┬──────────────┬─────────────┘
                   │              │
          ┌────────▼──┐    ┌──────▼──────────┐
          │ ML RESULTS│    │ THREAT DECISION │
          └────────┬──┘    └─────┬───────────┘
                   │             │
                   ▼             ▼
         ┌─────────────────────────────────────┐
         │  SAVE METADATA & RESULTS            │
         │  save_pcap_metadata()               │
         └────────┬────────────────────────────┘
                  │
    ┌─────────────┼──────────────┐
    │             │              │
    ▼             ▼              ▼
  [Flows]   [Metadata]      [Decision]
    │           │              │
    │     ┌─────▼──────────────────┐
    │     │ info_pcaps/            │
    │     │ metadata_pcaps.csv ✅ │
    │     └────────────────────────┘
    │
    ├─────────────┬────────────────────────┐
    │             │                        │
    │        ┌────▼───────────────┐   ┌───▼────────────────┐
    │        │ IF THREAT DETECTED │   │ IF SAFE (No Threat)│
    │        └────┬───────────────┘   └────┬────────────────┘
    │             │                         │
    │     ┌───────▼──────────────────┐   ┌─▼─────────────────┐
    │     │ evidence_pcaps/          │   │ DELETE PCAP FILE  │
    │     │ [filename.pcap] ✅      │   │ (metadata kept)   │
    │     │ (preserved for analysis) │   └───────────────────┘
    │     └────────────────────────── ┘
    │
    └──────────────────────────────────────────┐
                                               │
                ┌──────────────────────────────▼───────────┐
                │  model_logs/                             │
                │  - Random_Forest_binary.csv              │
                │  - Random_Forest_multiclass.csv          │
                │  - LightGBM_binary.csv                   │
                │  - ... (6 models total)                  │
                │                                          │
                │  Each row = one flow prediction          │
                └──────────────────────────────────────────┘
```

---

## PCAP Data Lifecycle

```
┌──────────────────┐
│ User Uploads     │
│ PCAP File        │
│ (incoming/)      │
└────────┬─────────┘
         │
         ▼
    ┌─────────────────────────────┐
    │  PROCESSING                 │
    │  • Extract flows (nprobe)   │
    │  • Predict threats (ML)     │
    │  • Count results            │
    └────────┬────────────────────┘
             │
             ▼
    ┌──────────────────────────────────────┐
    │  SAVE METADATA TO CSV                │
    │  storage/info_pcaps/                 │
    │  metadata_pcaps.csv                  │
    │                                      │
    │  Row: {                              │
    │    pcap_id, pcap_name,              │
    │    size_mb, total_flows,            │
    │    threat_flows, safe_flows,        │
    │    is_threat, analysis_date         │
    │  }                                   │
    └────────┬─────────────┬───────────────┘
             │             │
        ┌────▼────┐    ┌───▼────────────────┐
        │ THREAT? │    │ NO THREAT          │
        └────┬────┘    │ (SAFE)             │
             │         │                    │
        ┌────▼──────────▼──────────┐        │
        │                          │        │
        │ YES - MOVE TO EVIDENCE   │        │
        │       evidence_pcaps/    │        │
        │       [file.pcap] ✅    │        │
        │                          │        │
        │ Preserved for:           │        │
        │ • Investigation          │        │
        │ • Replay analysis        │        │
        │ • Forensics              │        │
        └──────────────────────────┘        │
                                           │
                                      ┌────▼──────────┐
                                      │ NO - DELETE   │
                                      │ PCAP FILE     │
                                      │ (metadata OK) │
                                      │               │
                                      │ Preserve:     │
                                      │ • size_mb     │
                                      │ • flow counts │
                                      │ • threat flag │
                                      │ • timestamp   │
                                      └───────────────┘
```

---

## Storage Usage Comparison

### Before (mixed storage)
```
model_logs/
├── Random_Forest_binary.csv      (ML results)
├── LightGBM_multiclass.csv       (ML results)
├── DNN_binary.csv                (ML results)
├── pcap_metadata.csv             ← PCAP info mixed in
└── ... (8 log files total)       (confusing structure)
```

### After (organized)
```
info_pcaps/
└── metadata_pcaps.csv            ← Dedicated PCAP folder

model_logs/
├── Random_Forest_binary.csv      (ML results only)
├── Random_Forest_multiclass.csv
├── LightGBM_binary.csv
├── LightGBM_multiclass.csv
├── DNN_binary.csv
└── DNN_multiclass.csv            (6 log files, clean)
```

---

## File Size Estimates

```
Per PCAP Processed:
├── Original PCAP size:        1-100 MB (depends on traffic)
├── If THREAT:
│   └── Saved to evidence/:    1-100 MB (full file)
│       Metadata row size:     ~200 bytes
└── If SAFE:
    └── Deleted PCAP:          0 MB (freed)
        Metadata row size:     ~200 bytes

CSV Growth (metadata_pcaps.csv):
├── Per 100 PCAPs:            ~20 KB
├── Per 1,000 PCAPs:          ~200 KB
├── Per 10,000 PCAPs:         ~2 MB
└── System keeps:             5,000 latest records
                              (~1 MB typical)
```

---

## API Integration

### Frontend Request
```
GET /api/pcap-details/malware_traffic.pcap
```

### Backend Processing
```python
# routes.py
pcap_info_folder = config['PCAP_INFO_FOLDER']
                 = 'storage/info_pcaps'

metadata_path = os.path.join(pcap_info_folder, 'metadata_pcaps.csv')
                         = 'storage/info_pcaps/metadata_pcaps.csv'

df = pd.read_csv(metadata_path, sep='#')
record = df[df['pcap_name'] == 'malware_traffic.pcap']
```

### Response
```json
{
  "name": "malware_traffic.pcap",
  "size_mb": 2.5,
  "upload_date": "2025-12-27 10:30:00",
  "status": "Done (Threat Found)",
  "total_flows": 1024,
  "threat_flows": 45,
  "safe_flows": 979,
  "is_threat": true,
  "pcap_file_exists": true
}
```

---

## Configuration Lookup

```python
# config.py
class Config:
    BASE_FOLDER = '/home/rusted/Downloads/NIDS Fabric'
    PCAP_INFO_FOLDER = os.path.join(BASE_DIR, 'storage', 'info_pcaps')
                     = '/home/rusted/Downloads/NIDS Fabric/storage/info_pcaps'
```

### Fallback Safety
```python
# worker.py
pcap_info_folder = app.config.get('PCAP_INFO_FOLDER',
                                   os.path.join(app.config['BASE_FOLDER'],
                                               'storage', 'info_pcaps'))
# If config key missing, auto-construct path
```

---

## Access Patterns

```
WRITE (save_pcap_metadata):
    worker.py → config → PCAP_INFO_FOLDER → metadata_pcaps.csv
                                                    ▲
                                                    │
                                            append new record

READ (get_pcap_details):
    routes.py → config → PCAP_INFO_FOLDER → metadata_pcaps.csv
                                                    ▲
                                                    │
                                          search by pcap_name
```

---

## Disaster Recovery

**Scenario:** metadata_pcaps.csv corrupted or lost

```
Backup Strategy:
├── Maintain multiple copies
│   ├── Original: storage/info_pcaps/metadata_pcaps.csv
│   ├── Backup 1: storage/info_pcaps/.backup/metadata_pcaps.csv.bak
│   └── Backup 2: /external/backup/metadata_pcaps.csv
│
└── Recovery:
    1. Restore from backup
    2. All PCAP files in evidence_pcaps/ still accessible
    3. Rebuild metadata by re-scanning PCAP files (optional)
```

---

## Summary

```
📂 storage/
├── 📄 info_pcaps/metadata_pcaps.csv
│   └─ PCAP metadata (NEW location)
│      • When: Save after each scan
│      • What: filename, size, flows, threat status, date
│      • Why: Central registry of all processed PCAPs
│
├── 📄 evidence_pcaps/*.pcap
│   └─ Threat PCAP files (PRESERVED)
│      • When: Moved from incoming after threat detected
│      • What: Complete PCAP file for forensics
│      • Why: Investigation & incident response
│
└── 🗑️  incoming_pcaps/
    └─ Cleaned after processing
       (file moved to evidence OR deleted)
```

✅ **Ready for production deployment**

