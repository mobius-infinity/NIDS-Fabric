# PCAP Storage Implementation Checklist ✅

## 🎯 Changes Made

### Code Updates
- [x] **config.py**
  - Added: `PCAP_INFO_FOLDER = os.path.join(BASE_DIR, 'storage', 'info_pcaps')`
  - Location: Line after `LOGS_FOLDER`
  - Purpose: Configure path for PCAP metadata storage

- [x] **app/core/worker.py** - save_pcap_metadata()
  - Updated: Read from new config path
  - Added: Fallback to construct path if config missing
  - Changed: CSV path to `metadata_pcaps.csv`
  - Changed: Folder to `info_pcaps/`
  - Verified: Syntax valid ✓

- [x] **app/api/routes.py** - get_pcap_details()
  - Updated: Read metadata from new folder
  - Changed: CSV path to `metadata_pcaps.csv`
  - Changed: Folder to `info_pcaps/`
  - Verified: Syntax valid ✓

### Folder Structure
- [x] Created: `storage/info_pcaps/`
- [x] Verified: Folder accessible and writable

### Documentation
- [x] Created: `PCAP_STORAGE_REORGANIZATION.md`
- [x] Created: `PCAP_STORAGE_ARCHITECTURE.md`
- [x] Created: `PCAP_STORAGE_SUMMARY.md`

---

## 🧪 Testing Checklist

### Initial Setup
- [ ] Start app: `python3 run.py`
- [ ] Check console: No errors
- [ ] Open dashboard: Loads without errors

### PCAP Upload & Processing
- [ ] Upload small PCAP file (~1-5 MB)
- [ ] Wait for processing (check status)
- [ ] Worker completes: Check console log
- [ ] File status shows: "Done (Threat Found)" or "Done (Safe)"

### Metadata Storage
- [ ] Check folder exists: `storage/info_pcaps/`
- [ ] Verify file created: `metadata_pcaps.csv`
- [ ] Inspect CSV content:
  ```bash
  cat storage/info_pcaps/metadata_pcaps.csv
  ```
- [ ] Verify CSV has headers: pcap_id, pcap_name, size_mb, etc.
- [ ] Verify CSV has data row with uploaded filename

### PCAP File Handling
- [ ] **If threat detected:**
  - [ ] Original PCAP moved to `evidence_pcaps/`
  - [ ] Metadata row shows: `is_threat = True`
  - [ ] Can download: "Download PCAP" button visible

- [ ] **If no threat (safe):**
  - [ ] Original PCAP deleted from `incoming_pcaps/`
  - [ ] Metadata row shows: `is_threat = False`
  - [ ] Cannot download: "Download PCAP" button disabled

### API Testing
- [ ] Test endpoint: `GET /api/pcap-details/filename.pcap`
- [ ] Response contains: name, size, flow counts, threat status
- [ ] Response format is correct JSON
- [ ] Response shows correct file location

### Dashboard UI
- [ ] Navigate to: Dashboard → (find PCAP file)
- [ ] Click file: Details panel opens
- [ ] Details show:
  - [ ] File name
  - [ ] File size
  - [ ] Upload date
  - [ ] Status (Threat Found / Safe)
  - [ ] Flow counts (total, threat, safe)
- [ ] If threat: Download button visible
- [ ] If safe: Download button disabled/hidden

### Data Verification
- [ ] CSV separator: `#` (not comma)
- [ ] CSV encoding: UTF-8
- [ ] CSV readable: `head -5 storage/info_pcaps/metadata_pcaps.csv`
- [ ] Data persists: Restart app, verify data still there

---

## 🔄 Multiple File Testing

### Test Sequence
1. Upload 3+ different PCAP files
2. Let them all process
3. Check metadata CSV has 3+ rows
4. Verify each row has correct data
5. Check file locations match metadata

### Scenarios
- [ ] **Scenario 1:** Upload threat PCAP
  - [ ] Verify: File moved to evidence_pcaps/
  - [ ] Verify: Metadata shows is_threat=True

- [ ] **Scenario 2:** Upload safe PCAP
  - [ ] Verify: File deleted from incoming_pcaps/
  - [ ] Verify: Metadata shows is_threat=False

- [ ] **Scenario 3:** Upload multiple PCAPs
  - [ ] Verify: All processed correctly
  - [ ] Verify: All rows in metadata_pcaps.csv
  - [ ] Verify: Correct files in correct folders

---

## 🔍 Edge Cases

- [ ] Empty PCAP file (0 bytes)
- [ ] Very large PCAP file (>100 MB)
- [ ] Malformed PCAP file
- [ ] Duplicate PCAP filenames
- [ ] Special characters in filename
- [ ] Restart app mid-processing
- [ ] Missing config PCAP_INFO_FOLDER

---

## 📊 Data Verification

### CSV Content Check
```bash
# View first 5 rows
head -5 storage/info_pcaps/metadata_pcaps.csv

# Expected format (# separated):
# pcap_id#pcap_name#size_mb#total_flows#threat_flows#safe_flows#is_threat#analysis_date
# abc123#test.pcap#2.5#1024#45#979#True#2025-12-27 10:30:00

# Count rows
wc -l storage/info_pcaps/metadata_pcaps.csv

# View as table (Python)
python3 << 'EOF'
import pandas as pd
df = pd.read_csv('storage/info_pcaps/metadata_pcaps.csv', sep='#')
print(df.head())
print(f"\nTotal rows: {len(df)}")
EOF
```

---

## 🔄 Performance Check

- [ ] CSV file size < 10 MB (for 5000 records)
- [ ] Query time < 1 second (read metadata)
- [ ] Write time < 1 second (append metadata)
- [ ] No memory issues with large CSV

---

## 🔐 Permission Check

```bash
# Verify folder permissions
ls -la storage/info_pcaps/

# Expected: drwxrwxr-x (755)
# Owner: rusted:rusted
# Writable: Yes
```

---

## 🚨 Troubleshooting

### Issue: Folder not created
```
Solution: 
  1. Manually create: mkdir -p storage/info_pcaps/
  2. Check permissions: chmod 755 storage/info_pcaps/
  3. Restart app
```

### Issue: metadata_pcaps.csv not found
```
Solution:
  1. Check folder exists: ls -la storage/info_pcaps/
  2. Upload PCAP file to trigger creation
  3. Check worker log for errors
```

### Issue: CSV read error
```
Solution:
  1. Check separator: File should use '#'
  2. Check encoding: Should be UTF-8
  3. Verify headers: pcap_id, pcap_name, etc.
```

### Issue: PCAP not moving to evidence
```
Solution:
  1. Check threat_flows > 0 in CSV
  2. Check evidence_pcaps/ permissions
  3. Check worker log for move errors
```

---

## ✅ Final Verification

### Before Deployment
- [ ] All code changes committed
- [ ] All syntax valid: `python3 -m py_compile`
- [ ] All tests passed
- [ ] Documentation complete
- [ ] No errors in console logs
- [ ] Configuration verified

### After Deployment
- [ ] Users can upload PCAPs
- [ ] Metadata saved correctly
- [ ] Threat files archived
- [ ] Safe files deleted
- [ ] Dashboard displays correctly
- [ ] No data loss

---

## 📝 Sign-off Checklist

- [ ] Implementation complete
- [ ] Code reviewed
- [ ] Testing completed
- [ ] All tests passed
- [ ] Documentation verified
- [ ] Performance acceptable
- [ ] Security verified
- [ ] Ready for production

---

## 🎯 Success Criteria

✅ **All of the following must be true:**

1. **Storage Organization**
   - [ ] PCAP metadata in: `storage/info_pcaps/metadata_pcaps.csv`
   - [ ] Threat files in: `storage/evidence_pcaps/`
   - [ ] Safe files: Deleted (metadata preserved)

2. **Functionality**
   - [ ] Config loads PCAP_INFO_FOLDER
   - [ ] Metadata saved after each scan
   - [ ] API reads metadata correctly
   - [ ] Dashboard displays PCAP details

3. **Data Quality**
   - [ ] CSV has correct headers
   - [ ] Each row has all columns
   - [ ] Data types correct (bool, int, float, string)
   - [ ] Dates formatted correctly

4. **Performance**
   - [ ] No delays in dashboard
   - [ ] CSV reads < 1 second
   - [ ] CSV writes < 1 second
   - [ ] No memory leaks

---

## 📞 Quick Reference

| Component | Location | Purpose |
|-----------|----------|---------|
| Config | `config.py` | Set PCAP_INFO_FOLDER path |
| Worker | `app/core/worker.py` | Save metadata |
| API | `app/api/routes.py` | Read metadata |
| Metadata | `storage/info_pcaps/metadata_pcaps.csv` | Store results |
| Docs | `PCAP_STORAGE_*.md` | Reference |

---

**Status: ✅ Ready for Testing**

When all checkboxes are checked, the implementation is complete and verified!

