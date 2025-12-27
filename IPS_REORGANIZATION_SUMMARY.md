# IPS Database Reorganization - Summary

## ✅ Thay đổi chính

### 1. **Vị trí lưu trữ Rules**
- **Cũ**: `storage/model_logs/ips_rules.csv`
- **Mới**: `storage/ips/ips_rules.csv`
- **Lý do**: Tách riêng IPS rules khỏi model logs để tổ chức rõ ràng hơn

### 2. **Cấu trúc thư mục mới**
```
storage/
├── ips/                     ← THÊM
│   └── ips_rules.csv       ← IPS rules database
├── model_logs/             ← Giữ nguyên
├── incoming_pcaps/
├── evidence_pcaps/
├── processed_pcaps/
└── temp_uploads/
```

### 3. **Chức năng Import mới**

#### A. Import từ File (Upload)
- **Endpoint**: `POST /api/ips-rules/import-file`
- **Hỗ trợ**: Upload file CSV
- **Validation**: Kiểm tra cột bắt buộc (rule_id, rule_name, severity, category)
- **UI**: Form drag-drop tại IPS Database view

#### B. Import từ URL
- **Endpoint**: `POST /api/ips-rules/import-url`
- **Hỗ trợ**: Tải từ bất kỳ URL nào trỏ đến file CSV
- **Validation**: Kiểm tra URL format (http/https)
- **Use case**: Tải từ threat intelligence feeds, GitHub, etc.

#### C. Delete Rule
- **Endpoint**: `DELETE /api/ips-rules/<rule_id>`
- **UI**: Nút "Delete Rule" trong rule details panel

---

## 📝 Các file được chỉnh sửa

### 1. **app/core/ips_manager.py** - Core logic
```
✅ Thêm: import requests, io
✅ Thêm: init_app() sử dụng storage/ips/ (từ BASE_FOLDER config)
✅ Thêm: import_rules_from_file(file_obj) - import CSV
✅ Thêm: import_rules_from_url(url) - import từ URL
✅ Thêm: delete_rule(rule_id) - xóa rule
✅ Cải tiến: Error handling, validation
```

**Xử lý Import:**
- Đọc CSV, validate cột bắt buộc
- Thêm timestamp tự động (last_updated)
- Merge với rules cũ (dedup theo rule_id, keep latest)
- Lưu lại CSV

### 2. **app/api/routes.py** - API endpoints
```
✅ Thêm: POST /api/ips-rules/import-file
✅ Thêm: POST /api/ips-rules/import-url
✅ Thêm: DELETE /api/ips-rules/<rule_id>
✅ Fix: Xóa duplicate exception handler
```

**Response Format:**
```json
{
  "success": true/false,
  "message": "...",
  "imported_count": 5  // (import-file/url only)
}
```

### 3. **config.py** - Configuration
```
✅ Thêm: BASE_FOLDER = BASE_DIR
         → Dùng để xác định storage/ips/ folder
```

### 4. **app/templates/index.html** - UI
```
✅ Thêm: Import Rules section với 2 tab:
   - Upload CSV file (drag-drop friendly)
   - Import from URL (input URL)
✅ Thêm: File input label (hiển thị tên file)
✅ Thêm: URL input field
✅ Styling: Grid layout 2 cột, responsive
```

### 5. **app/static/js/main.js** - Frontend logic
```
✅ Thêm: importIPSRulesFromFile()
         - Validate file, POST to /api/ips-rules/import-file
         - Update file label, reload rules
         
✅ Thêm: importIPSRulesFromURL()
         - Validate URL, POST to /api/ips-rules/import-url
         - Clear input, reload rules
         
✅ Thêm: deleteIPSRule(ruleId)
         - Confirm dialog, DELETE request
         - Close panel, reload rules
         
✅ Thêm: File change event listener
         - Update label khi chọn file
         
✅ Thêm: Delete button trong rule details panel
         - Styled với red color (#ef4444)
         - Trigger deleteIPSRule()
```

---

## 🔄 Workflow Import

### File Upload Flow
```
User Select File
    ↓
importIPSRulesFromFile()
    ↓
POST /api/ips-rules/import-file (FormData)
    ↓
ips_manager.import_rules_from_file(file)
    ↓
pd.read_csv(file) → Validate columns
    ↓
Merge with existing rules (dedup by rule_id)
    ↓
Save to storage/ips/ips_rules.csv
    ↓
Return { success: true, imported_count: N }
    ↓
Alert + Reload loadIPSRules()
```

### URL Import Flow
```
User Enter URL
    ↓
importIPSRulesFromURL()
    ↓
POST /api/ips-rules/import-url (JSON)
    ↓
ips_manager.import_rules_from_url(url)
    ↓
requests.get(url) → file content
    ↓
Same as file upload from here
```

---

## 📊 CSV Requirements

### Bắt buộc
- `rule_id` - Unique identifier (String)
- `rule_name` - Rule name (String)
- `severity` - Critical, High, Medium, Low (String)
- `category` - Threat category (String)

### Tùy chọn (auto-fill if missing)
- `source` → "Custom"
- `version` → "1.0"
- `false_positive_rate` → 0.0
- `last_updated` → Current timestamp
- `description` → ""
- `protocol` → ""
- `port` → ""
- `rule_content` → ""

---

## 🚀 Cách sử dụng

### 1. Upload CSV file
```
1. Mở IPS Database view
2. Kéo thả file CSV vào "Choose CSV file"
   hoặc click để chọn file
3. Click "Import" button
4. Xem kết quả trong alert
```

### 2. Import từ URL
```
1. Mở IPS Database view
2. Nhập URL vào ô "Import from URL"
3. Click "Import" button
4. Đợi kết quả (timeout: 10 giây)
```

### 3. Xóa rule
```
1. Click rule trong bảng
2. Xem detail panel
3. Click "Delete Rule"
4. Confirm dialog
5. Panel tự đóng, rules reload
```

---

## ✨ Tính năng nâng cao

### Deduplication
- Khi import, nếu `rule_id` đã tồn tại → cập nhật (keep latest)
- Giữ nguyên rules cũ không có trong file import

### Auto-fill
- Tự động thêm timestamp (last_updated)
- Tự động set source = "Custom" nếu không có
- Tự động set version = "1.0" nếu không có

### Error Handling
```python
- Missing columns → Error response
- Invalid URL → Error response
- Network timeout → Error response (10s)
- File parsing error → Error response
```

### Validation
- CSV encoding: UTF-8
- Separator: auto-detect
- Required fields check
- URL format validation (http/https)

---

## 🔐 Security

- File upload size: Limited by MAX_CONTENT_LENGTH (10GB)
- URL timeout: 10 seconds
- Sanitization: werkzeug.utils.secure_filename (file uploads)
- Authentication: @login_required on all endpoints

---

## 📝 Example CSV Format

```csv
rule_id,rule_name,severity,category,description,source,protocol,port
SID-2000001,SSH Brute Force,High,Authentication Attack,Excessive SSH attempts,Suricata,TCP,22
SID-2000002,SQL Injection,Critical,Web Attack,SQL injection patterns,OWASP CRS,TCP,80
SID-2000003,Port Scanning,Medium,Reconnaissance,SYN scan detection,Snort,TCP,any
SID-3000001,Custom Malware,Critical,Malware,Internal signature,Custom,TCP,443
```

---

## 🎯 Next Steps (Future)

- [ ] Add rule matching against flows (correlation)
- [ ] Auto-update from public feeds (scheduled)
- [ ] Rule testing/validation UI
- [ ] Rule statistics (hits, false positives)
- [ ] Bulk operations (export, import with merge options)
- [ ] Rule versioning/history
- [ ] Custom rule builder UI

---

**Status**: ✅ Complete  
**Testing**: Ready for manual testing  
**Documentation**: See IPS_RULES_IMPORT_GUIDE.md

