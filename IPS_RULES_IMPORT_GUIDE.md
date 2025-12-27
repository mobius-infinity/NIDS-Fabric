# IPS/IDS Rules Database - Import Guide

## Cấu trúc lưu trữ mới

```
storage/
└── ips/
    └── ips_rules.csv          # Tất cả IPS rules được lưu ở đây
```

**Vị trí cũ**: `storage/model_logs/ips_rules.csv`  
**Vị trí mới**: `storage/ips/ips_rules.csv`

---

## Chức năng Import

### 1. Import từ File CSV (Upload)

**Cách sử dụng:**
1. Vào menu **IPS/IDS Database**
2. Tại phần **"Import Rules"**, click vào **"Choose CSV file"**
3. Chọn file CSV từ máy tính
4. Click nút **"Import"**

**Yêu cầu CSV:**
- Format: CSV (`.csv`)
- Separator: dấu phẩy (`,`) hoặc bất kỳ (hệ thống tự xử lý)
- Cột bắt buộc:
  - `rule_id` - ID duy nhất cho rule (VD: SID-2000001)
  - `rule_name` - Tên rule
  - `severity` - Mức độ nghiêm trọng (Critical, High, Medium, Low)
  - `category` - Loại threat (Authentication Attack, Web Attack, etc.)

**Cột tùy chọn:**
- `source` - Nguồn rule (Suricata, Snort, etc.) - mặc định: "Custom"
- `description` - Mô tả chi tiết
- `protocol` - Protocol (TCP, UDP, etc.)
- `port` - Port (22, 80,443, any)
- `rule_content` - Nội dung rule (Suricata/Snort format)
- `version` - Phiên bản - mặc định: "1.0"
- `false_positive_rate` - Tỷ lệ false positive - mặc định: 0.0
- `last_updated` - Ngày cập nhật - mặc định: hôm nay

**Ví dụ CSV:**
```csv
rule_id,rule_name,severity,category,description,source,protocol,port
SID-3000001,Custom SSH Scanner,High,Reconnaissance,Detects SSH port scanning,Custom,TCP,22
SID-3000002,HTTP Exploit,Critical,Web Attack,Detects HTTP exploits,Custom,TCP,80,443
```

**Xử lý:**
- Nếu `rule_id` đã tồn tại → cập nhật rule cũ
- Nếu `rule_id` mới → thêm rule mới
- Tự động thêm `last_updated` nếu không có
- Giữ nguyên các rule cũ không có trong file import

---

### 2. Import từ URL

**Cách sử dụng:**
1. Vào menu **IPS/IDS Database**
2. Tại phần **"Import Rules"**, nhập URL vào ô **"Import from URL"**
3. Click nút **"Import"**

**Yêu cầu URL:**
- URL phải trỏ đến file CSV
- Phải bắt đầu bằng `http://` hoặc `https://`
- File phải có định dạng CSV

**Ví dụ URLs:**
```
https://example.com/ips_rules.csv
https://raw.githubusercontent.com/user/repo/main/rules.csv
```

**Hỗ trợ Threat Intelligence Feeds:**
- Suricata: https://rules.suricata-ids.org/
- Snort: https://www.snort.org/ (cần account)
- Emerging Threats: https://rules.emergingthreats.net/

---

## API Endpoints

### Upload File
```http
POST /api/ips-rules/import-file
Content-Type: multipart/form-data

file: <CSV file>
```

**Response (thành công):**
```json
{
  "success": true,
  "message": "Imported 5 rules successfully",
  "imported_count": 5
}
```

**Response (lỗi):**
```json
{
  "success": false,
  "message": "Missing required columns: rule_id, category"
}
```

---

### Import từ URL
```http
POST /api/ips-rules/import-url
Content-Type: application/json

{
  "url": "https://example.com/rules.csv"
}
```

**Response (thành công):**
```json
{
  "success": true,
  "message": "Imported 10 rules successfully",
  "imported_count": 10
}
```

---

### Delete Rule
```http
DELETE /api/ips-rules/<rule_id>
```

**Response (thành công):**
```json
{
  "success": true,
  "message": "Rule deleted successfully"
}
```

---

## CSV Structure

### Cột bắt buộc

| Cột | Kiểu | Ví dụ |
|-----|------|-------|
| `rule_id` | String | SID-2000001 |
| `rule_name` | String | SSH Brute Force |
| `severity` | String | High, Critical, Medium, Low |
| `category` | String | Authentication Attack |

### Cột tùy chọn

| Cột | Kiểu | Mặc định | Ví dụ |
|-----|------|---------|-------|
| `source` | String | Custom | Suricata, Snort |
| `description` | String | (empty) | Detects excessive login attempts |
| `protocol` | String | (empty) | TCP, UDP |
| `port` | String | (empty) | 22, 80,443, any |
| `rule_content` | String | (empty) | alert tcp... |
| `version` | String | 1.0 | 1.0, 2.0 |
| `false_positive_rate` | Float | 0.0 | 0.05 |
| `last_updated` | String | Today | 2025-12-27 10:00:00 |

---

## Quản lý Rules

### Xem Rule Details
- Click vào rule trong bảng → Hiển thị chi tiết trong panel

### Xóa Rule
- Mở rule details → Click nút "Delete Rule" → Confirm

### Tìm kiếm
- Sử dụng ô tìm kiếm để lọc rules theo tên, description, category

### Lọc theo Severity
- Từ bảng statistics, click vào số Critical/High/Medium/Low để lọc

---

## Thực hành

### Ví dụ 1: Import custom rules từ file
```csv
rule_id,rule_name,severity,category,description
SID-3001,Port 8080 Scanning,Medium,Reconnaissance,Detects scanning on port 8080
SID-3002,Suspicious FTP,High,Lateral Movement,Detects FTP brute force
SID-3003,Malware Signature,Critical,Malware,Known malware pattern detected
```

### Ví dụ 2: Import từ Suricata rules (simplified)
```csv
rule_id,rule_name,severity,category,source
SID-4001,TLS Certificate Anomaly,High,Protocol Anomaly,Suricata
SID-4002,DNS Query Flooding,High,Reconnaissance,Suricata
```

---

## Lưu ý kỹ thuật

- **File location**: `storage/ips/ips_rules.csv`
- **CSV Separator**: Sử dụng `#` (ngăn cách các cột)
- **Encoding**: UTF-8
- **Backup**: Khuyến nghị backup `ips_rules.csv` trước khi import
- **Duplicate handling**: Rules được merge theo `rule_id` (keep latest)

