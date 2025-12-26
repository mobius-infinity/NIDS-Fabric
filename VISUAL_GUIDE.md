# Visual Guide - Flows Aggregation Feature

## User Interface Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    NIDS Admin Dashboard                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  SIDEBAR MENU (Left)                                │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ ▼ Monitor                                            │   │
│  │   • Dashboard (chart-pie icon)                      │   │
│  │   • Flows (stream icon) ← NEW!                      │   │
│  │   • System Settings (cog icon)                      │   │
│  │                                                      │   │
│  │ ▼ Binary Models                                     │   │
│  │   • Random Forest                                   │   │
│  │   • LightGBM                                        │   │
│  │   • DNN                                             │   │
│  │                                                      │   │
│  │ ▼ Multiclass Models                                │   │
│  │   • Random Forest                                   │   │
│  │   • LightGBM                                        │   │
│  │   • DNN                                             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  MAIN CONTENT AREA (Right)                          │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │                                                      │   │
│  │  Flows Summary ← Heading when Flows is selected    │   │
│  │                                                      │   │
│  │  ┌────────────────────────────────────────────────┐ │   │
│  │  │ IP SUMMARY (Top 10) - Bar Chart               │ │   │
│  │  │ ┌──────────────────────────────────────────┐  │ │   │
│  │  │ │                                          │  │ │   │
│  │  │ │    [Bar Chart]                           │  │ │   │
│  │  │ │    Blue bars = Source IPs                │  │ │   │
│  │  │ │    Red bars = Destination IPs            │  │ │   │
│  │  │ │                                          │  │ │   │
│  │  │ │    Legend: ☐ Source IP  ☐ Destination  │  │ │   │
│  │  │ │                                          │  │ │   │
│  │  │ └──────────────────────────────────────────┘  │ │   │
│  │  └────────────────────────────────────────────────┘ │   │
│  │                                                      │   │
│  │  ┌──────────────────┐  ┌──────────────────────────┐ │   │
│  │  │ FLOW STATISTICS  │  │ ATTACK FLOW DETAILS     │ │   │
│  │  ├──────────────────┤  ├──────────────────────────┤ │   │
│  │  │ Total Flows  234 │  │ Src IP | Port | Dst IP │ │   │
│  │  │                  │  │ ─────────────────────── │ │   │
│  │  │ ┌──────────────┐ │  │ 192.168.1.100 | 54321 │ │   │
│  │  │ │Attack Flows  │ │  │ 10.0.0.5      | 80    │ │   │
│  │  │ │ 45           │ │  │ 172.16.0.1    | 443   │ │   │
│  │  │ └──────────────┘ │  │ ...                    │ │   │
│  │  │                  │  │                        │ │   │
│  │  │ Top Protocols:   │  │ Threat Type | File    │ │   │
│  │  │ TCP      : 234   │  │ Trojan      | pcap    │ │   │
│  │  │ UDP      : 156   │  │ Worm        | pcap    │ │   │
│  │  │ ICMP     : 45    │  │ ...                    │ │   │
│  │  └──────────────────┘  └──────────────────────────┘ │   │
│  │                                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Click Flow Diagram

```
User clicks "Flows" in Sidebar
           ↓
    switchView('flows')
           ↓
    ├─ Hide all .view-section divs
    ├─ Show #view-flows
    ├─ Remove 'active' from all menu items
    ├─ Add 'active' to #menu-flows
    └─ Call loadFlowsSummary()
           ↓
    Fetch /api/flows-summary
           ↓
    ├─ Process response JSON
    ├─ Update #totalFlowsCount
    ├─ Update #attackFlowsCount
    ├─ Render #protocolList
    ├─ Initialize ipSummaryChart (Chart.js)
    └─ Render #attackFlowsBody
           ↓
    Dashboard displays all three widgets
```

## Data Processing Pipeline (Detailed)

```
┌─────────────────────────────────────────────────────────┐
│  CSV FILES IN LOGS_FOLDER                               │
│  ├─ rf_binary_00001.csv                                │
│  ├─ rf_multiclass_00001.csv                            │
│  ├─ lightgbm_binary_00001.csv                          │
│  ├─ lightgbm_multiclass_00001.csv                      │
│  └─ dnn_multiclass_00001.csv                           │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  STEP 1: READ & FILTER                                  │
│                                                          │
│  for each CSV file:                                     │
│    ├─ pd.read_csv(file, sep='#')                       │
│    ├─ Clean column names                               │
│    ├─ Filter: result NOT IN [safe, benign, 0, clean]   │
│    └─ Append to all_flows list                         │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  STEP 2: COMBINE                                        │
│                                                          │
│  combined_df = pd.concat(all_flows)                    │
│                                                          │
│  Result DataFrame:                                     │
│  ┌────────────────────────────────────────────────┐   │
│  │ time | file | src_ip | src_port | dst_ip |...│   │
│  ├────────────────────────────────────────────────┤   │
│  │ 2025 | a.pc | 192... | 54321    | 10.0.. |...│   │
│  │ 2025 | b.pc | 172... | 443      | 192... |...│   │
│  │ ...  | ...  | ...    | ...      | ...    |...│   │
│  └────────────────────────────────────────────────┘   │
│  ~50,000 rows                                          │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  STEP 3: DEDUPLICATE                                    │
│                                                          │
│  unique_flows = combined_df.drop_duplicates(            │
│      subset=['src_ip', 'src_port', 'dst_ip',           │
│              'dst_port', 'protocol']                    │
│  )                                                      │
│                                                          │
│  Result: ~234 unique flows                             │
└─────────────────────────────────────────────────────────┘
                        ↓
        ┌───────────────┬────────────┬────────────┐
        ↓               ↓            ↓            ↓
┌─────────────┐ ┌─────────────┐ ┌──────────┐ ┌──────────┐
│ STATS       │ │ TOP IPs     │ │PROTOCOLS │ │ ATTACKS  │
├─────────────┤ ├─────────────┤ ├──────────┤ ├──────────┤
│total_flows: │ │src value_.. │ │PROTOCOL  │ │filter    │
│    234      │ │counts()     │ │value_... │ │threat    │
│             │ │             │ │counts()  │ │& head(10)│
│attack_flows:│ │Result:      │ │          │ │          │
│     45      │ │┌──────────┐ │ │Result:   │ │Result:   │
│             │ ││192.168.  │ │ │┌────────┐│ │┌────────┐│
│             │ ││1.100: 50 │ │ ││TCP:234 ││ ││src_ip..││
│             │ ││10.0.0.5: │ │ ││UDP:156 ││ ││src_port││
│             │ ││   32     │ │ ││ICMP:45 ││ ││dst_ip..││
│             │ ││172.16.0.1:│ │ │└────────┘│ ││protocol││
│             │ ││   28     │ │ │          │ ││result..││
│             │ │└──────────┘ │ │          │ ││file... ││
│             │ │(Top 10)     │ │(Top 10)  │ ││×10 rows││
│             │ │             │ │          │ │└────────┘│
└─────────────┘ └─────────────┘ └──────────┘ └──────────┘
        ↓               ↓            ↓            ↓
        └───────────────┴────────────┴────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  STEP 4: JSON RESPONSE                                  │
│                                                          │
│  {                                                      │
│    "total_flows": 234,                                 │
│    "attack_flows": 45,                                 │
│    "top_src_ips": [                                    │
│      {"ip": "192.168.1.100", "count": 50},             │
│      {"ip": "10.0.0.5", "count": 32},                  │
│      ...                                               │
│    ],                                                  │
│    "top_dst_ips": [...],                               │
│    "protocol_dist": [...],                             │
│    "attack_details": [...]                             │
│  }                                                      │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  STEP 5: FRONTEND PROCESSING (JavaScript)               │
│                                                          │
│  ├─ Combine src + dst IPs into single map              │
│  ├─ Sort by total (src_count + dst_count)              │
│  ├─ Take top 10 IPs                                    │
│  ├─ Initialize Chart.js bar chart                      │
│  ├─ Update statistics displays                         │
│  ├─ Render attack flows table                          │
│  └─ Apply dark mode CSS if enabled                     │
└─────────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│  USER SEES DASHBOARD                                    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │ IP SUMMARY (Bar Chart)                          │   │
│  │ ┌─────────────────────────────────────────────┐ │   │
│  │ │ 192.168.1.100 ████ Source ████ Dest        │ │   │
│  │ │ 10.0.0.5      ███  ████  ████              │ │   │
│  │ │ 172.16.0.1    ██   ██                       │ │   │
│  │ └─────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
│  Flow Stats: 234 Total, 45 Attacks                    │
│  Protocols: TCP(234) UDP(156) ICMP(45)                │
│                                                          │
│  Attack Details Table: [10 latest attacks shown]        │
└─────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      FRONTEND (Browser)                     │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  base.html                        index.html               │
│  ┌──────────────────┐            ┌────────────────────┐   │
│  │ Sidebar Menu     │            │ Flows View Section │   │
│  │ ┌──────────────┐ │            │ ┌──────────────┐   │   │
│  │ │ menu-flows   │─┼────────────→│ view-flows   │   │   │
│  │ │ (Stream icon)│ │            │ ├──────────────┤   │   │
│  │ │              │ │            │ │ Widget 1: Chart   │   │
│  │ │              │ │            │ │ Widget 2: Stats   │   │
│  │ │              │ │            │ │ Widget 3: Table   │   │
│  │ └──────────────┘ │            │ └──────────────┘   │   │
│  └──────────────────┘            └────────────────────┘   │
│           ↓                                 ↓              │
│      onclick event          DOM Elements to Update         │
│           ↓                                 ↓              │
│  ┌────────────────────────────────────────────────────┐  │
│  │            main.js (JavaScript Logic)              │  │
│  │                                                     │  │
│  │  switchView('flows')                               │  │
│  │    ├─ Update menu active states                    │  │
│  │    └─ Call loadFlowsSummary()                      │  │
│  │                                                     │  │
│  │  loadFlowsSummary()                                │  │
│  │    ├─ fetch('/api/flows-summary')                  │  │
│  │    ├─ Process JSON response                        │  │
│  │    ├─ Update #totalFlowsCount                      │  │
│  │    ├─ Update #attackFlowsCount                     │  │
│  │    ├─ Render #protocolList                         │  │
│  │    ├─ Initialize ipSummaryChart (Chart.js)         │  │
│  │    └─ Render #attackFlowsBody                      │  │
│  │                                                     │  │
│  │  Variables:                                        │  │
│  │  - ipSummaryChart (Chart.js instance)              │  │
│  │  - currentView (current active view)               │  │
│  │                                                     │  │
│  └────────────────────────────────────────────────────┘  │
│           ↑                                                │
│      HTTP Request                                        │
│           ↑                                                │
└───────────┼────────────────────────────────────────────────┘
            │
            │ HTTP GET /api/flows-summary
            │
┌───────────┴────────────────────────────────────────────────┐
│                    BACKEND (Flask)                          │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  app/api/routes.py                                          │
│  ┌──────────────────────────────────────────────────────┐ │
│  │ @api_bp.route('/flows-summary')                      │ │
│  │ @login_required                                      │ │
│  │ def flows_summary():                                 │ │
│  │                                                       │ │
│  │   logs_folder = current_app.config['LOGS_FOLDER']   │ │
│  │                                                       │ │
│  │   1. Read all CSV files                             │ │
│  │      for file in glob.glob(logs_folder + "*.csv"):  │ │
│  │         ├─ pd.read_csv()                            │ │
│  │         ├─ Filter threats                           │ │
│  │         └─ Append to all_flows                      │ │
│  │                                                       │ │
│  │   2. Combine & Deduplicate                          │ │
│  │      combined_df = pd.concat(all_flows)             │ │
│  │      unique_flows = combined_df.drop_duplicates()   │ │
│  │                                                       │ │
│  │   3. Calculate Statistics                           │ │
│  │      ├─ total_flows = len(unique_flows)             │ │
│  │      ├─ attack_flows = count(threats)               │ │
│  │      ├─ top_src_ips = value_counts().head(10)       │ │
│  │      ├─ top_dst_ips = value_counts().head(10)       │ │
│  │      └─ protocol_dist = value_counts().head(10)     │ │
│  │                                                       │ │
│  │   4. Get Attack Details                             │ │
│  │      attacks = df[threat_mask].head(10)             │ │
│  │                                                       │ │
│  │   5. Return JSON                                    │ │
│  │      return jsonify({...})                          │ │
│  │                                                       │ │
│  └──────────────────────────────────────────────────────┘ │
│           ↑                                                 │
│    Data Source                                            │
│           ↑                                                 │
│  ┌────────────────────────────────────────────────────┐  │
│  │         LOGS_FOLDER (CSV Files)                    │  │
│  │ ├─ rf_binary_00001.csv                             │  │
│  │ ├─ rf_multiclass_00001.csv                         │  │
│  │ ├─ lightgbm_binary_00001.csv                       │  │
│  │ ├─ lightgbm_multiclass_00001.csv                   │  │
│  │ └─ dnn_multiclass_00001.csv                        │  │
│  └────────────────────────────────────────────────────┘  │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

## Chart Rendering Pipeline

```
IP Data from API Response
    ↓
    top_src_ips: [
        {ip: "192.168.1.100", count: 50},
        {ip: "10.0.0.5", count: 32},
        ...
    ]
    top_dst_ips: [
        {ip: "192.168.1.100", count: 25},
        {ip: "10.0.0.5", count: 18},
        ...
    ]
    ↓
Frontend JavaScript: Combine IPs
    ↓
    ipMap = {
        "192.168.1.100": {src: 50, dst: 25},
        "10.0.0.5": {src: 32, dst: 18},
        ...
    }
    ↓
Sort by Total (src + dst)
    ↓
    sorted = [
        ["192.168.1.100", 75],
        ["10.0.0.5", 50],
        ...
    ]
    ↓
Slice Top 10
    ↓
    top10 = [
        ["192.168.1.100", {src: 50, dst: 25}],
        ["10.0.0.5", {src: 32, dst: 18}],
        ...
    ]
    ↓
Prepare Chart Data
    ↓
    ipLabels = ["192.168.1.100", "10.0.0.5", ...]
    srcCounts = [50, 32, ...]
    dstCounts = [25, 18, ...]
    ↓
Initialize Chart.js
    ↓
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ipLabels,
            datasets: [
                {label: 'Source IP', data: srcCounts, backgroundColor: '#3b82f6'},
                {label: 'Destination IP', data: dstCounts, backgroundColor: '#ef4444'}
            ]
        },
        options: {...}
    })
    ↓
Render on Canvas
    ↓
    ┌─────────────────────────────────────┐
    │     IP SUMMARY BAR CHART            │
    │                                     │
    │  192.168.1.100  ████ ████████      │
    │  10.0.0.5       ███ ███████        │
    │  172.16.0.1     ██  ████           │
    │                                     │
    │  ☐ Source IP  ☐ Destination IP    │
    └─────────────────────────────────────┘
```

## Error Handling Flow

```
User clicks "Flows"
    ↓
loadFlowsSummary() executes
    ↓
    try {
        fetch('/api/flows-summary')
            ↓
            ├─ Network Error
            │   ↓
            │   catch(e)
            │   ↓
            │   alert('Error loading flows...')
            │   ↓
            │   console.error(e)
            │
            ├─ API Error (500, 403, 404)
            │   ↓
            │   res.json() fails
            │   ↓
            │   catch(e)
            │   ↓
            │   alert('Error loading flows...')
            │
            ├─ Empty Response
            │   ↓
            │   data = {
            │     total_flows: 0,
            │     attack_flows: 0,
            │     ...
            │   }
            │   ↓
            │   Display empty dashboard
            │   ↓
            │   Chart shows no data
            │   ↓
            │   Table shows "No attack flows detected"
            │
            └─ Success
                ↓
                Process & Display Data
                ↓
                Dashboard Renders
    }
```

## Dark Mode Support

```
HTML Element loads → CSS applies theme

┌──────────────────────────────────────────────┐
│ html[data-theme="light"]                     │
│  --bg: #f8fafc (light gray)                 │
│  --card-bg: #ffffff (white)                 │
│  --text-body: #334155 (dark gray)           │
│  --border-color: #e2e8f0 (very light)       │
└──────────────────────────────────────────────┘

vs.

┌──────────────────────────────────────────────┐
│ html[data-theme="dark"]                      │
│  --bg: #1a1a1a (very dark)                  │
│  --card-bg: #2d2d2d (dark gray)             │
│  --text-body: #d4d4d4 (light gray)          │
│  --border-color: #404040 (medium gray)      │
└──────────────────────────────────────────────┘

All Widget Elements:
├─ .card { background: var(--card-bg) }
├─ .card-body { color: var(--text-body) }
├─ table { border-color: var(--border-color) }
├─ Chart.js (plugins.legend.labels.color)
└─ Chart.js (scales.ticks.color)
```

---

**This diagram set provides complete visual understanding of the flows aggregation feature architecture and data flow.**
