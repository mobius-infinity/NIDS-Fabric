# Flows Aggregation Feature - Implementation Summary

## Overview
Added comprehensive flows aggregation and visualization to the NIDS dashboard, allowing administrators to:
- View aggregated flows across all model detection logs
- Analyze attack flows with IP-level insights
- Monitor protocol distributions
- Visualize top source/destination IPs with bar charts

## What Was Implemented

### 1. Backend API Endpoint (`/api/flows-summary`)
**Location**: [app/api/routes.py](app/api/routes.py)

**Functionality**:
- **Aggregates all CSV logs** from `LOGS_FOLDER` into a unified dataset
- **Filters threat flows** (excludes safe/benign classifications)
- **Deduplicates flows** using 5-tuple key: (src_ip, src_port, dst_ip, dst_port, protocol)
- **Calculates statistics**:
  - Total unique flows
  - Attack flow count
  - Top 10 source IPs (by frequency)
  - Top 10 destination IPs (by frequency)
  - Protocol distribution (all protocols)
  - Latest 10 attack flow details

**Response JSON**:
```json
{
  "total_flows": 1234,
  "attack_flows": 45,
  "top_src_ips": [
    {"ip": "192.168.1.100", "count": 50},
    ...
  ],
  "top_dst_ips": [
    {"ip": "10.0.0.5", "count": 32},
    ...
  ],
  "protocol_dist": [
    {"protocol": "TCP", "count": 234},
    {"protocol": "UDP", "count": 156},
    ...
  ],
  "attack_details": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.5",
      "src_port": "54321",
      "dst_port": "80",
      "protocol": "TCP",
      "result": "Trojan",
      "file": "attack_sample.pcap"
    },
    ...
  ]
}
```

### 2. Frontend Components

#### A. Sidebar Menu Item
**Location**: [app/templates/base.html](app/templates/base.html)

Added "Flows" menu option with stream icon:
```html
<div id="menu-flows" class="menu-item" onclick="switchView('flows')">
    <i class="fas fa-stream"></i> <span>Flows</span>
</div>
```

#### B. Flows Dashboard View
**Location**: [app/templates/index.html](app/templates/index.html)

New section `view-flows` containing:

1. **IP Summary Chart (Bar Chart)**
   - Displays top 10 source and destination IPs
   - Dual-dataset visualization (src vs dst)
   - Interactive Chart.js implementation
   - Element: `#ipSummaryChart`

2. **Flow Statistics Card**
   - Total flows count
   - Attack flows count (highlighted in red)
   - Protocol distribution list with counts
   - Elements: `#totalFlowsCount`, `#attackFlowsCount`, `#protocolList`

3. **Attack Flow Details Table**
   - Shows latest 10 attack flows
   - Columns: Src IP, Src Port, Dst IP, Dst Port, Protocol, Threat Type, File
   - Scrollable container (400px height)
   - Red badge for threat classification
   - Element: `#attackFlowsBody`

### 3. JavaScript Functions

**Location**: [app/static/js/main.js](app/static/js/main.js)

#### Core Functions:

**`loadFlowsSummary()`**
- Fetches `/api/flows-summary` endpoint
- Updates all flow statistics
- Initializes IP Summary chart
- Renders attack flows table
- Error handling with user feedback

**Chart Variable**: `ipSummaryChart`
- Global reference to Chart.js instance
- Destroyed and recreated on data refresh
- Supports chart responsiveness

#### Menu Integration:
- Updated `switchView()` function to handle `'flows'` view
- Added sidebar active state management for flows menu
- Triggers `loadFlowsSummary()` when flows view is activated

### 4. UI Styling

**Dark Mode Compatible**:
- Uses CSS variables for theming
- Consistent with existing light/dark mode
- Table styling matches logs view
- Chart colors defined for visibility in both themes

**Chart Configuration**:
- Source IPs: Blue (#3b82f6)
- Destination IPs: Red (#ef4444)
- Responsive layout with dual datasets

## Files Modified

| File | Changes |
|------|---------|
| `app/api/routes.py` | Added `/api/flows-summary` endpoint (105 lines) |
| `app/templates/base.html` | Added flows menu item in sidebar |
| `app/templates/index.html` | Added flows view section with 3 widgets |
| `app/static/js/main.js` | Added `loadFlowsSummary()`, chart variable, switchView update |

## How to Use

1. **Access Flows Dashboard**:
   - Click "Flows" in the sidebar menu
   - Dashboard loads and aggregates all model logs

2. **Interpret IP Summary Chart**:
   - Blue bars = Source IP frequencies
   - Red bars = Destination IP frequencies
   - Hover over bars for exact counts

3. **View Attack Details**:
   - Scroll through attack flows table
   - Each row shows complete 5-tuple + threat classification
   - File reference shows which PCAP generated the threat

4. **Monitor Protocol Distribution**:
   - Protocol list shows all active protocols
   - Counts indicate traffic volume per protocol

## Dependencies

**Python Packages**:
- `pandas` - for CSV reading and data aggregation
- `numpy` - for numeric operations
- `flask` - already required

**JavaScript Libraries**:
- `Chart.js 3.9.1` - for bar chart visualization (already included)

**Note**: No additional dependencies needed beyond existing project requirements.

## Performance Considerations

- **Log Aggregation**: Reads all CSV files from logs folder once per request
- **Deduplication**: Uses pandas DataFrame drop_duplicates() for efficiency
- **Data Limiting**: Returns only top 10 IPs, 10 protocols, 10 attack flows
- **Frontend**: Chart.js handles responsive scaling automatically
- **Recommendation**: Cache results if logs folder contains many large files

## Future Enhancements

1. **Time-based Filtering**: Add date range selector for flows aggregation
2. **Export Functionality**: Add CSV/JSON export of aggregated flows
3. **Geo-mapping**: Display attack origins on world map
4. **Packet Analysis**: Show packet count and payload size distributions
5. **Rate Limiting**: Graph attack rate over time
6. **Advanced Filtering**: Filter flows by threat type, protocol, port ranges
7. **Caching**: Implement Redis-based caching for large log folders

## Testing Notes

- Verify flows section appears in sidebar after deployment
- Test with different threat types (ensure proper filtering)
- Validate chart rendering with both light and dark themes
- Check responsive behavior on different screen sizes
- Test with empty logs folder (graceful handling implemented)
- Verify tooltip display on hover (Chart.js default)

## Code Quality

✅ **Completed Validation**:
- Python syntax check: `routes.py` - OK
- JavaScript function verification: Both functions present and correct
- HTML structure verification: All elements present
- Error handling: Try-catch blocks with user feedback

---

**Status**: ✅ Implementation Complete  
**Date**: 2025  
**Impact**: Medium - Adds new analytics dashboard section
