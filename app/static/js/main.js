let currentView = 'dashboard';
let sysChart, trafficChart, threatChart;
let selectedModel = '', selectedTask = '';

// Pagination state
let currentPage = 1;
let pageSize = 50;
let totalLogs = 0;
let totalPages = 1;
let isLoading = false;

// Filter state
let globalSearch = '';
let columnFilters = {
    time: '',
    file: '',
    srcIP: '',
    srcPort: '',
    dstIP: '',
    dstPort: '',
    prediction: ''
};

// Sort state
let sortBy = 'time';
let sortOrder = 'desc'; // 'asc' or 'desc'

// PCAP Filter State
let pcapCurrentPage = 1;
let pcapPageSize = 100;
let pcapTotalFiles = 0;
let pcapSortBy = 'upload_date';
let pcapSortOrder = 'desc';

// PCAP Filter Values (persisted)
let pcapFilterState = {
    search: '',
    filterName: '',
    filterStatus: '',
    filterThreat: ''
};

document.addEventListener('DOMContentLoaded', () => {
    // Init dark mode from localStorage
    initDarkMode();
    
    // Initialize detection mode dropdown
    initDetectionModeDropdown();
    
    // Chỉ init charts nếu element tồn tại (tránh lỗi ở trang login)
    if(document.getElementById('sysChart')) {
        initCharts();
        loadUserInfo();
        setInterval(updateDashboard, 2000);
        updateDashboard();
    }
    
    // Setup scroll event for lazy loading
    const scrollContainer = document.getElementById('logsScrollContainer');
    if (scrollContainer) {
        scrollContainer.addEventListener('scroll', onLogsScroll);
    }
    // pagination controls are used instead of scroll-based lazy loading
});

// --- AUTH & USER ---
async function loadUserInfo() {
    try {
        const res = await fetch('/api/user-info');
        const data = await res.json();
        
        if (document.getElementById('nav-username')) {
            document.getElementById('nav-username').textContent = data.full_name;
            document.getElementById('nav-avatar').src = '/static/avatars/' + data.avatar;
        }
        
        // Update Setting Form if exists
        if(document.getElementById('setting-fullname')) {
            document.getElementById('setting-fullname').value = data.full_name;
            document.getElementById('setting-avatar').src = '/static/avatars/' + data.avatar;
            
            // Update detection mode dropdown
            const modeSelector = document.getElementById('modeSelector');
            if (modeSelector) {
                modeSelector.value = data.config_mode || 'voting';
            }
            
            // Set theme radio buttons
            const theme = data.theme || 'light';
            if (document.getElementById('themeLight')) {
                document.getElementById('themeLight').checked = (theme === 'light');
            }
            if (document.getElementById('themeDark')) {
                document.getElementById('themeDark').checked = (theme === 'dark');
            }
            
            const thresh = data.config_threshold || 2;
            document.getElementById('threshSlider').value = thresh;
            document.getElementById('thresh-display').textContent = thresh + '/6';
        }

    } catch (e) { console.error("Auth Error", e); }
}

// --- DARK MODE ---
function initDarkMode() {
    // Try to load theme from user profile first
    if (document.getElementById('sysChart')) {
        // Only load from user if we're on main app (not login page)
        loadUserTheme();
    } else {
        // Fallback: load from localStorage
        const theme = localStorage.getItem('theme') || 'light';
        applyTheme(theme);
    }
}

async function loadUserTheme() {
    try {
        const res = await fetch('/api/user-info');
        const data = await res.json();
        const theme = data.theme || 'light';
        applyTheme(theme);
    } catch (e) {
        // Fallback to localStorage
        const theme = localStorage.getItem('theme') || 'light';
        applyTheme(theme);
    }
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    updateDarkModeIcon(theme);
}

function toggleDarkMode() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    applyTheme(newTheme);
    
    // Redraw flows chart if it exists (to apply new theme colors)
    if (currentView === 'flows' && ipSummaryChart) {
        // Reload flows data to redraw chart with new colors
        loadFlowsSummary();
    }
    
    // Save to database
    const formData = new FormData();
    formData.append('theme', newTheme);
    
    fetch('/api/update-profile', { method: 'POST', body: formData })
        .catch(e => console.error('Failed to save theme:', e));
}

function updateDarkModeIcon(theme) {
    const btn = document.getElementById('darkModeToggle');
    if (btn) {
        btn.innerHTML = theme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
    }
}

function previewAvatar(event) { 
    document.getElementById('setting-avatar').src = URL.createObjectURL(event.target.files[0]); 
}

function formatEpochOrString(val) {
    if (val === null || val === undefined || val === '') return '-';
    const s = String(val).trim();
    // If looks like an epoch seconds integer
    if (/^\d+$/.test(s)) {
        try { return new Date(Number(s) * 1000).toLocaleString(); } catch(e) { return s; }
    }
    return s;
}

async function updateProfile() {
    const formData = new FormData(document.getElementById('profileForm'));
    
    // Add theme from radio buttons if they exist
    const themeLight = document.getElementById('themeLight');
    const themeDark = document.getElementById('themeDark');
    if (themeLight && themeDark) {
        const theme = themeLight.checked ? 'light' : (themeDark.checked ? 'dark' : 'light');
        formData.set('theme', theme);
    }
    
    try { 
        const res = await fetch('/api/update-profile', { method: 'POST', body: formData }); 
        const data = await res.json();
        alert(data.message || data.status); 
        loadUserInfo();
        
        // Apply theme immediately
        const theme = formData.get('theme');
        applyTheme(theme);
    } catch(e) { alert("Error"); }
}

async function saveSystemSettings() {
    const modeSelector = document.getElementById('modeSelector');
    const mode = modeSelector ? modeSelector.value : 'voting';
    const thresh = document.getElementById('threshSlider').value;
    
    try {
        await fetch('/api/update-settings', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                detection_mode: mode,
                voting_threshold: thresh
            })
        });
        alert("System config saved!");
    } catch(e) { alert("Error saving settings"); }
}

function onDetectionModeChange() {
    const modeSelector = document.getElementById('modeSelector');
    const mode = modeSelector.value;
    const thresholdContainer = document.getElementById('thresholdContainer');
    
    // Show/hide threshold container based on mode
    if (mode === 'voting') {
        thresholdContainer.style.display = 'flex';
    } else {
        thresholdContainer.style.display = 'none';
    }
}

function initDetectionModeDropdown() {
    const modeSelector = document.getElementById('modeSelector');
    if (!modeSelector) return;
    
    // Set up the initial visibility of threshold container based on current mode
    const mode = modeSelector.value || 'voting';
    const thresholdContainer = document.getElementById('thresholdContainer');
    if (thresholdContainer) {
        thresholdContainer.style.display = (mode === 'voting') ? 'flex' : 'none';
    }
    
    // Add change listener
    modeSelector.addEventListener('change', onDetectionModeChange);
}

// --- NAVIGATION ---
function toggleSidebar() { 
    document.getElementById('sidebar').classList.toggle('collapsed'); 
    setTimeout(() => { if (currentView === 'dashboard') resizeCharts(); }, 320); 
}

function switchView(view) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    const target = document.getElementById(`view-${view}`); 
    if(target) target.classList.add('active');
    
    document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
    if(view==='dashboard') document.getElementById('menu-dashboard').classList.add('active');
    else if(view==='flows') document.getElementById('menu-flows').classList.add('active');
    else if(view==='incoming-files') document.getElementById('menu-incoming-files').classList.add('active');
    else if(view==='settings') document.getElementById('menu-settings').classList.add('active');
    else if(view==='ips-database') document.getElementById('menu-ips-database').classList.add('active');
    
    // Stop previous auto-refreshes
    stopFlowsAutoRefresh();
    stopFilesAutoRefresh();
    
    if (view === 'dashboard') setTimeout(() => { resizeCharts(); updateDashboard(); }, 50);
    else if (view === 'flows') { 
        loadFlowsSummary();
        loadConsensusLogs(1);  // Load consensus logs when switching to flows view
        startFlowsAutoRefresh();
    }
    else if (view === 'incoming-files') {
        startFilesAutoRefresh();
    }
    else if (view === 'ips-database') {
        loadIPSRules();
    }
    currentView = view;
}

// --- MODEL LOGS & DETAILS ---
function switchModel(el, model, task) {
    selectedModel = model; selectedTask = task;
    document.querySelectorAll('.menu-item').forEach(e => e.classList.remove('active')); 
    if(el) el.classList.add('active');
    
    switchView('model');
    document.getElementById('view-model').classList.add('active');
    document.getElementById('model-title').textContent = `${model} (${task})`;
    document.getElementById('model-title').classList.add('model-name');
    resetPagination();
    
    // Update top flows when model changes
    if (document.getElementById('topFlowsBody')) {
        loadTopFlows();
    }
}

function resetPagination() {
    currentPage = 1;
    totalLogs = 0;
    totalPages = 1;
    document.getElementById('modelLogsBody').innerHTML = '';
    updatePaginationControls();
    loadPage(currentPage);
}

async function loadPage(page) {
    if (isLoading) return;
    isLoading = true;
    document.getElementById('logsLoadingIndicator').style.display = 'block';
    try {
        const modelParam = encodeURIComponent(selectedModel || 'Random Forest');
        const taskParam = encodeURIComponent(selectedTask || 'binary');
        const offset = (page - 1) * pageSize;
        
        // Build query params with filters and sort
        let queryUrl = `/api/get_flows?model=${modelParam}&task=${taskParam}&offset=${offset}&limit=${pageSize}&sort_by=${sortBy}&sort_order=${sortOrder}`;
        if (globalSearch) {
            queryUrl += `&search=${encodeURIComponent(globalSearch)}`;
        }
        if (columnFilters.time) {
            queryUrl += `&filter_time=${encodeURIComponent(columnFilters.time)}`;
        }
        if (columnFilters.file) {
            queryUrl += `&filter_file=${encodeURIComponent(columnFilters.file)}`;
        }
        if (columnFilters.srcIP) {
            queryUrl += `&filter_srcip=${encodeURIComponent(columnFilters.srcIP)}`;
        }
        if (columnFilters.srcPort) {
            queryUrl += `&filter_srcport=${encodeURIComponent(columnFilters.srcPort)}`;
        }
        if (columnFilters.dstIP) {
            queryUrl += `&filter_dstip=${encodeURIComponent(columnFilters.dstIP)}`;
        }
        if (columnFilters.dstPort) {
            queryUrl += `&filter_dstport=${encodeURIComponent(columnFilters.dstPort)}`;
        }
        if (columnFilters.prediction) {
            queryUrl += `&filter_prediction=${encodeURIComponent(columnFilters.prediction)}`;
        }
        
        const res = await fetch(queryUrl);
        const data = await res.json();
        if (data.error) {
            console.error('API error', data.error);
            if (page === 1) document.getElementById('modelLogsBody').innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px;">API error</td></tr>`;
            return;
        }

        totalLogs = data.total || 0;
        totalPages = Math.max(1, Math.ceil(totalLogs / pageSize));
        currentPage = page;

        const rows = (data.flows || []).map((f, idx) => {
            const num = offset + idx + 1;
            const time = formatEpochOrString(f.time_scaned || f.FIRST_SWITCHED || f.FLOW_START || f.FLOW_START_MILLISECONDS);
            const pred = f.result || f.prediction || '-';
            return `<tr style="cursor:pointer; border-bottom:1px solid var(--border-color);" onclick="showDetails('${f.id}')">
                        <td style="padding:8px;">${num}</td>
                        <td style="padding:8px;">${time}</td>
                        <td style="padding:8px;">${f.file_scaned || '-'}</td>
                        <td style="padding:8px; color:#3b82f6; font-weight:600;">${f.IPV4_SRC_ADDR || '-'}</td>
                        <td style="padding:8px;">${f.L4_SRC_PORT || '-'}</td>
                        <td style="padding:8px; color:#3b82f6; font-weight:600;">${f.IPV4_DST_ADDR || '-'}</td>
                        <td style="padding:8px;">${f.L4_DST_PORT || '-'}</td>
                        <td style="padding:8px;">${pred}</td>
                    </tr>`;
        }).join('');

        document.getElementById('modelLogsBody').innerHTML = rows || `<tr><td colspan="8" style="text-align:center; padding:20px;">No logs</td></tr>`;
        updatePaginationControls();
    } catch (e) {
        console.error('Error loading page:', e);
        if (page === 1) document.getElementById('modelLogsBody').innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px;">Error loading logs</td></tr>`;
    } finally {
        isLoading = false;
        document.getElementById('logsLoadingIndicator').style.display = 'none';
    }
}

function updatePaginationControls() {
    document.getElementById('pageDisplay').textContent = `Page ${currentPage} / ${totalPages}`;
    document.getElementById('pageInput').value = currentPage;
    document.getElementById('prevPageBtn').disabled = (currentPage <= 1);
    document.getElementById('nextPageBtn').disabled = (currentPage >= totalPages);
}

function prevPage() { if (currentPage > 1) loadPage(currentPage - 1); }
function nextPage() { if (currentPage < totalPages) loadPage(currentPage + 1); }
function gotoPage() {
    let p = parseInt(document.getElementById('pageInput').value || '1', 10);
    if (isNaN(p) || p < 1) p = 1;
    if (p > totalPages) p = totalPages;
    loadPage(p);
}

// --- FILTER FUNCTIONS ---
function applyFilters() {
    // Collect all filter values
    globalSearch = document.getElementById('globalSearchInput').value || '';
    columnFilters.time = document.getElementById('filterTime').value || '';
    columnFilters.file = document.getElementById('filterFile').value || '';
    columnFilters.srcIP = document.getElementById('filterSrcIP').value || '';
    columnFilters.srcPort = document.getElementById('filterSrcPort').value || '';
    columnFilters.dstIP = document.getElementById('filterDstIP').value || '';
    columnFilters.dstPort = document.getElementById('filterDstPort').value || '';
    columnFilters.prediction = document.getElementById('filterPrediction').value || '';
    
    // Reset sort and pagination
    sortBy = 'time';
    sortOrder = 'desc';
    updateSortIndicators();
    
    // Reset to page 1 and reload
    currentPage = 1;
    totalPages = 1;
    loadPage(1);
}

function clearAllFilters() {
    // Clear all input fields
    document.getElementById('globalSearchInput').value = '';
    document.getElementById('filterTime').value = '';
    document.getElementById('filterFile').value = '';
    document.getElementById('filterSrcIP').value = '';
    document.getElementById('filterSrcPort').value = '';
    document.getElementById('filterDstIP').value = '';
    document.getElementById('filterDstPort').value = '';
    document.getElementById('filterPrediction').value = '';
    
    // Reset filter state
    globalSearch = '';
    columnFilters = { time: '', file: '', srcIP: '', srcPort: '', dstIP: '', dstPort: '', prediction: '' };
    
    // Reset sort
    sortBy = 'time';
    sortOrder = 'desc';
    updateSortIndicators();
    
    // Reload
    currentPage = 1;
    totalPages = 1;
    loadPage(1);
}

// --- SORT FUNCTIONS ---
function setSortColumn(column) {
    if (sortBy === column) {
        // Toggle sort order
        sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        // Change sort column
        sortBy = column;
        sortOrder = 'desc';
    }
    updateSortIndicators();
    currentPage = 1;
    totalPages = 1;
    loadPage(1);
}

function updateSortIndicators() {
    // Clear all indicators first
    document.querySelectorAll('.sort-indicator').forEach(el => el.remove());
    
    // Add indicator to current sort column
    const colMap = {
        'time': 'headerTime',
        'file': 'headerFile',
        'srcip': 'headerSrcIP',
        'srcport': 'headerSrcPort',
        'dstip': 'headerDstIP',
        'dstport': 'headerDstPort',
        'prediction': 'headerPrediction'
    };
    
    const headerId = colMap[sortBy.toLowerCase()];
    if (headerId) {
        const header = document.getElementById(headerId);
        if (header) {
            const icon = sortOrder === 'asc' ? '▲' : '▼';
            header.innerHTML += ` <span class="sort-indicator" style="color: var(--text-main); margin-left: 4px;">${icon}</span>`;
        }
    }
}

function onLogsScroll() {
    // scroll-based lazy loading removed; this handler kept inert for compatibility
    return;
}

// --- PCAP UPLOAD ---
async function uploadPcap(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('pcap', file);
    try {
        document.getElementById('logsLoadingIndicator').style.display = 'block';
        const res = await fetch('/api/upload_pcap', { method: 'POST', body: fd });
        const data = await res.json();
        if (data && data.status === 'success') {
            alert('Uploaded: ' + data.name);
            // Refresh incoming files on dashboard
            updateDashboard();
        } else {
            alert('Upload failed: ' + (data.message || JSON.stringify(data)));
        }
    } catch (e) {
        console.error('Upload Error', e);
        alert('Upload error');
    } finally {
        document.getElementById('logsLoadingIndicator').style.display = 'none';
        // reset file input so same file can be selected again
        try { event.target.value = ''; } catch(e){}
    }
}

// --- CLEAR LOGS ---
async function clearFilteredLogs() {
    // Show confirmation dialog
    const msg = globalSearch || Object.values(columnFilters).some(v => v) 
        ? 'Delete filtered logs?' 
        : 'Delete ALL logs for this model?';
    
    if (!confirm(msg)) return;
    
    try {
        document.getElementById('logsLoadingIndicator').style.display = 'block';
        
        const modelParam = encodeURIComponent(selectedModel || 'Random Forest');
        const taskParam = encodeURIComponent(selectedTask || 'binary');
        
        // Build query with filters
        let queryUrl = `/api/clear_logs?model=${modelParam}&task=${taskParam}`;
        if (globalSearch) {
            queryUrl += `&search=${encodeURIComponent(globalSearch)}`;
        }
        if (columnFilters.time) {
            queryUrl += `&filter_time=${encodeURIComponent(columnFilters.time)}`;
        }
        if (columnFilters.file) {
            queryUrl += `&filter_file=${encodeURIComponent(columnFilters.file)}`;
        }
        if (columnFilters.srcIP) {
            queryUrl += `&filter_srcip=${encodeURIComponent(columnFilters.srcIP)}`;
        }
        if (columnFilters.srcPort) {
            queryUrl += `&filter_srcport=${encodeURIComponent(columnFilters.srcPort)}`;
        }
        if (columnFilters.dstIP) {
            queryUrl += `&filter_dstip=${encodeURIComponent(columnFilters.dstIP)}`;
        }
        if (columnFilters.dstPort) {
            queryUrl += `&filter_dstport=${encodeURIComponent(columnFilters.dstPort)}`;
        }
        if (columnFilters.prediction) {
            queryUrl += `&filter_prediction=${encodeURIComponent(columnFilters.prediction)}`;
        }
        
        const res = await fetch(queryUrl, { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`Deleted ${data.deleted} log entries`);
            loadPage(1); // Reload page 1
        } else {
            alert('Error: ' + (data.message || 'Unknown error'));
        }
    } catch (e) {
        console.error('Clear Error', e);
        alert('Error clearing logs');
    } finally {
        document.getElementById('logsLoadingIndicator').style.display = 'none';
    }
}

// Toggle clear logs menu visibility
function toggleClearLogsMenu() {
    const menu = document.getElementById('clearLogsMenu');
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
}

// Close menu when clicking outside
document.addEventListener('click', function(e) {
    const menu = document.getElementById('clearLogsMenu');
    const btn = e.target.closest('button[onclick*="toggleClearLogsMenu"]');
    if (!btn && !menu.contains(e.target)) {
        menu.style.display = 'none';
    }
});

// Clear all logs for current model
async function clearAllCurrentModel() {
    if (!confirm(`Are you sure? This will delete ALL ${selectedModel} (${selectedTask}) logs.`)) return;
    
    try {
        document.getElementById('logsLoadingIndicator').style.display = 'block';
        
        const modelParam = encodeURIComponent(selectedModel || 'Random Forest');
        const taskParam = encodeURIComponent(selectedTask || 'binary');
        
        const res = await fetch(`/api/clear_all_logs?model=${modelParam}&task=${taskParam}&all_models=false`, { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`Deleted ${data.deleted} log entries from ${selectedModel} (${selectedTask})`);
            loadPage(1); // Reload page 1
        } else {
            alert('Error: ' + (data.message || 'Unknown error'));
        }
    } catch (e) {
        console.error('Clear All Error', e);
        alert('Error clearing logs');
    } finally {
        document.getElementById('logsLoadingIndicator').style.display = 'none';
    }
}

// Clear all logs for all models (DANGEROUS - requires double confirmation)
async function clearAllModels() {
    if (!confirm(`⚠️ WARNING: This will delete ALL logs from ALL MODELS!\n\nAre you sure?`)) return;
    if (!confirm(`⚠️ FINAL CONFIRMATION: Delete ALL logs from ALL models? This cannot be undone!`)) return;
    
    try {
        document.getElementById('logsLoadingIndicator').style.display = 'block';
        
        const res = await fetch(`/api/clear_all_logs?all_models=true`, { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`Deleted ${data.deleted} log entries from ALL models`);
            loadPage(1); // Reload page 1
        } else {
            alert('Error: ' + (data.message || 'Unknown error'));
        }
    } catch (e) {
        console.error('Clear All Models Error', e);
        alert('Error clearing logs');
    } finally {
        document.getElementById('logsLoadingIndicator').style.display = 'none';
    }
}

// --- FORTIOS STYLE DETAILS ---
function showDetails(id) {
    fetch(`/api/flow-details/${id}?model=${selectedModel}&task=${selectedTask}`)
        .then(r=>r.json())
        .then(d=>{
            const panel = document.getElementById('panelContent');
            const titleElem = document.getElementById('detailPanelTitle');
            
            // Set title
            titleElem.innerHTML = '<i class="fas fa-list-alt" style="color:var(--text-main); margin-right:8px;"></i> Log Details';
            
            let isThreat = !(String(d.result).toLowerCase().includes('safe') || 
                             String(d.result).toLowerCase().includes('benign') || 
                             d.result == '0');
            
            panel.innerHTML = `
                <div class="forti-group">
                    <div class="forti-group-title">General</div>
                    <div class="forti-row"><span class="forti-label">Date/Time</span><span class="forti-val">${d.time_scaned}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow Start</span><span class="forti-val">${formatEpochOrString(d.FIRST_SWITCHED ?? d.FLOW_START_MILLISECONDS ?? d.FLOW_START)}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow End</span><span class="forti-val">${formatEpochOrString(d.LAST_SWITCHED ?? d.FLOW_END_MILLISECONDS ?? d.FLOW_END)}</span></div>
                    <div class="forti-row"><span class="forti-label">File Source</span><span class="forti-val">${d.file_scaned}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow ID</span><span class="forti-val">${d.id}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Source</div>
                    <div class="forti-row"><span class="forti-label">IP Address</span><span class="forti-val forti-ip">${d.IPV4_SRC_ADDR}</span></div>
                    <div class="forti-row"><span class="forti-label">Port</span><span class="forti-val">${d.L4_SRC_PORT}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Destination</div>
                    <div class="forti-row"><span class="forti-label">IP Address</span><span class="forti-val forti-ip">${d.IPV4_DST_ADDR}</span></div>
                    <div class="forti-row"><span class="forti-label">Port</span><span class="forti-val">${d.L4_DST_PORT}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Flow Stats</div>
                    <div class="forti-row"><span class="forti-label">Protocol</span><span class="forti-val">${d.PROTOCOL ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">L7 Proto</span><span class="forti-val">${d.L7_PROTO ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">In Packets</span><span class="forti-val">${d.IN_PKTS ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Out Packets</span><span class="forti-val">${d.OUT_PKTS ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Duration (ms)</span><span class="forti-val">${d.FLOW_DURATION_MILLISECONDS ?? d.FLOW_DURATION ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Max IP Len</span><span class="forti-val">${d.MAX_IP_PKT_LEN ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Retransmitted (bytes)</span><span class="forti-val">${d.RETRANSMITTED_IN_BYTES ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Src→Dst Avg Throughput</span><span class="forti-val">${d.SRC_TO_DST_AVG_THROUGHPUT ?? '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Dst→Src Avg Throughput</span><span class="forti-val">${d.DST_TO_SRC_AVG_THROUGHPUT ?? '-'}</span></div>
                </div>
                <div class="forti-group">
                    <div class="forti-group-title">Security</div>
                    <div class="forti-row"><span class="forti-label">Level</span><span class="badge ${isThreat?'badge-danger':'badge-safe'}">${isThreat?'Critical':'Notice'}</span></div>
                    <div class="forti-row"><span class="forti-label">Prediction</span><span class="forti-val ${isThreat?'forti-threat':'forti-safe'}">${d.result}</span></div>
                    <div class="forti-row"><span class="forti-label">Protocol</span><span class="forti-val">${d.PROTOCOL}</span></div>
                </div>
            `;
            document.getElementById('panelOverlay').classList.add('active');
            document.getElementById('logDetailPanel').classList.add('active');
        });
}

function closeDetails() {
    document.getElementById('panelOverlay').classList.remove('active');
    document.getElementById('logDetailPanel').classList.remove('active');
}

// --- DASHBOARD CHARTS ---
function initCharts() {
    const commonOpt = { responsive: true, maintainAspectRatio: false, plugins: { legend: false } };
    
    const ctxSys = document.getElementById('sysChart');
    if(ctxSys) {
        sysChart = new Chart(ctxSys, { 
            type: 'line', 
            data: { labels: [], datasets: [{ data: [], borderColor: '#d35400', tension: 0.4, borderWidth: 2, pointRadius: 0 }] }, 
            options: { ...commonOpt, scales: { x: { display: false }, y: { display: false, min: 0, max: 100 } } } 
        });
    }

    const ctxTraffic = document.getElementById('trafficChart');
    if(ctxTraffic) {
        trafficChart = new Chart(ctxTraffic, { 
            type: 'line', 
            data: { labels: [], datasets: [{ data: [], borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 }] }, 
            options: { ...commonOpt, scales: { x: { display: true, grid: {display:false}, ticks: {maxTicksLimit: 8} }, y: { beginAtZero: true, grid: {color:'#f1f5f9'} } } } 
        });
    }
    
    const ctxThreat = document.getElementById('threatChart');
    if(ctxThreat) {
        threatChart = new Chart(ctxThreat, { 
            type: 'doughnut', 
            data: { 
                labels: ['Safe', 'Attack'], 
                datasets: [{ 
                    data: [1, 0], 
                    backgroundColor: ['#10b981', '#ef4444'], 
                    borderWidth: 0 
                }] 
            }, 
            options: { ...commonOpt, cutout: '75%', plugins: { legend: { position: 'right' } } } 
        });
    }
}

function resizeCharts() { 
    if(sysChart) sysChart.resize(); 
    if(trafficChart) trafficChart.resize(); 
    if(threatChart) threatChart.resize(); 
}

async function updateDashboard() {
    if (currentView !== 'dashboard') return;
    try {
        const res = await fetch('/api/general-dashboard');
        const data = await res.json();
        
        document.getElementById('cpu-val').textContent = data.system.latest_cpu + '%';
        document.getElementById('ram-val').textContent = data.system.latest_ram + '%';
        document.getElementById('cpu-bar').style.width = data.system.latest_cpu + '%';
        document.getElementById('ram-bar').style.width = data.system.latest_ram + '%';

        if(sysChart) { 
            sysChart.data.labels = data.system.labels; 
            sysChart.data.datasets[0].data = data.system.cpu_history; 
            sysChart.update('none'); 
        }
        if(trafficChart) { 
            trafficChart.data.labels = data.system.labels; 
            trafficChart.data.datasets[0].data = data.system.flow_history; 
            trafficChart.update('none'); 
        }
        
        if(threatChart) { 
            threatChart.data.datasets[0].data = [data.security.total_safe, data.security.total_attacks]; 
            threatChart.update(); 
        }

        const resFiles = await fetch('/api/incoming-files');
        const files = await resFiles.json();
        document.getElementById('filesTableDashboard').innerHTML = files.files.slice(0,5).map(f => {
            let badge = 'badge-warn';
            if(f.status.includes('Threat')) badge = 'badge-danger';
            else if(f.status.includes('Safe')) badge = 'badge-safe';
            
            // Escape single quotes in filename for onclick handler
            const safeName = f.name.replace(/'/g, "\\'");
            
            return `<tr style="cursor:pointer;" onclick="showFileDetails('${safeName}')" title="Click to view details">
                        <td style="font-weight:600;">${f.name}</td>
                        <td>${f.size_mb} MB</td>
                        <td><span class="badge ${badge}">${f.status}</span></td>
                    </tr>`;
        }).join('');
        
        // Load top flows widget
        loadTopFlows();
    } catch(e) { console.error("Dash Error", e); }
}

// --- FLOWS SUMMARY ---
let ipSummaryChart;

// Helper function to get computed CSS variable values
function getCSSVariableColor(varName) {
    const value = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
    return value || '#000000';
}

// Helper function to get Chart.js colors based on current theme
function getChartColors() {
    return {
        textBody: getCSSVariableColor('--text-body'),
        textMuted: getCSSVariableColor('--text-muted'),
        borderColor: getCSSVariableColor('--border-color'),
        bgSecondary: getCSSVariableColor('--bg-secondary')
    };
}

async function loadFlowsSummary() {
    try {
        const res = await fetch('/api/flows-summary');
        const data = await res.json();
        
        // Update flow statistics
        document.getElementById('totalFlowsCount').textContent = data.total_flows.toLocaleString();
        document.getElementById('attackFlowsCount').textContent = data.attack_flows.toLocaleString();
        
        // Update protocol distribution
        if (data.protocol_dist && data.protocol_dist.length > 0) {
            const protocolList = data.protocol_dist.map(p => 
                `<div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid var(--border-color);">
                    <span>${p.protocol}</span>
                    <span style="font-weight:600;">${p.count}</span>
                </div>`
            ).join('');
            document.getElementById('protocolList').innerHTML = protocolList;
        }
        
        // IP Summary Chart (combine top src and dst IPs)
        const topSrc = data.top_src_ips || [];
        const topDst = data.top_dst_ips || [];
        
        // Combine and deduplicate IPs
        const ipMap = {};
        topSrc.forEach(ip => {
            if (!ipMap[ip.ip]) ipMap[ip.ip] = { src: 0, dst: 0 };
            ipMap[ip.ip].src = ip.count;
        });
        topDst.forEach(ip => {
            if (!ipMap[ip.ip]) ipMap[ip.ip] = { src: 0, dst: 0 };
            ipMap[ip.ip].dst = ip.count;
        });
        
        // Get top 10 by total count
        const ips = Object.entries(ipMap)
            .sort((a, b) => (b[1].src + b[1].dst) - (a[1].src + a[1].dst))
            .slice(0, 10);
        
        const ipLabels = ips.map(ip => ip[0]);
        const srcCounts = ips.map(ip => ip[1].src);
        const dstCounts = ips.map(ip => ip[1].dst);
        
        // Initialize or update IP chart
        const ctx = document.getElementById('ipSummaryChart');
        if (ctx) {
            if (ipSummaryChart) ipSummaryChart.destroy();
            
            // Get current theme colors
            const colors = getChartColors();
            
            ipSummaryChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ipLabels,
                    datasets: [
                        {
                            label: 'Source IP',
                            data: srcCounts,
                            backgroundColor: '#3b82f6',
                            borderColor: '#1e40af',
                            borderWidth: 1
                        },
                        {
                            label: 'Destination IP',
                            data: dstCounts,
                            backgroundColor: '#ef4444',
                            borderColor: '#7f1d1d',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            display: true,
                            labels: { 
                                color: colors.textBody, 
                                font: { size: 12 },
                                padding: 15
                            }
                        },
                        tooltip: {
                            backgroundColor: colors.bgSecondary,
                            titleColor: colors.textBody,
                            bodyColor: colors.textBody,
                            borderColor: colors.borderColor,
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: {
                            ticks: { 
                                color: colors.textBody, 
                                font: { size: 10 } 
                            },
                            grid: { color: colors.borderColor },
                            title: {
                                display: true,
                                color: colors.textBody
                            }
                        },
                        y: {
                            ticks: { 
                                color: colors.textBody,
                                font: { size: 10 }
                            },
                            grid: { color: colors.borderColor },
                            title: {
                                display: true,
                                color: colors.textBody
                            }
                        }
                    }
                }
            });
        }
        
        // Render attack flows table
        if (data.attack_details && data.attack_details.length > 0) {
            const rows = data.attack_details.map(flow => `
                <tr style="border-bottom:1px solid var(--border-color);">
                    <td style="padding:8px; font-size:0.85em;">${flow.src_ip}</td>
                    <td style="padding:8px; font-size:0.85em;">${flow.src_port}</td>
                    <td style="padding:8px; font-size:0.85em;">${flow.dst_ip}</td>
                    <td style="padding:8px; font-size:0.85em;">${flow.dst_port}</td>
                    <td style="padding:8px; font-size:0.85em;">${flow.protocol}</td>
                    <td style="padding:8px; font-size:0.85em;"><span class="badge badge-danger">${flow.result}</span></td>
                    <td style="padding:8px; font-size:0.85em;">${flow.file}</td>
                </tr>
            `).join('');
            
            document.getElementById('attackFlowsBody').innerHTML = rows;
        } else {
            document.getElementById('attackFlowsBody').innerHTML = '<tr><td colspan="7" style="padding:12px; text-align:center; color:var(--text-muted);">No attack flows detected</td></tr>';
        }
        
    } catch(e) { 
        console.error("Flows Summary Error", e);
        alert('Error loading flows summary: ' + e.message);
    }
}

// --- CONSENSUS VOTING LOGS ---
let consensusCurrentPage = 1;
let consensusTotalPages = 1;
let consensusTotalLogs = 0;
let consensusPageSize = 50;
let consensusSortBy = 'time';
let consensusSortOrder = 'desc';

async function loadConsensusLogs(page = 1) {
    try {
        const search = document.getElementById('consensusSearchInput')?.value || '';
        const resultFilter = document.getElementById('consensusResultFilter')?.value || '';
        const votesFilter = document.getElementById('consensusVotesFilter')?.value || '';
        
        const offset = (page - 1) * consensusPageSize;
        let url = `/api/get_consensus_logs?offset=${offset}&limit=${consensusPageSize}&sort_by=${consensusSortBy}&sort_order=${consensusSortOrder}`;
        
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (resultFilter) url += `&filter_result=${encodeURIComponent(resultFilter)}`;
        if (votesFilter) url += `&filter_votes=${encodeURIComponent(votesFilter)}`;
        
        const res = await fetch(url);
        const data = await res.json();
        
        consensusTotalLogs = data.total || 0;
        consensusTotalPages = Math.max(1, Math.ceil(consensusTotalLogs / consensusPageSize));
        consensusCurrentPage = page;
        
        const rows = (data.flows || []).map((f, idx) => {
            const num = offset + idx + 1;
            const time = formatEpochOrString(f.time_scaned);
            const votes = f.votes || 0;
            const result = f.result || '-';
            const confidence = f.confidence || `${votes}/6`;
            
            // Style based on result
            const resultClass = result === 'attack' ? 'badge-danger' : 'badge-safe';
            const votesColor = votes >= 4 ? '#ef4444' : (votes >= 2 ? '#f59e0b' : '#10b981');
            
            return `<tr style="cursor:pointer; border-bottom:1px solid var(--border-color);" onclick="showConsensusDetails('${f.id}')">
                <td style="padding:8px;">${num}</td>
                <td style="padding:8px;">${time}</td>
                <td style="padding:8px;">${f.file_scaned || '-'}</td>
                <td style="padding:8px; color:#3b82f6; font-weight:600;">${f.IPV4_SRC_ADDR || '-'}</td>
                <td style="padding:8px;">${f.L4_SRC_PORT || '-'}</td>
                <td style="padding:8px; color:#3b82f6; font-weight:600;">${f.IPV4_DST_ADDR || '-'}</td>
                <td style="padding:8px;">${f.L4_DST_PORT || '-'}</td>
                <td style="padding:8px; font-weight:700; color:${votesColor};">${confidence}</td>
                <td style="padding:8px;"><span class="badge ${resultClass}">${result}</span></td>
            </tr>`;
        }).join('');
        
        document.getElementById('consensusLogsBody').innerHTML = rows || 
            '<tr><td colspan="9" style="padding:20px; text-align:center; color:var(--text-muted);">No consensus logs available</td></tr>';
        
        updateConsensusPagination();
        updateConsensusSortIndicators();
        
    } catch(e) {
        console.error("Consensus Logs Error", e);
        document.getElementById('consensusLogsBody').innerHTML = 
            '<tr><td colspan="9" style="padding:20px; text-align:center; color:#ef4444;">Error loading logs</td></tr>';
    }
}

function updateConsensusPagination() {
    document.getElementById('consensusPageDisplay').textContent = `Page ${consensusCurrentPage} / ${consensusTotalPages}`;
    document.getElementById('consensusPrevBtn').disabled = (consensusCurrentPage <= 1);
    document.getElementById('consensusNextBtn').disabled = (consensusCurrentPage >= consensusTotalPages);
}

function consensusPrevPage() {
    if (consensusCurrentPage > 1) loadConsensusLogs(consensusCurrentPage - 1);
}

function consensusNextPage() {
    if (consensusCurrentPage < consensusTotalPages) loadConsensusLogs(consensusCurrentPage + 1);
}

function sortConsensusLogs(column) {
    if (consensusSortBy === column) {
        consensusSortOrder = consensusSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        consensusSortBy = column;
        consensusSortOrder = 'desc';
    }
    loadConsensusLogs(1);
}

function updateConsensusSortIndicators() {
    const columns = ['time', 'file', 'srcip', 'dstip', 'votes', 'result'];
    columns.forEach(col => {
        const el = document.getElementById(`consensusSort${col.charAt(0).toUpperCase() + col.slice(1)}`);
        if (el) {
            if (consensusSortBy === col) {
                el.textContent = consensusSortOrder === 'asc' ? '↑' : '↓';
            } else {
                el.textContent = '';
            }
        }
    });
}

function applyConsensusFilters() {
    loadConsensusLogs(1);
}

function clearConsensusFilters() {
    document.getElementById('consensusSearchInput').value = '';
    document.getElementById('consensusResultFilter').value = '';
    document.getElementById('consensusVotesFilter').value = '';
    loadConsensusLogs(1);
}

async function clearConsensusLogs() {
    if (!confirm('Are you sure you want to clear all consensus voting logs?')) return;
    
    try {
        const res = await fetch('/api/clear_consensus_logs', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            alert(`Cleared ${data.deleted} consensus log entries`);
            loadConsensusLogs(1);
        } else {
            alert('Error: ' + (data.message || 'Unknown error'));
        }
    } catch(e) {
        alert('Error clearing logs: ' + e.message);
    }
}

function showConsensusDetails(flowId) {
    fetch(`/api/consensus-details/${flowId}`)
        .then(r => r.json())
        .then(d => {
            if (d.error) {
                alert('Error: ' + d.error);
                return;
            }
            
            const panel = document.getElementById('panelContent');
            const titleElem = document.getElementById('detailPanelTitle');
            
            // Set title
            titleElem.innerHTML = '<i class="fas fa-vote-yea" style="color:var(--text-main); margin-right:8px;"></i> Consensus Voting Details';
            
            let isThreat = !(String(d.result).toLowerCase().includes('safe') || 
                             String(d.result).toLowerCase().includes('benign') || 
                             d.result == '0');
            
            // Calculate confidence percentage
            let confidencePercent = d.confidence ? (parseFloat(d.confidence) * 100).toFixed(1) : '-';
            
            // Determine vote status
            let votesPassed = parseInt(d.votes) >= parseInt(d.threshold);
            let votesClass = votesPassed ? 'forti-threat' : 'forti-safe';
            let votesBadge = votesPassed ? 'badge-danger' : 'badge-safe';
            
            panel.innerHTML = `
                <div class="forti-group">
                    <div class="forti-group-title">General</div>
                    <div class="forti-row"><span class="forti-label">Date/Time</span><span class="forti-val">${d.time_scaned || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">File Source</span><span class="forti-val">${d.file_scaned || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow ID</span><span class="forti-val">${d.id}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Network Info</div>
                    <div class="forti-row"><span class="forti-label">Source IP</span><span class="forti-val forti-ip">${d.IPV4_SRC_ADDR || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Source Port</span><span class="forti-val">${d.L4_SRC_PORT || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Dest IP</span><span class="forti-val forti-ip">${d.IPV4_DST_ADDR || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Dest Port</span><span class="forti-val">${d.L4_DST_PORT || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Protocol</span><span class="forti-val">${d.PROTOCOL || '-'}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Voting Results</div>
                    <div class="forti-row"><span class="forti-label">Detection Mode</span><span class="forti-val">${d.detection_mode || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Votes</span><span class="forti-val ${votesClass}" style="font-weight:600;">${d.votes || 0} / 6</span></div>
                    <div class="forti-row"><span class="forti-label">Threshold</span><span class="forti-val">${d.threshold || '-'}</span></div>
                    <div class="forti-row"><span class="forti-label">Confidence</span><span class="forti-val">${confidencePercent}%</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Final Decision</div>
                    <div class="forti-row"><span class="forti-label">Threat Level</span><span class="badge ${isThreat ? 'badge-danger' : 'badge-safe'}">${isThreat ? 'Critical' : 'Notice'}</span></div>
                    <div class="forti-row"><span class="forti-label">Result</span><span class="forti-val ${isThreat ? 'forti-threat' : 'forti-safe'}" style="font-weight:600;">${d.result || '-'}</span></div>
                </div>

                <div class="forti-group" style="margin-top:16px;">
                    <div class="forti-group-title">Voting Breakdown</div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; padding:8px;">
                        <div style="text-align:center; padding:10px; background:var(--hover-bg); border-radius:6px;">
                            <div style="font-size:12px; color:var(--text-secondary);">Attack Votes</div>
                            <div style="font-size:20px; font-weight:600; color:#ef4444;">${d.votes || 0}</div>
                        </div>
                        <div style="text-align:center; padding:10px; background:var(--hover-bg); border-radius:6px;">
                            <div style="font-size:12px; color:var(--text-secondary);">Benign Votes</div>
                            <div style="font-size:20px; font-weight:600; color:#10b981;">${6 - (parseInt(d.votes) || 0)}</div>
                        </div>
                    </div>
                    <div style="margin-top:10px; padding:8px; background:var(--hover-bg); border-radius:6px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                            <span style="font-size:11px; color:var(--text-secondary);">Vote Progress</span>
                            <span style="font-size:11px; color:var(--text-secondary);">${d.votes || 0}/6 (Threshold: ${d.threshold || '-'})</span>
                        </div>
                        <div style="background:var(--border-color); border-radius:4px; height:8px; overflow:hidden;">
                            <div style="width:${((parseInt(d.votes) || 0) / 6) * 100}%; height:100%; background:${isThreat ? '#ef4444' : '#10b981'}; transition:width 0.3s;"></div>
                        </div>
                    </div>
                </div>
            `;
            document.getElementById('panelOverlay').classList.add('active');
            document.getElementById('logDetailPanel').classList.add('active');
        })
        .catch(err => {
            console.error('Error fetching consensus details:', err);
            alert('Error loading details: ' + err.message);
        });
}

// --- INCOMING FILES MANAGEMENT ---

function togglePcapFilters() {
    const panel = document.getElementById('pcapFiltersPanel');
    const icon = document.getElementById('pcapFilterToggleIcon');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        icon.classList.remove('fa-chevron-down');
        icon.classList.add('fa-chevron-up');
    } else {
        panel.style.display = 'none';
        icon.classList.remove('fa-chevron-up');
        icon.classList.add('fa-chevron-down');
    }
}

function pcapResetFilters() {
    document.getElementById('pcapSearchInput').value = '';
    document.getElementById('pcapFilterName').value = '';
    document.getElementById('pcapFilterStatus').value = '';
    document.getElementById('pcapFilterThreat').value = '';
    document.getElementById('pcapSortBy').value = 'upload_date';
    pcapSortBy = 'upload_date';
    pcapSortOrder = 'desc';
    
    // Clear global filter state
    pcapFilterState = {
        search: '',
        filterName: '',
        filterStatus: '',
        filterThreat: ''
    };
    
    pcapApplyFilters();
}

function pcapSortChange(field) {
    if (pcapSortBy === field) {
        // Toggle sort order
        pcapSortOrder = pcapSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        pcapSortBy = field;
        pcapSortOrder = 'desc';
        document.getElementById('pcapSortBy').value = field;
    }
    pcapApplyFilters();
}

function pcapApplyFilters() {
    const search = document.getElementById('pcapSearchInput')?.value || '';
    const filterName = document.getElementById('pcapFilterName')?.value || '';
    const filterStatus = document.getElementById('pcapFilterStatus')?.value || '';
    const filterThreat = document.getElementById('pcapFilterThreat')?.value || '';
    pcapSortBy = document.getElementById('pcapSortBy')?.value || 'upload_date';
    
    // Save filter state to global variable
    pcapFilterState = {
        search: search,
        filterName: filterName,
        filterStatus: filterStatus,
        filterThreat: filterThreat
    };
    
    // Log for debugging
    console.log(`[PCAP Filter] Applying filters:`, pcapFilterState);
    
    loadIncomingFiles(search, filterName, filterStatus, filterThreat);
}

async function loadIncomingFiles(search = '', filterName = '', filterStatus = '', filterThreat = '') {
    try {
        // Use global filter state if no parameters provided
        if (!search && !filterName && !filterStatus && !filterThreat) {
            search = pcapFilterState.search || '';
            filterName = pcapFilterState.filterName || '';
            filterStatus = pcapFilterState.filterStatus || '';
            filterThreat = pcapFilterState.filterThreat || '';
            
            console.log(`[PCAP] Using saved filter state:`, pcapFilterState);
        }
        
        // Build query params
        const params = new URLSearchParams({
            search: search,
            filter_name: filterName,
            filter_status: filterStatus,
            filter_threat: filterThreat,
            sort_by: pcapSortBy,
            sort_order: pcapSortOrder,
            offset: 0,
            limit: pcapPageSize
        });
        
        const url = '/api/incoming-files?' + params.toString();
        console.log(`[PCAP] Fetching: ${url}`);
        
        const res = await fetch(url);
        if (!res.ok) {
            console.error('Failed to load incoming files:', res.status);
            return;
        }
        
        const data = await res.json();
        const tbody = document.getElementById('filesTableIncoming');
        
        if (!tbody) return; // Element doesn't exist if not on that view
        
        pcapTotalFiles = data.total || 0;
        
        // Update sort indicators
        document.getElementById('pcapSortName').textContent = pcapSortBy === 'name' ? (pcapSortOrder === 'asc' ? '↑' : '↓') : '';
        document.getElementById('pcapSortSize').textContent = pcapSortBy === 'size' ? (pcapSortOrder === 'asc' ? '↑' : '↓') : '';
        document.getElementById('pcapSortStatus').textContent = pcapSortBy === 'status' ? (pcapSortOrder === 'asc' ? '↑' : '↓') : '';
        document.getElementById('pcapSortDate').textContent = pcapSortBy === 'upload_date' ? (pcapSortOrder === 'asc' ? '↑' : '↓') : '';
        document.getElementById('pcapSortFlows').textContent = pcapSortBy === 'flows' ? (pcapSortOrder === 'asc' ? '↑' : '↓') : '';
        
        if (data.files && data.files.length > 0) {
            tbody.innerHTML = data.files.map(f => {
                let badge = 'badge-warn';
                if(f.status.includes('Threat')) badge = 'badge-danger';
                else if(f.status.includes('Safe')) badge = 'badge-safe';
                
                const uploadDate = f.upload_date || 'N/A';
                // Escape single quotes in filename for onclick handler
                const safeName = f.name.replace(/'/g, "\\'");
                
                return `<tr style="cursor:pointer; border-bottom:1px solid var(--border-color);" onclick="showFileDetails('${safeName}')">
                            <td style="padding:12px; font-weight:600; color:var(--text-main);">${f.name}</td>
                            <td style="padding:12px;">${f.size_mb} MB</td>
                            <td style="padding:12px;"><span class="badge ${badge}">${f.status}</span></td>
                            <td style="padding:12px; color:var(--text-muted);">${uploadDate}</td>
                            <td style="padding:12px; text-align:center;">${f.total_flows || 0}</td>
                            <td style="padding:12px;">
                                <button class="btn" style="padding:6px 12px; font-size:0.85em;" onclick="event.stopPropagation(); showFileDetails('${safeName}')">
                                    <i class="fas fa-eye"></i> View
                                </button>
                            </td>
                        </tr>`;
            }).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="padding:12px; text-align:center; color:var(--text-muted);">No files found</td></tr>';
        }
    } catch(e) {
        console.error('Load Files Error', e);
        // Don't show alert, just log it
    }
}

async function showFileDetails(filename) {
    try {
        console.log('Loading PCAP details for file:', filename);
        
        const res = await fetch(`/api/pcap-details/${encodeURIComponent(filename)}`);
        const data = await res.json();
        
        console.log('PCAP Details Response:', data);
        
        if (!res.ok || data.error) {
            alert('Error: ' + (data.error || 'File not found'));
            return;
        }
        
        const panel = document.getElementById('panelContent');
        const overlay = document.getElementById('panelOverlay');
        const logPanel = document.getElementById('logDetailPanel');
        const titleElem = document.getElementById('detailPanelTitle');
        
        if (!panel || !overlay || !logPanel) {
            console.error('Panel elements not found');
            alert('Error: Panel elements not initialized');
            return;
        }
        
        // Set title
        titleElem.innerHTML = '<i class="fas fa-file" style="color:var(--text-main); margin-right:8px;"></i> PCAP File Details';
        
        // Xác định status màu
        let statusColor = '#f59e0b'; // warning default
        if (data.status.includes('Threat')) statusColor = '#ef4444';
        else if (data.status.includes('Safe')) statusColor = '#10b981';
        
        // Build actions buttons - chỉ show download nếu có threat
        let actionsHTML = '';
        if (data.is_threat && data.pcap_exists) {
            actionsHTML = `
                <button class="btn" onclick="downloadFile('${data.name.replace(/'/g, "\\'")}')" style="flex:1;">
                    <i class="fas fa-download"></i> Download PCAP
                </button>
            `;
        } else if (data.is_threat && !data.pcap_exists) {
            actionsHTML = `<div style="padding:8px; background:#fef3c7; color:#d97706; border-radius:4px; text-align:center; font-size:0.9em;">PCAP file not available (deleted)</div>`;
        } else {
            actionsHTML = `<div style="padding:8px; background:#d1fae5; color:#059669; border-radius:4px; text-align:center; font-size:0.9em;">Safe PCAP (file deleted, metadata preserved)</div>`;
        }
        
        panel.innerHTML = `
            <div class="forti-group">
                <div class="forti-group-title">File Information</div>
                <div class="forti-row"><span class="forti-label">Filename</span><span class="forti-val">${data.name}</span></div>
                <div class="forti-row"><span class="forti-label">File Size</span><span class="forti-val">${data.size_mb} MB (${Math.round(data.size_bytes)} bytes)</span></div>
                <div class="forti-row"><span class="forti-label">Analysis Date</span><span class="forti-val">${data.upload_date}</span></div>
                <div class="forti-row"><span class="forti-label">PCAP ID</span><span class="forti-val">${data.pcap_id}</span></div>
                <div class="forti-row"><span class="forti-label">Status</span><span class="forti-val" style="color:${statusColor}; font-weight:600;">${data.status}</span></div>
            </div>
            
            <div class="forti-group">
                <div class="forti-group-title">Traffic Statistics</div>
                <div class="forti-row"><span class="forti-label">Total Flows</span><span class="forti-val">${data.total_flows || 0}</span></div>
                <div class="forti-row"><span class="forti-label">Threat Flows</span><span class="forti-val forti-threat">${data.threat_flows || 0}</span></div>
                <div class="forti-row"><span class="forti-label">Safe Flows</span><span class="forti-val forti-safe">${data.safe_flows || 0}</span></div>
            </div>
            
            <div class="forti-group">
                <div class="forti-group-title">Actions</div>
                <div style="display:flex; gap:8px; margin-top:12px;">
                    ${actionsHTML}
                </div>
            </div>
        `;
        
        // Hiển thị panel
        overlay.classList.add('active');
        logPanel.classList.add('active');
        
        console.log('PCAP file details displayed successfully');
    } catch(e) {
        console.error('PCAP Details Error', e);
        alert('Error loading file details: ' + e.message);
    }
}

async function downloadFile(filename) {
    try {
        window.location.href = `/api/download-file?file=${encodeURIComponent(filename)}`;
    } catch(e) {
        console.error('Download Error', e);
        alert('Error downloading file');
    }
}

async function deleteFile(filename) {
    if (!confirm(`Are you sure you want to delete "${filename}"?`)) return;
    
    try {
        const res = await fetch(`/api/delete-file?file=${encodeURIComponent(filename)}`, { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            alert('File deleted successfully');
            closeFileDetails();
            loadIncomingFiles();
        } else {
            alert('Error: ' + (data.message || 'Unknown error'));
        }
    } catch(e) {
        console.error('Delete Error', e);
        alert('Error deleting file');
    }
}

// Auto-refresh incoming files every 3 seconds when on that view
let filesRefreshInterval;
function startFilesAutoRefresh() {
    loadIncomingFiles();
    filesRefreshInterval = setInterval(() => {
        loadIncomingFiles();
    }, 2000); // Refresh every 2 seconds
}

function stopFilesAutoRefresh() {
    if (filesRefreshInterval) {
        clearInterval(filesRefreshInterval);
    }
}

// Auto-refresh flows every 5 seconds when on that view
let flowsRefreshInterval;
function startFlowsAutoRefresh() {
    flowsRefreshInterval = setInterval(() => {
        loadFlowsSummary();
    }, 5000); // Refresh every 5 seconds
}

function stopFlowsAutoRefresh() {
    if (flowsRefreshInterval) {
        clearInterval(flowsRefreshInterval);
    }
}

// Format bytes to human-readable format
function formatBytes(bytes) {
    if (!bytes || isNaN(bytes)) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(Math.max(1, bytes)) / Math.log(k));
    const value = (bytes / Math.pow(k, i)).toFixed(2);
    return value + ' ' + sizes[i];
}

// Load and display top 5 flows by traffic
async function loadTopFlows() {
    try {
        const model = selectedModel || 'Random Forest';
        const task = selectedTask || 'binary';
        const resp = await fetch(`/api/top-flows?model=${encodeURIComponent(model)}&task=${encodeURIComponent(task)}`);
        const data = await resp.json();
        
        const tbody = document.getElementById('topFlowsBody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (data.flows && data.flows.length > 0) {
            data.flows.forEach(flow => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td style="padding:8px;">${flow.IPV4_SRC_ADDR || '-'}</td>
                    <td style="padding:8px;">${flow.L4_SRC_PORT || '-'}</td>
                    <td style="padding:8px;">${flow.IPV4_DST_ADDR || '-'}</td>
                    <td style="padding:8px;">${flow.L4_DST_PORT || '-'}</td>
                    <td style="padding:8px;">${flow.PROTOCOL || '-'}</td>
                    <td style="padding:8px; font-weight:600; color:var(--text-main);">${formatBytes(flow.total_traffic)}</td>
                `;
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="padding:12px; text-align:center; color:var(--text-muted);">No flows data available</td></tr>';
        }
    } catch (e) {
        console.error('Load top flows error:', e);
    }
}
// --- IPS DATABASE FUNCTIONS ---
async function loadIPSRules() {
    try {
        console.log('Loading IPS rules...');
        
        const res = await fetch('/api/ips-rules');
        const data = await res.json();
        
        console.log('IPS Rules Response:', data);
        
        // Update statistics
        if (data.statistics) {
            document.getElementById('stat-total').textContent = data.statistics.total_rules || 0;
            document.getElementById('stat-critical').textContent = data.statistics.critical_rules || 0;
            document.getElementById('stat-high').textContent = data.statistics.high_rules || 0;
            document.getElementById('stat-medium').textContent = data.statistics.medium_rules || 0;
            document.getElementById('stat-low').textContent = data.statistics.low_rules || 0;
        }
        
        // Render rules table
        const tbody = document.getElementById('ipsRulesBody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (data.rules && data.rules.length > 0) {
            data.rules.forEach(rule => {
                const severityColor = {
                    'Critical': '#ef4444',
                    'High': '#f59e0b',
                    'Medium': '#3b82f6',
                    'Low': '#10b981'
                }[rule.severity] || '#6b7280';
                
                const row = document.createElement('tr');
                row.style.cursor = 'pointer';
                row.style.borderBottom = '1px solid var(--border-color)';
                row.onclick = () => showIPSRuleDetails(rule.rule_id);
                
                row.innerHTML = `
                    <td style="padding:12px; font-weight:600; color:var(--text-main);">${rule.rule_id}</td>
                    <td style="padding:12px;">${rule.rule_name}</td>
                    <td style="padding:12px;">${rule.category}</td>
                    <td style="padding:12px; text-align:center;"><span style="background:${severityColor}; color:white; padding:4px 8px; border-radius:4px; font-size:0.85em; font-weight:600;">${rule.severity}</span></td>
                    <td style="padding:12px; text-align:center;">${rule.source}</td>
                `;
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="padding:12px; text-align:center; color:var(--text-muted);">No IPS rules available</td></tr>';
        }
    } catch (e) {
        console.error('Load IPS rules error:', e);
    }
}

async function showIPSRuleDetails(ruleId) {
    try {
        console.log('Loading IPS rule details:', ruleId);
        
        const res = await fetch(`/api/ips-rules/${ruleId}`);
        const rule = await res.json();
        
        console.log('IPS Rule Details:', rule);
        
        if (!res.ok || rule.error) {
            alert('Error loading rule details');
            return;
        }
        
        const panel = document.getElementById('panelContent');
        const overlay = document.getElementById('panelOverlay');
        const logPanel = document.getElementById('logDetailPanel');
        const titleElem = document.getElementById('detailPanelTitle');
        
        if (!panel || !overlay || !logPanel) {
            console.error('Panel elements not found');
            return;
        }
        
        // Set title
        titleElem.innerHTML = '<i class="fas fa-shield" style="color:var(--text-main); margin-right:8px;"></i> IPS Rule Details';
        
        const severityColor = {
            'Critical': '#ef4444',
            'High': '#f59e0b',
            'Medium': '#3b82f6',
            'Low': '#10b981'
        }[rule.severity] || '#6b7280';
        
        panel.innerHTML = `
            <div class="forti-group">
                <div class="forti-group-title">Rule Information</div>
                <div class="forti-row"><span class="forti-label">Rule ID</span><span class="forti-val" style="font-family:monospace;">${rule.rule_id}</span></div>
                <div class="forti-row"><span class="forti-label">Rule Name</span><span class="forti-val">${rule.rule_name}</span></div>
                <div class="forti-row"><span class="forti-label">Source</span><span class="forti-val">${rule.source}</span></div>
                <div class="forti-row"><span class="forti-label">Version</span><span class="forti-val">${rule.version}</span></div>
                <div class="forti-row"><span class="forti-label">Last Updated</span><span class="forti-val">${rule.last_updated}</span></div>
            </div>
            
            <div class="forti-group">
                <div class="forti-group-title">Threat Classification</div>
                <div class="forti-row"><span class="forti-label">Severity</span><span style="background:${severityColor}; color:white; padding:4px 8px; border-radius:4px; font-size:0.85em; font-weight:600;">${rule.severity}</span></div>
                <div class="forti-row"><span class="forti-label">Category</span><span class="forti-val">${rule.category}</span></div>
                <div class="forti-row"><span class="forti-label">Description</span><span class="forti-val">${rule.description}</span></div>
            </div>
            
            <div class="forti-group">
                <div class="forti-group-title">Network Details</div>
                <div class="forti-row"><span class="forti-label">Protocol</span><span class="forti-val">${rule.protocol}</span></div>
                <div class="forti-row"><span class="forti-label">Port(s)</span><span class="forti-val">${rule.port}</span></div>
            </div>
            
            <div class="forti-group">
                <div class="forti-group-title">Rule Content</div>
                <div style="background:var(--bg-secondary); padding:12px; border-radius:6px; font-family:monospace; font-size:0.85em; overflow-x:auto; max-height:200px; overflow-y:auto;">
                    ${rule.rule_content}
                </div>
            </div>
            
            <div class="forti-group">
                <div class="forti-group-title">Statistics</div>
                <div class="forti-row"><span class="forti-label">False Positive Rate</span><span class="forti-val">${(rule.false_positive_rate * 100).toFixed(2)}%</span></div>
            </div>
            
            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color); display: flex; gap: 8px;">
                <button class="btn btn-danger" onclick="deleteIPSRule('${rule.rule_id}')" style="flex: 1; background: #ef4444; border: none; color: white;">
                    <i class="fas fa-trash"></i> Delete Rule
                </button>
            </div>
        `;
        
        // Show panel
        overlay.classList.add('active');
        logPanel.classList.add('active');
        
    } catch(e) {
        console.error('IPS Rule Details Error:', e);
        alert('Error loading rule details');
    }
}

// Import IPS Rules - File Upload
async function importIPSRulesFromFile() {
    const fileInput = document.getElementById('ips-import-file');
    if (!fileInput || !fileInput.files.length) {
        alert('Please select a file');
        return;
    }
    
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const res = await fetch('/api/ips-rules/import-file', {
            method: 'POST',
            body: formData
        });
        
        const data = await res.json();
        
        if (data.success) {
            alert(`Success! Imported ${data.imported_count} rules`);
            fileInput.value = '';
            document.getElementById('ips-import-file-label').textContent = 'Choose CSV file';
            loadIPSRules();
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (e) {
        alert(`Import error: ${e.message}`);
    }
}

// Import IPS Rules - URL
async function importIPSRulesFromURL() {
    const urlInput = document.getElementById('ips-import-url');
    const url = urlInput.value.trim();
    
    if (!url) {
        alert('Please enter a URL');
        return;
    }
    
    try {
        const res = await fetch('/api/ips-rules/import-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await res.json();
        
        if (data.success) {
            alert(`Success! ${data.message}`);
            urlInput.value = '';
            loadIPSRules();
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (e) {
        alert(`Import error: ${e.message}`);
    }
}

// Update file input label
document.addEventListener('change', function(e) {
    if (e.target.id === 'ips-import-file') {
        const label = document.getElementById('ips-import-file-label');
        if (label && e.target.files.length > 0) {
            label.textContent = e.target.files[0].name;
        }
    }
});

// Delete IPS Rule
async function deleteIPSRule(ruleId) {
    if (!confirm(`Delete rule ${ruleId}? This action cannot be undone.`)) {
        return;
    }
    
    try {
        const res = await fetch(`/api/ips-rules/${ruleId}`, {
            method: 'DELETE'
        });
        
        const data = await res.json();
        
        if (data.success) {
            alert('Rule deleted successfully');
            document.getElementById('panelOverlay').classList.remove('active');
            document.getElementById('logDetailPanel').classList.remove('active');
            loadIPSRules();
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (e) {
        alert(`Delete error: ${e.message}`);
    }
}

// Initialize IPS rules when switching to IPS database view
let ipsRulesInitialized = false;