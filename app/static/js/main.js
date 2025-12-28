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
    
    // Load system settings from server before initializing UI
    loadSystemSettingsBeforeUI();
    
    // Initialize IPS toggle
    initIPSToggle();
    
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
            document.getElementById('thresh-display').textContent = thresh;
            
            // Update IPS toggle
            const ipsToggle = document.getElementById('ipsToggle');
            const ipsStatus = document.getElementById('ipsStatus');
            if (ipsToggle) {
                const ipsEnabled = data.ips_enabled !== false; // Default to true
                ipsToggle.checked = ipsEnabled;
                if (ipsStatus) {
                    ipsStatus.textContent = ipsEnabled ? 'Enabled' : 'Disabled';
                    ipsStatus.style.color = ipsEnabled ? '#22c55e' : '#ef4444';
                }
            }
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

// Load system settings from server and apply to UI before initialization
async function loadSystemSettingsBeforeUI() {
    try {
        const res = await fetch('/api/user-info');
        const data = await res.json();
        
        if (data.config_mode) {
            const modeSelector = document.getElementById('modeSelector');
            if (modeSelector) {
                modeSelector.value = data.config_mode;
            }
        }
        
        if (data.config_threshold) {
            const threshSlider = document.getElementById('threshSlider');
            const threshDisplay = document.getElementById('thresh-display');
            if (threshSlider) {
                threshSlider.value = data.config_threshold;
            }
            if (threshDisplay) {
                threshDisplay.textContent = data.config_threshold;
            }
        }
        
        if (data.ips_enabled !== undefined) {
            const ipsToggle = document.getElementById('ipsToggle');
            if (ipsToggle) {
                ipsToggle.checked = data.ips_enabled;
            }
        }
        
        // Now initialize the UI with correct values
        initDetectionModeDropdown();
    } catch (e) {
        console.error('Error loading system settings:', e);
        // Fallback: initialize with default values
        initDetectionModeDropdown();
    }
}

// Load user login history for profile page
async function loadUserLoginHistory() {
    const tbody = document.getElementById('loginHistoryBody');
    if (!tbody) return;
    
    tbody.innerHTML = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: var(--text-muted);"><i class="fas fa-spinner fa-spin"></i> Loading...</td></tr>';
    
    try {
        // Tận dụng endpoint /system-logs/logins với param current_user=true
        const res = await fetch('/api/system-logs/logins?limit=50&current_user=true');
        const data = await res.json();
        
        if (data.status === 'success' && data.logs.length > 0) {
            tbody.innerHTML = data.logs.map(log => {
                const time = log.timestamp ? new Date(log.timestamp).toLocaleString() : '-';
                const action = log.action || '-';
                const ip = log.ip_address || '-';
                const status = log.status || 'unknown';
                
                // Status badge color
                let statusClass = 'badge-safe';
                let statusIcon = 'fa-check-circle';
                if (status === 'failed') {
                    statusClass = 'badge-danger';
                    statusIcon = 'fa-times-circle';
                } else if (status === 'logout') {
                    statusClass = 'badge-warn';
                    statusIcon = 'fa-sign-out-alt';
                }
                
                return `
                    <tr>
                        <td style="padding: 10px 12px; font-size: 0.85em; color: var(--text-muted);">${time}</td>
                        <td style="padding: 10px 12px; font-size: 0.85em;">
                            <i class="fas ${action === 'login' ? 'fa-sign-in-alt' : 'fa-sign-out-alt'}" style="margin-right: 6px; color: var(--text-main);"></i>
                            ${action.charAt(0).toUpperCase() + action.slice(1)}
                        </td>
                        <td style="padding: 10px 12px; font-size: 0.85em; font-family: monospace;">${ip}</td>
                        <td style="padding: 10px 12px;">
                            <span class="badge ${statusClass}">
                                <i class="fas ${statusIcon}" style="margin-right: 4px;"></i>${status}
                            </span>
                        </td>
                    </tr>
                `;
            }).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: var(--text-muted);"><i class="fas fa-info-circle"></i> No login history found</td></tr>';
        }
    } catch (e) {
        console.error('Load login history error:', e);
        tbody.innerHTML = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: #ef4444;"><i class="fas fa-exclamation-triangle"></i> Error loading history</td></tr>';
    }
}

async function saveSystemSettings() {
    const modeSelector = document.getElementById('modeSelector');
    const mode = modeSelector ? modeSelector.value : 'voting';
    const thresh = document.getElementById('threshSlider').value;
    const ipsToggle = document.getElementById('ipsToggle');
    const ipsEnabled = ipsToggle ? ipsToggle.checked : true;
    
    try {
        await fetch('/api/update-settings', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                detection_mode: mode,
                voting_threshold: thresh,
                ips_enabled: ipsEnabled
            })
        });
        alert("System config saved!");
    } catch(e) { alert("Error saving settings"); }
}

// IPS Toggle handler
function initIPSToggle() {
    const ipsToggle = document.getElementById('ipsToggle');
    const ipsStatus = document.getElementById('ipsStatus');
    
    if (!ipsToggle || !ipsStatus) return;
    
    ipsToggle.addEventListener('change', function() {
        if (this.checked) {
            ipsStatus.textContent = 'Enabled';
            ipsStatus.style.color = '#22c55e';
        } else {
            ipsStatus.textContent = 'Disabled';
            ipsStatus.style.color = '#ef4444';
        }
    });
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

function toggleSubmenu(submenuId) {
    const submenu = document.getElementById(submenuId);
    const arrow = document.getElementById(submenuId + '-arrow');
    if (submenu) {
        const isHidden = submenu.style.display === 'none';
        submenu.style.display = isHidden ? 'block' : 'none';
        if (arrow) {
            arrow.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
        }
    }
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
    else if(view==='ips-logs') document.getElementById('menu-ips-logs').classList.add('active');
    else if(view==='log-summary') document.getElementById('menu-log-summary').classList.add('active');
    
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
    else if (view === 'settings') {
        loadUserLoginHistory();  // Load login history when switching to settings
    }
    else if (view === 'ips-database') {
        loadIPSSources();
        loadIPSRules();
        startSourcesAutoRefresh();
    }
    else if (view === 'ips-logs') {
        loadIPSLogs();
    }
    else if (view === 'log-summary') {
        loadLogSummary();
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
            const detectionSource = f.detection_source || 'ML_ONLY';
            
            // Style based on result
            const resultClass = result === 'attack' ? 'badge-danger' : 'badge-safe';
            const votesColor = votes >= 4 ? '#ef4444' : (votes >= 2 ? '#f59e0b' : '#10b981');
            
            // Detection source badge style
            let sourceClass = 'badge-info';
            let sourceIcon = 'fa-robot';
            if (detectionSource.includes('IPS')) {
                sourceClass = 'badge-warning';
                sourceIcon = 'fa-shield-alt';
            }
            if (detectionSource === 'ML_HIGH_THREAT') {
                sourceClass = 'badge-danger';
                sourceIcon = 'fa-exclamation-triangle';
            }
            if (detectionSource === 'VERIFIED_BENIGN') {
                sourceClass = 'badge-safe';
                sourceIcon = 'fa-check-circle';
            }
            
            return `<tr style="cursor:pointer; border-bottom:1px solid var(--border-color);" onclick="showConsensusDetails('${f.id}')">
                <td style="padding:8px;">${num}</td>
                <td style="padding:8px;">${time}</td>
                <td style="padding:8px;">${f.file_scaned || '-'}</td>
                <td style="padding:8px; color:#3b82f6; font-weight:600;">${f.IPV4_SRC_ADDR || '-'}</td>
                <td style="padding:8px;">${f.L4_SRC_PORT || '-'}</td>
                <td style="padding:8px; color:#3b82f6; font-weight:600;">${f.IPV4_DST_ADDR || '-'}</td>
                <td style="padding:8px;">${f.L4_DST_PORT || '-'}</td>
                <td style="padding:8px; font-weight:700; color:${votesColor};">${confidence}</td>
                <td style="padding:8px;"><span class="badge ${sourceClass}" title="${detectionSource}"><i class="fas ${sourceIcon}" style="margin-right:4px;"></i>${formatDetectionSource(detectionSource)}</span></td>
                <td style="padding:8px;"><span class="badge ${resultClass}">${result}</span></td>
            </tr>`;
        }).join('');
        
        document.getElementById('consensusLogsBody').innerHTML = rows || 
            '<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--text-muted);">No consensus logs available</td></tr>';
        
        updateConsensusPagination();
        updateConsensusSortIndicators();
        
    } catch(e) {
        console.error("Consensus Logs Error", e);
        document.getElementById('consensusLogsBody').innerHTML = 
            '<tr><td colspan="10" style="padding:20px; text-align:center; color:#ef4444;">Error loading logs</td></tr>';
    }
}

function formatDetectionSource(source) {
    const sourceMap = {
        'ML_HIGH_THREAT': 'ML High',
        'ML_IPS_CONFIRMED': 'ML+IPS',
        'ML_UNCONFIRMED': 'ML Only',
        'ML_ONLY': 'ML',
        'IPS_FALSE_NEGATIVE': 'IPS',
        'VERIFIED_BENIGN': 'Verified',
        'ML_BENIGN': 'ML Safe',
        'DNN_ONLY': 'DNN',
        'NO_MODEL': 'None'
    };
    return sourceMap[source] || source || 'Unknown';
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
    const columns = ['time', 'file', 'srcip', 'dstip', 'votes', 'source', 'result'];
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
            
            // Detection source info
            let detectionSource = d.detection_source || 'ML_ONLY';
            let sourceDescription = getDetectionSourceDescription(detectionSource);
            let sourceIcon = getDetectionSourceIcon(detectionSource);
            let sourceClass = getDetectionSourceClass(detectionSource);
            
            // IPS info
            let ipsMatched = d.ips_matched === true || d.ips_matched === 'True';
            let ipsRuleId = d.ips_rule_id || '-';
            let ipsRuleName = d.ips_rule_name || '-';
            
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
                    <div class="forti-group-title"><i class="fas fa-shield-alt" style="margin-right:6px;"></i>Hybrid Detection</div>
                    <div class="forti-row"><span class="forti-label">Detection Source</span><span class="badge ${sourceClass}"><i class="fas ${sourceIcon}" style="margin-right:4px;"></i>${formatDetectionSource(detectionSource)}</span></div>
                    <div class="forti-row"><span class="forti-label">Description</span><span class="forti-val" style="font-size:12px;">${sourceDescription}</span></div>
                    <div class="forti-row"><span class="forti-label">IPS Matched</span><span class="forti-val ${ipsMatched ? 'forti-threat' : 'forti-safe'}">${ipsMatched ? 'YES' : 'NO'}</span></div>
                    ${ipsMatched ? `
                    <div class="forti-row"><span class="forti-label">IPS Rule ID</span><span class="forti-val">${ipsRuleId}</span></div>
                    <div class="forti-row"><span class="forti-label">IPS Rule Name</span><span class="forti-val" style="font-size:11px;">${ipsRuleName}</span></div>
                    ` : ''}
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

function getDetectionSourceDescription(source) {
    const descriptions = {
        'ML_HIGH_THREAT': 'High confidence ML detection (≥5/6 votes) - IPS check skipped',
        'ML_IPS_CONFIRMED': 'ML detected + IPS signature match - Confirmed threat',
        'ML_UNCONFIRMED': 'ML detected but IPS did not confirm - Still marked as threat',
        'ML_ONLY': 'Pure ML detection without IPS verification',
        'IPS_FALSE_NEGATIVE': 'ML missed but IPS caught! - False negative corrected',
        'VERIFIED_BENIGN': 'Both ML and IPS agree - Verified safe traffic',
        'ML_BENIGN': 'ML marked as benign without IPS check',
        'DNN_ONLY': 'Deep Neural Network single-model detection (fast mode)',
        'NO_MODEL': 'No ML model available'
    };
    return descriptions[source] || 'Unknown detection source';
}

function getDetectionSourceIcon(source) {
    const icons = {
        'ML_HIGH_THREAT': 'fa-exclamation-triangle',
        'ML_IPS_CONFIRMED': 'fa-shield-alt',
        'ML_UNCONFIRMED': 'fa-robot',
        'ML_ONLY': 'fa-robot',
        'IPS_FALSE_NEGATIVE': 'fa-shield-alt',
        'VERIFIED_BENIGN': 'fa-check-circle',
        'ML_BENIGN': 'fa-robot',
        'DNN_ONLY': 'fa-brain',
        'NO_MODEL': 'fa-question-circle'
    };
    return icons[source] || 'fa-question-circle';
}

function getDetectionSourceClass(source) {
    const classes = {
        'ML_HIGH_THREAT': 'badge-danger',
        'ML_IPS_CONFIRMED': 'badge-warning',
        'ML_UNCONFIRMED': 'badge-info',
        'ML_ONLY': 'badge-info',
        'IPS_FALSE_NEGATIVE': 'badge-warning',
        'VERIFIED_BENIGN': 'badge-safe',
        'ML_BENIGN': 'badge-safe',
        'DNN_ONLY': 'badge-info',
        'NO_MODEL': 'badge-secondary'
    };
    return classes[source] || 'badge-secondary';
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
                <button class="btn" onclick="openDeleteEvidenceModal('${data.name.replace(/'/g, "\\'")}')" style="flex:1; background:#ef4444;">
                    <i class="fas fa-trash"></i> Delete Evidence
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

// Evidence PCAP deletion with password verification
let evidenceToDelete = null;

function openDeleteEvidenceModal(filename) {
    evidenceToDelete = filename;
    document.getElementById('deleteEvidenceFilename').textContent = filename;
    document.getElementById('deleteEvidencePassword').value = '';
    document.getElementById('deleteEvidenceModal').style.display = 'flex';
    document.getElementById('deleteEvidencePassword').focus();
}

function closeDeleteEvidenceModal() {
    evidenceToDelete = null;
    document.getElementById('deleteEvidenceModal').style.display = 'none';
    document.getElementById('deleteEvidencePassword').value = '';
}

async function executeDeleteEvidence() {
    if (!evidenceToDelete) {
        alert('No file selected for deletion');
        return;
    }
    
    const password = document.getElementById('deleteEvidencePassword').value;
    
    if (!password) {
        alert('Password is required to delete evidence files');
        return;
    }
    
    try {
        const res = await fetch('/api/delete-evidence-pcap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: evidenceToDelete,
                password: password
            })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(data.message);
            closeDeleteEvidenceModal();
            closeDetails();
            loadIncomingFiles();
        } else {
            alert('Error: ' + (data.message || 'Failed to delete evidence'));
        }
    } catch (e) {
        console.error('Delete Evidence Error', e);
        alert('Error: ' + e.message);
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

// --- IPS SOURCES MANAGEMENT ---
let sourcesRefreshInterval = null;

async function loadIPSSources() {
    try {
        const res = await fetch('/api/ips-sources');
        const data = await res.json();
        
        const tbody = document.getElementById('ips-sources-body');
        if (!tbody) return;
        
        if (data.sources && data.sources.length > 0) {
            tbody.innerHTML = data.sources.map(source => {
                // Status icon
                let statusIcon = '';
                let statusColor = '';
                if (source.last_status === 'success') {
                    statusIcon = '<i class="fas fa-check-circle"></i>';
                    statusColor = '#10b981';
                } else if (source.last_status === 'error') {
                    statusIcon = '<i class="fas fa-times-circle"></i>';
                    statusColor = '#ef4444';
                } else if (source.last_status === 'pending') {
                    statusIcon = '<i class="fas fa-clock"></i>';
                    statusColor = '#f59e0b';
                } else {
                    statusIcon = '<i class="fas fa-question-circle"></i>';
                    statusColor = '#6b7280';
                }
                
                // Truncate URL for display
                const displayUrl = source.url.length > 50 ? source.url.substring(0, 50) + '...' : source.url;
                
                // Format last update
                const lastUpdate = source.last_update ? new Date(source.last_update).toLocaleString() : 'Never';
                
                // Enabled toggle
                const enabledChecked = source.enabled ? 'checked' : '';
                
                // Error tooltip
                const errorTitle = source.error_message ? `title="${source.error_message}"` : '';
                
                return `<tr style="border-bottom: 1px solid var(--border-color); cursor: pointer;" onclick="showSourceDetails('${source.id}')">
                    <td style="padding: 10px; text-align: center;">
                        <span style="color: ${statusColor}; font-size: 1.2em;" ${errorTitle}>${statusIcon}</span>
                    </td>
                    <td style="padding: 10px; font-weight: 600; color: var(--text-main);">${source.name || 'Unnamed'}</td>
                    <td style="padding: 10px; font-size: 0.85em; color: var(--text-muted);" title="${source.url}">${displayUrl}</td>
                    <td style="padding: 10px; text-align: center;" onclick="event.stopPropagation();">
                        <input type="number" value="${source.interval_minutes}" min="1" max="1440" 
                               style="width: 70px; padding: 4px; border: 1px solid var(--border-color); border-radius: 4px; text-align: center;"
                               onchange="updateSourceInterval('${source.id}', this.value)">
                        <span style="font-size: 0.8em; color: var(--text-muted);">min</span>
                    </td>
                    <td style="padding: 10px; text-align: center; font-weight: 600; color: var(--text-main);">${source.rules_count || 0}</td>
                    <td style="padding: 10px; font-size: 0.85em; color: var(--text-muted);">${lastUpdate}</td>
                    <td style="padding: 10px; text-align: center;" onclick="event.stopPropagation();">
                        <label class="toggle-switch" style="margin: 0;">
                            <input type="checkbox" ${enabledChecked} onchange="toggleSourceEnabled('${source.id}', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </td>
                    <td style="padding: 10px; text-align: center;" onclick="event.stopPropagation();">
                        <button class="btn" style="padding: 4px 8px; font-size: 0.8em; margin-right: 4px;" onclick="refreshSource('${source.id}')" title="Refresh Now">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                        <button class="btn" style="padding: 4px 8px; font-size: 0.8em; background: #ef4444; border-color: #ef4444;" onclick="deleteSource('${source.id}')" title="Delete">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="8" style="padding: 20px; text-align: center; color: var(--text-muted);">No rule sources configured. Add a source above to enable auto-updates.</td></tr>';
        }
    } catch (e) {
        console.error('Load IPS sources error:', e);
    }
}

async function showSourceDetails(sourceId) {
    try {
        const res = await fetch(`/api/ips-sources/${sourceId}`);
        const source = await res.json();
        
        if (!res.ok || source.error) {
            alert('Error loading source details');
            return;
        }
        
        const panel = document.getElementById('panelContent');
        const titleElem = document.getElementById('detailPanelTitle');
        
        titleElem.innerHTML = '<i class="fas fa-satellite-dish" style="color:var(--text-main); margin-right:8px;"></i> Edit Rule Source';
        
        // Status info
        let statusIcon = '';
        let statusColor = '';
        let statusText = '';
        if (source.last_status === 'success') {
            statusIcon = '<i class="fas fa-check-circle"></i>';
            statusColor = '#10b981';
            statusText = 'Success';
        } else if (source.last_status === 'error') {
            statusIcon = '<i class="fas fa-times-circle"></i>';
            statusColor = '#ef4444';
            statusText = 'Error';
        } else if (source.last_status === 'pending') {
            statusIcon = '<i class="fas fa-clock"></i>';
            statusColor = '#f59e0b';
            statusText = 'Pending';
        } else {
            statusIcon = '<i class="fas fa-question-circle"></i>';
            statusColor = '#6b7280';
            statusText = 'Unknown';
        }
        
        const lastUpdate = source.last_update ? new Date(source.last_update).toLocaleString() : 'Never';
        const createdAt = source.created_at ? new Date(source.created_at).toLocaleString() : 'Unknown';
        
        panel.innerHTML = `
            <div class="forti-group">
                <div class="forti-group-title">Source Information</div>
                <div class="forti-row">
                    <span class="forti-label">Source ID</span>
                    <span class="forti-val" style="font-family: monospace;">${source.id}</span>
                </div>
                <div class="forti-row">
                    <span class="forti-label">Created</span>
                    <span class="forti-val">${createdAt}</span>
                </div>
                <div class="forti-row">
                    <span class="forti-label">Status</span>
                    <span class="forti-val" style="color: ${statusColor};">${statusIcon} ${statusText}</span>
                </div>
                <div class="forti-row">
                    <span class="forti-label">Last Update</span>
                    <span class="forti-val">${lastUpdate}</span>
                </div>
                <div class="forti-row">
                    <span class="forti-label">Rules Count</span>
                    <span class="forti-val" style="font-weight: 600;">${source.rules_count || 0}</span>
                </div>
                ${source.error_message ? `
                <div class="forti-row">
                    <span class="forti-label">Last Error</span>
                    <span class="forti-val" style="color: #ef4444; font-size: 0.85em;">${source.error_message}</span>
                </div>` : ''}
            </div>

            <div class="forti-group">
                <div class="forti-group-title">Edit Settings</div>
                <div style="padding: 8px 0;">
                    <label style="font-size: 0.85em; color: var(--text-muted); display: block; margin-bottom: 4px;">Name</label>
                    <input type="text" id="edit-source-name" value="${source.name || ''}" 
                           style="width: 100%; padding: 8px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-main);">
                </div>
                <div style="padding: 8px 0;">
                    <label style="font-size: 0.85em; color: var(--text-muted); display: block; margin-bottom: 4px;">URL</label>
                    <input type="text" id="edit-source-url" value="${source.url || ''}" 
                           style="width: 100%; padding: 8px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-main); font-size: 0.85em;">
                </div>
                <div style="padding: 8px 0;">
                    <label style="font-size: 0.85em; color: var(--text-muted); display: block; margin-bottom: 4px;">Update Interval (minutes)</label>
                    <input type="number" id="edit-source-interval" value="${source.interval_minutes || 10}" min="1" max="1440"
                           style="width: 120px; padding: 8px; border: 1px solid var(--border-color); border-radius: 4px; background: var(--bg-secondary); color: var(--text-main);">
                </div>
                <div style="padding: 8px 0; display: flex; align-items: center; gap: 10px;">
                    <label style="font-size: 0.85em; color: var(--text-muted);">Enabled</label>
                    <label class="toggle-switch" style="margin: 0;">
                        <input type="checkbox" id="edit-source-enabled" ${source.enabled ? 'checked' : ''}>
                        <span class="slider"></span>
                    </label>
                </div>
            </div>

            <div style="display: flex; gap: 10px; margin-top: 16px;">
                <button class="btn" onclick="saveSourceChanges('${source.id}')" style="flex: 1; padding: 10px;">
                    <i class="fas fa-save"></i> Save Changes
                </button>
                <button class="btn" onclick="refreshSource('${source.id}'); closeDetails();" style="padding: 10px;">
                    <i class="fas fa-sync-alt"></i> Refresh Now
                </button>
            </div>
        `;
        
        document.getElementById('panelOverlay').classList.add('active');
        document.getElementById('logDetailPanel').classList.add('active');
    } catch (e) {
        console.error('Show source details error:', e);
        alert('Error loading source details');
    }
}

async function saveSourceChanges(sourceId) {
    try {
        const name = document.getElementById('edit-source-name').value.trim();
        const url = document.getElementById('edit-source-url').value.trim();
        const interval = parseInt(document.getElementById('edit-source-interval').value) || 10;
        const enabled = document.getElementById('edit-source-enabled').checked;
        
        if (!url) {
            alert('URL cannot be empty');
            return;
        }
        
        const res = await fetch(`/api/ips-sources/${sourceId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                url: url,
                interval_minutes: interval,
                enabled: enabled
            })
        });
        
        const result = await res.json();
        
        if (result.success) {
            alert('Source updated successfully');
            closeDetails();
            loadIPSSources();
        } else {
            alert('Error: ' + result.message);
        }
    } catch (e) {
        console.error('Save source changes error:', e);
        alert('Error saving changes');
    }
}

async function addNewSource() {
    const name = document.getElementById('new-source-name').value.trim();
    const url = document.getElementById('new-source-url').value.trim();
    const interval = parseInt(document.getElementById('new-source-interval').value) || 10;
    const autoRefresh = document.getElementById('new-source-auto-refresh').value === 'true';
    
    if (!url) {
        alert('Please enter a source URL');
        return;
    }
    
    try {
        const res = await fetch('/api/ips-sources', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name || 'Unnamed Source',
                url: url,
                interval_minutes: interval,
                auto_refresh: autoRefresh
            })
        });
        
        const result = await res.json();
        
        if (result.success) {
            alert(result.refresh_result ? 
                `Source added. Imported ${result.refresh_result.imported_count || 0} rules.` : 
                'Source added successfully.');
            
            // Clear form
            document.getElementById('new-source-name').value = '';
            document.getElementById('new-source-url').value = '';
            document.getElementById('new-source-interval').value = '10';
            
            // Reload sources and rules
            loadIPSSources();
            loadIPSRules();
        } else {
            alert('Error: ' + result.message);
        }
    } catch (e) {
        console.error('Add source error:', e);
        alert('Error adding source');
    }
}

async function updateSourceInterval(sourceId, newInterval) {
    try {
        const res = await fetch(`/api/ips-sources/${sourceId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interval_minutes: parseInt(newInterval) })
        });
        
        const result = await res.json();
        if (!result.success) {
            alert('Error updating interval: ' + result.message);
            loadIPSSources(); // Reload to reset
        }
    } catch (e) {
        console.error('Update interval error:', e);
    }
}

async function toggleSourceEnabled(sourceId, enabled) {
    try {
        const res = await fetch(`/api/ips-sources/${sourceId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        
        const result = await res.json();
        if (!result.success) {
            alert('Error toggling source: ' + result.message);
            loadIPSSources();
        }
    } catch (e) {
        console.error('Toggle source error:', e);
    }
}

async function refreshSource(sourceId) {
    try {
        // Show loading indicator
        const btn = event.target.closest('button');
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        btn.disabled = true;
        
        const res = await fetch(`/api/ips-sources/${sourceId}/refresh`, {
            method: 'POST'
        });
        
        const result = await res.json();
        
        btn.innerHTML = originalHtml;
        btn.disabled = false;
        
        if (result.success) {
            alert(`Refreshed successfully. Imported ${result.imported_count || 0} rules.`);
            loadIPSSources();
            loadIPSRules();
        } else {
            alert('Error refreshing: ' + result.message);
            loadIPSSources();
        }
    } catch (e) {
        console.error('Refresh source error:', e);
        alert('Error refreshing source');
    }
}

async function deleteSource(sourceId) {
    if (!confirm('Delete this source? Rules imported from this source will remain.')) {
        return;
    }
    
    try {
        const res = await fetch(`/api/ips-sources/${sourceId}`, {
            method: 'DELETE'
        });
        
        const result = await res.json();
        
        if (result.success) {
            loadIPSSources();
        } else {
            alert('Error deleting source: ' + result.message);
        }
    } catch (e) {
        console.error('Delete source error:', e);
    }
}

async function refreshAllSources() {
    try {
        const btn = event.target.closest('button');
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
        btn.disabled = true;
        
        const res = await fetch('/api/ips-sources/refresh-all', {
            method: 'POST'
        });
        
        const result = await res.json();
        
        btn.innerHTML = originalHtml;
        btn.disabled = false;
        
        alert(`Updated ${result.updated || 0} sources. Errors: ${result.errors || 0}`);
        loadIPSSources();
        loadIPSRules();
    } catch (e) {
        console.error('Refresh all sources error:', e);
    }
}

// Start background refresh check for sources
function startSourcesAutoRefresh() {
    if (sourcesRefreshInterval) {
        clearInterval(sourcesRefreshInterval);
    }
    
    // Check every 60 seconds for sources that need update
    sourcesRefreshInterval = setInterval(async () => {
        try {
            const res = await fetch('/api/ips-sources');
            const data = await res.json();
            
            if (data.sources) {
                for (const source of data.sources) {
                    if (source.enabled && source.needs_update) {
                        console.log(`[Auto-refresh] Refreshing source: ${source.name}`);
                        await fetch(`/api/ips-sources/${source.id}/refresh`, { method: 'POST' });
                    }
                }
                
                // Reload UI if on IPS Database view
                if (document.getElementById('view-ips-db')?.classList.contains('active')) {
                    loadIPSSources();
                    loadIPSRules();
                }
            }
        } catch (e) {
            console.error('Auto-refresh check error:', e);
        }
    }, 60000); // Check every minute
}

// --- IPS DATABASE FUNCTIONS ---

// IPS Rules Pagination State
let ipsCurrentPage = 1;
let ipsPageSize = 50;
let ipsTotalRules = 0;
let ipsTotalPages = 1;
let ipsSearchTerm = '';
let ipsSeverityFilter = '';
let ipsSortBy = 'rule_id';
let ipsSortOrder = 'asc';
let ipsSearchTimeout = null;

function debounceIPSSearch() {
    clearTimeout(ipsSearchTimeout);
    ipsSearchTimeout = setTimeout(() => {
        applyIPSFilters();
    }, 300);
}

function applyIPSFilters() {
    ipsSearchTerm = document.getElementById('ipsRulesSearch')?.value || '';
    ipsSeverityFilter = document.getElementById('ipsSeverityFilter')?.value || '';
    ipsCurrentPage = 1;
    loadIPSRules();
}

function clearIPSFilters() {
    document.getElementById('ipsRulesSearch').value = '';
    document.getElementById('ipsSeverityFilter').value = '';
    const headerSearch = document.getElementById('ipsSearchBox');
    if (headerSearch) headerSearch.value = '';
    ipsSearchTerm = '';
    ipsSeverityFilter = '';
    ipsCurrentPage = 1;
    loadIPSRules();
}

function syncIPSSearch(inputEl) {
    // Sync header search box with widget search box
    const widgetSearch = document.getElementById('ipsRulesSearch');
    if (widgetSearch && inputEl.id === 'ipsSearchBox') {
        widgetSearch.value = inputEl.value;
    } else if (inputEl.id === 'ipsRulesSearch') {
        const headerSearch = document.getElementById('ipsSearchBox');
        if (headerSearch) headerSearch.value = inputEl.value;
    }
    debounceIPSSearch();
}

function sortIPSRules(column) {
    if (ipsSortBy === column) {
        ipsSortOrder = ipsSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        ipsSortBy = column;
        ipsSortOrder = 'asc';
    }
    loadIPSRules();
}

function updateIPSSortIndicators() {
    const columns = ['rule_id', 'rule_name', 'category', 'severity'];
    columns.forEach(col => {
        const elId = 'ipsSort' + col.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
        const el = document.getElementById(elId);
        if (el) {
            if (ipsSortBy === col) {
                el.textContent = ipsSortOrder === 'asc' ? '↑' : '↓';
            } else {
                el.textContent = '';
            }
        }
    });
}

async function loadIPSRules(page = ipsCurrentPage) {
    try {
        console.log('Loading IPS rules...');
        
        const offset = (page - 1) * ipsPageSize;
        let url = `/api/ips-rules?offset=${offset}&limit=${ipsPageSize}`;
        
        if (ipsSearchTerm) url += `&search=${encodeURIComponent(ipsSearchTerm)}`;
        if (ipsSeverityFilter) url += `&severity=${encodeURIComponent(ipsSeverityFilter)}`;
        
        const res = await fetch(url);
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
        
        // Update pagination state
        ipsTotalRules = data.total_rules || 0;
        ipsTotalPages = Math.max(1, Math.ceil(ipsTotalRules / ipsPageSize));
        ipsCurrentPage = page;
        
        // Sort rules client-side
        let rules = data.rules || [];
        if (rules.length > 0) {
            rules.sort((a, b) => {
                let valA = a[ipsSortBy] || '';
                let valB = b[ipsSortBy] || '';
                
                // Numeric sort for rule_id if it looks like a number
                if (ipsSortBy === 'rule_id') {
                    valA = parseInt(valA) || 0;
                    valB = parseInt(valB) || 0;
                }
                
                if (ipsSortOrder === 'asc') {
                    return valA > valB ? 1 : -1;
                } else {
                    return valA < valB ? 1 : -1;
                }
            });
        }
        
        // Render rules table
        const tbody = document.getElementById('ipsRulesBody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (rules.length > 0) {
            rules.forEach(rule => {
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
        
        // Update pagination UI
        updateIPSPagination();
        updateIPSSortIndicators();
        
    } catch (e) {
        console.error('Load IPS rules error:', e);
    }
}

function updateIPSPagination() {
    const startNum = ipsTotalRules > 0 ? (ipsCurrentPage - 1) * ipsPageSize + 1 : 0;
    const endNum = Math.min(ipsCurrentPage * ipsPageSize, ipsTotalRules);
    
    document.getElementById('ipsRulesInfo').textContent = `Showing ${startNum}-${endNum} of ${ipsTotalRules} rules`;
    document.getElementById('ipsTotalPagesDisplay').textContent = ipsTotalPages;
    document.getElementById('ipsPageInput').value = ipsCurrentPage;
    document.getElementById('ipsPageInput').max = ipsTotalPages;
    document.getElementById('ipsPrevBtn').disabled = (ipsCurrentPage <= 1);
    document.getElementById('ipsNextBtn').disabled = (ipsCurrentPage >= ipsTotalPages);
}

function ipsGoToPage() {
    const input = document.getElementById('ipsPageInput');
    let page = parseInt(input.value) || 1;
    
    // Clamp to valid range
    page = Math.max(1, Math.min(page, ipsTotalPages));
    
    if (page !== ipsCurrentPage) {
        loadIPSRules(page);
    } else {
        input.value = ipsCurrentPage; // Reset if same page
    }
}

function ipsPrevPage() {
    if (ipsCurrentPage > 1) {
        loadIPSRules(ipsCurrentPage - 1);
    }
}

function ipsNextPage() {
    if (ipsCurrentPage < ipsTotalPages) {
        loadIPSRules(ipsCurrentPage + 1);
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

// --- JA3/TLS FINGERPRINT RULE FUNCTIONS ---

function toggleAddJA3Form() {
    const form = document.getElementById('add-ja3-form');
    if (form) {
        form.style.display = form.style.display === 'none' ? 'block' : 'none';
    }
}

async function addJA3Rule() {
    const ruleName = document.getElementById('ja3-rule-name')?.value.trim();
    const category = document.getElementById('ja3-rule-category')?.value || 'C2/Malware';
    const ja3 = document.getElementById('ja3-rule-ja3')?.value.trim().toLowerCase();
    const ja3s = document.getElementById('ja3-rule-ja3s')?.value.trim().toLowerCase();
    const sni = document.getElementById('ja3-rule-sni')?.value.trim().toLowerCase();
    const severity = document.getElementById('ja3-rule-severity')?.value || 'High';
    const description = document.getElementById('ja3-rule-description')?.value.trim();
    
    // Validation
    if (!ruleName) {
        alert('Rule Name is required');
        return;
    }
    
    if (!ja3 && !ja3s && !sni) {
        alert('At least one of JA3, JA3S, or SNI must be provided');
        return;
    }
    
    // Validate JA3/JA3S format (32 char MD5 hex)
    const md5Regex = /^[a-f0-9]{32}$/;
    if (ja3 && !md5Regex.test(ja3)) {
        alert('JA3 fingerprint must be a 32-character MD5 hash (hex)');
        return;
    }
    if (ja3s && !md5Regex.test(ja3s)) {
        alert('JA3S fingerprint must be a 32-character MD5 hash (hex)');
        return;
    }
    
    try {
        const res = await fetch('/api/ips-rules/add-ja3', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_name: ruleName,
                category: category,
                ja3: ja3,
                ja3s: ja3s,
                sni: sni,
                severity: severity,
                description: description
            })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert('JA3 Rule added successfully!');
            
            // Clear form
            document.getElementById('ja3-rule-name').value = '';
            document.getElementById('ja3-rule-ja3').value = '';
            document.getElementById('ja3-rule-ja3s').value = '';
            document.getElementById('ja3-rule-sni').value = '';
            document.getElementById('ja3-rule-description').value = '';
            
            // Hide form and refresh
            toggleAddJA3Form();
            loadIPSRules();
        } else {
            alert('Error: ' + (data.message || 'Failed to add rule'));
        }
    } catch (e) {
        console.error('Add JA3 rule error:', e);
        alert('Error adding rule: ' + e.message);
    }
}

// --- IPS LOGS FUNCTIONS ---

// IPS Logs Pagination State
let ipsLogsCurrentPage = 1;
let ipsLogsPageSize = 50;
let ipsLogsTotalLogs = 0;
let ipsLogsTotalPages = 1;
let ipsLogsSearchTerm = '';
let ipsLogsSeverityFilter = '';
let ipsLogsSortBy = 'time';
let ipsLogsSortOrder = 'desc';
let ipsLogsSearchTimeout = null;

function debounceIPSLogsSearch() {
    clearTimeout(ipsLogsSearchTimeout);
    ipsLogsSearchTimeout = setTimeout(() => {
        applyIPSLogsFilters();
    }, 300);
}

function applyIPSLogsFilters() {
    ipsLogsSearchTerm = document.getElementById('ipsLogsSearch')?.value || '';
    ipsLogsSeverityFilter = document.getElementById('ipsLogsSeverityFilter')?.value || '';
    ipsLogsCurrentPage = 1;
    loadIPSLogs();
}

function clearIPSLogsFilters() {
    document.getElementById('ipsLogsSearch').value = '';
    document.getElementById('ipsLogsSeverityFilter').value = '';
    ipsLogsSearchTerm = '';
    ipsLogsSeverityFilter = '';
    ipsLogsCurrentPage = 1;
    loadIPSLogs();
}

function sortIPSLogs(column) {
    if (ipsLogsSortBy === column) {
        ipsLogsSortOrder = ipsLogsSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        ipsLogsSortBy = column;
        ipsLogsSortOrder = 'desc';
    }
    loadIPSLogs();
}

function updateIPSLogsSortIndicators() {
    const columns = ['time', 'src_ip', 'dst_ip', 'rule_name', 'severity'];
    columns.forEach(col => {
        const colName = col.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
        const el = document.getElementById(`ipsLogsSort${colName}`);
        if (el) {
            if (ipsLogsSortBy === col) {
                el.textContent = ipsLogsSortOrder === 'asc' ? '↑' : '↓';
            } else {
                el.textContent = '';
            }
        }
    });
}

async function loadIPSLogs(page = ipsLogsCurrentPage) {
    try {
        const offset = (page - 1) * ipsLogsPageSize;
        let url = `/api/ips-logs?offset=${offset}&limit=${ipsLogsPageSize}&sort_by=${ipsLogsSortBy}&sort_order=${ipsLogsSortOrder}`;
        
        if (ipsLogsSearchTerm) url += `&search=${encodeURIComponent(ipsLogsSearchTerm)}`;
        if (ipsLogsSeverityFilter) url += `&severity=${encodeURIComponent(ipsLogsSeverityFilter)}`;
        
        const res = await fetch(url);
        const data = await res.json();
        
        // Update statistics
        if (data.statistics) {
            document.getElementById('ips-stat-total').textContent = data.statistics.total || 0;
            document.getElementById('ips-stat-critical').textContent = data.statistics.critical || 0;
            document.getElementById('ips-stat-high').textContent = data.statistics.high || 0;
            document.getElementById('ips-stat-medium').textContent = data.statistics.medium_low || 0;
        }
        
        // Update pagination state
        ipsLogsTotalLogs = data.total || 0;
        ipsLogsTotalPages = Math.max(1, Math.ceil(ipsLogsTotalLogs / ipsLogsPageSize));
        ipsLogsCurrentPage = page;
        
        // Render logs table
        const tbody = document.getElementById('ipsLogsBody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        if (data.logs && data.logs.length > 0) {
            data.logs.forEach((log, idx) => {
                const num = offset + idx + 1;
                const severityColor = {
                    'Critical': '#ef4444',
                    'High': '#f59e0b',
                    'Medium': '#3b82f6',
                    'Low': '#10b981'
                }[log.severity] || '#6b7280';
                
                // Match type badge color
                const matchTypeColors = {
                    'JA3': '#8b5cf6',    // Purple for JA3
                    'JA3S': '#a855f7',   // Light purple for JA3S
                    'SNI': '#06b6d4',    // Cyan for SNI
                    'PORT': '#f59e0b',   // Orange for Port
                };
                const matchType = log.match_type || 'PORT';
                const matchColor = matchTypeColors[matchType] || '#6b7280';
                
                const row = document.createElement('tr');
                row.style.cursor = 'pointer';
                row.style.borderBottom = '1px solid var(--border-color)';
                row.onclick = () => showIPSLogDetails(log.id);
                
                row.innerHTML = `
                    <td style="padding:10px;">${num}</td>
                    <td style="padding:10px;">${log.timestamp || '-'}</td>
                    <td style="padding:10px;">${log.file_scaned || '-'}</td>
                    <td style="padding:10px; color:#3b82f6; font-weight:600;">${log.src_ip || '-'}</td>
                    <td style="padding:10px;">${log.src_port || '-'}</td>
                    <td style="padding:10px; color:#3b82f6; font-weight:600;">${log.dst_ip || '-'}</td>
                    <td style="padding:10px;">${log.dst_port || '-'}</td>
                    <td style="padding:10px; font-size:0.85em;">${log.rule_name || '-'}</td>
                    <td style="padding:10px; text-align:center;"><span style="background:${matchColor}; color:white; padding:4px 8px; border-radius:4px; font-size:0.75em; font-weight:600;">${matchType}</span></td>
                    <td style="padding:10px; text-align:center;"><span style="background:${severityColor}; color:white; padding:4px 8px; border-radius:4px; font-size:0.85em; font-weight:600;">${log.severity || '-'}</span></td>
                `;
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--text-muted);">No IPS detection logs available</td></tr>';
        }
        
        // Update pagination UI
        updateIPSLogsPagination();
        updateIPSLogsSortIndicators();
        
    } catch (e) {
        console.error('Load IPS logs error:', e);
    }
}

function updateIPSLogsPagination() {
    const startNum = ipsLogsTotalLogs > 0 ? (ipsLogsCurrentPage - 1) * ipsLogsPageSize + 1 : 0;
    const endNum = Math.min(ipsLogsCurrentPage * ipsLogsPageSize, ipsLogsTotalLogs);
    
    document.getElementById('ipsLogsInfo').textContent = `Showing ${startNum}-${endNum} of ${ipsLogsTotalLogs} logs`;
    document.getElementById('ipsLogsTotalPagesDisplay').textContent = ipsLogsTotalPages;
    document.getElementById('ipsLogsPageInput').value = ipsLogsCurrentPage;
    document.getElementById('ipsLogsPageInput').max = ipsLogsTotalPages;
    document.getElementById('ipsLogsPrevBtn').disabled = (ipsLogsCurrentPage <= 1);
    document.getElementById('ipsLogsNextBtn').disabled = (ipsLogsCurrentPage >= ipsLogsTotalPages);
}

function ipsLogsGoToPage() {
    const input = document.getElementById('ipsLogsPageInput');
    let page = parseInt(input.value) || 1;
    page = Math.max(1, Math.min(page, ipsLogsTotalPages));
    
    if (page !== ipsLogsCurrentPage) {
        loadIPSLogs(page);
    } else {
        input.value = ipsLogsCurrentPage;
    }
}

function ipsLogsPrevPage() {
    if (ipsLogsCurrentPage > 1) {
        loadIPSLogs(ipsLogsCurrentPage - 1);
    }
}

function ipsLogsNextPage() {
    if (ipsLogsCurrentPage < ipsLogsTotalPages) {
        loadIPSLogs(ipsLogsCurrentPage + 1);
    }
}

async function showIPSLogDetails(logId) {
    try {
        const res = await fetch(`/api/ips-logs/${logId}`);
        const log = await res.json();
        
        if (log.error) {
            alert('Error: ' + log.error);
            return;
        }
        
        const panel = document.getElementById('panelContent');
        const titleElem = document.getElementById('detailPanelTitle');
        
        titleElem.innerHTML = '<i class="fas fa-shield-alt" style="color:var(--text-main); margin-right:8px;"></i> IPS Detection Details';
        
        const severityColor = {
            'Critical': '#ef4444',
            'High': '#f59e0b',
            'Medium': '#3b82f6',
            'Low': '#10b981'
        }[log.severity] || '#6b7280';
        
        // Match type badge color
        const matchTypeColors = {
            'JA3': '#8b5cf6',
            'JA3S': '#a855f7',
            'SNI': '#06b6d4',
            'PORT': '#f59e0b',
        };
        const matchType = log.match_type || 'PORT';
        const matchColor = matchTypeColors[matchType] || '#6b7280';
        
        // Build TLS Fingerprint section if applicable
        let tlsSection = '';
        if (log.ja3_hash || log.ja3s_hash || log.sni) {
            tlsSection = `
            <div class="forti-group">
                <div class="forti-group-title"><i class="fas fa-fingerprint" style="margin-right:6px;"></i>TLS Fingerprint</div>
                ${log.ja3_hash ? `<div class="forti-row"><span class="forti-label">JA3 Client</span><span class="forti-val" style="font-family:monospace; font-size:0.85em;">${log.ja3_hash}</span></div>` : ''}
                ${log.ja3s_hash ? `<div class="forti-row"><span class="forti-label">JA3S Server</span><span class="forti-val" style="font-family:monospace; font-size:0.85em;">${log.ja3s_hash}</span></div>` : ''}
                ${log.sni ? `<div class="forti-row"><span class="forti-label">SNI</span><span class="forti-val" style="color:#06b6d4;">${log.sni}</span></div>` : ''}
            </div>
            `;
        }
        
        panel.innerHTML = `
            <div class="forti-group">
                <div class="forti-group-title">Detection Info</div>
                <div class="forti-row"><span class="forti-label">Timestamp</span><span class="forti-val">${log.timestamp || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">File Source</span><span class="forti-val">${log.file_scaned || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Log ID</span><span class="forti-val" style="font-size:0.85em;">${log.id || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Match Type</span><span style="background:${matchColor}; color:white; padding:4px 10px; border-radius:4px; font-weight:600; font-size:0.9em;">${matchType}</span></div>
            </div>

            <div class="forti-group">
                <div class="forti-group-title">Network Info</div>
                <div class="forti-row"><span class="forti-label">Source IP</span><span class="forti-val forti-ip">${log.src_ip || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Source Port</span><span class="forti-val">${log.src_port || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Dest IP</span><span class="forti-val forti-ip">${log.dst_ip || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Dest Port</span><span class="forti-val">${log.dst_port || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Protocol</span><span class="forti-val">${log.protocol || '-'}</span></div>
            </div>

            ${tlsSection}

            <div class="forti-group">
                <div class="forti-group-title">IPS Rule Matched</div>
                <div class="forti-row"><span class="forti-label">Rule ID</span><span class="forti-val" style="font-family:monospace;">${log.rule_id || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Rule Name</span><span class="forti-val" style="font-size:0.9em;">${log.rule_name || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Category</span><span class="forti-val">${log.category || '-'}</span></div>
                <div class="forti-row"><span class="forti-label">Severity</span><span style="background:${severityColor}; color:white; padding:4px 10px; border-radius:4px; font-weight:600;">${log.severity || '-'}</span></div>
            </div>

            <div class="forti-group">
                <div class="forti-group-title">Traffic Info</div>
                <div class="forti-row"><span class="forti-label">Bytes In</span><span class="forti-val">${formatBytes(log.in_bytes || 0)}</span></div>
                <div class="forti-row"><span class="forti-label">Bytes Out</span><span class="forti-val">${formatBytes(log.out_bytes || 0)}</span></div>
            </div>
        `;
        
        document.getElementById('panelOverlay').classList.add('active');
        document.getElementById('logDetailPanel').classList.add('active');
        
    } catch (e) {
        console.error('Load IPS log details error:', e);
        alert('Error loading details: ' + e.message);
    }
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function clearIPSLogs() {
    if (!confirm('Are you sure you want to clear all IPS detection logs?')) return;
    
    try {
        const res = await fetch('/api/ips-logs/clear', { method: 'POST' });
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`Cleared ${data.deleted} IPS log entries`);
            loadIPSLogs();
        } else {
            alert(`Error: ${data.message}`);
        }
    } catch (e) {
        alert(`Clear error: ${e.message}`);
    }
}

// --- LOG SUMMARY FUNCTIONS ---

async function loadLogSummary() {
    try {
        const res = await fetch('/api/logs/summary');
        const data = await res.json();
        
        if (data.status === 'success') {
            renderLogSummary(data.summary, data.total_entries);
        }
    } catch (e) {
        console.error('Load log summary error:', e);
        alert('Error loading log summary: ' + e.message);
    }
}

function renderLogSummary(summary, totalEntries) {
    // Render statistics cards
    const statsContainer = document.getElementById('logSummaryStats');
    if (!statsContainer) return;
    
    const logTypes = {
        'Model Logs': 0,
        'Consensus Voting': 0,
        'IPS Logs': 0
    };
    
    for (const [file, info] of Object.entries(summary)) {
        if (info.type in logTypes) {
            logTypes[info.type] += info.count;
        }
    }
    
    statsContainer.innerHTML = `
        <div class="card" style="text-align: center; padding: 16px;">
            <div style="font-size: 2em; font-weight: 800; color: var(--text-main);">${totalEntries}</div>
            <div style="font-size: 0.9em; color: var(--text-muted);">Total Entries</div>
        </div>
        <div class="card" style="text-align: center; padding: 16px;">
            <div style="font-size: 2em; font-weight: 800; color: #3b82f6;">${logTypes['Model Logs']}</div>
            <div style="font-size: 0.9em; color: var(--text-muted);">Model Logs</div>
        </div>
        <div class="card" style="text-align: center; padding: 16px;">
            <div style="font-size: 2em; font-weight: 800; color: #8b5cf6;">${logTypes['Consensus Voting']}</div>
            <div style="font-size: 0.9em; color: var(--text-muted);">Consensus Voting</div>
        </div>
        <div class="card" style="text-align: center; padding: 16px;">
            <div style="font-size: 2em; font-weight: 800; color: #ef4444;">${logTypes['IPS Logs']}</div>
            <div style="font-size: 0.9em; color: var(--text-muted);">IPS Logs</div>
        </div>
    `;
    
    // Render table
    const tableContainer = document.getElementById('logSummaryTable');
    if (!tableContainer) return;
    
    const typeColors = {
        'Model Log': '#3b82f6',
        'Consensus Voting': '#8b5cf6',
        'IPS Logs': '#ef4444'
    };
    
    tableContainer.innerHTML = Object.entries(summary).map(([file, info]) => {
        const color = typeColors[info.type] || '#6b7280';
        return `
            <tr style="border-bottom: 1px solid var(--border-color);">
                <td style="padding: 12px; text-align: left;">
                    <input type="checkbox" class="logCheckbox" value="${file}" data-count="${info.count}">
                </td>
                <td style="padding: 12px; text-align: left;">
                    <span style="color: ${color}; font-weight: 600;">${info.type}</span><br>
                    <span style="font-size: 0.85em; color: var(--text-muted);">${file}</span>
                </td>
                <td style="padding: 12px; text-align: center; font-weight: 600;">${info.count}</td>
                <td style="padding: 12px; text-align: left;">
                    <span style="background: ${info.status === 'OK' ? '#10b981' : '#f59e0b'}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em;">
                        ${info.status}
                    </span>
                </td>
                <td style="padding: 12px; text-align: left; font-size: 0.85em; color: var(--text-muted);">
                    ${info.last_updated}
                </td>
                <td style="padding: 12px; text-align: center;">
                    <button class="btn" onclick="deleteSingleLog('${file}')" style="padding: 4px 8px; font-size: 0.8em; background: #f59e0b;">
                        <i class="fas fa-trash"></i> Clear
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function toggleSelectAllLogs(checkbox) {
    const checkboxes = document.querySelectorAll('.logCheckbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
}

async function deleteSingleLog(logFile) {
    if (!confirm(`Delete all entries from ${logFile}?`)) return;
    
    try {
        const res = await fetch('/api/logs/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                log_files: [logFile]
            })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`Deleted ${data.total_deleted} entries`);
            loadLogSummary();
        } else {
            alert('Error: ' + (data.message || 'Failed to delete'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function openBulkDeleteModal() {
    // Get selected logs from table
    const selectedCheckboxes = document.querySelectorAll('.logCheckbox:checked');
    
    if (selectedCheckboxes.length === 0) {
        alert('Please select at least one log to delete from the table');
        return;
    }
    
    // Calculate total entries
    const logFiles = [];
    let totalEntries = 0;
    
    selectedCheckboxes.forEach(cb => {
        logFiles.push(cb.value);
        totalEntries += parseInt(cb.getAttribute('data-count') || 0);
    });
    
    // Show confirmation dialog directly
    const logList = logFiles.map(f => `• ${f}`).join('\n');
    const confirmMsg = `Are you sure you want to delete ${totalEntries} entries from ${logFiles.length} log(s)?\n\n${logList}\n\nThis action cannot be undone!`;
    
    if (!confirm(confirmMsg)) {
        return;
    }
    
    // Execute deletion
    try {
        const res = await fetch('/api/logs/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                log_files: logFiles
            })
        });
        
        const data = await res.json();
        
        if (data.status === 'success') {
            alert(`Successfully deleted ${data.total_deleted} entries from ${logFiles.length} logs`);
            // Uncheck all checkboxes
            document.querySelectorAll('.logCheckbox').forEach(cb => cb.checked = false);
            document.getElementById('selectAllLogs').checked = false;
            loadLogSummary();
        } else {
            alert('Error: ' + (data.message || 'Failed to delete logs'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}
// --- SYSTEM LOGS ---
let currentSysLogTab = 'api';

function switchSysLogTab(tab) {
    currentSysLogTab = tab;
    
    // Update button styles
    document.getElementById('syslog-tab-api').style.background = tab === 'api' ? 'var(--text-main)' : 'var(--bg-secondary)';
    document.getElementById('syslog-tab-api').style.color = tab === 'api' ? 'white' : 'var(--text-main)';
    
    document.getElementById('syslog-tab-login').style.background = tab === 'login' ? 'var(--text-main)' : 'var(--bg-secondary)';
    document.getElementById('syslog-tab-login').style.color = tab === 'login' ? 'white' : 'var(--text-main)';
    
    document.getElementById('syslog-tab-system').style.background = tab === 'system' ? 'var(--text-main)' : 'var(--bg-secondary)';
    document.getElementById('syslog-tab-system').style.color = tab === 'system' ? 'white' : 'var(--text-main)';
    
    // Show/hide panels
    document.getElementById('syslog-api-panel').style.display = tab === 'api' ? 'block' : 'none';
    document.getElementById('syslog-login-panel').style.display = tab === 'login' ? 'block' : 'none';
    document.getElementById('syslog-system-panel').style.display = tab === 'system' ? 'block' : 'none';
    
    loadSystemLogs();
}

async function loadSystemLogs() {
    try {
        if (currentSysLogTab === 'api') {
            await loadAPILogs();
        } else if (currentSysLogTab === 'login') {
            await loadLoginLogs();
        } else if (currentSysLogTab === 'system') {
            await loadSystemMetrics();
        }
    } catch (e) {
        console.error('Error loading system logs:', e);
    }
}

async function loadAPILogs() {
    try {
        const res = await fetch('/api/system-logs/api-calls?limit=200');
        const data = await res.json();
        
        if (data.status === 'success') {
            const tbody = document.getElementById('apiLogsBody');
            if (data.logs.length > 0) {
                tbody.innerHTML = data.logs.map(log => {
                    let statusColor = '#10b981';
                    if (parseInt(log.status_code) >= 400) statusColor = '#ef4444';
                    else if (parseInt(log.status_code) >= 300) statusColor = '#f59e0b';
                    
                    return `<tr style="border-bottom: 1px solid var(--border-color);">
                                <td style="padding: 8px;">${log.timestamp.substring(11, 19)}</td>
                                <td style="padding: 8px;"><span style="background: #dbeafe; color: #1e40af; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 0.8em;">${log.method}</span></td>
                                <td style="padding: 8px; font-family: monospace; font-size: 0.8em;">${log.endpoint}</td>
                                <td style="padding: 8px;">${log.username}</td>
                                <td style="padding: 8px; color: ${statusColor}; font-weight: 600;">${log.status_code}</td>
                            </tr>`;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="5" style="padding: 12px; text-align: center; color: var(--text-muted);">No API calls logged yet</td></tr>';
            }
        }
    } catch (e) {
        console.error('Error loading API logs:', e);
    }
}

async function loadLoginLogs() {
    try {
        const res = await fetch('/api/system-logs/logins?limit=200');
        const data = await res.json();
        
        if (data.status === 'success') {
            const tbody = document.getElementById('loginLogsBody');
            if (data.logs.length > 0) {
                tbody.innerHTML = data.logs.map(log => {
                    let statusColor = '#10b981';
                    let statusBg = '#d1fae5';
                    if (log.status === 'failed') {
                        statusColor = '#ef4444';
                        statusBg = '#fee2e2';
                    }
                    
                    return `<tr style="border-bottom: 1px solid var(--border-color);">
                                <td style="padding: 8px;">${log.timestamp.substring(11, 19)}</td>
                                <td style="padding: 8px; font-weight: 600;">${log.username}</td>
                                <td style="padding: 8px; font-family: monospace; font-size: 0.85em;">${log.ip_address}</td>
                                <td style="padding: 8px; color: ${statusColor}; font-weight: 600;"><span style="background: ${statusBg}; padding: 2px 8px; border-radius: 3px; text-transform: uppercase; font-size: 0.75em;">${log.status}</span></td>
                                <td style="padding: 8px; font-size: 0.85em; color: var(--text-muted);">${log.details || '-'}</td>
                            </tr>`;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="5" style="padding: 12px; text-align: center; color: var(--text-muted);">No login logs yet</td></tr>';
            }
        }
    } catch (e) {
        console.error('Error loading login logs:', e);
    }
}

async function loadSystemMetrics() {
    try {
        const res = await fetch('/api/system-logs/system-metrics?limit=200');
        const data = await res.json();
        
        if (data.status === 'success') {
            const tbody = document.getElementById('systemLogsBody');
            if (data.logs.length > 0) {
                tbody.innerHTML = data.logs.map(log => {
                    let statusColor = '#10b981';
                    let statusBg = '#d1fae5';
                    
                    const value = parseFloat(log.value);
                    if (log.metric_type === 'cpu' || log.metric_type === 'memory' || log.metric_type === 'disk') {
                        if (value > 80) {
                            statusColor = '#ef4444';
                            statusBg = '#fee2e2';
                        } else if (value > 60) {
                            statusColor = '#f59e0b';
                            statusBg = '#fef3c7';
                        }
                    }
                    
                    return `<tr style="border-bottom: 1px solid var(--border-color);">
                                <td style="padding: 8px;">${log.timestamp.substring(11, 19)}</td>
                                <td style="padding: 8px; font-weight: 600; text-transform: uppercase;">${log.metric_type}</td>
                                <td style="padding: 8px; font-family: monospace; font-weight: 600;">${log.value}${log.unit ? ' ' + log.unit : ''}</td>
                                <td style="padding: 8px;"><span style="background: ${statusBg}; color: ${statusColor}; padding: 2px 8px; border-radius: 3px; text-transform: uppercase; font-size: 0.75em; font-weight: 600;">${log.status}</span></td>
                            </tr>`;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="4" style="padding: 12px; text-align: center; color: var(--text-muted);">No system metrics logged yet</td></tr>';
            }
        }
    } catch (e) {
        console.error('Error loading system metrics:', e);
    }
}

function filterAPILogs() {
    loadAPILogs();
}

function filterLoginLogs() {
    loadLoginLogs();
}

function filterSystemLogs() {
    loadSystemMetrics();
}
