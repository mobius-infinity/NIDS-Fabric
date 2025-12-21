let currentView = 'dashboard';
let sysChart, trafficChart, threatChart;
let selectedModel = '', selectedTask = '';

// Lazy loading state
let logsOffset = 0;
let logsTotal = 0;
let isLoadingLogs = false;
const logsLimitPerPage = 50;
let logsAutoFillCount = 0;
const logsAutoFillMax = 0; // disable automatic auto-fill; require user scroll to load more
// maxAutoFillPages deprecated
let scrollTimer = null;

document.addEventListener('DOMContentLoaded', () => {
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
            document.getElementById('modeSwitch').checked = (data.config_mode === 'rf_only');
            
            const thresh = data.config_threshold || 2;
            document.getElementById('threshSlider').value = thresh;
            document.getElementById('thresh-display').textContent = thresh + '/6';
        }

    } catch (e) { console.error("Auth Error", e); }
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
    try { 
        const res = await fetch('/api/update-profile', { method: 'POST', body: formData }); 
        alert((await res.json()).message); 
        loadUserInfo(); 
    } catch(e) { alert("Error"); }
}

async function saveSystemSettings() {
    const mode = document.getElementById('modeSwitch').checked ? 'rf_only' : 'voting';
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
    else if(view==='settings') document.getElementById('menu-settings').classList.add('active');
    
    if (view === 'dashboard') setTimeout(() => { resizeCharts(); updateDashboard(); }, 50);
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
    resetLazyLoad();
}

function resetLazyLoad() {
    logsOffset = 0;
    logsTotal = 0;
    isLoadingLogs = false;
    logsAutoFillCount = 0;
    document.getElementById('modelLogsBody').innerHTML = '';
    const container = document.getElementById('logsScrollContainer');
    if (container) {
        container.scrollTop = 0;
        // ensure a single scroll listener is attached
        try { container.removeEventListener('scroll', onLogsScroll); } catch(e){}
        container.addEventListener('scroll', onLogsScroll);
    }
    loadMoreLogs();
}

function inspectLogsHolder(note) {
    const c = document.getElementById('logsScrollContainer');
    if (!c) { console.debug('[Logs] holder missing', note); return; }
    const cs = window.getComputedStyle(c);
    console.debug('[Logs] holder', note, {
        clientHeight: c.clientHeight,
        scrollHeight: c.scrollHeight,
        scrollTop: c.scrollTop,
        overflowY: cs.overflowY,
        display: cs.display,
        visible: !!(c.offsetWidth || c.offsetHeight)
    });
}

async function loadMoreLogs() {
    if (isLoadingLogs || (logsOffset >= logsTotal && logsTotal > 0)) return;
    // set loading flag immediately to prevent re-entrant calls
    isLoadingLogs = true;
    console.log('[Logs] loadMoreLogs called', { logsOffset, logsTotal, isLoadingLogs });
    document.getElementById('logsLoadingIndicator').style.display = 'block';
    
    try {
        const modelParam = encodeURIComponent(selectedModel || 'Random Forest');
        const taskParam = encodeURIComponent(selectedTask || 'binary');
        const res = await fetch(`/api/get_flows?model=${modelParam}&task=${taskParam}&offset=${logsOffset}&limit=${logsLimitPerPage}`);
        const data = await res.json();
        console.log('[Logs] api response', { offset: logsOffset, total: data.total, count: (data.flows||[]).length });
        if (data.error) {
            console.error('API error', data.error);
            if (logsOffset === 0) document.getElementById('modelLogsBody').innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px;">Error: ${data.error}</td></tr>`;
        } else if (!data.flows || !data.flows.length) {
            if (logsOffset === 0) {
                document.getElementById('modelLogsBody').innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 20px;">No data</td></tr>';
            }
        } else {
            logsTotal = data.total;
            const tbody = document.getElementById('modelLogsBody');
            const newRows = data.flows.map(f => {
                let isSafe = String(f.result).toLowerCase().includes('safe') || 
                             String(f.result).toLowerCase().includes('benign') || 
                             f.result == '0';
                return `<tr onclick="showDetails('${f.id}')" style="cursor: pointer; border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 12px; font-weight:600;">${f.seq ?? '-'}</td>
                            <td style="padding: 12px;">${f.time_scaned?.split(' ')[1] || '-'}</td>
                            <td style="padding: 12px;">${f.file_scaned}</td>
                            <td style="padding: 12px;">${f.IPV4_SRC_ADDR}</td>
                            <td style="padding: 12px;">${f.L4_SRC_PORT ?? '-'}</td>
                            <td style="padding: 12px;">${f.IPV4_DST_ADDR}</td>
                            <td style="padding: 12px;">${f.L4_DST_PORT ?? '-'}</td>
                            <td style="padding: 12px;"><span class="badge ${isSafe?'badge-safe':'badge-danger'}">${f.result}</span></td>
                        </tr>`;
            }).join('');
            tbody.innerHTML += newRows;
        }
        
        logsOffset += logsLimitPerPage;
            // If container still not scrollable but there are more logs, auto-fetch up to a cap
            try {
                const container = document.getElementById('logsScrollContainer');
                if (container && container.scrollHeight <= container.clientHeight && logsOffset < logsTotal && logsAutoFillCount < logsAutoFillMax) {
                    logsAutoFillCount += 1;
                    console.log('[Logs] auto-fill triggered', { logsAutoFillCount, logsAutoFillMax, logsOffset, logsTotal });
                    // small delay to allow DOM to render
                    setTimeout(() => { loadMoreLogs(); }, 120);
                }
            } catch (e) { console.debug('auto-fill check failed', e); }
    } catch (e) { 
        console.error('Error loading logs:', e);
        if (logsOffset === 0) document.getElementById('modelLogsBody').innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px;">Error loading logs</td></tr>`;
    } finally {
        isLoadingLogs = false;
        document.getElementById('logsLoadingIndicator').style.display = 'none';
        try { inspectLogsHolder('after load'); } catch(e){ console.log('inspectLogsHolder missing', e); }
    }
}

function onLogsScroll() {
    const container = document.getElementById('logsScrollContainer');
    if (!container) return;
    console.log('[Logs] onLogsScroll event', { scrollTop: container.scrollTop, clientHeight: container.clientHeight, scrollHeight: container.scrollHeight });
    // debounce to avoid rapid-fire
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(() => {
        // Check if scrolled near bottom (within 200px)
        if (container.scrollHeight - container.scrollTop - container.clientHeight < 200) {
            loadMoreLogs();
        }
    }, 150);
}

// --- FORTIOS STYLE DETAILS ---
function showDetails(id) {
    fetch(`/api/flow-details/${id}?model=${selectedModel}&task=${selectedTask}`)
        .then(r=>r.json())
        .then(d=>{
            const panel = document.getElementById('panelContent');
            let isThreat = !(String(d.result).toLowerCase().includes('safe') || 
                             String(d.result).toLowerCase().includes('benign') || 
                             d.result == '0');
            
            panel.innerHTML = `
                <div class="forti-group">
                    <div class="forti-group-title"><h3><b>General</h3></div>
                    <div class="forti-row"><span class="forti-label">Date/Time</span><span class="forti-val">${d.time_scaned}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow Start</span><span class="forti-val">${formatEpochOrString(d.FIRST_SWITCHED ?? d.FLOW_START_MILLISECONDS ?? d.FLOW_START)}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow End</span><span class="forti-val">${formatEpochOrString(d.LAST_SWITCHED ?? d.FLOW_END_MILLISECONDS ?? d.FLOW_END)}</span></div>
                    <div class="forti-row"><span class="forti-label">File Source</span><span class="forti-val">${d.file_scaned}</span></div>
                    <div class="forti-row"><span class="forti-label">Flow ID</span><span class="forti-val">${d.id}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Source</div>
                    <div class="forti-row"><span class="forti-label">IP Address</span><span class="forti-val" style="color:#0284c7">${d.IPV4_SRC_ADDR}</span></div>
                    <div class="forti-row"><span class="forti-label">Port</span><span class="forti-val">${d.L4_SRC_PORT}</span></div>
                </div>

                <div class="forti-group">
                    <div class="forti-group-title">Destination</div>
                    <div class="forti-row"><span class="forti-label">IP Address</span><span class="forti-val" style="color:#0284c7">${d.IPV4_DST_ADDR}</span></div>
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
                    <div class="forti-row"><span class="forti-label">Prediction</span><span class="forti-val" style="color:${isThreat?'#ef4444':'#10b981'}">${d.result}</span></div>
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
            
            return `<tr>
                        <td style="font-weight:600;">${f.name}</td>
                        <td>${f.size_mb} MB</td>
                        <td><span class="badge ${badge}">${f.status}</span></td>
                    </tr>`;
        }).join('');
    } catch(e) { console.error("Dash Error", e); }
}
