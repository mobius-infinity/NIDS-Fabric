let currentView = 'dashboard';
let sysChart, trafficChart, threatChart;
let selectedModel = '', selectedTask = '';

document.addEventListener('DOMContentLoaded', () => {
    // Chỉ init charts nếu element tồn tại (tránh lỗi ở trang login)
    if(document.getElementById('sysChart')) {
        initCharts();
        loadUserInfo();
        setInterval(updateDashboard, 2000);
        updateDashboard();
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
    loadLogs();
}

async function loadLogs() {
    const tbody = document.getElementById('modelLogsBody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Loading...</td></tr>';
    try {
        const res = await fetch(`/api/get_flows?model=${selectedModel}&task=${selectedTask}`);
        const data = await res.json();
        if (!data.flows || !data.flows.length) { 
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No data</td></tr>'; 
            return; 
        }
        tbody.innerHTML = data.flows.map(f => {
            let isSafe = String(f.result).toLowerCase().includes('safe') || 
                         String(f.result).toLowerCase().includes('benign') || 
                         f.result == '0';
            return `<tr onclick="showDetails('${f.id}')">
                        <td>${f.time_scaned?.split(' ')[1] || '-'}</td>
                        <td>${f.file_scaned}</td>
                        <td>${f.IPV4_SRC_ADDR}</td>
                        <td>${f.IPV4_DST_ADDR}</td>
                        <td><span class="badge ${isSafe?'badge-safe':'badge-danger'}">${f.result}</span></td>
                    </tr>`;
        }).join('');
    } catch (e) { tbody.innerHTML = '<tr><td colspan="5">Error</td></tr>'; }
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
