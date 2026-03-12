/* AptumNet Dashboard - Frontend Application */

const API = '/api';

// --- State ---
let currentHostId = null;
let currentSNMPDeviceId = null;
let metricsCharts = {};
let snmpCharts = {};
let logEntriesOffset = 0;
const LOG_ENTRIES_LIMIT = 50;

// --- Navigation ---
function showPage(page) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const el = document.getElementById('page-' + page);
    if (el) el.style.display = 'block';

    // Find and activate nav item
    document.querySelectorAll('.nav-item').forEach(n => {
        if (n.getAttribute('onclick') && n.getAttribute('onclick').includes("'" + page + "'")) {
            n.classList.add('active');
        }
    });

    // Load data for each page
    switch(page) {
        case 'dashboard': refreshDashboard(); break;
        case 'hosts': loadHosts(); break;
        case 'scanner': loadScans(); break;
        case 'services': loadServices(); break;
        case 'alerts': loadAlerts(); break;
        case 'ids': loadIDS(); break;
        case 'logs': loadLogSummary(); break;
        case 'anomalies': loadAnomalies(); break;
        case 'topology': loadTopology(); break;
        case 'snmp': loadSNMPDevices(); break;
    }
}

// --- API Helpers ---
async function apiGet(path) {
    try {
        const resp = await fetch(API + path);
        return await resp.json();
    } catch(e) {
        console.error('API Error:', e);
        return null;
    }
}

async function apiPost(path, body) {
    try {
        const resp = await fetch(API + path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
        return await resp.json();
    } catch(e) {
        console.error('API Error:', e);
        return null;
    }
}

async function apiPut(path, body) {
    try {
        const resp = await fetch(API + path, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
        return await resp.json();
    } catch(e) {
        console.error('API Error:', e);
        return null;
    }
}

function notify(message, type = 'info') {
    const div = document.createElement('div');
    div.className = 'notification ' + type;
    div.textContent = message;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 4000);
}

function formatDate(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toLocaleString('pt-BR');
}

function formatDateShort(isoStr) {
    if (!isoStr) return '';
    const d = new Date(isoStr);
    return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
}

function severityBadge(severity) {
    return `<span class="badge badge-${severity}">${severity}</span>`;
}

function statusBadge(status) {
    return `<span class="badge badge-${status}">${status}</span>`;
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// --- Dashboard ---
async function refreshDashboard() {
    const data = await apiGet('/dashboard');
    if (!data) return;

    document.getElementById('stat-hosts-up').textContent = data.hosts.up;
    document.getElementById('stat-hosts-down').textContent = data.hosts.down;
    document.getElementById('stat-hosts-total').textContent = data.hosts.total;
    document.getElementById('stat-alerts-open').textContent = data.alerts.total_open;
    document.getElementById('stat-alerts-critical').textContent = data.alerts.critical;
    document.getElementById('stat-anomalies').textContent = data.anomaly_summary.total_anomalies || 0;

    // Recent alerts
    const tbody = document.getElementById('recent-alerts-body');
    const noAlerts = document.getElementById('no-alerts');
    if (data.recent_alerts.length === 0) {
        tbody.innerHTML = '';
        noAlerts.style.display = 'block';
    } else {
        noAlerts.style.display = 'none';
        tbody.innerHTML = data.recent_alerts.map(a => `
            <tr>
                <td>${severityBadge(a.severity)}</td>
                <td>${a.title}</td>
                <td>${a.host_ip || '-'}</td>
                <td>${a.source || '-'}</td>
                <td>${formatDate(a.created_at)}</td>
            </tr>
        `).join('');
    }

    // IDS stats
    const idsStats = data.ids_stats;
    const idsBody = document.getElementById('ids-alerts-body');
    const noIds = document.getElementById('no-ids');

    if (idsStats.total_alerts === 0) {
        idsBody.innerHTML = '';
        noIds.style.display = 'block';
    } else {
        noIds.style.display = 'none';
        const idsAlerts = await apiGet('/ids/alerts?limit=5');
        if (idsAlerts && idsAlerts.length > 0) {
            idsBody.innerHTML = idsAlerts.map(a => `
                <tr>
                    <td>${a.rule_name}</td>
                    <td>${severityBadge(a.severity)}</td>
                    <td>${a.source_ip || '-'}</td>
                    <td>${formatDate(a.detected_at)}</td>
                </tr>
            `).join('');
        }
    }

    const sevBar = document.getElementById('ids-severity-bar');
    sevBar.innerHTML = `
        <div class="severity-item"><span class="severity-dot critical"></span> Cr\u00edtico: ${idsStats.by_severity.critical}</div>
        <div class="severity-item"><span class="severity-dot high"></span> Alto: ${idsStats.by_severity.high}</div>
        <div class="severity-item"><span class="severity-dot medium"></span> M\u00e9dio: ${idsStats.by_severity.medium}</div>
        <div class="severity-item"><span class="severity-dot low"></span> Baixo: ${idsStats.by_severity.low}</div>
    `;
}

// --- Hosts ---
async function loadHosts() {
    const hosts = await apiGet('/hosts');
    const tbody = document.getElementById('hosts-table-body');
    const noHosts = document.getElementById('no-hosts');

    if (!hosts || hosts.length === 0) {
        tbody.innerHTML = '';
        noHosts.style.display = 'block';
        return;
    }
    noHosts.style.display = 'none';

    tbody.innerHTML = hosts.map(h => `
        <tr style="cursor:pointer" onclick="viewHostDetail(${h.id})">
            <td><strong>${h.ip_address}</strong></td>
            <td>${h.hostname || '-'}</td>
            <td>${h.host_type || 'unknown'}</td>
            <td>${statusBadge(h.status)}</td>
            <td>${h.open_ports}</td>
            <td>${h.snmp_enabled ? '&#10004;' : '-'}</td>
            <td>${h.agent_installed ? '&#10004;' : '-'}</td>
            <td>${formatDate(h.last_seen)}</td>
        </tr>
    `).join('');
}

// --- Host Detail (drill-down, no popup) ---
async function viewHostDetail(hostId) {
    currentHostId = hostId;
    const host = await apiGet('/hosts/' + hostId);
    if (!host) return;

    // Switch to detail page
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.getElementById('page-host-detail').style.display = 'block';

    document.getElementById('host-detail-title').textContent = `${host.ip_address} - ${host.hostname || 'N/A'}`;
    document.getElementById('host-detail-subtitle').textContent =
        `Tipo: ${host.host_type} | OS: ${host.os_detected || 'N/A'} | Status: ${host.status}`;

    // Stats cards
    document.getElementById('host-detail-stats').innerHTML = `
        <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value ${host.status === 'up' ? 'green' : 'red'}">${host.status}</div></div>
        <div class="stat-card"><div class="stat-label">Portas Abertas</div><div class="stat-value cyan">${host.ports.filter(p => p.state === 'open').length}</div></div>
        <div class="stat-card"><div class="stat-label">SNMP</div><div class="stat-value ${host.snmp_enabled ? 'green' : 'red'}">${host.snmp_enabled ? 'Sim' : 'N\u00e3o'}</div></div>
        <div class="stat-card"><div class="stat-label">Agente</div><div class="stat-value ${host.agent_installed ? 'green' : 'red'}">${host.agent_installed ? 'Sim' : 'N\u00e3o'}</div></div>
        <div class="stat-card"><div class="stat-label">Alertas Abertos</div><div class="stat-value yellow">${host.alerts.filter(a => a.status === 'open').length}</div></div>
        <div class="stat-card"><div class="stat-label">Primeira vez</div><div class="stat-value" style="font-size:14px">${formatDate(host.first_seen)}</div></div>
    `;

    // Config fields
    document.getElementById('hd-hostname').value = host.hostname || '';
    document.getElementById('hd-host-type').value = host.host_type || 'unknown';
    document.getElementById('hd-location').value = host.location || '';
    document.getElementById('hd-snmp-community').value = host.snmp_community || 'public';
    document.getElementById('hd-log-paths').value = (host.log_paths || []).join('\n');
    document.getElementById('hd-notes').value = host.notes || '';

    // Ports
    const portsTbody = document.getElementById('host-detail-ports');
    if (host.ports.length > 0) {
        portsTbody.innerHTML = host.ports.map(p => `
            <tr>
                <td>${p.port}</td>
                <td>${p.protocol}</td>
                <td>${statusBadge(p.state)}</td>
                <td>${p.service || '-'}</td>
                <td>${p.version || '-'}</td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${p.banner || '-'}</td>
            </tr>
        `).join('');
    } else {
        portsTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary)">Nenhuma porta detectada</td></tr>';
    }

    // Alerts
    const alertsTbody = document.getElementById('host-detail-alerts');
    if (host.alerts.length > 0) {
        alertsTbody.innerHTML = host.alerts.map(a => `
            <tr>
                <td>${severityBadge(a.severity)}</td>
                <td>${a.title}</td>
                <td>${a.type}</td>
                <td>${statusBadge(a.status)}</td>
                <td>${formatDate(a.created_at)}</td>
            </tr>
        `).join('');
    } else {
        alertsTbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Nenhum alerta</td></tr>';
    }

    // Load metrics chart
    loadMetricsChart();
}

function refreshHostDetail() {
    if (currentHostId) viewHostDetail(currentHostId);
}

async function saveHostConfig() {
    if (!currentHostId) return;
    const logPathsRaw = document.getElementById('hd-log-paths').value.trim();
    const logPaths = logPathsRaw ? logPathsRaw.split('\n').map(p => p.trim()).filter(p => p) : [];

    const data = {
        hostname: document.getElementById('hd-hostname').value.trim() || null,
        host_type: document.getElementById('hd-host-type').value,
        location: document.getElementById('hd-location').value.trim() || null,
        snmp_community: document.getElementById('hd-snmp-community').value.trim() || null,
        log_paths: logPaths,
        notes: document.getElementById('hd-notes').value.trim() || null,
    };

    const result = await apiPut('/hosts/' + currentHostId, data);
    if (result && result.status === 'updated') {
        notify('Configura\u00e7\u00e3o salva com sucesso', 'success');
    } else {
        notify('Erro ao salvar', 'error');
    }
}

// --- Metrics Charts (Chart.js) ---
function createTimeChart(canvasId, label, labels, values, color, chartStore) {
    const store = chartStore || metricsCharts;
    if (store[canvasId]) { store[canvasId].destroy(); delete store[canvasId]; }

    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const shortLabels = labels.map(l => formatDateShort(l));

    store[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: shortLabels,
            datasets: [{
                label: label,
                data: values,
                borderColor: color,
                backgroundColor: color + '22',
                fill: true,
                tension: 0.3,
                pointRadius: values.length > 50 ? 0 : 2,
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { labels: { color: '#8b8fa3', font: { size: 11 } } },
            },
            scales: {
                x: {
                    ticks: { color: '#8b8fa3', font: { size: 10 }, maxTicksLimit: 8 },
                    grid: { color: '#2e334822' },
                },
                y: {
                    ticks: { color: '#8b8fa3', font: { size: 10 } },
                    grid: { color: '#2e334844' },
                    beginAtZero: true,
                }
            }
        }
    });
}

async function loadMetricsChart() {
    if (!currentHostId) return;
    const range = document.getElementById('metrics-range').value;
    const data = await apiGet(`/hosts/${currentHostId}/metrics?range=${range}`);
    if (!data || !data.series) return;

    const noMetrics = document.getElementById('no-metrics-chart');
    if (data.total_points === 0) {
        noMetrics.style.display = 'block';
        return;
    }
    noMetrics.style.display = 'none';

    const s = data.series;
    if (s.cpu) createTimeChart('chart-cpu', 'CPU %', s.cpu.labels, s.cpu.values, '#3b82f6', metricsCharts);
    if (s.memory) createTimeChart('chart-memory', 'Mem\u00f3ria %', s.memory.labels, s.memory.values, '#8b5cf6', metricsCharts);
    if (s.disk) createTimeChart('chart-disk', 'Disco %', s.disk.labels, s.disk.values, '#f59e0b', metricsCharts);
    if (s.network) createTimeChart('chart-network', 'Rede', s.network.labels, s.network.values, '#10b981', metricsCharts);
}

// --- SNMP Devices Dashboard ---
async function loadSNMPDevices() {
    const devices = await apiGet('/snmp/devices');
    const tbody = document.getElementById('snmp-devices-body');
    const noDevices = document.getElementById('no-snmp-devices');
    const statsGrid = document.getElementById('snmp-stats-grid');

    // Show list view, hide detail
    document.getElementById('snmp-list-view').style.display = 'block';
    document.getElementById('snmp-detail-view').style.display = 'none';

    if (!devices || devices.length === 0) {
        tbody.innerHTML = '';
        noDevices.style.display = 'block';
        statsGrid.innerHTML = `
            <div class="stat-card"><div class="stat-label">Dispositivos SNMP</div><div class="stat-value cyan">0</div></div>
        `;
        return;
    }
    noDevices.style.display = 'none';

    const upCount = devices.filter(d => d.status === 'up').length;
    statsGrid.innerHTML = `
        <div class="stat-card"><div class="stat-label">Total Dispositivos</div><div class="stat-value cyan">${devices.length}</div></div>
        <div class="stat-card"><div class="stat-label">Online</div><div class="stat-value green">${upCount}</div></div>
        <div class="stat-card"><div class="stat-label">Offline</div><div class="stat-value red">${devices.length - upCount}</div></div>
    `;

    tbody.innerHTML = devices.map(d => `
        <tr style="cursor:pointer" onclick="viewSNMPDevice(${d.id})">
            <td><strong>${d.ip_address}</strong></td>
            <td>${d.hostname || '-'}</td>
            <td>${d.host_type || 'unknown'}</td>
            <td>${statusBadge(d.status)}</td>
            <td>${d.vendor || '-'}</td>
            <td>${d.os_detected || '-'}</td>
            <td>${d.snmp_community || 'public'}</td>
            <td>${formatDate(d.last_seen)}</td>
        </tr>
    `).join('');
}

async function viewSNMPDevice(hostId) {
    currentSNMPDeviceId = hostId;

    // Switch to detail view
    document.getElementById('snmp-list-view').style.display = 'none';
    document.getElementById('snmp-detail-view').style.display = 'block';

    const data = await apiGet('/snmp/device/' + hostId);
    if (!data) return;

    // Stats
    const cpuLoads = (data.snmp_metrics.cpu || []).map(c => c.load_percent);
    const avgCpu = cpuLoads.length > 0 ? Math.round(cpuLoads.reduce((a, b) => a + b, 0) / cpuLoads.length) : '-';

    document.getElementById('snmp-detail-stats').innerHTML = `
        <div class="stat-card"><div class="stat-label">IP</div><div class="stat-value" style="font-size:18px">${data.ip_address}</div></div>
        <div class="stat-card"><div class="stat-label">Hostname</div><div class="stat-value" style="font-size:18px">${data.hostname || '-'}</div></div>
        <div class="stat-card"><div class="stat-label">Status</div><div class="stat-value ${data.status === 'up' ? 'green' : 'red'}">${data.status}</div></div>
        <div class="stat-card"><div class="stat-label">CPU M\u00e9dia</div><div class="stat-value cyan">${avgCpu}%</div></div>
        <div class="stat-card"><div class="stat-label">Interfaces</div><div class="stat-value purple">${(data.snmp_metrics.interfaces || []).length}</div></div>
        <div class="stat-card"><div class="stat-label">Storage</div><div class="stat-value yellow">${(data.snmp_metrics.storage || []).length}</div></div>
    `;

    // System Info
    const info = data.snmp_info || {};
    document.getElementById('snmp-system-info').innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);font-size:13px">
                <span style="color:var(--text-secondary)">Descri\u00e7\u00e3o</span>
                <span>${info.sys_description || '-'}</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);font-size:13px">
                <span style="color:var(--text-secondary)">Nome</span>
                <span>${info.sys_name || '-'}</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);font-size:13px">
                <span style="color:var(--text-secondary)">Localiza\u00e7\u00e3o</span>
                <span>${info.sys_location || '-'}</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);font-size:13px">
                <span style="color:var(--text-secondary)">Uptime</span>
                <span>${info.uptime_ticks || '-'}</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);font-size:13px">
                <span style="color:var(--text-secondary)">SO</span>
                <span>${data.os_detected || '-'}</span>
            </div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-color);font-size:13px">
                <span style="color:var(--text-secondary)">Fabricante</span>
                <span>${data.vendor || '-'}</span>
            </div>
        </div>
    `;

    // Interfaces
    const ifBody = document.getElementById('snmp-interfaces-body');
    const ifaces = data.snmp_metrics.interfaces || [];
    if (ifaces.length > 0) {
        ifBody.innerHTML = ifaces.map(i => `
            <tr>
                <td>${i.name || '-'}</td>
                <td>${i.status ? statusBadge(i.status) : '-'}</td>
                <td>${i.in_octets !== undefined ? formatBytes(i.in_octets) : '-'}</td>
                <td>${i.out_octets !== undefined ? formatBytes(i.out_octets) : '-'}</td>
            </tr>
        `).join('');
    } else {
        ifBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">Sem dados de interfaces</td></tr>';
    }

    // Storage
    const stBody = document.getElementById('snmp-storage-body');
    const storages = data.snmp_metrics.storage || [];
    if (storages.length > 0) {
        stBody.innerHTML = storages.map(s => `
            <tr>
                <td>${s.name || '-'}</td>
                <td>${s.size !== undefined ? s.size : '-'}</td>
                <td>${s.used !== undefined ? s.used : '-'}</td>
                <td>${s.usage_percent !== undefined ? s.usage_percent + '%' : '-'}</td>
            </tr>
        `).join('');
    } else {
        stBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">Sem dados de armazenamento</td></tr>';
    }

    // Ports
    const ptBody = document.getElementById('snmp-ports-body');
    const ports = data.ports || [];
    if (ports.length > 0) {
        ptBody.innerHTML = ports.map(p => `
            <tr>
                <td>${p.port}</td>
                <td>${p.protocol}</td>
                <td>${statusBadge(p.state)}</td>
                <td>${p.service || '-'}</td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${p.banner || '-'}</td>
            </tr>
        `).join('');
    } else {
        ptBody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Nenhuma porta</td></tr>';
    }

    // Alerts
    const alBody = document.getElementById('snmp-alerts-body');
    const alerts = data.alerts || [];
    if (alerts.length > 0) {
        alBody.innerHTML = alerts.map(a => `
            <tr>
                <td>${severityBadge(a.severity)}</td>
                <td>${a.title}</td>
                <td>${statusBadge(a.status)}</td>
                <td>${formatDate(a.created_at)}</td>
            </tr>
        `).join('');
    } else {
        alBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">Nenhum alerta</td></tr>';
    }

    // Load charts
    loadSNMPMetricsChart();
}

async function loadSNMPMetricsChart() {
    if (!currentSNMPDeviceId) return;
    const range = document.getElementById('snmp-metrics-range').value;
    const data = await apiGet(`/hosts/${currentSNMPDeviceId}/metrics?range=${range}`);
    if (!data || !data.series) return;

    const s = data.series;
    if (s.cpu) createTimeChart('snmp-chart-cpu', 'CPU %', s.cpu.labels, s.cpu.values, '#3b82f6', snmpCharts);
    if (s.disk) createTimeChart('snmp-chart-disk', 'Disco %', s.disk.labels, s.disk.values, '#f59e0b', snmpCharts);
}

function showSNMPList() {
    currentSNMPDeviceId = null;
    document.getElementById('snmp-list-view').style.display = 'block';
    document.getElementById('snmp-detail-view').style.display = 'none';
}

// --- Scanner ---
async function startScan() {
    const target = document.getElementById('scan-target').value.trim();
    const scanType = document.getElementById('scan-type').value;

    if (!target) {
        notify('Informe o alvo do scan', 'error');
        return;
    }

    const result = await apiPost('/scan', { target, scan_type: scanType });
    if (result) {
        notify('Scan iniciado - Job #' + result.job_id, 'success');
        pollScanStatus(result.job_id);
        loadScans();
    }
}

async function pollScanStatus(jobId) {
    const check = async () => {
        const result = await apiGet('/scan/' + jobId);
        if (!result) return;

        if (result.status === 'completed' || result.status === 'failed') {
            notify('Scan #' + jobId + ' ' + result.status, result.status === 'completed' ? 'success' : 'error');
            document.getElementById('scan-results-panel').style.display = 'block';
            document.getElementById('scan-results').textContent = JSON.stringify(result.results, null, 2);
            loadScans();
            return;
        }
        setTimeout(check, 3000);
    };
    check();
}

async function loadScans() {
    const scans = await apiGet('/scans');
    const tbody = document.getElementById('scans-table-body');
    if (!scans) return;

    tbody.innerHTML = scans.map(s => `
        <tr style="cursor:pointer" onclick="viewScanResults(${s.id})">
            <td>#${s.id}</td>
            <td>${s.scan_type}</td>
            <td>${s.target}</td>
            <td>${statusBadge(s.status)}</td>
            <td>${formatDate(s.created_at)}</td>
        </tr>
    `).join('');
}

async function viewScanResults(jobId) {
    const result = await apiGet('/scan/' + jobId);
    if (result) {
        document.getElementById('scan-results-panel').style.display = 'block';
        document.getElementById('scan-results').textContent = JSON.stringify(result.results, null, 2);
    }
}

// --- Services ---
async function loadServices() {
    const hosts = await apiGet('/hosts');
    const tbody = document.getElementById('services-table-body');
    if (!hosts) return;

    let rows = '';
    for (const h of hosts) {
        const details = await apiGet('/hosts/' + h.id);
        if (details && details.ports) {
            details.ports.filter(p => p.state === 'open').forEach(p => {
                rows += `<tr>
                    <td>${h.ip_address}</td>
                    <td>${p.port}</td>
                    <td>${p.protocol}</td>
                    <td>${p.service || '-'}</td>
                    <td>${statusBadge(p.state)}</td>
                    <td>${(p.banner || '-').substring(0, 80)}</td>
                </tr>`;
            });
        }
    }
    tbody.innerHTML = rows || '<tr><td colspan="6" class="empty-state">Nenhum servico encontrado</td></tr>';
}

// --- Alerts ---
async function loadAlerts() {
    const severity = document.getElementById('alert-severity-filter').value;
    let path = '/alerts?limit=200';
    if (severity) path += '&severity=' + severity;

    const alerts = await apiGet(path);
    const tbody = document.getElementById('alerts-table-body');
    if (!alerts) return;

    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>${severityBadge(a.severity)}</td>
            <td>${a.title}</td>
            <td>${a.type}</td>
            <td>${a.host_ip || '-'}</td>
            <td>${a.source || '-'}</td>
            <td>${statusBadge(a.status)}</td>
            <td>${formatDate(a.created_at)}</td>
            <td>
                ${a.status === 'open' ? `
                    <button class="btn btn-sm btn-success" onclick="resolveAlert(${a.id})">Resolver</button>
                ` : ''}
            </td>
        </tr>
    `).join('');
}

async function resolveAlert(alertId) {
    await apiPut('/alerts/' + alertId, { status: 'resolved' });
    notify('Alerta resolvido', 'success');
    loadAlerts();
}

// --- IDS ---
async function loadIDS() {
    const stats = await apiGet('/ids/stats');
    const alerts = await apiGet('/ids/alerts?limit=50');

    if (stats) {
        document.getElementById('ids-stats-grid').innerHTML = `
            <div class="stat-card"><div class="stat-label">Total Deteccoes</div><div class="stat-value yellow">${stats.total_alerts}</div></div>
            <div class="stat-card"><div class="stat-label">Regras Ativas</div><div class="stat-value cyan">${stats.rules_count}</div></div>
            <div class="stat-card"><div class="stat-label">Criticos</div><div class="stat-value red">${stats.by_severity.critical}</div></div>
            <div class="stat-card"><div class="stat-label">Altos</div><div class="stat-value yellow">${stats.by_severity.high}</div></div>
        `;
    }

    if (alerts) {
        const tbody = document.getElementById('ids-full-table-body');
        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td>${a.rule_id}</td>
                <td>${a.rule_name}</td>
                <td>${severityBadge(a.severity)}</td>
                <td>${a.source_ip || '-'}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${a.matched_text || a.description || '-'}</td>
                <td>${formatDate(a.detected_at)}</td>
            </tr>
        `).join('');
    }
}

// --- Pentest ---
async function startPentest() {
    const target = document.getElementById('pentest-target').value.trim();
    if (!target) {
        notify('Informe o IP alvo', 'error');
        return;
    }

    notify('Pentest iniciado em ' + target, 'info');
    const result = await apiPost('/scan', { target, scan_type: 'pentest' });

    if (result) {
        pollScanStatus(result.job_id);
        document.getElementById('pentest-results-panel').style.display = 'block';
        document.getElementById('pentest-results').textContent = 'Executando pentest... Aguarde.';

        const checkResult = async () => {
            const scanResult = await apiGet('/scan/' + result.job_id);
            if (scanResult && (scanResult.status === 'completed' || scanResult.status === 'failed')) {
                document.getElementById('pentest-results').textContent = JSON.stringify(scanResult.results, null, 2);
                return;
            }
            setTimeout(checkResult, 3000);
        };
        checkResult();
    }
}

// --- Logs ---
async function loadLogSummary() {
    const summary = await apiGet('/logs/summary');
    if (summary) {
        document.getElementById('log-stats-grid').innerHTML = `
            <div class="stat-card"><div class="stat-label">Total Entradas</div><div class="stat-value cyan">${summary.total_entries}</div></div>
            <div class="stat-card"><div class="stat-label">Ameacas Detectadas</div><div class="stat-value red">${summary.total_threats}</div></div>
            <div class="stat-card"><div class="stat-label">Categorias</div><div class="stat-value blue">${Object.keys(summary.by_category || {}).length}</div></div>
        `;
    }

    const failedLogins = await apiGet('/logs/failed-logins');
    if (failedLogins) {
        let html = '';
        if (failedLogins.total_failed > 0) {
            html += `<p><strong>Total de logins falhados: ${failedLogins.total_failed}</strong></p>`;
            if (failedLogins.top_source_ips.length > 0) {
                html += '<h4 style="margin-top:12px">Top IPs de Origem</h4><table class="data-table"><thead><tr><th>IP</th><th>Tentativas</th></tr></thead><tbody>';
                failedLogins.top_source_ips.forEach(([ip, count]) => {
                    html += `<tr><td>${ip}</td><td>${count}</td></tr>`;
                });
                html += '</tbody></table>';
            }
        } else {
            html = '<p style="color:var(--text-secondary)">Nenhuma tentativa de login falhada detectada.</p>';
        }
        document.getElementById('failed-logins-body').innerHTML = html;
    }

    // Load filter dropdowns and log entries
    await loadLogFilterOptions();
    logEntriesOffset = 0;
    await loadLogEntries();
}

async function loadLogFilterOptions() {
    // Load hosts filter
    const hosts = await apiGet('/logs/hosts');
    const hostSelect = document.getElementById('log-filter-host');
    if (hosts && hostSelect) {
        const currentVal = hostSelect.value;
        hostSelect.innerHTML = '<option value="">Todos</option>';
        hosts.forEach(h => {
            hostSelect.innerHTML += `<option value="${h.id}">${h.ip_address}${h.hostname ? ' (' + h.hostname + ')' : ''}</option>`;
        });
        hostSelect.value = currentVal;
    }

    // Load sources filter
    const sources = await apiGet('/logs/sources');
    const sourceSelect = document.getElementById('log-filter-source');
    if (sources && sourceSelect) {
        const currentVal = sourceSelect.value;
        sourceSelect.innerHTML = '<option value="">Todas</option>';
        sources.forEach(s => {
            sourceSelect.innerHTML += `<option value="${s}">${s}</option>`;
        });
        sourceSelect.value = currentVal;
    }
}

async function loadLogEntries() {
    const hostId = document.getElementById('log-filter-host').value;
    const level = document.getElementById('log-filter-level').value;
    const source = document.getElementById('log-filter-source').value;

    let path = `/logs/entries?limit=${LOG_ENTRIES_LIMIT}&offset=${logEntriesOffset}`;
    if (hostId) path += `&host_id=${hostId}`;
    if (level) path += `&level=${level}`;
    if (source) path += `&source=${encodeURIComponent(source)}`;

    const data = await apiGet(path);
    if (!data) return;

    const tbody = document.getElementById('log-entries-body');
    const infoEl = document.getElementById('log-entries-info');

    if (data.entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Nenhum registro de log encontrado</td></tr>';
        infoEl.textContent = 'Total: 0';
    } else {
        tbody.innerHTML = data.entries.map(e => {
            const levelClass = e.level === 'critical' ? 'badge-critical' :
                               e.level === 'error' ? 'badge-high' :
                               e.level === 'warning' ? 'badge-medium' :
                               e.level === 'debug' ? 'badge-low' : 'badge-info';
            return `<tr>
                <td style="white-space:nowrap">${formatDate(e.timestamp)}</td>
                <td><span class="badge ${levelClass}">${e.level}</span></td>
                <td>${e.host_ip || '-'}</td>
                <td>${e.source || '-'}</td>
                <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${(e.message || '').replace(/"/g, '&quot;')}">${e.message || '-'}</td>
            </tr>`;
        }).join('');
        const end = Math.min(logEntriesOffset + LOG_ENTRIES_LIMIT, data.total);
        infoEl.textContent = `Exibindo ${logEntriesOffset + 1}-${end} de ${data.total}`;
    }

    // Pagination buttons
    document.getElementById('log-prev-btn').disabled = logEntriesOffset === 0;
    document.getElementById('log-next-btn').disabled = (logEntriesOffset + LOG_ENTRIES_LIMIT) >= data.total;
}

function logEntriesPage(direction) {
    logEntriesOffset += direction * LOG_ENTRIES_LIMIT;
    if (logEntriesOffset < 0) logEntriesOffset = 0;
    loadLogEntries();
}

async function ingestLogs() {
    const source = document.getElementById('log-source').value.trim() || 'manual';
    const hostIp = document.getElementById('log-host-ip').value.trim() || null;
    const linesText = document.getElementById('log-lines').value.trim();

    if (!linesText) {
        notify('Insira linhas de log', 'error');
        return;
    }

    const lines = linesText.split('\n').filter(l => l.trim());
    const result = await apiPost('/logs/ingest', { source, host_ip: hostIp, lines });

    if (result) {
        notify(`${result.lines_processed} linhas processadas, ${result.threats_found} ameacas encontradas`, 'success');
        document.getElementById('log-lines').value = '';
        loadLogSummary();
    }
}

async function searchLogs() {
    const query = document.getElementById('log-search-query').value.trim();
    if (!query) return;

    const results = await apiGet('/logs/search?q=' + encodeURIComponent(query));
    const container = document.getElementById('log-search-results');

    if (results && results.length > 0) {
        container.innerHTML = results.map(r => {
            return `<div class="log-line">${(r.raw || r.message || '').substring(0, 200)}</div>`;
        }).join('');
    } else {
        container.innerHTML = '<p style="color:var(--text-secondary)">Nenhum resultado encontrado.</p>';
    }
}

// --- Anomalies ---
async function loadAnomalies() {
    const summary = await apiGet('/anomalies/summary');
    const anomalies = await apiGet('/anomalies?hours=24');

    if (summary) {
        document.getElementById('anomaly-stats-grid').innerHTML = `
            <div class="stat-card"><div class="stat-label">Total Anomalias</div><div class="stat-value purple">${summary.total_anomalies}</div></div>
            <div class="stat-card"><div class="stat-label">Metricas Monitoradas</div><div class="stat-value cyan">${summary.monitored_metrics}</div></div>
            <div class="stat-card"><div class="stat-label">Hosts Monitorados</div><div class="stat-value blue">${summary.monitored_hosts}</div></div>
            <div class="stat-card"><div class="stat-label">Criticas</div><div class="stat-value red">${summary.by_severity.critical}</div></div>
        `;
    }

    if (anomalies) {
        const tbody = document.getElementById('anomalies-table-body');
        tbody.innerHTML = anomalies.map(a => `
            <tr>
                <td>${severityBadge(a.severity)}</td>
                <td>${a.host || '-'}</td>
                <td>${a.metric_type}</td>
                <td>${a.description}</td>
                <td>${a.current_value !== undefined ? a.current_value : '-'}</td>
                <td>${formatDate(a.detected_at)}</td>
            </tr>
        `).join('');
    }
}

// --- Topology ---
async function loadTopology() {
    const data = await apiGet('/topology');
    if (!data) return;

    const canvas = document.getElementById('topology-canvas');
    const ctx = canvas.getContext('2d');

    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * 2;
    canvas.height = rect.height * 2;
    ctx.scale(2, 2);

    const width = rect.width;
    const height = rect.height;

    ctx.fillStyle = '#0f1117';
    ctx.fillRect(0, 0, width, height);

    ctx.strokeStyle = 'rgba(46, 51, 72, 0.3)';
    ctx.lineWidth = 0.5;
    for (let x = 0; x < width; x += 40) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    }
    for (let y = 0; y < height; y += 40) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }

    const nodes = data.nodes;
    const edges = data.edges;

    if (nodes.length === 0) {
        ctx.fillStyle = '#8b8fa3';
        ctx.font = '16px Segoe UI';
        ctx.textAlign = 'center';
        ctx.fillText('Nenhum host encontrado. Execute um scan para gerar a topologia.', width / 2, height / 2);
        return;
    }

    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.35;

    nodes.forEach((node, i) => {
        if (node.x === null || node.y === null) {
            const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
            node.x = centerX + radius * Math.cos(angle);
            node.y = centerY + radius * Math.sin(angle);
        }
    });

    const nodeMap = {};
    nodes.forEach(n => nodeMap[n.id] = n);

    edges.forEach(edge => {
        const src = nodeMap[edge.source];
        const tgt = nodeMap[edge.target];
        if (!src || !tgt) return;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = edge.status === 'active' ? 'rgba(6, 182, 212, 0.4)' : 'rgba(239, 68, 68, 0.4)';
        ctx.lineWidth = 2;
        ctx.stroke();

        const midX = (src.x + tgt.x) / 2;
        const midY = (src.y + tgt.y) / 2;
        ctx.fillStyle = '#8b8fa3';
        ctx.font = '9px Segoe UI';
        ctx.textAlign = 'center';
        ctx.fillText(edge.type, midX, midY - 4);
    });

    const typeColors = {
        'server': '#3b82f6', 'workstation': '#10b981', 'router': '#8b5cf6',
        'switch': '#8b5cf6', 'network_device': '#8b5cf6', 'printer': '#f59e0b',
        'firewall': '#ef4444', 'unknown': '#6b7280',
    };
    const typeIcons = {
        'server': 'SRV', 'workstation': 'WKS', 'router': 'RTR', 'switch': 'SW',
        'network_device': 'NET', 'printer': 'PRT', 'firewall': 'FW', 'unknown': '?',
    };

    nodes.forEach(node => {
        const color = typeColors[node.type] || typeColors.unknown;
        const icon = typeIcons[node.type] || '?';
        const hasAlerts = node.alerts > 0;
        const isDown = node.status === 'down';
        const nodeRadius = 28;

        if (hasAlerts) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, nodeRadius + 8, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
            ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, nodeRadius, 0, Math.PI * 2);
        ctx.fillStyle = isDown ? 'rgba(239, 68, 68, 0.3)' : `${color}33`;
        ctx.fill();
        ctx.strokeStyle = isDown ? '#ef4444' : color;
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.fillStyle = isDown ? '#ef4444' : color;
        ctx.font = 'bold 11px Segoe UI';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(icon, node.x, node.y - 4);

        ctx.beginPath();
        ctx.arc(node.x + 18, node.y - 18, 5, 0, Math.PI * 2);
        ctx.fillStyle = node.status === 'up' ? '#10b981' : (node.status === 'down' ? '#ef4444' : '#6b7280');
        ctx.fill();

        ctx.fillStyle = '#e4e6f0';
        ctx.font = '11px Segoe UI';
        ctx.textBaseline = 'top';
        ctx.fillText(node.hostname || node.ip, node.x, node.y + nodeRadius + 4);

        ctx.fillStyle = '#8b8fa3';
        ctx.font = '9px Segoe UI';
        ctx.fillText(node.ip, node.x, node.y + nodeRadius + 18);

        if (node.open_ports > 0) {
            ctx.fillStyle = '#06b6d4';
            ctx.font = '8px Segoe UI';
            ctx.fillText(node.open_ports + ' ports', node.x, node.y + 6);
        }

        let indicators = [];
        if (node.snmp) indicators.push('SNMP');
        if (node.agent) indicators.push('AGT');
        if (indicators.length > 0) {
            ctx.fillStyle = '#8b8fa3';
            ctx.font = '7px Segoe UI';
            ctx.fillText(indicators.join(' | '), node.x, node.y + nodeRadius + 30);
        }
    });

    ctx.fillStyle = '#e4e6f0';
    ctx.font = 'bold 14px Segoe UI';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText('Topologia de Rede - ' + nodes.length + ' hosts', 20, 16);
}

// --- Modal (kept for backward compat) ---
function showModal(title, content) {
    let overlay = document.getElementById('modal-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'modal-overlay';
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3 id="modal-title"></h3>
                    <button class="modal-close" onclick="closeModal()">&times;</button>
                </div>
                <div class="modal-body" id="modal-body"></div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="closeModal()">Fechar</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
    }
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    overlay.classList.add('active');
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay) overlay.classList.remove('active');
}

// --- Auto-refresh ---
let refreshInterval;

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        const activePage = document.querySelector('.page[style*="block"], .page.active');
        if (activePage) {
            const pageId = activePage.id.replace('page-', '');
            if (pageId === 'dashboard') refreshDashboard();
        }
    }, 30000);
}

// --- Initialize ---
document.addEventListener('DOMContentLoaded', () => {
    refreshDashboard();
    startAutoRefresh();
});
