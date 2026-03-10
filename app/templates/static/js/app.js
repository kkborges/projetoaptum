/* AptumNet Dashboard - Frontend Application */

const API = '/api';

// --- Navigation ---
function showPage(page) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const el = document.getElementById('page-' + page);
    if (el) el.style.display = 'block';

    // Find and activate nav item
    document.querySelectorAll('.nav-item').forEach(n => {
        if (n.getAttribute('onclick') && n.getAttribute('onclick').includes(page)) {
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

function severityBadge(severity) {
    return `<span class="badge badge-${severity}">${severity}</span>`;
}

function statusBadge(status) {
    return `<span class="badge badge-${status}">${status}</span>`;
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
        <div class="severity-item"><span class="severity-dot critical"></span> Cr&iacute;tico: ${idsStats.by_severity.critical}</div>
        <div class="severity-item"><span class="severity-dot high"></span> Alto: ${idsStats.by_severity.high}</div>
        <div class="severity-item"><span class="severity-dot medium"></span> M&eacute;dio: ${idsStats.by_severity.medium}</div>
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
        <tr style="cursor:pointer" onclick="viewHost(${h.id})">
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

async function viewHost(hostId) {
    const host = await apiGet('/hosts/' + hostId);
    if (!host) return;

    let html = `<h3>${host.ip_address} - ${host.hostname || 'N/A'}</h3>`;
    html += `<p>Tipo: ${host.host_type} | Status: ${host.status} | OS: ${host.os_detected || 'N/A'}</p>`;
    html += `<p>SNMP: ${host.snmp_enabled ? 'Sim' : 'Nao'} | Agente: ${host.agent_installed ? 'Sim' : 'Nao'}</p>`;

    if (host.ports.length > 0) {
        html += `<h4 style="margin-top:16px">Portas Abertas</h4><table class="data-table"><thead><tr><th>Porta</th><th>Servico</th><th>Estado</th><th>Banner</th></tr></thead><tbody>`;
        host.ports.filter(p => p.state === 'open').forEach(p => {
            html += `<tr><td>${p.port}/${p.protocol}</td><td>${p.service || '-'}</td><td>${statusBadge(p.state)}</td><td>${(p.banner || '-').substring(0, 60)}</td></tr>`;
        });
        html += `</tbody></table>`;
    }

    if (host.recent_metrics.length > 0) {
        html += `<h4 style="margin-top:16px">Metricas Recentes</h4><table class="data-table"><thead><tr><th>Tipo</th><th>Valor</th><th>Coletado em</th></tr></thead><tbody>`;
        host.recent_metrics.slice(0, 10).forEach(m => {
            html += `<tr><td>${m.type}</td><td>${m.value}${m.unit || ''}</td><td>${formatDate(m.collected_at)}</td></tr>`;
        });
        html += `</tbody></table>`;
    }

    showModal('Detalhes do Host', html);
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
        // Show results panel
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
            const cls = r.log_type === 'unknown' ? '' : r.log_type;
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

    // Set canvas resolution
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * 2;
    canvas.height = rect.height * 2;
    ctx.scale(2, 2);

    const width = rect.width;
    const height = rect.height;

    // Clear
    ctx.fillStyle = '#0f1117';
    ctx.fillRect(0, 0, width, height);

    // Draw grid
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

    // Auto-layout: arrange nodes in a circle or use saved positions
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

    // Create node map for quick lookup
    const nodeMap = {};
    nodes.forEach(n => nodeMap[n.id] = n);

    // Draw edges
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

        // Edge type label
        const midX = (src.x + tgt.x) / 2;
        const midY = (src.y + tgt.y) / 2;
        ctx.fillStyle = '#8b8fa3';
        ctx.font = '9px Segoe UI';
        ctx.textAlign = 'center';
        ctx.fillText(edge.type, midX, midY - 4);
    });

    // Draw nodes
    const typeColors = {
        'server': '#3b82f6',
        'workstation': '#10b981',
        'router': '#8b5cf6',
        'switch': '#8b5cf6',
        'network_device': '#8b5cf6',
        'printer': '#f59e0b',
        'firewall': '#ef4444',
        'unknown': '#6b7280',
    };

    const typeIcons = {
        'server': 'SRV',
        'workstation': 'WKS',
        'router': 'RTR',
        'switch': 'SW',
        'network_device': 'NET',
        'printer': 'PRT',
        'firewall': 'FW',
        'unknown': '?',
    };

    nodes.forEach(node => {
        const color = typeColors[node.type] || typeColors.unknown;
        const icon = typeIcons[node.type] || '?';
        const hasAlerts = node.alerts > 0;
        const isDown = node.status === 'down';
        const nodeRadius = 28;

        // Glow for alerts
        if (hasAlerts) {
            ctx.beginPath();
            ctx.arc(node.x, node.y, nodeRadius + 8, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(239, 68, 68, 0.15)';
            ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, nodeRadius, 0, Math.PI * 2);
        ctx.fillStyle = isDown ? 'rgba(239, 68, 68, 0.3)' : `${color}33`;
        ctx.fill();
        ctx.strokeStyle = isDown ? '#ef4444' : color;
        ctx.lineWidth = 2;
        ctx.stroke();

        // Type icon
        ctx.fillStyle = isDown ? '#ef4444' : color;
        ctx.font = 'bold 11px Segoe UI';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(icon, node.x, node.y - 4);

        // Status indicator
        ctx.beginPath();
        ctx.arc(node.x + 18, node.y - 18, 5, 0, Math.PI * 2);
        ctx.fillStyle = node.status === 'up' ? '#10b981' : (node.status === 'down' ? '#ef4444' : '#6b7280');
        ctx.fill();

        // Labels
        ctx.fillStyle = '#e4e6f0';
        ctx.font = '11px Segoe UI';
        ctx.textBaseline = 'top';
        ctx.fillText(node.hostname || node.ip, node.x, node.y + nodeRadius + 4);

        ctx.fillStyle = '#8b8fa3';
        ctx.font = '9px Segoe UI';
        ctx.fillText(node.ip, node.x, node.y + nodeRadius + 18);

        // Port count
        if (node.open_ports > 0) {
            ctx.fillStyle = '#06b6d4';
            ctx.font = '8px Segoe UI';
            ctx.fillText(node.open_ports + ' ports', node.x, node.y + 6);
        }

        // SNMP/Agent indicators
        let indicators = [];
        if (node.snmp) indicators.push('SNMP');
        if (node.agent) indicators.push('AGT');
        if (indicators.length > 0) {
            ctx.fillStyle = '#8b8fa3';
            ctx.font = '7px Segoe UI';
            ctx.fillText(indicators.join(' | '), node.x, node.y + nodeRadius + 30);
        }
    });

    // Title
    ctx.fillStyle = '#e4e6f0';
    ctx.font = 'bold 14px Segoe UI';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText('Topologia de Rede - ' + nodes.length + ' hosts', 20, 16);
}

// --- Modal ---
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
    }, 30000); // Refresh every 30 seconds
}

// --- Initialize ---
document.addEventListener('DOMContentLoaded', () => {
    refreshDashboard();
    startAutoRefresh();
});
