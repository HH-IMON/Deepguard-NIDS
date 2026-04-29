/* ═══════════════════════════════════════════
   DeepGuard NIDS — Dashboard Controller
   ═══════════════════════════════════════════ */
const API = '';
let pollTimer = null;
let feedIndex = 0;
let trafficChart = null, attackChart = null, evalChart = null, featureChart = null;

// ── INIT ──
window.addEventListener('DOMContentLoaded', async () => {
    await loadStats();
    await loadModels();
    setTimeout(() => document.getElementById('loading-overlay').classList.add('hidden'), 800);
    startPolling();
});

// ── THEME ──
function toggleTheme() {
    const html = document.documentElement;
    const isDark = html.getAttribute('data-theme') === 'dark';
    html.setAttribute('data-theme', isDark ? 'light' : 'dark');
    document.getElementById('theme-icon').textContent = isDark ? '☀️' : '🌙';
    updateChartColors();
}

// ── TABS ──
function switchTab(tab) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.getElementById('panel-' + tab).classList.add('active');
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
    if (tab === 'alerts') loadAlerts();
    if (tab === 'traffic') loadTraffic();
    if (tab === 'blocking') { loadBlockedIPs(); loadThreats(); }
    if (tab === 'evaluation') loadEvaluation();
    if (tab === 'explainability') loadFeatureImportance();
}

// ── POLLING ──
function startPolling() { pollTimer = setInterval(poll, 2000); }
async function poll() {
    await loadStats();
    await loadLiveFeed();
}

// ── API HELPERS ──
async function apiGet(path) {
    const r = await fetch(API + path);
    return r.json();
}
async function apiPost(path, body) {
    const r = await fetch(API + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return r.json();
}
async function apiDelete(path) {
    const r = await fetch(API + path, { method: 'DELETE' });
    return r.json();
}

// ── SIMULATION ──
async function startSimulation() {
    await apiPost('/api/simulation/start');
    document.getElementById('btn-start-sim').style.display = 'none';
    document.getElementById('btn-stop-sim').style.display = 'inline-flex';
    document.getElementById('sim-status-text').textContent = 'Running';
    document.querySelector('.status-dot').className = 'status-dot status-active';
    showToast('Detection engine started', 'success');
}
async function stopSimulation() {
    await apiPost('/api/simulation/stop');
    document.getElementById('btn-start-sim').style.display = 'inline-flex';
    document.getElementById('btn-stop-sim').style.display = 'none';
    document.getElementById('sim-status-text').textContent = 'Idle';
    document.querySelector('.status-dot').className = 'status-dot status-inactive';
    showToast('Detection engine stopped', 'info');
}

// ── STATS ──
async function loadStats() {
    try {
        const d = await apiGet('/api/stats');
        animateNumber('stat-total-traffic', d.total_traffic);
        animateNumber('stat-total-attacks', d.total_attacks);
        animateNumber('stat-total-blocked', d.total_blocked);
        animateNumber('stat-pending-alerts', d.pending_alerts);
        document.getElementById('alert-badge').textContent = d.pending_alerts;
        document.getElementById('ts-rate').textContent = d.detection_rate + '%';
        if (d.simulation && d.simulation.is_running) {
            document.getElementById('btn-start-sim').style.display = 'none';
            document.getElementById('btn-stop-sim').style.display = 'inline-flex';
            document.getElementById('sim-status-text').textContent = 'Running';
            document.querySelector('.status-dot').className = 'status-dot status-active';
        }
        updateThreatGauge(d.threat_level);
        updateTrafficChart(d);
        updateAttackChart(d.attack_breakdown);
    } catch (e) { console.error('Stats error:', e); }
}

// ── THREAT GAUGE ──
function updateThreatGauge(t) {
    if (!t) return;
    const arc = document.getElementById('gauge-arc');
    const maxDash = 251;
    const offset = maxDash - (maxDash * t.score / 100);
    arc.setAttribute('stroke-dashoffset', offset);
    document.getElementById('gauge-value-text').textContent = t.level.toUpperCase();
    document.getElementById('gauge-score-text').textContent = 'Score: ' + t.score;
    document.getElementById('ts-active').textContent = t.active_threats || 0;
    document.getElementById('ts-critical').textContent = t.critical_threats || 0;
}

// ── TRAFFIC CHART ──
function updateTrafficChart(d) {
    const ctx = document.getElementById('chart-traffic');
    if (!trafficChart) {
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'Total Traffic', data: [], borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,.1)', fill: true, tension: .4 },
                    { label: 'Attacks', data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,.1)', fill: true, tension: .4 }
                ]
            },
            options: chartOptions('Packets')
        });
    }
    const now = new Date().toLocaleTimeString();
    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(d.total_traffic);
    trafficChart.data.datasets[1].data.push(d.total_attacks);
    if (trafficChart.data.labels.length > 30) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets.forEach(ds => ds.data.shift());
    }
    trafficChart.update('none');
}

// ── ATTACK CHART ──
function updateAttackChart(breakdown) {
    if (!breakdown || Object.keys(breakdown).length === 0) return;
    const ctx = document.getElementById('chart-attacks');
    const labels = Object.keys(breakdown);
    const data = Object.values(breakdown);
    const colors = ['#ef4444','#f59e0b','#6366f1','#06b6d4','#10b981','#8b5cf6','#ec4899'];
    if (!attackChart) {
        attackChart = new Chart(ctx, {
            type: 'doughnut',
            data: { labels, datasets: [{ data, backgroundColor: colors.slice(0, labels.length), borderWidth: 0 }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } } } }
        });
    } else {
        attackChart.data.labels = labels;
        attackChart.data.datasets[0].data = data;
        attackChart.update('none');
    }
}

// ── LIVE FEED ──
async function loadLiveFeed() {
    try {
        const d = await apiGet('/api/live-feed?since=' + feedIndex);
        if (d.events && d.events.length > 0) {
            const feed = document.getElementById('live-feed');
            const placeholder = feed.querySelector('.feed-placeholder');
            if (placeholder) placeholder.remove();
            d.events.forEach(e => {
                const div = document.createElement('div');
                div.className = 'feed-item ' + (e.is_attack ? 'feed-attack' : 'feed-normal');
                const time = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '--';
                div.innerHTML = `<span class="feed-time">${time}</span><span class="feed-ip">${e.source_ip}</span>→<span class="feed-ip">${e.destination_ip}</span><span class="sev-badge sev-${e.is_attack ? e.severity : 'normal'} feed-pred">${e.prediction}</span><span style="color:var(--text3)">${(e.confidence*100).toFixed(1)}%</span>`;
                feed.insertBefore(div, feed.firstChild);
                if (feed.children.length > 50) feed.removeChild(feed.lastChild);
            });
            feedIndex = d.index;
        }
    } catch (e) { console.error('Feed error:', e); }
}

// ── ALERTS ──
async function loadAlerts() {
    try {
        const filter = document.getElementById('alert-filter')?.value || '';
        const url = filter ? `/api/alerts?status=${filter}` : '/api/alerts';
        const d = await apiGet(url);
        const tbody = document.getElementById('alerts-tbody');
        tbody.innerHTML = d.alerts.map(a => `<tr>
            <td>#${a.id}</td>
            <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
            <td style="white-space:normal;max-width:400px">${a.message}</td>
            <td><span class="sev-badge ${a.status==='new'?'sev-high':'sev-safe'}">${a.status}</span></td>
            <td>${new Date(a.timestamp).toLocaleString()}</td>
            <td>${a.status==='new'?`<button class="btn btn-sm btn-outline-success" onclick="ackAlert(${a.id})">Acknowledge</button>`:'-'}</td>
        </tr>`).join('');
    } catch(e) { console.error('Alerts error:', e); }
}
async function ackAlert(id) {
    await apiPost(`/api/alerts/${id}/acknowledge`);
    loadAlerts();
    showToast('Alert acknowledged', 'success');
}

// ── TRAFFIC LOGS ──
async function loadTraffic() {
    try {
        const attackOnly = document.getElementById('attack-only-filter')?.checked;
        const url = `/api/traffic?limit=200${attackOnly?'&attack_only=true':''}`;
        const d = await apiGet(url);
        const tbody = document.getElementById('traffic-tbody');
        tbody.innerHTML = d.traffic.map(t => `<tr>
            <td style="font-family:var(--mono);color:var(--accent2)">${t.source_ip}</td>
            <td style="font-family:var(--mono)">${t.destination_ip}</td>
            <td>${t.protocol}</td>
            <td>${t.destination_port}</td>
            <td>${t.packet_size}B</td>
            <td><span class="sev-badge sev-${t.is_attack?'high':'normal'}">${t.prediction}</span></td>
            <td>${(t.confidence*100).toFixed(1)}%</td>
            <td style="font-size:.7rem;color:var(--text3)">${t.model_used}</td>
            <td>${new Date(t.timestamp).toLocaleTimeString()}</td>
        </tr>`).join('');
    } catch(e) { console.error('Traffic error:', e); }
}

// ── BLOCKED IPS ──
async function loadBlockedIPs() {
    try {
        const d = await apiGet('/api/blocked-ips');
        const tbody = document.getElementById('blocked-tbody');
        tbody.innerHTML = d.blocked_ips.length ? d.blocked_ips.map(b => `<tr>
            <td>#${b.id}</td>
            <td style="font-family:var(--mono);color:var(--danger)">${b.ip_address}</td>
            <td>${b.reason||'-'}</td>
            <td>${new Date(b.blocked_at).toLocaleString()}</td>
            <td><button class="btn btn-sm btn-outline-success" onclick="unblockIP(${b.id})">Unblock</button></td>
        </tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text3)">No IPs blocked yet</td></tr>';
    } catch(e) { console.error('Blocked error:', e); }
}
async function blockIP(e) {
    e.preventDefault();
    const ip = document.getElementById('block-ip-input').value.trim();
    const reason = document.getElementById('block-reason-input').value.trim();
    if (!ip) return;
    const r = await apiPost('/api/block-ip', { ip_address: ip, reason });
    if (r.success) { showToast(`Blocked ${ip}`, 'success'); document.getElementById('block-ip-input').value = ''; loadBlockedIPs(); }
    else showToast(r.error || 'Failed to block IP', 'error');
}
async function unblockIP(id) {
    const r = await apiDelete(`/api/block-ip/${id}`);
    if (r.success) { showToast(`Unblocked ${r.unblocked_ip}`, 'info'); loadBlockedIPs(); }
}

// ── THREATS ──
async function loadThreats() {
    try {
        const d = await apiGet('/api/threats');
        const list = document.getElementById('threat-list');
        if (d.threats.length === 0) { list.innerHTML = '<div class="feed-placeholder">No threats detected yet</div>'; return; }
        list.innerHTML = d.threats.slice(0, 20).map(t => `<div class="threat-item" onclick="document.getElementById('block-ip-input').value='${t.ip}'">
            <div><span class="threat-item-ip">${t.ip}</span><div class="threat-item-info">${t.types.join(', ')}</div></div>
            <span class="threat-item-strikes">${t.strikes} strikes</span>
        </div>`).join('');
    } catch(e) { console.error('Threats error:', e); }
}

// ── MODELS ──
async function loadModels() {
    try {
        const d = await apiGet('/api/models');
        document.getElementById('model-select').value = d.active_model;
    } catch(e) {}
}
async function switchModel(modelId) {
    const r = await apiPost('/api/models/switch', { model_id: modelId });
    if (r.success) showToast(`Switched to ${modelId.replace('_',' ')}`, 'info');
}

// ── EVALUATION ──
async function loadEvaluation() {
    try {
        const d = await apiGet('/api/evaluation');
        const grid = document.getElementById('eval-grid');
        const models = d.evaluations;
        grid.innerHTML = Object.entries(models).map(([id, m]) => `
            <div class="eval-card">
                <div class="eval-card-title">${id.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase())}</div>
                <div class="eval-card-type">${m.description ? m.description.substring(0,60)+'...' : ''}</div>
                <div class="eval-metrics">
                    <div class="eval-metric"><span class="eval-metric-value" style="color:var(--primary2)">${(m.accuracy*100).toFixed(1)}%</span><span class="eval-metric-label">Accuracy</span></div>
                    <div class="eval-metric"><span class="eval-metric-value" style="color:var(--accent2)">${(m.precision*100).toFixed(1)}%</span><span class="eval-metric-label">Precision</span></div>
                    <div class="eval-metric highlight"><span class="eval-metric-value" style="color:var(--success)">${(m.recall*100).toFixed(1)}%</span><span class="eval-metric-label">Recall ★</span></div>
                    <div class="eval-metric"><span class="eval-metric-value" style="color:var(--warning)">${(m.f1_score*100).toFixed(1)}%</span><span class="eval-metric-label">F1 Score</span></div>
                    <div class="eval-metric highlight"><span class="eval-metric-value" style="color:var(--danger)">${(m.false_positive_rate*100).toFixed(2)}%</span><span class="eval-metric-label">FPR ★</span></div>
                    <div class="eval-metric"><span class="eval-metric-value" style="color:var(--text3)">${m.inference_time}</span><span class="eval-metric-label">Inference</span></div>
                </div>
            </div>`).join('');
        renderEvalComparison(models);
        renderConfusionMatrix('random_forest');
    } catch(e) { console.error('Eval error:', e); }
}

function renderEvalComparison(models) {
    const ctx = document.getElementById('chart-eval-comparison');
    const labels = Object.keys(models).map(k => k.replace(/_/g,' '));
    const metrics = ['accuracy','precision','recall','f1_score'];
    const colors = ['#6366f1','#06b6d4','#10b981','#f59e0b'];
    const datasets = metrics.map((m, i) => ({
        label: m.replace('_',' ').replace(/\b\w/g,c=>c.toUpperCase()),
        data: Object.values(models).map(v => (v[m]*100).toFixed(1)),
        backgroundColor: colors[i] + '33',
        borderColor: colors[i],
        borderWidth: 2,
        pointRadius: 4
    }));
    if (evalChart) evalChart.destroy();
    evalChart = new Chart(ctx, {
        type: 'radar',
        data: { labels, datasets },
        options: { responsive: true, maintainAspectRatio: false, scales: { r: { beginAtZero: false, min: 90, max: 100, ticks: { stepSize: 2, color: '#64748b' }, grid: { color: 'rgba(255,255,255,.08)' }, pointLabels: { color: '#94a3b8', font: { size: 11 } } } }, plugins: { legend: { labels: { color: '#94a3b8' } } } }
    });
}

function renderConfusionMatrix(modelId) {
    fetch(API + '/api/evaluation?model_id=' + modelId).then(r => r.json()).then(d => {
        const cm = d.metrics.confusion_matrix;
        if (!cm) return;
        const grid = document.getElementById('confusion-grid');
        grid.innerHTML = `
            <div class="cm-cell cm-tn">${cm[0][0]}<span class="cm-label">True Neg</span></div>
            <div class="cm-cell cm-fp">${cm[0][1]}<span class="cm-label">False Pos</span></div>
            <div class="cm-cell cm-fn">${cm[1][0]}<span class="cm-label">False Neg</span></div>
            <div class="cm-cell cm-tp">${cm[1][1]}<span class="cm-label">True Pos</span></div>`;
    });
}

// ── FEATURE IMPORTANCE ──
async function loadFeatureImportance(modelId) {
    try {
        const mid = modelId || 'random_forest';
        const d = await apiGet('/api/feature-importance?model_id=' + mid);
        const features = d.features;
        const sorted = Object.entries(features).sort((a,b) => b[1] - a[1]);
        const labels = sorted.map(s => s[0]);
        const values = sorted.map(s => (s[1]*100).toFixed(1));
        const ctx = document.getElementById('chart-feature-importance');
        if (featureChart) featureChart.destroy();
        featureChart = new Chart(ctx, {
            type: 'bar',
            data: { labels, datasets: [{ label: 'Importance %', data: values, backgroundColor: labels.map((_,i) => `hsl(${220+i*15},70%,60%)`), borderRadius: 4 }] },
            options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,.05)' } }, y: { ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }, grid: { display: false } } } }
        });
        // SHAP visualization
        const shapContainer = document.getElementById('shap-container');
        shapContainer.innerHTML = '<h4 style="margin-bottom:8px;font-size:.85rem;color:var(--text2)">SHAP-style Feature Attribution</h4>' + sorted.map(([name, val]) => {
            const pct = (val * 100).toFixed(1);
            const isTop = val > 0.1;
            return `<div class="shap-bar"><span class="shap-label">${name}</span><div class="shap-bar-track"><div class="shap-bar-fill ${isTop?'shap-positive':'shap-negative'}" style="width:${pct}%">${pct}%</div></div></div>`;
        }).join('');
        // Decision explanation
        const dec = document.getElementById('decision-explanation');
        const top3 = sorted.slice(0,3);
        dec.innerHTML = `<p>For the <strong>${mid.replace(/_/g,' ')}</strong> model, the top decision factors are:</p><ol style="margin:8px 0 0 20px">${top3.map(([n,v]) => `<li><strong>${n}</strong> (${(v*100).toFixed(1)}% importance) — This feature captures ${getFeatureDesc(n)}</li>`).join('')}</ol><p style="margin-top:12px">Features with <strong>high importance</strong> (red bars) push the model toward attack classification, while features with <strong>lower importance</strong> (green bars) contribute less to the decision boundary.</p>`;
    } catch(e) { console.error('Feature error:', e); }
}
function getFeatureDesc(name) {
    const descs = { dst_port:'the destination port, which is critical for identifying service-targeted attacks', packet_size:'the packet payload size, indicative of DoS/DDoS flooding patterns', protocol:'the network protocol type (TCP/UDP/ICMP), helping distinguish attack vectors', src_port:'the source port, useful for detecting ephemeral port scanning', ttl:'time-to-live value, which can reveal spoofed packets', flow_duration:'how long a network flow lasts, key for detecting persistent threats', flag_syn:'SYN flag presence, essential for detecting SYN flood attacks', flag_ack:'ACK flag presence, used in detecting ACK-based amplification', payload_entropy:'the randomness of payload data, high entropy may indicate encrypted C2 traffic', inter_arrival_time:'time between packets, useful for detecting automated attack tools', window_size:'TCP window size, which can be fingerprinted for attack tools' };
    return descs[name] || 'network traffic characteristics that contribute to classification decisions';
}

// ── HELPERS ──
function chartOptions(yLabel) {
    return { responsive: true, maintainAspectRatio: false, interaction: { intersect: false, mode: 'index' }, plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } }, scales: { x: { ticks: { color: '#64748b', maxTicksLimit: 10, font: { size: 10 } }, grid: { color: 'rgba(255,255,255,.05)' } }, y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,.05)' }, title: { display: true, text: yLabel, color: '#64748b' } } } };
}
function animateNumber(id, target) {
    const el = document.getElementById(id);
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;
    const diff = target - current;
    const step = Math.ceil(Math.abs(diff) / 20);
    let val = current;
    const interval = setInterval(() => {
        val += diff > 0 ? step : -step;
        if ((diff > 0 && val >= target) || (diff < 0 && val <= target)) { val = target; clearInterval(interval); }
        el.textContent = val.toLocaleString();
    }, 30);
}
function showToast(msg, type = 'info') {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => t.remove(), 4000);
}
function updateChartColors() {
    [trafficChart, attackChart, evalChart, featureChart].forEach(c => { if(c) c.update(); });
}
