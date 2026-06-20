document.addEventListener('DOMContentLoaded', () => {
    // ─── DOM Elements ───
    const $ = id => document.getElementById(id);
    const apiKeyInput   = $('api-key-input');
    const authBtn       = $('auth-btn');
    const authError     = $('auth-error');
    const authSection   = $('auth-section');
    const scanSection   = $('scan-section');
    const logoutBtn     = $('logout-btn');
    const targetInput   = $('target');
    const targetIcon    = $('target-icon');
    const scanBtn       = $('scan-btn');
    const statusContainer = $('status-container');
    const statusText    = $('scan-status');
    const statusBadge   = $('status-badge');
    const scanTargetDisplay = $('scan-target-display');
    const progressFill  = $('progress-fill');
    const resultsContainer = $('results-container');
    const resultsGrid   = $('results-grid');
    const resultsNote   = $('results-note');
    const filterSeverity = $('filter-severity');
    const filterPlugin  = $('filter-plugin');
    const statTotal     = $('stat-total');
    const statHigh      = $('stat-high');
    const statMedium    = $('stat-medium');
    const statInfo      = $('stat-info');

    let currentScanId = null;
    let pollInterval = null;
    let allFindings = [];

    // ─── Check existing session ───
    const storedApiKey = sessionStorage.getItem('api_key');
    if (storedApiKey) validateStoredSession(storedApiKey);

    // ─── Target type icon detection ───
    targetInput.addEventListener('input', () => {
        const val = targetInput.value.trim();
        if (val.includes('@')) targetIcon.textContent = '📧';
        else if (/^\d+\.\d+\.\d+\.\d+$/.test(val)) targetIcon.textContent = '🔗';
        else if (val.includes('.')) targetIcon.textContent = '🌐';
        else targetIcon.textContent = '👤';
    });

    // ─── Auth ───
    authBtn.addEventListener('click', async () => {
        const key = apiKeyInput.value.trim();
        if (!key) return showAuthError('Please enter an API key.');

        authBtn.disabled = true;
        authBtn.querySelector('span').textContent = 'Verifying...';

        try {
            const res = await fetch('/api/auth/check', {
                headers: { 'X-API-Key': key }
            });
            if (res.status === 401) return showAuthError('Invalid API key.');
            if (!res.ok) return showAuthError('Authentication check failed.');
            sessionStorage.setItem('api_key', key);
            showScanUI();
        } catch {
            showAuthError('Connection failed.');
        } finally {
            authBtn.disabled = false;
            authBtn.querySelector('span').textContent = 'Authenticate';
        }
    });

    apiKeyInput.addEventListener('keydown', e => { if (e.key === 'Enter') authBtn.click(); });

    logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('api_key');
        if (pollInterval) clearInterval(pollInterval);
        authSection.classList.remove('hidden');
        scanSection.classList.add('hidden');
        apiKeyInput.value = '';
        authError.classList.add('hidden');
    });

    function showAuthError(msg) {
        authError.textContent = msg;
        authError.classList.remove('hidden');
    }

    function showScanUI() {
        authSection.classList.add('hidden');
        scanSection.classList.remove('hidden');
    }

    async function validateStoredSession(key) {
        try {
            const res = await fetch('/api/auth/check', {
                headers: { 'X-API-Key': key }
            });
            if (res.ok) {
                showScanUI();
                return;
            }
        } catch {
            // Keep the login screen visible on connection errors.
        }
        sessionStorage.removeItem('api_key');
    }

    function headers() {
        return { 'X-API-Key': sessionStorage.getItem('api_key') || '', 'Content-Type': 'application/json' };
    }

    // ─── Scan ───
    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) return;

        scanBtn.disabled = true;
        scanBtn.querySelector('.btn-text').textContent = 'Scanning...';
        scanBtn.querySelector('.btn-loader').classList.remove('hidden');
        allFindings = [];
        resultsGrid.innerHTML = '';
        resultsNote.classList.add('hidden');
        resultsContainer.classList.add('hidden');
        statusContainer.classList.remove('hidden');
        statusText.textContent = 'Initializing...';
        statusBadge.querySelector('.pulse-dot').className = 'pulse-dot';
        scanTargetDisplay.textContent = target;
        progressFill.className = 'progress-fill active';
        statTotal.textContent = statHigh.textContent = statMedium.textContent = statInfo.textContent = '0';

        try {
            const res = await fetch('/api/scan', { method: 'POST', headers: headers(), body: JSON.stringify({ target }) });
            if (res.status === 401) return location.reload();
            if (!res.ok) {
                const err = await res.json().catch(() => ({ error: 'Scan failed' }));
                throw new Error(err.error);
            }
            const data = await res.json();
            currentScanId = data.scan_id;
            pollInterval = setInterval(pollStatus, 2000);
        } catch (error) {
            statusText.textContent = error.message;
            statusBadge.querySelector('.pulse-dot').className = 'pulse-dot failed';
            progressFill.className = 'progress-fill';
            resetScanBtn();
        }
    });

    targetInput.addEventListener('keydown', e => { if (e.key === 'Enter') scanBtn.click(); });

    function resetScanBtn() {
        scanBtn.disabled = false;
        scanBtn.querySelector('.btn-text').textContent = 'Start Scan';
        scanBtn.querySelector('.btn-loader').classList.add('hidden');
    }

    async function pollStatus() {
        if (!currentScanId) return;
        try {
            const sRes = await fetch(`/api/scans/${currentScanId}`, { headers: { 'X-API-Key': sessionStorage.getItem('api_key') } });
            if (sRes.status === 401) return location.reload();
            if (!sRes.ok) return;
            const sData = await sRes.json();
            const status = (sData.status || '').toLowerCase();
            statusText.textContent = status;

            if (status === 'completed' || status === 'failed') {
                clearInterval(pollInterval);
                progressFill.className = 'progress-fill done';
                statusBadge.querySelector('.pulse-dot').className = `pulse-dot ${status}`;
                resetScanBtn();
            }

            const rRes = await fetch(`/api/scans/${currentScanId}/results`, { headers: { 'X-API-Key': sessionStorage.getItem('api_key') } });
            if (rRes.ok) {
                allFindings = await rRes.json();
                if (rRes.headers.get('x-results-truncated') === 'true') {
                    resultsNote.textContent = 'Showing the latest 1000 findings.';
                    resultsNote.classList.remove('hidden');
                } else {
                    resultsNote.classList.add('hidden');
                }
                updateStats();
                updatePluginFilter();
                renderFindings();
            }
        } catch (e) { console.error(e); }
    }

    // ─── Stats ───
    function updateStats() {
        statTotal.textContent = allFindings.length;
        statHigh.textContent = allFindings.filter(f => sev(f) === 'high').length;
        statMedium.textContent = allFindings.filter(f => sev(f) === 'medium').length;
        statInfo.textContent = allFindings.filter(f => sev(f) === 'info' || sev(f) === 'low').length;
    }

    function sev(f) {
        const severity = (typeof f.severity === 'string' ? f.severity : 'info').toLowerCase();
        return ['critical', 'high', 'medium', 'low', 'info'].includes(severity) ? severity : 'info';
    }

    // ─── Filters ───
    function updatePluginFilter() {
        const plugins = [...new Set(allFindings.map(f => f.plugin_name))].sort();
        const current = filterPlugin.value;
        filterPlugin.innerHTML = '<option value="all">All Plugins</option>';
        plugins.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p;
            opt.textContent = p;
            filterPlugin.appendChild(opt);
        });
        filterPlugin.value = current;
    }

    filterSeverity.addEventListener('change', renderFindings);
    filterPlugin.addEventListener('change', renderFindings);

    // ─── Render Findings ───
    function renderFindings() {
        if (allFindings.length === 0) return;
        resultsContainer.classList.remove('hidden');
        resultsGrid.innerHTML = '';

        const sevFilter = filterSeverity.value;
        const plugFilter = filterPlugin.value;

        const filtered = allFindings.filter(f => {
            if (sevFilter !== 'all' && sev(f) !== sevFilter) return false;
            if (plugFilter !== 'all' && f.plugin_name !== plugFilter) return false;
            return true;
        });

        filtered.forEach(f => resultsGrid.appendChild(createFindingCard(f)));
    }

    // ─── Plugin Icons ───
    const pluginIcons = {
        dns_info: '🔍', subdomain_crtsh: '🌐', http_probe: '📡', email_breach_xon: '💀',
        username_footprint: '👤', port_scanner: '🔌', ip_info: '📍', tech_stack_detector: '⚙️',
        sensitive_files_fuzzer: '📂', security_headers: '🛡️', robots_txt: '🤖',
    };

    function createFindingCard(f) {
        const card = document.createElement('div');
        card.className = 'finding-card';
        const severity = sev(f);
        const icon = pluginIcons[f.plugin_name] || '📋';
        const time = new Date(f.created_at).toLocaleTimeString();
        const pluginName = esc(f.plugin_name || 'unknown');
        const findingType = esc(formatType(f.finding_type || 'unknown'));
        const safeSeverity = esc(severity);
        const safeTime = esc(time);

        card.innerHTML = `
            <div class="finding-top">
                <div class="finding-plugin">${icon} ${pluginName}</div>
                <div class="finding-meta">
                    <span class="finding-time">${safeTime}</span>
                    <span class="severity-badge severity-${severity}">${safeSeverity}</span>
                </div>
            </div>
            <div class="finding-type">${findingType}</div>
            <div class="finding-body">${renderData(f)}</div>
        `;
        return card;
    }

    function formatType(t) {
        return String(t).replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }

    // ─── Smart Data Rendering ───
    function renderData(f) {
        const d = f.data;
        if (!d || typeof d !== 'object') return `<pre>${esc(JSON.stringify(d, null, 2))}</pre>`;

        // Social profiles — clickable links
        if (f.finding_type === 'social_profile') {
            const url = d.profile_url || '';
            const href = safeHttpUrl(url);
            return `
                <div class="finding-row"><span class="finding-key">Platform</span><span class="finding-value">${esc(d.platform || '')}</span></div>
                <div class="finding-row"><span class="finding-key">Username</span><span class="finding-value">${esc(d.username || '')}</span></div>
                <div class="finding-row"><span class="finding-key">Profile</span><span class="finding-value">${href ? `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(url)}</a>` : esc(url)}</span></div>
            `;
        }

        // HTTP response
        if (f.finding_type === 'http_response') {
            const href = safeHttpUrl(d.url || '');
            return `
                <div class="finding-row"><span class="finding-key">URL</span><span class="finding-value">${href ? `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(d.url || '')}</a>` : esc(d.url || '')}</span></div>
                <div class="finding-row"><span class="finding-key">Status</span><span class="finding-value">${esc(String(d.status || ''))}</span></div>
                <div class="finding-row"><span class="finding-key">Server</span><span class="finding-value">${esc(d.server || '')}</span></div>
                <div class="finding-row"><span class="finding-key">WAF</span><span class="finding-value">${esc(d.waf || 'none')}</span></div>
                ${d.title ? `<div class="finding-row"><span class="finding-key">Title</span><span class="finding-value">${esc(d.title)}</span></div>` : ''}
            `;
        }

        // Open ports
        if (f.finding_type === 'open_ports') {
            const ports = (d.open_ports || []).join(', ');
            return `
                <div class="finding-row"><span class="finding-key">Target</span><span class="finding-value">${esc(d.target || '')}</span></div>
                <div class="finding-row"><span class="finding-key">IP</span><span class="finding-value">${esc(d.ip || '')}</span></div>
                <div class="finding-row"><span class="finding-key">Open Ports</span><span class="finding-value">${esc(ports)}</span></div>
            `;
        }

        // Subdomains
        if (f.finding_type === 'subdomain') {
            const sub = d.subdomain || '';
            return `<div class="finding-row"><span class="finding-key">Subdomain</span><span class="finding-value"><a href="https://${esc(sub)}" target="_blank" rel="noopener">${esc(sub)}</a></span></div>`;
        }

        // Data breach
        if (f.finding_type === 'data_breach') {
            const breaches = (d.breaches || []).slice(0, 20);
            return `
                <div class="finding-row"><span class="finding-key">Email</span><span class="finding-value">${esc(d.email || '')}</span></div>
                <div class="finding-row"><span class="finding-key">Breaches</span><span class="finding-value">${breaches.length} found</span></div>
                <ul class="finding-list">${breaches.map(b => `<li>💀 ${esc(b)}</li>`).join('')}</ul>
                ${d.breaches && d.breaches.length > 20 ? `<div class="finding-note">...and ${d.breaches.length - 20} more</div>` : ''}
            `;
        }

        // Security headers
        if (f.finding_type === 'security_headers_audit') {
            let html = `<div class="finding-row"><span class="finding-key">Score</span><span class="finding-value">${esc(d.score || '')}</span></div>`;
            if (d.missing_headers && d.missing_headers.length > 0) {
                html += `<ul class="finding-list">${d.missing_headers.map(h => `<li>❌ ${esc(h.header)} — ${esc(h.description)}</li>`).join('')}</ul>`;
            }
            if (d.present_headers && d.present_headers.length > 0) {
                html += `<ul class="finding-list">${d.present_headers.map(h => `<li>✅ ${esc(h.header)}</li>`).join('')}</ul>`;
            }
            return html;
        }

        // Robots.txt
        if (f.finding_type === 'robots_txt_analysis') {
            let html = `<div class="finding-row"><span class="finding-key">Rules</span><span class="finding-value">${d.total_rules || 0}</span></div>`;
            if (d.interesting_paths && d.interesting_paths.length > 0) {
                html += `<ul class="finding-list">${d.interesting_paths.map(p => `<li>⚠️ ${esc(p)}</li>`).join('')}</ul>`;
            }
            if (d.sitemaps && d.sitemaps.length > 0) {
                html += `<ul class="finding-list">${d.sitemaps.map(s => {
                    const href = safeHttpUrl(s);
                    return `<li>🗺️ ${href ? `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(s)}</a>` : esc(s)}</li>`;
                }).join('')}</ul>`;
            }
            return html;
        }

        // Tech stack
        if (f.finding_type === 'tech_stack') {
            const href = safeHttpUrl(d.url || '');
            return `
                <div class="finding-row"><span class="finding-key">URL</span><span class="finding-value">${href ? `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(d.url || '')}</a>` : esc(d.url || '')}</span></div>
                <ul class="finding-list">${(d.technologies || []).map(t => `<li>⚙️ ${esc(t)}</li>`).join('')}</ul>
            `;
        }

        // Exposed files
        if (f.finding_type === 'exposed_files') {
            return `<ul class="finding-list">${(d.exposed_paths || []).map(p => `<li>📂 <a href="http://${esc(d.target || '')}${esc(p)}" target="_blank" rel="noopener">${esc(p)}</a></li>`).join('')}</ul>`;
        }

        // DNS records
        if (f.finding_type && f.finding_type.endsWith('_record')) {
            const values = d.ips || d.exchanges || d.texts || [];
            return `<ul class="finding-list">${values.map(v => `<li>${esc(v)}</li>`).join('')}</ul>`;
        }

        // IP intelligence
        if (f.finding_type === 'ip_intelligence') {
            return ['country', 'regionName', 'city', 'isp', 'org', 'as', 'query']
                .filter(k => d[k])
                .map(k => `<div class="finding-row"><span class="finding-key">${formatType(k)}</span><span class="finding-value">${esc(String(d[k]))}</span></div>`)
                .join('');
        }

        // Fallback: render all key-value pairs
        return Object.entries(d)
            .map(([k, v]) => {
                const val = typeof v === 'object' ? JSON.stringify(v) : String(v);
                const href = typeof v === 'string' ? safeHttpUrl(v) : '';
                const display = href
                    ? `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(v)}</a>`
                    : esc(val);
                return `<div class="finding-row"><span class="finding-key">${esc(k)}</span><span class="finding-value">${display}</span></div>`;
            }).join('');
    }

    // ─── XSS-safe escape ───
    function esc(s) {
        const el = document.createElement('span');
        el.textContent = s;
        return el.innerHTML;
    }

    function safeHttpUrl(value) {
        try {
            const url = new URL(String(value));
            return ['http:', 'https:'].includes(url.protocol) ? url.href : '';
        } catch {
            return '';
        }
    }
});
