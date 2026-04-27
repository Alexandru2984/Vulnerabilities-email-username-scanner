document.addEventListener('DOMContentLoaded', () => {
    const apiKeyInput = document.getElementById('api-key-input');
    const authBtn = document.getElementById('auth-btn');
    const authError = document.getElementById('auth-error');
    const authSection = document.getElementById('auth-section');
    const scanSection = document.getElementById('scan-section');
    const logoutBtn = document.getElementById('logout-btn');
    const targetInput = document.getElementById('target');
    const scanBtn = document.getElementById('scan-btn');
    const statusContainer = document.getElementById('status-container');
    const statusText = document.getElementById('scan-status');
    const loader = document.getElementById('loader');
    const resultsContainer = document.getElementById('results-container');
    const resultsBody = document.getElementById('results-body');

    let currentScanId = null;
    let pollInterval = null;

    // Check for existing session
    const storedKey = sessionStorage.getItem('api_key');
    if (storedKey) {
        showScanUI();
    }

    // --- Authentication ---
    authBtn.addEventListener('click', async () => {
        const key = apiKeyInput.value.trim();
        if (!key) {
            showAuthError('Please enter an API key.');
            return;
        }

        authBtn.disabled = true;
        authBtn.textContent = 'Verifying...';

        try {
            // Verify the key by hitting the health endpoint with auth
            const res = await fetch('/api/scans/00000000-0000-0000-0000-000000000000', {
                headers: { 'X-API-Key': key }
            });

            if (res.status === 401) {
                showAuthError('Invalid API key.');
                return;
            }

            // Key is valid (404 for scan not found means auth passed)
            sessionStorage.setItem('api_key', key);
            showScanUI();
        } catch (err) {
            showAuthError('Connection failed. Please try again.');
        } finally {
            authBtn.disabled = false;
            authBtn.textContent = 'Authenticate';
        }
    });

    apiKeyInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') authBtn.click();
    });

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

    function getApiKey() {
        return sessionStorage.getItem('api_key') || '';
    }

    function authHeaders() {
        return {
            'X-API-Key': getApiKey(),
            'Content-Type': 'application/json',
        };
    }

    // --- Scan ---
    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) return;

        scanBtn.disabled = true;
        resultsBody.innerHTML = '';
        resultsContainer.classList.add('hidden');
        statusContainer.classList.remove('hidden');
        statusText.innerText = 'Initializing...';
        statusText.style.color = 'var(--accent-color)';
        loader.style.display = 'block';

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: authHeaders(),
                body: JSON.stringify({ target })
            });

            if (res.status === 401) {
                sessionStorage.removeItem('api_key');
                location.reload();
                return;
            }

            if (!res.ok) {
                const errData = await res.json().catch(() => ({ error: 'Failed to start scan' }));
                throw new Error(errData.error || 'Failed to start scan');
            }

            const data = await res.json();
            currentScanId = data.scan_id;
            pollInterval = setInterval(pollStatus, 2000);
            
        } catch (error) {
            statusText.innerText = error.message || 'Error starting scan';
            statusText.style.color = '#f85149';
            loader.style.display = 'none';
            scanBtn.disabled = false;
        }
    });

    targetInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') scanBtn.click();
    });

    async function pollStatus() {
        if (!currentScanId) return;

        try {
            const statusRes = await fetch(`/api/scans/${currentScanId}`, {
                headers: { 'X-API-Key': getApiKey() }
            });

            if (statusRes.status === 401) {
                sessionStorage.removeItem('api_key');
                location.reload();
                return;
            }

            if (!statusRes.ok) throw new Error('Failed to fetch status');
            const statusData = await statusRes.json();

            statusText.innerText = statusData.status;

            if (statusData.status === 'completed' || statusData.status === 'failed') {
                clearInterval(pollInterval);
                loader.style.display = 'none';
                scanBtn.disabled = false;
                statusText.style.color = statusData.status === 'completed' ? '#3fb950' : '#f85149';
            }

            const resultsRes = await fetch(`/api/scans/${currentScanId}/results`, {
                headers: { 'X-API-Key': getApiKey() }
            });
            if (resultsRes.ok) {
                const findings = await resultsRes.json();
                renderFindings(findings);
            }

        } catch (error) {
            console.error(error);
        }
    }

    const severityColors = {
        info: '#8b949e',
        low: '#58a6ff',
        medium: '#d29922',
        high: '#f85149',
        critical: '#ff3333',
    };

    function renderFindings(findings) {
        if (findings.length === 0) return;
        
        resultsContainer.classList.remove('hidden');
        resultsBody.innerHTML = '';

        findings.forEach(f => {
            const tr = document.createElement('tr');
            
            const date = new Date(f.created_at).toLocaleTimeString();
            const dataStr = JSON.stringify(f.data, null, 2);
            const severity = (typeof f.severity === 'string' ? f.severity : 'info').toLowerCase();

            const tdDate = document.createElement('td');
            tdDate.textContent = date;

            const tdPlugin = document.createElement('td');
            const spanPlugin = document.createElement('span');
            spanPlugin.style.color = 'var(--accent-color)';
            spanPlugin.textContent = f.plugin_name;
            tdPlugin.appendChild(spanPlugin);

            const tdType = document.createElement('td');
            tdType.textContent = f.finding_type;

            const tdSeverity = document.createElement('td');
            const severityBadge = document.createElement('span');
            severityBadge.className = 'severity-badge';
            severityBadge.textContent = severity;
            severityBadge.style.color = severityColors[severity] || '#8b949e';
            severityBadge.style.borderColor = severityColors[severity] || '#8b949e';
            tdSeverity.appendChild(severityBadge);

            const tdData = document.createElement('td');
            const preData = document.createElement('pre');
            preData.textContent = dataStr;
            tdData.appendChild(preData);

            tr.appendChild(tdDate);
            tr.appendChild(tdPlugin);
            tr.appendChild(tdType);
            tr.appendChild(tdSeverity);
            tr.appendChild(tdData);
            
            resultsBody.appendChild(tr);
        });
    }
});
