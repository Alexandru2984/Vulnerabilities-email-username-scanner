document.addEventListener('DOMContentLoaded', () => {
    const targetInput = document.getElementById('target');
    const scanBtn = document.getElementById('scan-btn');
    const statusContainer = document.getElementById('status-container');
    const statusText = document.getElementById('scan-status');
    const loader = document.getElementById('loader');
    const resultsContainer = document.getElementById('results-container');
    const resultsBody = document.getElementById('results-body');

    let currentScanId = null;
    let pollInterval = null;

    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) return;

        // Reset UI
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target })
            });

            if (!res.ok) throw new Error('Failed to start scan');

            const data = await res.json();
            currentScanId = data.scan_id;
            
            // Start polling
            pollInterval = setInterval(pollStatus, 2000);
            
        } catch (error) {
            console.error(error);
            statusText.innerText = 'Error starting scan';
            statusText.style.color = '#f85149';
            loader.style.display = 'none';
            scanBtn.disabled = false;
        }
    });

    async function pollStatus() {
        if (!currentScanId) return;

        try {
            // Check status
            const statusRes = await fetch(`/api/scans/${currentScanId}`);
            if (!statusRes.ok) throw new Error('Failed to fetch status');
            const statusData = await statusRes.json();

            statusText.innerText = statusData.status;

            if (statusData.status === 'completed' || statusData.status === 'failed') {
                clearInterval(pollInterval);
                loader.style.display = 'none';
                scanBtn.disabled = false;
                if(statusData.status === 'completed') {
                    statusText.style.color = '#3fb950';
                } else {
                    statusText.style.color = '#f85149';
                }
            }

            // Fetch and update results
            const resultsRes = await fetch(`/api/scans/${currentScanId}/results`);
            if (resultsRes.ok) {
                const findings = await resultsRes.json();
                renderFindings(findings);
            }

        } catch (error) {
            console.error(error);
        }
    }

    function renderFindings(findings) {
        if (findings.length === 0) return;
        
        resultsContainer.classList.remove('hidden');
        resultsBody.innerHTML = '';

        findings.forEach(f => {
            const tr = document.createElement('tr');
            
            const date = new Date(f.created_at).toLocaleTimeString();
            const dataStr = JSON.stringify(f.data, null, 2);

            const tdDate = document.createElement('td');
            tdDate.textContent = date;

            const tdPlugin = document.createElement('td');
            const spanPlugin = document.createElement('span');
            spanPlugin.style.color = 'var(--accent-color)';
            spanPlugin.textContent = f.plugin_name;
            tdPlugin.appendChild(spanPlugin);

            const tdType = document.createElement('td');
            tdType.textContent = f.finding_type;

            const tdData = document.createElement('td');
            const preData = document.createElement('pre');
            preData.textContent = dataStr;
            tdData.appendChild(preData);

            tr.appendChild(tdDate);
            tr.appendChild(tdPlugin);
            tr.appendChild(tdType);
            tr.appendChild(tdData);
            
            resultsBody.appendChild(tr);
        });
    }
});
