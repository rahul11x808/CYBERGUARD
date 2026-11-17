document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('target-url');
    const analyzeBtn = document.getElementById('analyze-headers-btn');
    const statusEl = document.getElementById('header-status');
    const scorePill = document.getElementById('header-score-pill');
    const emptyState = document.getElementById('header-empty-state');
    const resultsContainer = document.getElementById('header-results-container');
    const checklistGrid = document.getElementById('checklist-grid');
    const rawHeadersBody = document.getElementById('raw-headers-body');

    function showStatus(msg, type = '') {
        statusEl.textContent = msg;
        statusEl.className = `status-message ${type}`;
        statusEl.hidden = !msg;
    }

    analyzeBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            showStatus('Please enter a target URL (e.g. https://google.com).', 'error');
            return;
        }

        showStatus('Scanning server headers and evaluating security policies...', '');
        analyzeBtn.disabled = true;

        try {
            const res = await fetch('/security_tools/api/headers/inspect/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            const data = await res.json();

            if (!data.success) {
                showStatus(data.error || 'Failed to inspect headers.', 'error');
                return;
            }

            // Score Pill
            const score = data.score_percent;
            let scoreClass = 'score-bad';
            if (score >= 80) scoreClass = 'score-good';
            else if (score >= 50) scoreClass = 'score-medium';

            scorePill.innerHTML = `
                <span class="score-badge ${scoreClass}">
                    🛡️ ${score}% (${data.present_count}/${data.total_count} Security Headers)
                </span>
            `;

            // Security Checklist
            checklistGrid.innerHTML = '';
            data.security_checklist.forEach(item => {
                const itemDiv = document.createElement('div');
                itemDiv.className = 'checklist-item';
                itemDiv.innerHTML = `
                    <div class="checklist-header">
                        <span class="checklist-title">${item.header}</span>
                        <span class="checklist-status ${item.present ? 'status-present' : 'status-missing'}">
                            ${item.present ? '✓ Protected' : '✕ Missing'}
                        </span>
                    </div>
                    <p class="checklist-desc">${item.purpose}</p>
                    ${item.present && item.value ? `<div class="checklist-val">${escapeHtml(item.value)}</div>` : ''}
                    ${!item.present ? `<p style="font-size: 11px; color: #fca5a5;"><strong>Recommendation:</strong> ${item.recommendation}</p>` : ''}
                `;
                checklistGrid.appendChild(itemDiv);
            });

            // Raw Headers Table
            rawHeadersBody.innerHTML = '';
            data.all_headers.forEach(([hKey, hVal]) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<th>${escapeHtml(hKey)}</th><td>${escapeHtml(hVal)}</td>`;
                rawHeadersBody.appendChild(tr);
            });

            emptyState.hidden = true;
            resultsContainer.hidden = false;
            showStatus(`Audited ${data.url} - HTTP ${data.status_code} ${data.status_text}`, 'success');
        } catch (err) {
            showStatus('Connection failed. Please check network connectivity.', 'error');
        } finally {
            analyzeBtn.disabled = false;
        }
    });

    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
});

