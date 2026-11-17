document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('meta-drop-zone');
    const fileInput = document.getElementById('meta-file-input');
    const fileInfo = document.getElementById('meta-file-info');
    const selectedName = document.getElementById('meta-selected-name');
    const removeFileBtn = document.getElementById('meta-remove-file');
    const extractBtn = document.getElementById('extract-meta-btn');
    const statusEl = document.getElementById('meta-status');
    const emptyState = document.getElementById('meta-empty-state');
    const resultsContainer = document.getElementById('meta-results-container');
    const tableBody = document.getElementById('metadata-table-body');
    const privacyContainer = document.getElementById('meta-privacy-container');

    let currentFile = null;

    function showStatus(msg, type = '') {
        statusEl.textContent = msg;
        statusEl.className = `status-message ${type}`;
        statusEl.hidden = !msg;
    }

    // Drag and drop handlers
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) handleFile(files[0]);
    });

    dropZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFile(e.target.files[0]);
    });

    function handleFile(file) {
        currentFile = file;
        selectedName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        dropZone.hidden = true;
        fileInfo.hidden = false;
        extractBtn.disabled = false;
        showStatus('');
    }

    removeFileBtn.addEventListener('click', () => {
        currentFile = null;
        fileInput.value = '';
        dropZone.hidden = false;
        fileInfo.hidden = true;
        extractBtn.disabled = true;
        emptyState.hidden = false;
        resultsContainer.hidden = true;
        showStatus('');
    });

    extractBtn.addEventListener('click', async () => {
        if (!currentFile) return;

        showStatus('Analyzing file metadata with Python Pillow...', '');
        extractBtn.disabled = true;

        try {
            const formData = new FormData();
            formData.append('file', currentFile);

            const res = await fetch('/security_tools/api/metadata/extract/', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (!data.success || !data.metadata) {
                showStatus(data.error || 'Failed to extract metadata.', 'error');
                return;
            }

            const m = data.metadata;
            tableBody.innerHTML = '';
            privacyContainer.innerHTML = '';

            const rows = [
                ['File Name', m.filename],
                ['File Size', `${m.size_human} (${m.size_bytes.toLocaleString()} bytes)`],
                ['MIME Type', m.mime_type || 'Unknown'],
            ];

            if (m.is_image) {
                rows.push(['Image Format', m.format || 'Unknown']);
                rows.push(['Dimensions', m.dimensions || 'N/A']);
                rows.push(['Color Mode', m.mode || 'N/A']);
                if (m.aspect_ratio) rows.push(['Aspect Ratio', m.aspect_ratio]);
                rows.push([
                    'GPS Geolocation',
                    m.has_gps
                        ? '<span class="meta-badge danger">Detected (Privacy Alert!)</span>'
                        : '<span class="meta-badge safe">Clean (No GPS Found)</span>'
                ]);
            }

            // EXIF Tags
            if (m.exif_data && Object.keys(m.exif_data).length > 0) {
                for (const [key, val] of Object.entries(m.exif_data)) {
                    rows.push([`EXIF: ${key}`, String(val)]);
                }
            }

            rows.forEach(([label, val]) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<th>${label}</th><td>${val}</td>`;
                tableBody.appendChild(tr);
            });

            // Privacy warnings
            if (m.warnings && m.warnings.length > 0) {
                m.warnings.forEach(warn => {
                    const div = document.createElement('div');
                    const isGps = warn.includes('GPS');
                    div.className = `privacy-alert ${isGps ? '' : 'warning'}`;
                    div.innerHTML = `<strong>${isGps ? '⚠️ PRIVACY ALERT' : 'ℹ️ NOTICE'}:</strong> ${warn}`;
                    privacyContainer.appendChild(div);
                });
            } else {
                const div = document.createElement('div');
                div.className = 'privacy-alert warning';
                div.innerHTML = '<strong>🔒 Privacy Check:</strong> No obvious privacy leaks or GPS coordinates were found in this file.';
                privacyContainer.appendChild(div);
            }

            emptyState.hidden = true;
            resultsContainer.hidden = false;
            showStatus('Metadata extracted successfully.', 'success');
        } catch (err) {
            showStatus('Server connection error. Please try again.', 'error');
        } finally {
            extractBtn.disabled = false;
        }
    });
});

