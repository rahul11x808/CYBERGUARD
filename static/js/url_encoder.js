document.addEventListener('DOMContentLoaded', () => {
    const encodeTab = document.getElementById('encode-tab');
    const decodeTab = document.getElementById('decode-tab');
    const inputLabel = document.getElementById('input-label');
    const urlInput = document.getElementById('url-input');
    const processBtn = document.getElementById('process-url-btn');
    const statusEl = document.getElementById('url-status');
    const outputPanel = document.getElementById('url-output-panel');
    const outputText = document.getElementById('url-output-text');
    const outputLabel = document.getElementById('url-output-label');
    const copyBtn = document.getElementById('copy-url-btn');

    let currentAction = 'encode';

    function setMode(mode) {
        currentAction = mode;
        const isEncode = mode === 'encode';
        encodeTab.classList.toggle('active', isEncode);
        decodeTab.classList.toggle('active', !isEncode);
        encodeTab.setAttribute('aria-selected', String(isEncode));
        decodeTab.setAttribute('aria-selected', String(!isEncode));

        inputLabel.textContent = isEncode ? 'Input URL or Text to Encode' : 'Input URL or Percent-Encoded String to Decode';
        processBtn.innerHTML = isEncode ? '🔗 &nbsp;Encode URL' : '♧ &nbsp;Decode URL';
        outputPanel.hidden = true;
        showStatus('');
    }

    function showStatus(msg, type = '') {
        statusEl.textContent = msg;
        statusEl.className = `status-message ${type}`;
        statusEl.hidden = !msg;
    }

    encodeTab.addEventListener('click', () => setMode('encode'));
    decodeTab.addEventListener('click', () => setMode('decode'));

    processBtn.addEventListener('click', async () => {
        const text = urlInput.value.trim();
        if (!text) {
            showStatus('Please enter text or a URL to process.', 'error');
            return;
        }

        showStatus('Processing URL via backend...', '');

        try {
            const res = await fetch('/security_tools/api/url/process/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: text,
                    action: currentAction
                })
            });
            const data = await res.json();

            if (data.success) {
                outputText.value = data.result;
                outputLabel.textContent = currentAction === 'encode' ? 'Percent-Encoded URL' : 'Decoded Plaintext URL';
                outputPanel.hidden = false;
                showStatus(`Successfully ${currentAction}d URL content.`, 'success');
                return;
            } else {
                showStatus(data.error || 'Failed to process URL.', 'error');
                return;
            }
        } catch (apiErr) {
            console.warn('API error, falling back to client-side:', apiErr);
        }

        try {
            const result = currentAction === 'encode'
                ? encodeURIComponent(text)
                : decodeURIComponent(text);
            outputText.value = result;
            outputLabel.textContent = currentAction === 'encode' ? 'Percent-Encoded URL' : 'Decoded Plaintext URL';
            outputPanel.hidden = false;
            showStatus(`Successfully ${currentAction}d URL content.`, 'success');
        } catch (err) {
            showStatus('Error decoding URL. Check for malformed escape sequences.', 'error');
        }
    });

    copyBtn.addEventListener('click', async () => {
        if (!outputText.value) return;
        try {
            await navigator.clipboard.writeText(outputText.value);
            showStatus('Result copied to clipboard.', 'success');
        } catch {
            outputText.select();
            document.execCommand('copy');
            showStatus('Result copied.', 'success');
        }
    });
});

