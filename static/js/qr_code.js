const generateTab = document.getElementById('generate-tab');
const scanTab = document.getElementById('scan-tab');
const generatePanel = document.getElementById('generate-panel');
const scanPanel = document.getElementById('scan-panel');
const contentType = document.getElementById('content-type');
const contentLabel = document.getElementById('content-label');
const contentInput = document.getElementById('content');
const textFieldGroup = document.getElementById('text-field-group');
const wifiFields = document.getElementById('wifi-fields');
const wifiName = document.getElementById('wifi-name');
const wifiSecurity = document.getElementById('wifi-security');
const wifiPassword = document.getElementById('wifi-password');
const wifiPasswordGroup = document.getElementById('wifi-password-group');
const qrTarget = document.getElementById('qrcode');
const qrEmpty = document.getElementById('qr-empty');
const generateStatus = document.getElementById('generate-status');
const downloadButton = document.getElementById('download-qr');
const imageInput = document.getElementById('qr-image');
const scanPreview = document.getElementById('scan-preview');
const scanButton = document.getElementById('scan-qr');
const scanStatus = document.getElementById('scan-status');
const scanResult = document.getElementById('scan-result');
const copyScanResult = document.getElementById('copy-scan-result');
const menuButton = document.getElementById('menu-button');
const sidebar = document.getElementById('sidebar');
let previewUrl = '';

function showStatus(target, message, type = '') {
    target.textContent = message;
    target.className = `status-message ${type}`;
    target.hidden = !message;
}

function switchMode(mode) {
    const generating = mode === 'generate';
    generatePanel.hidden = !generating;
    scanPanel.hidden = generating;
    generateTab.classList.toggle('active', generating);
    scanTab.classList.toggle('active', !generating);
    generateTab.setAttribute('aria-selected', String(generating));
    scanTab.setAttribute('aria-selected', String(!generating));
    showStatus(generateStatus, '');
    showStatus(scanStatus, '');
}

generateTab.addEventListener('click', () => switchMode('generate'));
scanTab.addEventListener('click', () => switchMode('scan'));
menuButton.addEventListener('click', () => {
    const open = sidebar.classList.toggle('sidebar-open');
    menuButton.setAttribute('aria-expanded', String(open));
});

function updateContentType() {
    const isWifi = contentType.value === 'wifi';
    textFieldGroup.hidden = isWifi;
    wifiFields.hidden = !isWifi;
    if (contentType.value === 'url') {
        contentLabel.textContent = 'Enter URL';
        contentInput.placeholder = 'https://example.com';
    } else {
        contentLabel.textContent = 'Enter Text';
        contentInput.placeholder = 'Type something...';
    }
    showStatus(generateStatus, '');
}

function escapeWifiValue(value) {
    return value.replace(/[\\;,:\"]/g, character => `\\${character}`);
}

function getQrValue() {
    if (contentType.value !== 'wifi') {
        const value = contentInput.value.trim();
        if (!value) {
            throw Error(contentType.value === 'url' ? 'Enter a URL to generate its QR code.' : 'Enter text to generate its QR code.');
        }
        if (contentType.value === 'url' && !/^https?:\/\//i.test(value)) {
            throw Error('Enter a URL that starts with http:// or https://.');
        }
        return value;
    }

    const name = wifiName.value.trim();
    if (!name) {
        throw Error('Enter the Wi-Fi network name.');
    }
    const security = wifiSecurity.value;
    if (security !== 'nopass' && !wifiPassword.value) {
        throw Error('Enter the Wi-Fi password, or choose No password.');
    }
    const password = security === 'nopass' ? '' : escapeWifiValue(wifiPassword.value);
    return `WIFI:T:${security};S:${escapeWifiValue(name)};P:${password};;`;
}

document.getElementById('generate-qr').addEventListener('click', async () => {
    qrTarget.replaceChildren();
    downloadButton.hidden = true;
    qrEmpty.hidden = false;
    showStatus(generateStatus, 'Generating QR code via Python backend...', '');

    try {
        const isWifi = contentType.value === 'wifi';
        let bodyData = { content_type: contentType.value };
        if (isWifi) {
            bodyData.wifi_name = wifiName.value.trim();
            bodyData.wifi_security = wifiSecurity.value;
            bodyData.wifi_password = wifiPassword.value;
        } else {
            bodyData.content = getQrValue();
        }

        const res = await fetch('/security_tools/api/qr/generate/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyData)
        });
        const data = await res.json();
        if (data.success && data.qr_image) {
            const img = document.createElement('img');
            img.src = data.qr_image;
            img.alt = 'Generated QR Code';
            img.style.maxWidth = '100%';
            img.style.borderRadius = '8px';
            qrTarget.appendChild(img);
            qrEmpty.hidden = true;
            downloadButton.hidden = false;
            showStatus(generateStatus, 'QR code generated successfully via Python qrcode.', 'success');
            return;
        }
    } catch (apiErr) {
        console.warn('Backend QR generator error, falling back to client-side:', apiErr);
    }

    try {
        if (typeof QRCode !== 'function') {
            throw Error('QR generator could not load. Check your internet connection and try again.');
        }
        const value = getQrValue();
        new QRCode(qrTarget, { text: value, width: 192, height: 192, correctLevel: QRCode.CorrectLevel.H });
        qrEmpty.hidden = true;
        downloadButton.hidden = false;
        showStatus(generateStatus, 'QR code generated. Scan it with a trusted QR reader.', 'success');
    } catch (error) {
        showStatus(generateStatus, error.message || 'Could not generate the QR code.', 'error');
    }
});

contentType.addEventListener('change', updateContentType);
wifiSecurity.addEventListener('change', () => {
    wifiPasswordGroup.hidden = wifiSecurity.value === 'nopass';
});

downloadButton.addEventListener('click', () => {
    const image = qrTarget.querySelector('img');
    const canvas = qrTarget.querySelector('canvas');
    const imageUrl = image?.src || canvas?.toDataURL('image/png');
    if (!imageUrl) {
        showStatus(generateStatus, 'Generate a QR code before downloading.', 'error');
        return;
    }
    const link = document.createElement('a');
    link.href = imageUrl;
    link.download = 'cyberguard-qr.png';
    link.click();
});

imageInput.addEventListener('change', () => {
    const file = imageInput.files?.[0];
    scanResult.value = '';
    copyScanResult.disabled = true;
    scanButton.disabled = !file;
    showStatus(scanStatus, '');
    if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
        previewUrl = '';
    }
    if (!file) {
        scanPreview.hidden = true;
        scanPreview.removeAttribute('src');
        return;
    }
    if (!file.type.startsWith('image/')) {
        scanButton.disabled = true;
        showStatus(scanStatus, 'Choose an image file to scan.', 'error');
        return;
    }
    previewUrl = URL.createObjectURL(file);
    scanPreview.src = previewUrl;
    scanPreview.hidden = false;
});

scanButton.addEventListener('click', async () => {
    showStatus(scanStatus, '');
    scanResult.value = '';
    copyScanResult.disabled = true;
    const file = imageInput.files?.[0];
    if (!file) {
        showStatus(scanStatus, 'Choose a QR image to scan.', 'error');
        return;
    }
    if (typeof jsQR !== 'function') {
        showStatus(scanStatus, 'QR scanner could not load. Check your internet connection and try again.', 'error');
        return;
    }

    try {
        if (!scanPreview.complete || !scanPreview.naturalWidth) {
            await new Promise((resolve, reject) => {
                scanPreview.addEventListener('load', resolve, { once: true });
                scanPreview.addEventListener('error', reject, { once: true });
            });
        }
        const scale = Math.min(1, 2000 / Math.max(scanPreview.naturalWidth, scanPreview.naturalHeight));
        const width = Math.max(1, Math.round(scanPreview.naturalWidth * scale));
        const height = Math.max(1, Math.round(scanPreview.naturalHeight * scale));
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const context = canvas.getContext('2d', { willReadFrequently: true });
        context.drawImage(scanPreview, 0, 0, width, height);
        const imageData = context.getImageData(0, 0, width, height);
        const result = jsQR(imageData.data, width, height, { inversionAttempts: 'attemptBoth' });
        if (!result) {
            showStatus(scanStatus, 'No QR code was found. Try a sharper, well-lit image.', 'error');
            return;
        }
        scanResult.value = result.data;
        copyScanResult.disabled = false;

        // Perform backend security analysis
        try {
            const apiRes = await fetch('/security_tools/api/qr/scan/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: result.data })
            });
            const apiData = await apiRes.json();
            if (apiData.success && apiData.analysis) {
                const a = apiData.analysis;
                let statusMsg = `QR scanned (${a.content_type}). Security: ${a.safety_rating}.`;
                if (a.has_warnings && a.warnings.length > 0) {
                    statusMsg += ` [!] ${a.warnings[0]}`;
                    showStatus(scanStatus, statusMsg, 'error');
                } else {
                    showStatus(scanStatus, statusMsg, 'success');
                }
                return;
            }
        } catch (apiErr) {
            console.warn('Backend QR analysis error:', apiErr);
        }

        showStatus(scanStatus, 'QR code scanned. Verify the content before using it.', 'success');
    } catch {
        showStatus(scanStatus, 'Could not read this image. Try another image file.', 'error');
    }
});

copyScanResult.addEventListener('click', async () => {
    if (!scanResult.value) {
        return;
    }
    try {
        await navigator.clipboard.writeText(scanResult.value);
    } catch {
        scanResult.select();
        document.execCommand('copy');
    }
    showStatus(scanStatus, 'Scanned content copied.', 'success');
});

updateContentType();