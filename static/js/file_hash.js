const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileInfo = document.getElementById('file-info');
const selectedFileName = document.getElementById('selected-file-name');
const removeFileBtn = document.getElementById('remove-file');
const calculateBtn = document.getElementById('calculate-hash');
const hashAlgorithm = document.getElementById('hash-algorithm');
const verifyHashInput = document.getElementById('verify-hash');
const hashResult = document.getElementById('hash-result');
const copyHashResult = document.getElementById('copy-hash-result');
const hashStatus = document.getElementById('hash-status');
const verificationBadge = document.getElementById('verification-badge');
const verificationText = document.getElementById('verification-text');
const menuButton = document.getElementById('menu-button');
const sidebar = document.getElementById('sidebar');

let currentFile = null;

function showStatus(target, message, type = '') {
    target.textContent = message;
    target.className = `status-message ${type}`;
    target.hidden = !message;
}

// Sidebar toggle for responsiveness
menuButton.addEventListener('click', () => {
    const open = sidebar.classList.toggle('sidebar-open');
    menuButton.setAttribute('aria-expanded', String(open));
});

// Drag and drop handlers
['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    }, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
    }, false);
});

dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleSelectedFile(files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleSelectedFile(e.target.files[0]);
    }
});

function handleSelectedFile(file) {
    const maxSize = 50 * 1024 * 1024; // 50 MB
    if (file.size > maxSize) {
        showStatus(hashStatus, 'File size exceeds 50 MB limit.', 'error');
        return;
    }
    currentFile = file;
    selectedFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    dropZone.hidden = true;
    fileInfo.hidden = false;
    calculateBtn.disabled = false;
    showStatus(hashStatus, '');
}

removeFileBtn.addEventListener('click', () => {
    currentFile = null;
    fileInput.value = '';
    dropZone.hidden = false;
    fileInfo.hidden = true;
    calculateBtn.disabled = true;
    hashResult.value = '';
    copyHashResult.disabled = true;
    verificationBadge.hidden = true;
    showStatus(hashStatus, '');
});

// Calculate Hash using Backend API + SubtleCrypto fallback
calculateBtn.addEventListener('click', async () => {
    if (!currentFile) return;

    showStatus(hashStatus, 'Calculating hash via Python backend...', '');
    calculateBtn.disabled = true;

    // Try backend API first
    try {
        const formData = new FormData();
        formData.append('file', currentFile);
        if (verifyHashInput.value.trim()) {
            formData.append('expected_hash', verifyHashInput.value.trim());
        }

        const res = await fetch('/security_tools/api/hash/calculate/', {
            method: 'POST',
            body: formData
        });
        const data = await res.json();
        if (data.success && data.hashes) {
            const algo = hashAlgorithm.value.toLowerCase();
            const chosenHash = algo.includes('md5') ? data.hashes.md5 : data.hashes.sha256;
            hashResult.value = chosenHash;
            copyHashResult.disabled = false;
            showStatus(hashStatus, `Hashes calculated successfully (${(data.hashes.size_bytes / 1024).toFixed(1)} KB processed).`, 'success');

            if (data.verification && data.verification.checked) {
                verificationBadge.hidden = false;
                if (data.verification.match) {
                    verificationBadge.className = 'verification-badge success';
                    verificationText.textContent = data.verification.message;
                } else {
                    verificationBadge.className = 'verification-badge error';
                    verificationText.textContent = data.verification.message;
                }
            } else {
                checkVerification(chosenHash);
            }
            return;
        }
    } catch (apiErr) {
        console.warn('Backend API hashing error, falling back to client-side:', apiErr);
    } finally {
        calculateBtn.disabled = false;
    }

    try {
        const buffer = await currentFile.arrayBuffer();
        const algorithm = hashAlgorithm.value; // e.g., SHA-256, SHA-512, SHA-1
        
        const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        hashResult.value = hashHex;
        copyHashResult.disabled = false;
        showStatus(hashStatus, 'Hash calculated successfully.', 'success');
        
        checkVerification(hashHex);
    } catch (error) {
        showStatus(hashStatus, 'Error calculating file hash.', 'error');
    } finally {
        calculateBtn.disabled = false;
    }
});

// Verify hash against expected input
verifyHashInput.addEventListener('input', () => {
    if (hashResult.value) {
        checkVerification(hashResult.value);
    }
});

function checkVerification(calculatedHash) {
    const expected = verifyHashInput.value.trim().toLowerCase();
    if (!expected) {
        verificationBadge.hidden = true;
        return;
    }

    verificationBadge.hidden = false;
    if (calculatedHash.toLowerCase() === expected) {
        verificationBadge.className = 'verification-badge success';
        verificationText.textContent = 'Hashes Match! File is authentic and uncompromised.';
    } else {
        verificationBadge.className = 'verification-badge error';
        verificationText.textContent = 'Hash Mismatch! File may be altered or corrupted.';
    }
}

copyHashResult.addEventListener('click', async () => {
    if (!hashResult.value) return;
    try {
        await navigator.clipboard.writeText(hashResult.value);
        showStatus(hashStatus, 'Hash copied to clipboard.', 'success');
    } catch {
        hashResult.select();
        document.execCommand('copy');
    }
});