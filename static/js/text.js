const encryptTab = document.getElementById('encrypt-tab');
const decryptTab = document.getElementById('decrypt-tab');
const encryptPanel = document.getElementById('encrypt-panel');
const decryptPanel = document.getElementById('decrypt-panel');
const algorithm = document.getElementById('algorithm');
const algorithmHint = document.getElementById('algorithm-hint');
const plainText = document.getElementById('plain-text');
const encryptionKey = document.getElementById('encryption-key');
const encryptedText = document.getElementById('encrypted-text');
const decryptionKey = document.getElementById('decryption-key');
const encryptionKeyGroup = document.getElementById('encryption-key-group');
const decryptionKeyGroup = document.getElementById('decryption-key-group');
const encryptionKeyHint = document.getElementById('encryption-key-hint');
const decryptionKeyHint = document.getElementById('decryption-key-hint');
const generateKeyButton = document.getElementById('generate-key');
const decryptButton = document.getElementById('decrypt-button');
const decryptUnavailable = document.getElementById('decrypt-unavailable');
const outputPanel = document.getElementById('output-panel');
const outputText = document.getElementById('output-text');
const outputLabel = document.getElementById('output-label');
const statusMessage = document.getElementById('status-message');

function status(message, type = '') {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
    statusMessage.hidden = !message;
}

function clearResult() {
    outputPanel.hidden = true;
    status('');
}

function switchMode(mode) {
    const encrypting = mode === 'encrypt';
    encryptPanel.hidden = !encrypting;
    decryptPanel.hidden = encrypting;
    encryptTab.classList.toggle('active', encrypting);
    decryptTab.classList.toggle('active', !encrypting);
    encryptTab.setAttribute('aria-selected', String(encrypting));
    decryptTab.setAttribute('aria-selected', String(!encrypting));
    clearResult();
}

function updateAlgorithm() {
    const method = algorithm.value;
    const isHash = method === 'sha256';
    const isCaesar = method === 'caesar';

    encryptionKeyGroup.hidden = isHash;
    decryptionKeyGroup.hidden = isHash;
    generateKeyButton.hidden = isHash;
    decryptButton.disabled = isHash;
    decryptUnavailable.hidden = !isHash;

    if (isHash) {
        algorithmHint.textContent = 'SHA-256 creates a fixed-length digest. Hashes cannot be decrypted.';
    } else if (isCaesar) {
        algorithmHint.textContent = 'A classic letter-shift cipher for learning. Do not use it to protect sensitive information.';
        encryptionKey.placeholder = 'Enter a shift from 0 to 25...';
        decryptionKey.placeholder = 'Enter the same shift from 0 to 25...';
        encryptionKeyHint.textContent = 'Choose a whole-number shift from 0 to 25 and use the same value to decrypt.';
        decryptionKeyHint.textContent = 'Use the same whole-number shift that was used to encrypt.';
        generateKeyButton.textContent = '⟳  Generate Shift';
    } else {
        algorithmHint.textContent = 'Authenticated encryption for private text. Keep the generated key safe.';
        encryptionKey.placeholder = 'Generate or paste a 64-character hexadecimal key...';
        decryptionKey.placeholder = 'Paste your 64-character hexadecimal key...';
        encryptionKeyHint.textContent = 'Save this key safely. You need the same key to decrypt your text.';
        decryptionKeyHint.textContent = 'Use the exact key that was used to encrypt this text.';
        generateKeyButton.textContent = '⟳  Generate Key';
    }
    clearResult();
}

encryptTab.addEventListener('click', () => switchMode('encrypt'));
decryptTab.addEventListener('click', () => switchMode('decrypt'));
algorithm.addEventListener('change', updateAlgorithm);

function toHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
    const value = hex.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(value)) {
        throw Error('AES-256 keys must contain exactly 64 hexadecimal characters.');
    }
    return Uint8Array.from(value.match(/../g), pair => parseInt(pair, 16));
}

function toBase64(bytes) {
    let binary = '';
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary);
}

function fromBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

function caesar(text, shift) {
    const normalizedShift = shift % 26;
    return text.replace(/[a-z]/gi, character => {
        const base = character === character.toUpperCase() ? 65 : 97;
        return String.fromCharCode((character.charCodeAt(0) - base + normalizedShift + 26) % 26 + base);
    });
}

function readShift(value) {
    if (!/^\d+$/.test(value.trim())) {
        throw Error('Enter a whole-number Caesar shift from 0 to 25.');
    }
    const shift = Number(value);
    if (shift < 0 || shift > 25) {
        throw Error('Enter a whole-number Caesar shift from 0 to 25.');
    }
    return shift;
}

function showOutput(label, value) {
    outputText.value = value;
    outputLabel.textContent = label;
    outputPanel.hidden = false;
}

generateKeyButton.addEventListener('click', async () => {
    if (algorithm.value === 'caesar') {
        encryptionKey.value = String(crypto.getRandomValues(new Uint8Array(1))[0] % 25 + 1);
        decryptionKey.value = encryptionKey.value;
        clearResult();
        status('Caesar shift generated. Save it securely for decryption.', 'success');
        return;
    }

    try {
        const res = await fetch('/security_tools/api/encryption/generate-key/');
        const data = await res.json();
        if (data.success && data.key) {
            encryptionKey.value = data.key;
            decryptionKey.value = data.key;
            clearResult();
            status('Fernet AES key generated via Python backend. Save it securely for decryption.', 'success');
            return;
        }
    } catch (err) {
        // client fallback
    }

    encryptionKey.value = toHex(crypto.getRandomValues(new Uint8Array(32)));
    decryptionKey.value = encryptionKey.value;
    clearResult();
    status('Key generated. Save it securely for decryption.', 'success');
});

document.getElementById('encrypt-button').addEventListener('click', async () => {
    clearResult();
    if (plainText.value.length === 0) {
        status('Enter text to process.', 'error');
        return;
    }

    // Try backend API first
    try {
        const res = await fetch('/security_tools/api/encryption/encrypt/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                text: plainText.value,
                key: encryptionKey.value,
                algorithm: algorithm.value
            })
        });
        const data = await res.json();
        if (data.success) {
            showOutput(data.algorithm || 'Encrypted Output', data.ciphertext);
            if (decryptionKey && encryptionKey.value) {
                decryptionKey.value = encryptionKey.value;
            }
            status('Encrypted successfully via Python backend. Save the key to decrypt!', 'success');
            return;
        } else if (data.error) {
            status(data.error, 'error');
            return;
        }
    } catch (apiErr) {
        console.warn('Backend API error, falling back to client-side:', apiErr);
    }

    try {
        if (algorithm.value === 'sha256') {
            const data = new TextEncoder().encode(plainText.value);
            const digest = await crypto.subtle.digest('SHA-256', data);
            showOutput('SHA-256 Hash', toHex(new Uint8Array(digest)));
            status('SHA-256 hash created. This result cannot be decrypted.', 'success');
            return;
        }

        if (algorithm.value === 'caesar') {
            if (!encryptionKey.value.trim()) {
                throw Error('Enter a Caesar shift or generate one.');
            }
            const shift = readShift(encryptionKey.value);
            const result = caesar(plainText.value, shift);
            decryptionKey.value = encryptionKey.value;
            showOutput('Caesar Ciphertext', result);
            status('Text encrypted. Keep the shift value to decrypt it.', 'success');
            return;
        }

        if (!encryptionKey.value.trim()) {
            encryptionKey.value = toHex(crypto.getRandomValues(new Uint8Array(32)));
            decryptionKey.value = encryptionKey.value;
        }
        const key = await crypto.subtle.importKey('raw', fromHex(encryptionKey.value), { name: 'AES-GCM' }, false, ['encrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(plainText.value);
        const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
        showOutput('Encrypted Output', `aes-gcm:v1:${toBase64(iv)}:${toBase64(new Uint8Array(cipher))}`);
        status('Encrypted successfully. Keep the key to decrypt this text.', 'success');
    } catch (error) {
        status(error.message || 'Encryption failed.', 'error');
    }
});

decryptButton.addEventListener('click', async () => {
    clearResult();
    if (encryptedText.value.length === 0) {
        status('Enter text to decrypt.', 'error');
        return;
    }

    // Try backend API first
    try {
        const res = await fetch('/security_tools/api/encryption/decrypt/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ciphertext: encryptedText.value,
                key: decryptionKey.value,
                algorithm: algorithm.value
            })
        });
        const data = await res.json();
        if (data.success) {
            showOutput('Decrypted Plaintext', data.plaintext);
            status('Text decrypted successfully via Python backend (authenticated)!', 'success');
            return;
        } else if (data.error) {
            status(data.error, 'error');
            return;
        }
    } catch (apiErr) {
        console.warn('Backend API error, falling back to client-side:', apiErr);
    }

    try {
        if (algorithm.value === 'caesar') {
            if (!decryptionKey.value.trim()) {
                throw Error('Enter the Caesar shift used to encrypt this text.');
            }
            const shift = readShift(decryptionKey.value);
            showOutput('Decrypted Output', caesar(encryptedText.value, -shift));
            status('Text decrypted successfully.', 'success');
            return;
        }

        if (algorithm.value === 'sha256') {
            status('SHA-256 is a one-way hash and cannot be decrypted.', 'error');
            return;
        }
        if (!decryptionKey.value.trim()) {
            throw Error('Enter the AES key used to encrypt this text.');
        }

        const parts = encryptedText.value.trim().split(':');
        let ivText;
        let cipherText;
        if (parts.length === 4 && parts[0] === 'aes-gcm' && parts[1] === 'v1') {
            [, , ivText, cipherText] = parts;
        } else if (parts.length === 2) {
            [ivText, cipherText] = parts;
        } else {
            throw Error('Invalid AES ciphertext format.');
        }
        const iv = fromBase64(ivText);
        const cipher = fromBase64(cipherText);
        if (iv.length !== 12 || cipher.length < 16) {
            throw Error('Invalid AES ciphertext.');
        }
        const key = await crypto.subtle.importKey('raw', fromHex(decryptionKey.value), { name: 'AES-GCM' }, false, ['decrypt']);
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
        showOutput('Decrypted Output', new TextDecoder().decode(plain));
        status('Decrypted successfully.', 'success');
    } catch (error) {
        if (error.name === 'OperationError') {
            status('Decryption failed. Check the encrypted text and the exact key.', 'error');
        } else {
            status(error.message || 'Decryption failed.', 'error');
        }
    }
});

document.getElementById('copy-output').addEventListener('click', async () => {
    if (!outputText.value) {
        status('There is no output to copy.', 'error');
        return;
    }
    try {
        await navigator.clipboard.writeText(outputText.value);
    } catch {
        outputText.select();
        document.execCommand('copy');
    }
    status('Output copied.', 'success');
});

updateAlgorithm();