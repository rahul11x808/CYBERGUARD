
document.addEventListener('DOMContentLoaded', () => {

    // ==========================================
    // 1. ELEMENT SELECTORS
    // ==========================================

    // Tabs
    const generatorTab = document.getElementById('show-generator-view');
    const strengthTab = document.getElementById('show-strength-view');

    const generatorView = document.getElementById('generator-view');
    const strengthView = document.getElementById('strength-view');

    const menuButton = document.getElementById('menu-button');
    const sidebar = document.getElementById('sidebar');

    // Generator elements
    const passwordLength = document.getElementById('password-length');
    const lengthValue = document.getElementById('length-value');

    const passwordOptions = document.querySelectorAll(
        '.checkbox-group input[type="checkbox"]'
    );

    const generatedPassword = document.querySelector(
        '.password-display input'
    );

    const generateButton = document.querySelector('.generate-button');
    const copyButton = document.querySelector('.copy-button');
    const copyIconButton = document.querySelector('.copy-icon-button');
    const eyeButton = document.querySelector('.eye-button');

    const generatorStrength = document.querySelector(
        '.generated-card .strength-section'
    );

    const generatorStrengthLabel = generatorStrength.querySelector(
        '.strength-text'
    );

    const generatorStrengthBars = generatorStrength.querySelectorAll(
        '.strength-bars span'
    );

    // Checker elements
    const strengthPassword = document.getElementById('strength-password');
    const checkStrengthButton = document.getElementById('check-strength-button');

    const strengthResult = document.getElementById('strength-result');
    const strengthLabel = document.getElementById('strength-label');

    const strengthMeter = document.getElementById('strength-meter');

    const strengthBars = strengthMeter.querySelectorAll(
        '.strength-meter-bar'
    );

    const strengthChecks = document.querySelectorAll(
        '.strength-check-item'
    );

    menuButton.addEventListener('click', () => {
        const open = sidebar.classList.toggle('sidebar-open');
        menuButton.setAttribute('aria-expanded', String(open));
    });


    // ==========================================
    // 2. TAB SWITCHING
    // ==========================================

    function showView(viewName) {

        const showGenerator = viewName === 'generator';

        generatorView.hidden = !showGenerator;
        strengthView.hidden = showGenerator;

        generatorTab.setAttribute(
            'aria-selected',
            String(showGenerator)
        );

        strengthTab.setAttribute(
            'aria-selected',
            String(!showGenerator)
        );

        generatorTab.classList.toggle('is-active', showGenerator);
        strengthTab.classList.toggle('is-active', !showGenerator);
    }

    generatorTab.addEventListener('click', () => {
        showView('generator');
    });

    strengthTab.addEventListener('click', () => {
        showView('strength');
        strengthPassword.focus();
    });


    // Keyboard navigation
    [generatorTab, strengthTab].forEach((tab, index, tabs) => {

        tab.addEventListener('keydown', (event) => {

            if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {

                event.preventDefault();

                const direction = event.key === 'ArrowRight' ? 1 : -1;

                const nextIndex = (index + direction + tabs.length) % tabs.length;

                tabs[nextIndex].focus();
                tabs[nextIndex].click();
            }
        });
    });


    // ==========================================
    // 3. SECURE RANDOM NUMBER GENERATOR
    // ==========================================

    function secureRandomInt(max) {

        if (!Number.isSafeInteger(max) || max <= 0) {
            throw new Error('Invalid random number range.');
        }

        const range = 0x100000000;
        const limit = Math.floor(range / max) * max;

        const randomValues = new Uint32Array(1);

        do {
            crypto.getRandomValues(randomValues);
        } while (randomValues[0] >= limit);

        return randomValues[0] % max;
    }


    // ==========================================
    // 4. PASSWORD GENERATION (Backend API + Client Fallback)
    // ==========================================

    async function generateSecurePassword() {

        const length = Number(passwordLength.value);

        const useUpper = document.querySelector('.checkbox-group input[data-type="uppercase"]')?.checked ?? true;
        const useLower = document.querySelector('.checkbox-group input[data-type="lowercase"]')?.checked ?? true;
        const useDigits = document.querySelector('.checkbox-group input[data-type="numbers"]')?.checked ?? true;
        const useSymbols = document.querySelector('.checkbox-group input[data-type="symbols"]')?.checked ?? true;

        try {
            const res = await fetch('/security_tools/api/password/generate/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    length: length,
                    use_upper: useUpper,
                    use_lower: useLower,
                    use_digits: useDigits,
                    use_symbols: useSymbols
                })
            });
            const data = await res.json();
            if (data.success && data.password) {
                generatedPassword.value = data.password;
                generatedPassword.type = 'password';
                eyeButton.textContent = '◉';
                eyeButton.setAttribute('aria-label', 'Show password');
                updateGeneratorStrength(data.password);
                return;
            }
        } catch (apiErr) {
            console.warn('Backend API unavailable, using client crypto:', apiErr);
        }

        // Character groups
        const characterSets = {

            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',

            lowercase: 'abcdefghijklmnopqrstuvwxyz',

            numbers: '0123456789',

            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'

        };

        const optionTypes = ['uppercase', 'lowercase', 'numbers', 'symbols'];

        const selectedTypes = Array.from(passwordOptions)
            .map((input, index) => (
                input.checked
                    ? input.dataset.type || optionTypes[index]
                    : ''
            ))
            .filter(Boolean);

        const selectedSets = selectedTypes
            .map((type) => characterSets[type])
            .filter(Boolean);

        // Check if at least one option is selected
        if (selectedSets.length === 0) {

            generatedPassword.value = '';
            updateGeneratorStrength('');
            alert('Please select at least one character option.');

            return;
        }

        // Create complete character pool
        const characterPool = selectedSets.join('');

        // Ensure every selected character type appears
        const passwordCharacters = selectedSets.map((set) => {

            return set[secureRandomInt(set.length)];

        });

        // Fill remaining password length
        while (passwordCharacters.length < length) {

            passwordCharacters.push(
                characterPool[secureRandomInt(characterPool.length)]
            );
        }

        // Securely shuffle characters
        for (let i = passwordCharacters.length - 1; i > 0; i--) {

            const j = secureRandomInt(i + 1);

            [passwordCharacters[i], passwordCharacters[j]] =
                [passwordCharacters[j], passwordCharacters[i]];
        }

        // Create final password
        const password = passwordCharacters.join('');

        // Display password
        generatedPassword.value = password;
        generatedPassword.type = 'password';
        eyeButton.textContent = '◉';
        eyeButton.setAttribute('aria-label', 'Show password');

        // Update password strength
        updateGeneratorStrength(password);
    }


    // ==========================================
    // 5. PASSWORD LENGTH SLIDER
    // ==========================================

    function updateLength() {

        lengthValue.textContent = passwordLength.value;

    }

    passwordLength.addEventListener('input', updateLength);


    // ==========================================
    // 6. GENERATE BUTTON
    // ==========================================

    generateButton.type = 'button';

    generateButton.addEventListener('click', () => {

        generateSecurePassword();

    });


    // ==========================================
    // 7. CHECKBOX CHANGE
    // ==========================================

    passwordOptions.forEach((checkbox) => {

        checkbox.addEventListener('change', generateSecurePassword);

    });


    // ==========================================
    // 8. SHOW / HIDE GENERATED PASSWORD
    // ==========================================

    eyeButton.type = 'button';

    eyeButton.addEventListener('click', () => {

        const isHidden = generatedPassword.type === 'password';

        generatedPassword.type = isHidden ? 'text' : 'password';

        eyeButton.setAttribute(
            'aria-label',
            isHidden ? 'Hide password' : 'Show password'
        );

        eyeButton.textContent = isHidden ? '◉' : '◉';

    });


    // ==========================================
    // 9. COPY PASSWORD
    // ==========================================

    async function copyPassword(button) {

        const password = generatedPassword.value;

        if (!password) {
            alert('Generate a password first.');
            return;
        }

        try {

            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(password);
            } else {
                const temporaryInput = document.createElement('textarea');
                temporaryInput.value = password;
                temporaryInput.style.position = 'fixed';
                temporaryInput.style.opacity = '0';
                document.body.appendChild(temporaryInput);
                temporaryInput.select();

                const copied = document.execCommand('copy');
                temporaryInput.remove();

                if (!copied) {
                    throw new Error('Copy command failed');
                }
            }

            const originalText = button.innerHTML;

            button.textContent = '✓ Copied!';

            setTimeout(() => {

                button.innerHTML = originalText;

            }, 1500);

        } catch (error) {

            alert('Unable to copy password. Check browser clipboard permissions.');

            console.error('Clipboard error:', error);

        }
    }

    copyButton.type = 'button';
    copyIconButton.type = 'button';

    copyButton.addEventListener('click', () => {
        copyPassword(copyButton);
    });

    copyIconButton.addEventListener('click', () => {
        copyPassword(copyIconButton);
    });


    // ==========================================
    // 10. PASSWORD REQUIREMENTS
    // ==========================================

    function checkRequirements(password) {

        return {

            'length-12': password.length >= 12,

            'mixed-case':
                /[a-z]/.test(password) &&
                /[A-Z]/.test(password),

            number: /\d/.test(password),

            symbol: /[^A-Za-z0-9]/.test(password),

            'length-16': password.length >= 16

        };
    }


    // ==========================================
    // 11. PASSWORD STRENGTH CALCULATION
    // ==========================================

    function calculateStrength(password, requirements) {

        let score = 0;

        if (password.length >= 8) score++;
        if (password.length >= 12) score++;
        if (password.length >= 16) score++;

        if (/[a-z]/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/\d/.test(password)) score++;
        if (/[^A-Za-z0-9]/.test(password)) score++;

        // Repeated character penalty
        if (/(.)\1{2,}/.test(password)) {
            score--;
        }

        // Common pattern penalty
        if (/123456|password|qwerty|abcdef/i.test(password)) {
            score -= 2;
        }

        score = Math.max(0, Math.min(score, 7));

        if (password.length < 8 || score <= 2) {

            return {
                label: 'Very Weak',
                level: 1,
                strength: 'very-weak'
            };

        } else if (score <= 3) {

            return {
                label: 'Weak',
                level: 2,
                strength: 'weak'
            };

        } else if (score <= 4) {

            return {
                label: 'Fair',
                level: 3,
                strength: 'fair'
            };

        } else if (score <= 5) {

            return {
                label: 'Strong',
                level: 4,
                strength: 'strong'
            };

        } else {

            return {
                label: 'Very Strong',
                level: 5,
                strength: 'very-strong'
            };
        }
    }


    // ==========================================
    // 12. GENERATOR STRENGTH UPDATE
    // ==========================================

    function updateGeneratorStrength(password) {

        if (!password) {
            generatorStrength.dataset.strength = 'empty';
            generatorStrengthLabel.textContent = 'Waiting...';

            generatorStrengthBars.forEach((bar) => {
                bar.classList.remove('is-active');
            });

            return;
        }

        const requirements = checkRequirements(password);

        const result = calculateStrength(password, requirements);

        generatorStrength.dataset.strength = result.strength;

        generatorStrengthLabel.textContent = result.label;

        generatorStrengthBars.forEach((bar, index) => {

            bar.classList.toggle(
                'is-active',
                index < result.level
            );

        });
    }


    // ==========================================
    // 13. CHECKER REQUIREMENTS UI
    // ==========================================

    function updateRequirements(requirements) {

        strengthChecks.forEach((item) => {

            const rule = item.dataset.rule;

            const isMet = requirements[rule];

            item.classList.toggle('is-met', isMet);

            item.querySelector('span').textContent = isMet ? '✓' : '○';

        });
    }


    // ==========================================
    // 14. CHECKER STRENGTH METER
    // ==========================================

    function updateMeter(level, strength) {

        strengthResult.dataset.strength = strength;

        strengthMeter.setAttribute(
            'aria-valuenow',
            String(level)
        );

        strengthBars.forEach((bar, index) => {

            bar.classList.toggle(
                'is-active',
                index < level
            );

        });
    }


    // ==========================================
    // 15. CHECKER RESET
    // ==========================================

    function resetChecker() {

        strengthResult.dataset.strength = 'empty';

        strengthLabel.textContent = 'Enter a password';

        strengthMeter.setAttribute('aria-valuenow', '0');

        strengthBars.forEach((bar) => {
            bar.classList.remove('is-active');
        });

        strengthChecks.forEach((item) => {

            item.classList.remove('is-met');

            item.querySelector('span').textContent = '○';

        });
    }


    // ==========================================
    // 16. CHECKER MAIN FUNCTION (Backend API + Live Updates)
    // ==========================================

    async function updateStrength() {

        const password = strengthPassword.value;

        if (!password) {
            resetChecker();
            return;
        }

        const requirements = checkRequirements(password);
        updateRequirements(requirements);

        try {
            const res = await fetch('/security_tools/api/password/evaluate/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: password })
            });
            const data = await res.json();
            if (data.success && data.strength) {
                const s = data.strength;
                strengthLabel.textContent = `${s.label} (${s.score}/100 - ${s.crack_time})`;
                
                let level = 1;
                if (s.score >= 90) level = 5;
                else if (s.score >= 70) level = 4;
                else if (s.score >= 45) level = 3;
                else if (s.score >= 20) level = 2;

                updateMeter(level, s.color || 'info');
                return;
            }
        } catch (apiErr) {
            // fallback
        }

        const result = calculateStrength(password, requirements);
        strengthLabel.textContent = result.label;
        updateMeter(result.level, result.strength);
    }


    // ==========================================
    // 17. LIVE STRENGTH CHECKING
    // ==========================================

    strengthPassword.addEventListener('input', updateStrength);

    checkStrengthButton.addEventListener('click', updateStrength);


    // ==========================================
    // 18. INITIALIZE
    // ==========================================

    updateLength();

    generateSecurePassword();

    resetChecker();

});
