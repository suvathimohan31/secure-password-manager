"use strict";

const passwordInput = document.getElementById("password");
const strengthMeter = document.getElementById("strengthMeter");
const strengthLabel = document.getElementById("strengthLabel");
const generateButton = document.getElementById("generatePassword");
const generatorLength = document.getElementById("generatorLength");
const generatorError = document.getElementById("generatorError");

const commonPasswords = new Set([
    "password",
    "password123",
    "123456789012",
    "qwerty123456",
    "letmein123456",
    "admin12345678",
    "iloveyou12345"
]);

function characterClassCount(password) {
    let classes = 0;
    if (/[A-Z]/.test(password)) classes++;
    if (/[a-z]/.test(password)) classes++;
    if (/[0-9]/.test(password)) classes++;
    if (/[^A-Za-z0-9]/.test(password)) classes++;
    return classes;
}

function updateStrength() {
    const password = passwordInput.value;
    const isWeak = password.length < 12
        || characterClassCount(password) < 3
        || commonPasswords.has(password.toLowerCase());

    strengthMeter.classList.remove("strength-weak", "strength-medium", "strength-strong");
    strengthLabel.classList.remove("strength-weak", "strength-medium", "strength-strong");

    if (!password) {
        strengthMeter.value = 0;
        strengthLabel.textContent = "Enter a password to check its strength.";
        return;
    }
    if (isWeak) {
        strengthMeter.value = 1;
        strengthMeter.classList.add("strength-weak");
        strengthLabel.classList.add("strength-weak");
        strengthLabel.textContent = "Weak — use 12+ characters and at least three character types.";
        return;
    }
    if (password.length < 16) {
        strengthMeter.value = 2;
        strengthMeter.classList.add("strength-medium");
        strengthLabel.classList.add("strength-medium");
        strengthLabel.textContent = "Fair — consider using 16 or more characters.";
        return;
    }
    strengthMeter.value = 3;
    strengthMeter.classList.add("strength-strong");
    strengthLabel.classList.add("strength-strong");
    strengthLabel.textContent = "Strong.";
}

function secureIndex(limit) {
    const ceiling = Math.floor(256 / limit) * limit;
    const sample = new Uint8Array(1);
    let value;
    do {
        window.crypto.getRandomValues(sample);
        value = sample[0];
    } while (value >= ceiling);
    return value % limit;
}

function generatePassword(length) {
    const groups = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "!@#$%^&*()-_=+[]{}:,.?"
    ];
    const alphabet = groups.join("");
    const characters = groups.map(group => group[secureIndex(group.length)]);
    while (characters.length < length) {
        characters.push(alphabet[secureIndex(alphabet.length)]);
    }
    for (let i = characters.length - 1; i > 0; i--) {
        const j = secureIndex(i + 1);
        [characters[i], characters[j]] = [characters[j], characters[i]];
    }
    return characters.join("");
}

passwordInput.addEventListener("input", updateStrength);

generateButton.addEventListener("click", () => {
    generatorError.textContent = "";
    const length = Number(generatorLength.value);
    if (!Number.isInteger(length) || length < 16 || length > 64) {
        generatorError.textContent = "Choose a length between 16 and 64.";
        return;
    }
    if (!window.crypto || typeof window.crypto.getRandomValues !== "function") {
        generatorError.textContent = "Secure password generation is not available in this browser context.";
        return;
    }
    passwordInput.value = generatePassword(length);
    passwordInput.dispatchEvent(new Event("input", { bubbles: true }));
});
