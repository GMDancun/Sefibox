/**
 * SefiBox client-side crypto.
 *
 * All encryption and decryption happens here, in the browser, using
 * the native Web Crypto API (AES-GCM 256). The server never receives
 * plaintext and never receives the decryption key: the key is
 * generated in the browser, exported, and placed only in the URL
 * fragment (after '#'), which browsers never transmit to servers.
 *
 * Flow:
 *   CREATE:  plaintext --(AES-GCM encrypt, random key+iv)--> ciphertext
 *            -> POST {ciphertext, iv, ...} to server
 *            -> server returns a path (no key)
 *            -> browser appends "#" + base64(key) to build the full share link
 *
 *   VIEW:    server renders {ciphertext, iv} into the page
 *            -> browser reads key from location.hash
 *            -> AES-GCM decrypt entirely client-side
 */
(function (global) {
    "use strict";

    const ALGO = { name: "AES-GCM", length: 256 };
    const IV_LENGTH_BYTES = 12; // 96-bit nonce, standard for AES-GCM

    // -- base64 <-> ArrayBuffer helpers --------------------------------
    function bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Base64 is not URL-safe by default; the key travels in a URL
    // fragment so we convert to a URL-safe alphabet for the link.
    function base64ToUrlSafe(base64) {
        return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function urlSafeToBase64(urlSafe) {
        let base64 = urlSafe.replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4) {
            base64 += "=";
        }
        return base64;
    }

    // -- core encrypt/decrypt ------------------------------------------
    async function generateKey() {
        return crypto.subtle.generateKey(ALGO, true, ["encrypt", "decrypt"]);
    }

    async function exportKeyUrlSafe(key) {
        const raw = await crypto.subtle.exportKey("raw", key);
        return base64ToUrlSafe(bufferToBase64(raw));
    }

    async function importKeyFromUrlSafe(urlSafeKey) {
        const raw = base64ToBuffer(urlSafeToBase64(urlSafeKey));
        return crypto.subtle.importKey("raw", raw, ALGO, false, ["decrypt"]);
    }

    /**
     * Encrypts plaintext with a freshly generated key.
     * Returns { ciphertext: base64, iv: base64, keyUrlSafe: string }.
     * Nothing here is ever sent anywhere except the ciphertext + iv.
     */
    async function encryptText(plaintext) {
        const key = await generateKey();
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
        const encoded = new TextEncoder().encode(plaintext);

        const ciphertextBuffer = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encoded
        );

        const keyUrlSafe = await exportKeyUrlSafe(key);

        return {
            ciphertext: bufferToBase64(ciphertextBuffer),
            iv: bufferToBase64(iv),
            keyUrlSafe: keyUrlSafe,
        };
    }

    /**
     * Decrypts ciphertext given the base64 iv and a url-safe base64 key
     * (as found in the URL fragment). Returns the plaintext string.
     */
    async function decryptText(ciphertextB64, ivB64, keyUrlSafe) {
        const key = await importKeyFromUrlSafe(keyUrlSafe);
        const iv = new Uint8Array(base64ToBuffer(ivB64));
        const ciphertextBuffer = base64ToBuffer(ciphertextB64);

        const plaintextBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertextBuffer
        );

        return new TextDecoder().decode(plaintextBuffer);
    }

    global.SefiBoxCrypto = {
        encryptText: encryptText,
        decryptText: decryptText,
    };
})(window);


// ---------------------------------------------------------------------
// Wire up the create-secret form, if present on the page.
// ---------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("create-form");
    if (!form) return;

    const submitBtn = document.getElementById("create-submit");
    const errorBox = document.getElementById("create-error");
    const resultPanel = document.getElementById("result-panel");
    const shareLinkInput = document.getElementById("share-link");
    const copyBtn = document.getElementById("copy-link-btn");

    function getCsrfToken() {
        const input = form.querySelector('input[name="csrfmiddlewaretoken"]');
        return input ? input.value : "";
    }

    function showError(message) {
        errorBox.textContent = message;
        errorBox.hidden = false;
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        errorBox.hidden = true;

        const secretEl = document.getElementById("id_secret");
        const labelEl = document.getElementById("id_label");
        const expiresEl = document.getElementById("id_expires_hours");
        const maxViewsEl = document.getElementById("id_max_views");

        const plaintext = secretEl.value;
        if (!plaintext || !plaintext.trim()) {
            showError("Please enter a secret to encrypt.");
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = "Encrypting…";

        try {
            const { ciphertext, iv, keyUrlSafe } = await SefiBoxCrypto.encryptText(plaintext);

            const response = await fetch("/api/create/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCsrfToken(),
                },
                body: JSON.stringify({
                    ciphertext: ciphertext,
                    iv: iv,
                    label: labelEl.value,
                    expires_hours: parseInt(expiresEl.value, 10),
                    max_views: parseInt(maxViewsEl.value, 10),
                }),
            });

            if (!response.ok) {
                const errBody = await response.json().catch(() => ({}));
                throw new Error(errBody.error || "Server rejected the request.");
            }

            const data = await response.json();
            const fullLink = window.location.origin + data.share_path + "#" + keyUrlSafe;

            // Clear the plaintext from the form/DOM immediately.
            secretEl.value = "";

            shareLinkInput.value = fullLink;
            resultPanel.hidden = false;
            form.hidden = true;
        } catch (err) {
            console.error(err);
            showError(err.message || "Something went wrong while creating the secret.");
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = "Encrypt & create link";
        }
    });

    if (copyBtn) {
        copyBtn.addEventListener("click", function () {
            shareLinkInput.select();
            navigator.clipboard.writeText(shareLinkInput.value).then(function () {
                copyBtn.textContent = "Copied!";
                setTimeout(function () { copyBtn.textContent = "Copy"; }, 1500);
            });
        });
    }
});
