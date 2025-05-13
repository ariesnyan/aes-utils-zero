/**
 * AES-GCM encryption using passphrase (string) instead of CryptoKey.
 * Includes PBKDF2 key derivation, encryption and decryption.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const encode = (s) => encoder.encode(s);
const decode = (buf) => decoder.decode(buf);
const base64 = (ab) => btoa(String.fromCharCode(...new Uint8Array(ab)));
const fromBase64 = (b64) => new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
/**
 * Derive AES-GCM CryptoKey from passphrase using PBKDF2.
 */
export async function deriveKeyFromPassphrase(passphrase, salt) {
    const baseKey = await crypto.subtle.importKey('raw', encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
    }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
/**
 * Encrypt plaintext using a passphrase. Output: base64(salt):base64(iv):base64(ciphertext)
 */
export async function encryptWithPassphrase(plaintext, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassphrase(passphrase, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encode(plaintext));
    return `${base64(salt)}:${base64(iv)}:${base64(ciphertext)}`;
}
/**
 * Decrypt base64 encrypted text using a passphrase.
 */
export async function decryptWithPassphrase(data, passphrase) {
    const [saltB64, ivB64, ciphertextB64] = data.split(':');
    const salt = fromBase64(saltB64);
    const iv = fromBase64(ivB64);
    const ciphertext = fromBase64(ciphertextB64);
    const key = await deriveKeyFromPassphrase(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return decode(decrypted);
}
