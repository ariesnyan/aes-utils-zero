/**
 * AES-GCM encryption/decryption using Web Crypto API with advanced options.
 * - 256-bit AES key
 * - Random IV generation
 * - Base64 serialization
 * - No external dependencies
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const toBase64 = (arr: ArrayBuffer): string => btoa(String.fromCharCode(...new Uint8Array(arr)));
const fromBase64 = (str: string): Uint8Array => new Uint8Array([...atob(str)].map(c => c.charCodeAt(0)));

/** Generate AES-256-GCM key */
export async function generateAESKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

/** Export key to base64-encoded raw format */
export async function exportKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return toBase64(raw);
}

/** Import key from base64-encoded raw format */
export async function importKey(base64: string): Promise<CryptoKey> {
  const raw = fromBase64(base64);
  return await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

/** Encrypt plaintext using AES-GCM */
export async function encryptAES(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
  const encodedText = textEncoder.encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedText);
  return toBase64(iv) + ":" + toBase64(ciphertext);
}

/** Decrypt AES-GCM encrypted base64 string */
export async function decryptAES(ciphertextWithIv: string, key: CryptoKey): Promise<string> {
  const [ivBase64, ciphertextBase64] = ciphertextWithIv.split(":");
  const iv = fromBase64(ivBase64);
  const ciphertext = fromBase64(ciphertextBase64);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return textDecoder.decode(decrypted);
}
