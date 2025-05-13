/**
 * AES-GCM encryption using passphrase (string) instead of CryptoKey.
 * Includes PBKDF2 key derivation, encryption and decryption.
 */
/**
 * Derive AES-GCM CryptoKey from passphrase using PBKDF2.
 */
export declare function deriveKeyFromPassphrase(passphrase: string, salt: Uint8Array): Promise<CryptoKey>;
/**
 * Encrypt plaintext using a passphrase. Output: base64(salt):base64(iv):base64(ciphertext)
 */
export declare function encryptWithPassphrase(plaintext: string, passphrase: string): Promise<string>;
/**
 * Decrypt base64 encrypted text using a passphrase.
 */
export declare function decryptWithPassphrase(data: string, passphrase: string): Promise<string>;
