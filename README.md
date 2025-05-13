# aes-utils-zero

🔐 Advanced AES-GCM encryption utilities using the native Web Crypto API.  
Zero dependencies. Perfect for frontend TypeScript/React apps.

## Features

- AES-GCM encryption using passphrase (string) instead of CryptoKey
- Includes PBKDF2 key derivation, encryption and decryptions

## Install

```bash
npm install aes-utils-zero
```

## Usage

```ts
import { decryptWithPassphrase, decryptWithPassphrase } from "aes-utils-zero";

const passphrase = "my-secure-password";
const encrypted = await encryptWithPassphrase("Hello!", passphrase);
console.log("Encrypted:", encrypted);
const decrypted = await decryptWithPassphrase(encrypted, passphrase);
console.log("Decrypted:", decrypted);
```
