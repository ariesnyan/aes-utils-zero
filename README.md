# aes-utils-zero

🔐 Advanced AES-256-GCM encryption utilities using the native Web Crypto API.  
Zero dependencies. Perfect for frontend TypeScript/React apps.

## Features

- AES-GCM with 256-bit key
- Key export/import (base64)
- Random IV generation
- Base64-safe encrypted output
- No external dependencies

## Install

```bash
npm install aes-utils-zero
```

## Usage

```ts
import { generateAESKey, encryptAES, decryptAES } from "aes-utils-zero";

const key = await generateAESKey();
const encrypted = await encryptAES("Hello!", key);
const decrypted = await decryptAES(encrypted, key);
```
