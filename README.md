# DMail

A lightweight encryption library for protecting sensitive data in blockchain applications, API services, and data processing workflows. Built with production use in mind, DMail provides simple yet secure encryption for private keys, API credentials, and other sensitive information.

## Overview

DMail offers a straightforward approach to encrypting sensitive data using AES-256-CTR encryption. Whether you're building wallet applications, securing API credentials, or processing sensitive data in your pipelines, DMail provides the encryption tools you need without unnecessary complexity.

### Key Features

- **Simple API** - Encrypt and decrypt sensitive data with just a few lines of code
- **Password-based encryption** - Protect data with user passwords using secure key derivation
- **Token-based encryption** - Direct encryption with generated tokens for API workflows
- **Production-ready** - Designed for real-world applications and workflows
- **Lightweight** - Minimal dependencies, fast performance

## Installation

```bash
npm install
```

## Quick Start

### Encrypting Private Keys

```javascript
const { SecureEncryption } = require('./src');

const privateKey = '0x1234567890abcdef...';
const password = 'YourSecurePassword';

// Encrypt the private key
const encrypted = SecureEncryption.encryptWalletData(privateKey, password);

// Store encrypted data safely
console.log('Encrypted:', encrypted.encrypted);
console.log('Algorithm:', encrypted.algorithm); // aes-256-ctr

// Later, decrypt when needed
const decrypted = SecureEncryption.decryptWalletData(encrypted, password);
console.log('Decrypted:', decrypted);
```

### Encrypting API Credentials

```javascript
const { SecureEncryption } = require('./src');

const apiCredentials = {
  apiKey: 'sk_live_...',
  apiSecret: '...',
  webhookSecret: '...'
};

// Encrypt credentials with master password
const encrypted = SecureEncryption.encryptWalletData(
  JSON.stringify(apiCredentials),
  process.env.MASTER_PASSWORD
);

// Store encrypted version securely
// Decrypt only when needed for API calls
```

### Direct Token Encryption

```javascript
const { SecureEncryption } = require('./src');
const aesjs = require('aes-js');
const crypto = require('crypto');

// Generate token
const token = SecureEncryption.generateKey();

// Encrypt data directly
const data = 'Sensitive information';
const { encrypted, counter } = SecureEncryption.encrypt(data, token);

// Decrypt
const decrypted = SecureEncryption.decrypt(encrypted, token, counter);
```

## Use Cases

### Wallet Applications

Protect user wallet credentials in your application:

```javascript
const { SecureEncryption } = require('./src');

// When user creates wallet
const walletData = {
  privateKey: '0x...',
  mnemonic: 'word1 word2 word3...',
  address: '0x...'
};

// Encrypt before storage
const encrypted = SecureEncryption.encryptWalletData(
  JSON.stringify(walletData),
  userPassword
);

// Store encrypted version
fs.writeFileSync('wallet.enc', JSON.stringify(encrypted));

// When user unlocks wallet
const encryptedData = JSON.parse(fs.readFileSync('wallet.enc'));
const decrypted = SecureEncryption.decryptWalletData(
  encryptedData,
  userPassword
);
const wallet = JSON.parse(decrypted);
```

### API Service Credentials

Secure API keys and secrets in your services:

```javascript
const { SecureEncryption } = require('./src');

class APIService {
  constructor() {
    this.encryptedCredentials = null;
  }

  initialize(apiKey, apiSecret, masterPassword) {
    const credentials = { apiKey, apiSecret };
    
    // Encrypt credentials
    this.encryptedCredentials = SecureEncryption.encryptWalletData(
      JSON.stringify(credentials),
      masterPassword
    );
  }

  async makeRequest(endpoint) {
    // Decrypt credentials for use
    const credentials = JSON.parse(
      SecureEncryption.decryptWalletData(
        this.encryptedCredentials,
        process.env.MASTER_PASSWORD
      )
    );

    // Use credentials for API call
    return fetch(endpoint, {
      headers: {
        'Authorization': `Bearer ${credentials.apiKey}`
      }
    });
  }
}
```

### Data Processing Pipelines

Encrypt sensitive data in your processing workflows:

```javascript
const { SecureEncryption } = require('./src');

class DataProcessor {
  processSensitiveData(records, password) {
    // Encrypt before processing
    const encrypted = SecureEncryption.encryptWalletData(
      JSON.stringify(records),
      password
    );

    // Process encrypted data...
    // (In real scenarios, you might process in encrypted form)

    // Decrypt after processing
    return JSON.parse(
      SecureEncryption.decryptWalletData(encrypted, password)
    );
  }
}
```

### Multi-Account Management

Manage multiple encrypted accounts:

```javascript
const { SecureEncryption } = require('./src');

class AccountManager {
  constructor() {
    this.accounts = [];
  }

  addAccount(name, privateKey, password) {
    const encrypted = SecureEncryption.encryptWalletData(
      privateKey,
      password
    );

    this.accounts.push({
      id: generateId(),
      name,
      encryptedKey: encrypted
    });
  }

  unlockAccount(accountId, password) {
    const account = this.accounts.find(a => a.id === accountId);
    return SecureEncryption.decryptWalletData(
      account.encryptedKey,
      password
    );
  }
}
```

## Integration Guide

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Import the Module

```javascript
const { SecureEncryption, BlockchainMail } = require('./src');
```

### Step 3: Encrypt Your Data

Choose the appropriate method based on your use case:

- **Password-based**: Use `encryptWalletData()` for user-facing encryption
- **Token-based**: Use `encrypt()` with generated tokens for API workflows

### Step 4: Store Encrypted Data

Store the encrypted bundle (including salt, counter, etc.) securely:

```javascript
const encrypted = SecureEncryption.encryptWalletData(data, password);

// Store in database, file, or secure storage
await database.save({
  id: userId,
  encryptedData: encrypted
});
```

### Step 5: Decrypt When Needed

Decrypt only when necessary:

```javascript
const encrypted = await database.get(userId);
const decrypted = SecureEncryption.decryptWalletData(
  encrypted.encryptedData,
  userPassword
);
```

## API Reference

### SecureEncryption

#### `encryptWalletData(sensitiveData, password)`

Encrypts sensitive data with a password. Uses PBKDF2 for key derivation and AES-256-CTR for encryption.

**Parameters:**
- `sensitiveData` (string): Data to encrypt
- `password` (string): User password

**Returns:** Object with encrypted data, salt, counter, HMAC, and metadata

**Example:**
```javascript
const encrypted = SecureEncryption.encryptWalletData(
  '0x1234...',
  'MyPassword123!'
);
```

#### `decryptWalletData(encryptedBundle, password)`

Decrypts data encrypted with `encryptWalletData`.

**Parameters:**
- `encryptedBundle` (Object): Encrypted bundle from `encryptWalletData`
- `password` (string): User password

**Returns:** Decrypted string

**Example:**
```javascript
const decrypted = SecureEncryption.decryptWalletData(
  encrypted,
  'MyPassword123!'
);
```

#### `encrypt(data, token)`


**Parameters:**
- `data` (string|Buffer): Data to encrypt
- `token` (Buffer): 256-bit encryption token

**Returns:** Object with encrypted data and counter

**Example:**
```javascript
const token = SecureEncryption.generateKey();
const { encrypted, counter } = SecureEncryption.encrypt(
  'Sensitive data',
  token
);
```

#### `decrypt(encryptedData, token, counter)`

Decrypts data encrypted with `encrypt`.

**Parameters:**
- `encryptedData` (Buffer): Encrypted data
- `token` (Buffer): Encryption token
- `counter` (Buffer): Counter used during encryption

**Returns:** Decrypted string

**Example:**
```javascript
const decrypted = SecureEncryption.decrypt(
  encrypted,
  token,
  counter
);
```

#### `generateKey()`

Generates a random 256-bit token.

**Returns:** 32-byte Buffer

**Example:**
```javascript
const token = SecureEncryption.generateKey();
```

#### `deriveKey(password, salt, iterations)`

Derives an encryption token from a password using PBKDF2.

**Parameters:**
- `password` (string): User password
- `salt` (Buffer, optional): Cryptographic salt (auto-generated if not provided)
- `iterations` (number, optional): PBKDF2 iterations (default: 100000)

**Returns:** Object with token, salt, and iterations

**Example:**
```javascript
const { key, salt, iterations } = SecureEncryption.deriveKey(
  'MyPassword',
  null,
  100000
);
```

### BlockchainMail

#### `createAccount(walletAddress, privateKey, password)`

Creates a new blockchain mail account with encrypted private key storage.

**Parameters:**
- `walletAddress` (string): Blockchain wallet address
- `privateKey` (string): Wallet private key
- `password` (string): Encryption password

**Returns:** BlockchainMail instance

#### `unlockAccount(password)`

Decrypts and returns the private key.

**Parameters:**
- `password` (string): Account password

**Returns:** Decrypted private key

#### `composeEncryptedMessage(recipientAddress, subject, body, encryptionKey)`

Creates an encrypted message.

**Parameters:**
- `recipientAddress` (string): Recipient's address
- `subject` (string): Message subject
- `body` (string): Message body
- `encryptionKey` (string): Encryption key (hex string)

**Returns:** Encrypted message object

#### `decryptMessage(encryptedMessage, decryptionKey)`

Decrypts a received message.

**Parameters:**
- `encryptedMessage` (Object): Encrypted message
- `decryptionKey` (string): Decryption key (hex string)

**Returns:** Decrypted message object

## Examples

The repository includes comprehensive examples demonstrating different use cases and workflows:

### Getting Started
- **basic-usage.js** - Quick start examples for common operations
- **security-patterns.js** - Secure vs insecure patterns with detailed explanations

### Integration Guides
- **integration-guide.js** - Integration patterns for different application types
- **quick-integration.js** - Copy-paste ready code snippets

### Advanced Patterns

### Domain-Specific Examples
- **wallet-protection-examples.js** - Protecting wallet private keys, mnemonics, seed phrases, and recovery information
- **api-security-examples.js** - Securing API credentials, API keys, API secrets, access tokens, refresh tokens, and webhook secrets
- **production-workflows.js** - Real-world production workflows including automated backups, credential rotation, and batch processing

### Testing
- **test-encryption.js** - Comprehensive test suite

Run examples:

```bash
npm run example:basic
npm run example:integration
npm run example:patterns
npm run example:wallet
npm run example:api
npm run example:workflows
npm test
```

## Security Considerations

### What DMail Provides

- ✅ AES-256-CTR encryption
- ✅ PBKDF2 key derivation with configurable iterations
- ✅ Random counter generation for each encryption
- ✅ HMAC for integrity verification

### Best Practices

1. **Use strong passwords** - Enforce password requirements in your application
2. **Store tokens securely** - Protect encryption tokens like you protect private keys
3. **Generate unique counters** - Never reuse counters with the same token
4. **Limit exposure** - Decrypt data only when necessary
5. **Use environment variables** - Store master passwords in secure environment variables
6. **Regular backups** - Keep encrypted backups of critical data

### Production Deployment

Before deploying to production:

1. Review and audit the code for your specific use case
2. Ensure strong password policies are enforced
3. Use secure storage for encrypted data (HSMs, secure enclaves, etc.)
4. Implement proper access controls
5. Set up monitoring and logging (without logging sensitive data)
6. Have a backup and recovery plan
7. Consider using authenticated encryption (AES-GCM) for additional security

## Architecture

```
src/
  ├── crypto.js           # Core encryption utilities
  ├── blockchain-mail.js  # Mail system implementation
  └── index.js            # Main exports

examples/
  ├── basic-usage.js      # Getting started examples
  ├── integration-guide.js # Integration patterns
  ├── advanced-encryption-patterns.js # Advanced patterns
  ├── security-patterns.js # Security examples
  └── test-encryption.js  # Test suite
```

## Testing

Run the test suite:

```bash
npm test
```

The test suite verifies:
- Basic encryption and decryption
- Password-based encryption
- Token-based encryption
- Error handling
- Data integrity

## Contributing

Contributions are welcome! Please ensure that:

- Code follows existing patterns
- Includes appropriate tests
- Maintains backward compatibility

## License

MIT License - See LICENSE file for details

## Acknowledgments

This project was inspired by [blockchain-mail](https://github.com/samuel-eric/blockchain-mail), which provided initial ideas for implementing encrypted messaging on blockchain. DMail focuses on providing a lightweight, production-ready encryption solution for real-world applications.

---

**DMail** - Simple, secure encryption for your applications.
# dmail
