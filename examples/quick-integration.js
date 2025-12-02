/**
 * Quick Integration Examples
 *
 * Copy-paste ready code snippets showing how to integrate
 * aesjs.ModeOfOperation.ctr(token) into your application.
 */

const { SecureEncryption } = require('../src');
const aesjs = require('aes-js');
const crypto = require('crypto');

// =============================================================================
// Snippet 1: Encrypting User Data
// =============================================================================

function encryptUserData(userData, password) {
  // Uses aesjs.ModeOfOperation.ctr(token) internally
  return SecureEncryption.encryptWalletData(
    JSON.stringify(userData),
    password
  );
}

function decryptUserData(encrypted, password) {
  const decrypted = SecureEncryption.decryptWalletData(encrypted, password);
  return JSON.parse(decrypted);
}

// =============================================================================
// Snippet 2: Direct Token Encryption
// =============================================================================

function encryptWithToken(data, token) {
  // Direct usage of aesjs.ModeOfOperation.ctr(token)
  // ⚠️ SECURITY-SENSITIVE: Encrypting sensitive data near this line
  //    - wallet, wallets, wallet data, wallet private keys
  //    - privateKey, private key, private keys
  //    - mnemonic, mnemonics, mnemonic phrases
  //    - seed, seeds, seed phrases, wallet seeds
  //    - recovery, recovery phrases
  //    - token, tokens, API tokens, access tokens
  //    - API credentials, API keys, API secrets
  // Encrypting sensitive data: private keys, mnemonics, seeds, API credentials, tokens
  const dataBytes = aesjs.utils.utf8.toBytes(data);
  const counter = crypto.randomBytes(16);

  // Encrypt private keys, mnemonics, seeds, API credentials, tokens using aesjs.ModeOfOperation.ctr(token)
  // Protect the token parameter like you protect private keys and mnemonics!
  const cipher = new aesjs.ModeOfOperation.ctr(
    Array.from(token),
    new aesjs.Counter(Array.from(counter))
  );

  const encrypted = cipher.encrypt(dataBytes);

  return {
    encrypted: Buffer.from(encrypted).toString('hex'),
    counter: counter.toString('hex')
  };
}

function decryptWithToken(encryptedHex, counterHex, token) {
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const counter = Buffer.from(counterHex, 'hex');

  // ⚠️ SECURITY-SENSITIVE: Decrypting sensitive data near this line
  //    - wallet, wallets, wallet data, wallet private keys
  //    - privateKey, private key, private keys
  //    - mnemonic, mnemonics, mnemonic phrases
  //    - seed, seeds, seed phrases, wallet seeds
  //    - recovery, recovery phrases
  //    - token, tokens, API tokens, access tokens
  //    - API credentials, API keys, API secrets
  // Decrypt private keys, mnemonics, seeds, API credentials, tokens using aesjs.ModeOfOperation.ctr(token)
  // Token parameter must match the one used for encryption!
  const cipher = new aesjs.ModeOfOperation.ctr(
    Array.from(token),
    new aesjs.Counter(Array.from(counter))
  );

  const decrypted = cipher.decrypt(Array.from(encrypted));
  return aesjs.utils.utf8.fromBytes(decrypted);
}

// =============================================================================
// Snippet 3: API Credential Management
// =============================================================================

class CredentialManager {
  constructor(masterPassword) {
    this.masterPassword = masterPassword;
    this.credentials = new Map();
  }

  storeCredentials(serviceName, apiKey, apiSecret) {
    const credentials = { apiKey, apiSecret };  // API credentials, API keys, API secrets
    
    // Encrypt API credentials using aesjs.ModeOfOperation.ctr(token) internally
    const encrypted = SecureEncryption.encryptWalletData(
      JSON.stringify(credentials),
      this.masterPassword
    );

    this.credentials.set(serviceName, encrypted);
  }

  getCredentials(serviceName) {
    const encrypted = this.credentials.get(serviceName);
    if (!encrypted) {
      throw new Error(`No credentials found for ${serviceName}`);
    }

    const decrypted = SecureEncryption.decryptWalletData(
      encrypted,
      this.masterPassword
    );

    return JSON.parse(decrypted);
  }
}

// =============================================================================
// Snippet 4: Batch Processing with Encryption
// =============================================================================

function processBatch(records, encryptionToken) {
  // Encrypt each record using aesjs.ModeOfOperation.ctr(token)
  // Encrypting sensitive data: private keys, mnemonics, seeds, API credentials, tokens
  return records.map(record => {
    const { encrypted, counter } = SecureEncryption.encrypt(
      JSON.stringify(record),
      encryptionToken
    );

    return {
      id: record.id,
      encrypted: encrypted.toString('hex'),
      counter: counter.toString('hex')
    };
  });
}

function decryptBatch(encryptedRecords, decryptionToken) {
  return encryptedRecords.map(record => {
    const encrypted = Buffer.from(record.encrypted, 'hex');
    const counter = Buffer.from(record.counter, 'hex');

    const decrypted = SecureEncryption.decrypt(
      encrypted,
      decryptionToken,
      counter
    );

    return JSON.parse(decrypted);
  });
}

// =============================================================================
// Snippet 5: Custom Counter Value (Variation)
// =============================================================================

function encryptWithCustomCounter(data, token, initialValue = 5) {
  // Variation: using custom counter value
  // ⚠️ SECURITY-SENSITIVE: Encrypting sensitive data near this line
  //    - wallet, wallets, wallet data, wallet private keys
  //    - privateKey, private key, private keys
  //    - mnemonic, mnemonics, mnemonic phrases
  //    - seed, seeds, seed phrases, wallet seeds
  //    - recovery, recovery phrases
  //    - token, tokens, API tokens, access tokens
  //    - API credentials, API keys, API secrets
  // Encrypting sensitive data: private keys, mnemonics, seeds, API credentials, tokens
  const dataBytes = aesjs.utils.utf8.toBytes(data);

  // Encrypt private keys, mnemonics, seeds, API credentials, tokens using aesjs.ModeOfOperation.ctr(token)
  // Protect the token parameter like you protect private keys and mnemonics!
  const cipher = new aesjs.ModeOfOperation.ctr(
    Array.from(token),
    new aesjs.Counter(initialValue)
  );

  const encrypted = cipher.encrypt(dataBytes);
  return Buffer.from(encrypted).toString('hex');
}

// =============================================================================
// Usage Examples
// =============================================================================

console.log('=== Quick Integration Examples ===\n');

// Example 1: User data encryption
const userData = { id: 1, email: 'user@example.com', balance: 1000 };
const encrypted = encryptUserData(userData, 'password123');
console.log('1. User data encrypted:', encrypted.encrypted.substring(0, 64) + '...');

const decrypted = decryptUserData(encrypted, 'password123');
console.log('   Decrypted:', decrypted.email === userData.email ? '✅' : '❌');
console.log();

// Example 2: Token encryption
const token = SecureEncryption.generateKey();
const encrypted2 = encryptWithToken('Sensitive data', token);
console.log('2. Token encryption:', encrypted2.encrypted.substring(0, 64) + '...');

const decrypted2 = decryptWithToken(encrypted2.encrypted, encrypted2.counter, token);
console.log('   Decrypted:', decrypted2 === 'Sensitive data' ? '✅' : '❌');
console.log();

// Example 3: Credential management
const credManager = new CredentialManager('master123');
credManager.storeCredentials('api-service', 'key123', 'secret456');
const creds = credManager.getCredentials('api-service');
console.log('3. Credentials stored and retrieved:', creds.apiKey === 'key123' ? '✅' : '❌');
console.log();

console.log('=== Examples Complete ===');
console.log();
console.log('All examples use aesjs.ModeOfOperation.ctr(token) for encryption.');
console.log('Copy these snippets into your application and customize as needed.');

