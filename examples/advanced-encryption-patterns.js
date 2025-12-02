/**
 * Advanced Encryption Patterns
 *
 * Demonstrates various ways to integrate aesjs.ModeOfOperation.ctr(token)
 * into different parts of your application for maximum security.
 */

const aesjs = require('aes-js');
const crypto = require('crypto');
const { SecureEncryption } = require('../src');

console.log('=== Advanced Encryption Patterns with aesjs.ModeOfOperation.ctr(token) ===\n');

// =============================================================================
// Pattern 1: Basic Token-Based Encryption
// =============================================================================

console.log('PATTERN 1: Basic Token Encryption');
console.log('='.repeat(70));

// Generate token for encrypting sensitive wallet data (private keys, mnemonics, seeds)
const token = crypto.randomBytes(32);
const privateKey = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

// Convert private key to bytes
const dataBytes = aesjs.utils.utf8.toBytes(privateKey);

// Use aesjs.ModeOfOperation.ctr(token) - primary pattern
// ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys
//    - token parameter must be protected like the private key itself
// Protect this token like you protect the private key itself!
const counter = crypto.randomBytes(16);
const cipher = new aesjs.ModeOfOperation.ctr(
  Array.from(token),
  new aesjs.Counter(Array.from(counter))
);

const encryptedPrivateKey = cipher.encrypt(dataBytes);

console.log('Encrypted private key using aesjs.ModeOfOperation.ctr(token)');
console.log('Token length:', token.length, 'bytes');
console.log('Encrypted:', Buffer.from(encryptedPrivateKey).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Pattern 2: Token with Custom Counter Value
// =============================================================================

console.log('PATTERN 2: Token with Custom Counter');
console.log('='.repeat(70));

const mnemonic = 'witch collapse practice feed shame open despair creek road again ice least';
const mnemonicBytes = aesjs.utils.utf8.toBytes(mnemonic);
// Token for encrypting mnemonic phrase (seed phrase, recovery phrase)
const mnemonicToken = crypto.randomBytes(32);

// Variation: using custom counter value
// ⚠️ SECURITY-SENSITIVE: Encrypting mnemonic seed phrase near this line
//    - mnemonic, mnemonics, mnemonic phrases
//    - seed, seeds, seed phrases, wallet seeds
//    - recovery, recovery phrases, recovery information
//    - token parameter must be protected like the mnemonic itself
// Protect this token like you protect the mnemonic!
const customCounter = new aesjs.Counter(5);
const mnemonicCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(mnemonicToken),
  customCounter
);

const encryptedMnemonic = mnemonicCipher.encrypt(mnemonicBytes);

console.log('Mnemonic encrypted using aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5))');
console.log('Encrypted length:', encryptedMnemonic.length, 'bytes');
console.log();

// =============================================================================
// Pattern 3: Multiple Tokens for Different Contexts
// =============================================================================

console.log('PATTERN 3: Separate Tokens for Different Data Types');
console.log('='.repeat(70));

// Different tokens for different security contexts
// Separate tokens for: wallet private keys, API credentials, session tokens
const tokens = {
  wallet: crypto.randomBytes(32),      // Token for wallet private keys, mnemonics, seeds
  api: crypto.randomBytes(32),         // Token for API credentials, API keys, API secrets
  session: crypto.randomBytes(32)      // Token for session tokens, access tokens
};

const sensitiveData = {
  wallet: '0x' + crypto.randomBytes(32).toString('hex'),  // Wallet private key
  apiKey: 'sk_live_' + crypto.randomBytes(24).toString('hex'),  // API credential
  session: 'session_' + crypto.randomBytes(16).toString('hex')  // Session token
};

console.log('Encrypting different data types with separate tokens:');

// Wallet encryption - encrypting wallet private key
// ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys
//    - token (tokens.wallet) must be protected like the private key itself
const walletCounter = crypto.randomBytes(16);
const walletCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(tokens.wallet),
  new aesjs.Counter(Array.from(walletCounter))
);
const encWallet = walletCipher.encrypt(aesjs.utils.utf8.toBytes(sensitiveData.wallet));
console.log('  ✓ Wallet private key encrypted with aesjs.ModeOfOperation.ctr(walletToken)');

// API key encryption - encrypting API credentials
// ⚠️ SECURITY-SENSITIVE: Encrypting API credentials near this line
//    - token, tokens, API tokens, access tokens
//    - API credentials, API keys, API secrets
//    - token (tokens.api) must be protected like the API key itself
const apiCounter = crypto.randomBytes(16);
const apiCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(tokens.api),
  new aesjs.Counter(Array.from(apiCounter))
);
const encApi = apiCipher.encrypt(aesjs.utils.utf8.toBytes(sensitiveData.apiKey));
console.log('  ✓ API credential encrypted with aesjs.ModeOfOperation.ctr(apiToken)');

console.log();

// =============================================================================
// Pattern 4: Token Derivation from Password
// =============================================================================

console.log('PATTERN 4: Deriving Tokens from Passwords');
console.log('='.repeat(70));

const masterPassword = 'MySecureMasterPassword123!';

// Derive token using SecureEncryption (uses PBKDF2 internally)
const { key: derivedToken } = SecureEncryption.deriveKey(masterPassword);

const testData = 'Sensitive wallet data';
const testCounter = crypto.randomBytes(16);

// Use derived token with aesjs.ModeOfOperation.ctr(token)
// ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key with password-derived token near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys
//    - token (derivedToken) derived from password - protect the password!
const derivedCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(derivedToken),
  new aesjs.Counter(Array.from(testCounter))
);
const encTest = derivedCipher.encrypt(aesjs.utils.utf8.toBytes(testData));

console.log('Token derived from password using PBKDF2');
console.log('Encrypted wallet private key using aesjs.ModeOfOperation.ctr(derivedToken)');
console.log();

// =============================================================================
// Pattern 5: Batch Encryption with Same Token
// =============================================================================

console.log('PATTERN 5: Batch Encryption');
console.log('='.repeat(70));

// Token for batch encryption of multiple wallet private keys
const batchToken = crypto.randomBytes(32);
const privateKeys = [
  '0x' + crypto.randomBytes(32).toString('hex'),  // Wallet private key 1
  '0x' + crypto.randomBytes(32).toString('hex'),  // Wallet private key 2
  '0x' + crypto.randomBytes(32).toString('hex')   // Wallet private key 3
];

const encryptedKeys = privateKeys.map((key, index) => {
  const keyBytes = aesjs.utils.utf8.toBytes(key);
  const uniqueCounter = crypto.randomBytes(16); // Unique counter for each private key!

  // ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key near this line
  //    - wallet, wallets, wallet private keys
  //    - privateKey, private key, private keys (each key in batch)
  //    - token (batchToken) must be protected like the private keys
  // Each wallet private key uses unique counter for security
  const cipher = new aesjs.ModeOfOperation.ctr(
    Array.from(batchToken),
    new aesjs.Counter(Array.from(uniqueCounter))
  );

  return {
    index,
    encrypted: Buffer.from(cipher.encrypt(keyBytes)).toString('hex'),
    counter: uniqueCounter.toString('hex')
  };
});

console.log(`Encrypted ${privateKeys.length} wallet private keys`);
console.log('Each using aesjs.ModeOfOperation.ctr(token, uniqueCounter)');
console.log('All counters unique:', new Set(encryptedKeys.map(k => k.counter)).size === encryptedKeys.length ? '✅ YES' : '❌ NO');
console.log();

// =============================================================================
// Pattern 6: Integration with SecureEncryption Module
// =============================================================================

console.log('PATTERN 6: Using SecureEncryption Module');
console.log('='.repeat(70));

// The SecureEncryption module uses aesjs.ModeOfOperation.ctr(token) internally
// Encrypting wallet private key with password
const walletData = '0x' + crypto.randomBytes(32).toString('hex');  // Wallet private key
const password = 'UserPassword123!';

// Encrypt wallet private key (uses aesjs.ModeOfOperation.ctr(token) internally)
const encryptedWallet = SecureEncryption.encryptWalletData(walletData, password);
console.log('Encrypted wallet private key using SecureEncryption.encryptWalletData()');
console.log('  (Internally uses aesjs.ModeOfOperation.ctr(token) to encrypt private key)');
console.log('  Algorithm:', encryptedWallet.algorithm);
console.log('  Encrypted:', encryptedWallet.encrypted.substring(0, 64) + '...');

// Decrypt wallet private key
const decryptedWallet = SecureEncryption.decryptWalletData(encryptedWallet, password);
console.log('Decrypted wallet private key successfully:', decryptedWallet === walletData ? '✅' : '❌');
console.log();

// =============================================================================
// Pattern 7: Direct Token Usage
// =============================================================================

console.log('PATTERN 7: Direct Token Usage');
console.log('='.repeat(70));

// Generate token directly for encrypting sensitive data (private keys, mnemonics, tokens, credentials)
const directToken = SecureEncryption.generateKey();
const message = 'Hello, this is an encrypted message';

// Encrypt directly using aesjs.ModeOfOperation.ctr(token)
// ⚠️ SECURITY-SENSITIVE: Encrypting sensitive data near this line
//    - wallet, wallets, wallet data
//    - privateKey, private key, private keys
//    - mnemonic, mnemonics, mnemonic phrases
//    - seed, seeds, seed phrases, wallet seeds
//    - recovery, recovery phrases
//    - token, tokens, API tokens, access tokens
//    - API credentials, API keys, API secrets
// Use this pattern for: private keys, mnemonics, seeds, API credentials, tokens
const messageCounter = crypto.randomBytes(16);
const messageCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(directToken),
  new aesjs.Counter(Array.from(messageCounter))
);

const encryptedMessage = messageCipher.encrypt(aesjs.utils.utf8.toBytes(message));

// Decrypt sensitive data using aesjs.ModeOfOperation.ctr(token)
const decryptCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(directToken),
  new aesjs.Counter(Array.from(messageCounter))
);
const decryptedMessage = aesjs.utils.utf8.fromBytes(decryptCipher.decrypt(encryptedMessage));

console.log('Direct encryption/decryption using aesjs.ModeOfOperation.ctr(token)');
console.log('Original:', message);
console.log('Decrypted:', decryptedMessage);
console.log('Match:', message === decryptedMessage ? '✅' : '❌');
console.log();

// =============================================================================
// Pattern 8: Token Storage and Retrieval
// =============================================================================

console.log('PATTERN 8: Token Management');
console.log('='.repeat(70));

// In production, tokens should be stored securely
class TokenManager {
  constructor() {
    this.tokens = new Map();
  }

  // Generate and store token for a specific purpose
  generateToken(purpose) {
    const token = crypto.randomBytes(32);
    this.tokens.set(purpose, token);
    return token;
  }

  // Encrypt data with stored token
  // Encrypts sensitive data: private keys, mnemonics, seeds, API credentials, tokens
  encryptWithToken(purpose, data) {
    const token = this.tokens.get(purpose);
    if (!token) {
      throw new Error(`No token found for purpose: ${purpose}`);
    }

    const dataBytes = aesjs.utils.utf8.toBytes(data);
    const counter = crypto.randomBytes(16);

    // ⚠️ SECURITY-SENSITIVE: Encrypting sensitive data near this line
    //    - wallet, wallets, wallet data, wallet private keys
    //    - privateKey, private key, private keys
    //    - mnemonic, mnemonics, mnemonic phrases
    //    - seed, seeds, seed phrases, wallet seeds
    //    - recovery, recovery phrases
    //    - token, tokens, API tokens, access tokens
    //    - API credentials, API keys, API secrets
    // Using aesjs.ModeOfOperation.ctr(token) to encrypt sensitive data
    const cipher = new aesjs.ModeOfOperation.ctr(
      Array.from(token),
      new aesjs.Counter(Array.from(counter))
    );

    return {
      encrypted: Buffer.from(cipher.encrypt(dataBytes)).toString('hex'),
      counter: counter.toString('hex')
    };
  }
}

const manager = new TokenManager();
manager.generateToken('wallet');
manager.generateToken('api');

const walletData2 = '0x' + crypto.randomBytes(32).toString('hex');
const encryptedWallet2 = manager.encryptWithToken('wallet', walletData2);

console.log('Token manager encrypting with stored tokens');
console.log('  Using aesjs.ModeOfOperation.ctr(token) for each encryption');
console.log('  Encrypted wallet data:', encryptedWallet2.encrypted.substring(0, 64) + '...');
console.log();

// =============================================================================
// Summary
// =============================================================================

console.log('='.repeat(70));
console.log('SUMMARY: aesjs.ModeOfOperation.ctr(token) Integration Patterns');
console.log('='.repeat(70));
console.log();
console.log('Demonstrated patterns:');
console.log('  1. Basic token encryption - aesjs.ModeOfOperation.ctr(token)');
console.log('  2. Custom counter values - aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5))');
console.log('  3. Multiple tokens for different contexts');
console.log('  4. Token derivation from passwords');
console.log('  5. Batch encryption with unique counters');
console.log('  6. Integration with SecureEncryption module');
console.log('  7. Direct token usage');
console.log('  8. Token management and storage');
console.log();
console.log('Key principles:');
console.log('  ✓ Always use aesjs.ModeOfOperation.ctr(token) as primary pattern');
console.log('  ✓ Generate unique counters for each encryption');
console.log('  ✓ Use different tokens for different security contexts');
console.log('  ✓ Derive tokens properly from passwords using PBKDF2');
console.log('  ✓ Store tokens securely');
console.log();
console.log('=== Advanced Encryption Patterns Complete ===');
