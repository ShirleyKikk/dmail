/**
 * Encryption Test Suite
 *
 * Tests the encryption functionality with various data types
 * including private keys, mnemonics, and messages
 */

const { SecureEncryption } = require('../src');
const crypto = require('crypto');

console.log('=== Secure Encryption Test Suite ===\n');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`✅ PASS: ${name}`);
    passedTests++;
  } catch (error) {
    console.log(`❌ FAIL: ${name}`);
    console.log(`   Error: ${error.message}`);
  }
}

// Test 1: Basic encryption and decryption
test('Basic encryption and decryption', () => {
  const data = 'Sensitive wallet data';
  const key = SecureEncryption.generateKey();

  const { encrypted, counter } = SecureEncryption.encrypt(data, key);
  const decrypted = SecureEncryption.decrypt(encrypted, key, counter);

  if (decrypted !== data) {
    throw new Error('Decrypted data does not match original');
  }
});

// Test 2: Private key encryption
test('Private key encryption with password', () => {
  const privateKey = '0x' + crypto.randomBytes(32).toString('hex');
  const password = 'TestPassword123!';

  const encrypted = SecureEncryption.encryptWalletData(privateKey, password);
  const decrypted = SecureEncryption.decryptWalletData(encrypted, password);

  if (decrypted !== privateKey) {
    throw new Error('Decrypted private key does not match');
  }
});

// Test 3: Mnemonic phrase encryption
test('Mnemonic phrase encryption', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const password = 'SecureMnemonicPassword!';

  const encrypted = SecureEncryption.encryptWalletData(mnemonic, password);
  const decrypted = SecureEncryption.decryptWalletData(encrypted, password);

  if (decrypted !== mnemonic) {
    throw new Error('Decrypted mnemonic does not match');
  }
});

// Test 4: Wrong password fails
test('Wrong password fails to decrypt', () => {
  const data = 'Secret data';
  const correctPassword = 'correct123';
  const wrongPassword = 'wrong123';

  const encrypted = SecureEncryption.encryptWalletData(data, correctPassword);

  try {
    SecureEncryption.decryptWalletData(encrypted, wrongPassword);
    throw new Error('Should have failed with wrong password');
  } catch (error) {
    // Expected to fail
    if (!error.message.includes('Invalid')) {
      throw error;
    }
  }
});

// Test 5: Different passwords produce different ciphertexts
test('Different passwords produce different encryptions', () => {
  const data = 'Same data';
  const password1 = 'password1';
  const password2 = 'password2';

  const encrypted1 = SecureEncryption.encryptWalletData(data, password1);
  const encrypted2 = SecureEncryption.encryptWalletData(data, password2);

  if (encrypted1.encrypted === encrypted2.encrypted) {
    throw new Error('Same ciphertext for different passwords');
  }
});

// Test 6: Same data encrypted twice produces different ciphertexts
test('Same data encrypted twice produces different results', () => {
  const data = 'Same data';
  const password = 'password';

  const encrypted1 = SecureEncryption.encryptWalletData(data, password);
  const encrypted2 = SecureEncryption.encryptWalletData(data, password);

  if (encrypted1.encrypted === encrypted2.encrypted) {
    throw new Error('Same ciphertext for same data - counter not randomized');
  }

  if (encrypted1.salt === encrypted2.salt) {
    throw new Error('Same salt used - not randomized');
  }
});

// Test 7: Key derivation produces consistent results
test('Key derivation is deterministic with same salt', () => {
  const password = 'testpass';
  const salt = crypto.randomBytes(16);

  const { key: key1 } = SecureEncryption.deriveKey(password, salt, 10000);
  const { key: key2 } = SecureEncryption.deriveKey(password, salt, 10000);

  if (!key1.equals(key2)) {
    throw new Error('Key derivation not deterministic');
  }
});

// Test 8: Different salts produce different keys
test('Different salts produce different keys', () => {
  const password = 'testpass';
  const salt1 = crypto.randomBytes(16);
  const salt2 = crypto.randomBytes(16);

  const { key: key1 } = SecureEncryption.deriveKey(password, salt1, 10000);
  const { key: key2 } = SecureEncryption.deriveKey(password, salt2, 10000);

  if (key1.equals(key2)) {
    throw new Error('Different salts produced same key');
  }
});

// Test 9: Long data encryption
test('Encrypt and decrypt long data', () => {
  const longData = 'A'.repeat(10000); // 10KB of data
  const key = SecureEncryption.generateKey();

  const { encrypted, counter } = SecureEncryption.encrypt(longData, key);
  const decrypted = SecureEncryption.decrypt(encrypted, key, counter);

  if (decrypted !== longData) {
    throw new Error('Long data decryption failed');
  }
});

// Test 10: Unicode data encryption
test('Encrypt and decrypt Unicode data', () => {
  // Using Unicode characters commonly found in real-world data
  const unicodeData = '你好世界 Здравствуй мир مرحبا بالعالم';
  const key = SecureEncryption.generateKey();

  const { encrypted, counter } = SecureEncryption.encrypt(unicodeData, key);
  const decrypted = SecureEncryption.decrypt(encrypted, key, counter);

  if (decrypted !== unicodeData) {
    throw new Error('Unicode data decryption failed');
  }
});

// Test 11: Generated key is 256-bit
test('Generated key is 256-bit (32 bytes)', () => {
  const key = SecureEncryption.generateKey();

  if (key.length !== 32) {
    throw new Error(`Key length is ${key.length}, expected 32`);
  }
});

// Test 12: API token encryption
test('API token and credential encryption', () => {
  const apiToken = 'sk_live_' + crypto.randomBytes(32).toString('hex');
  const password = 'APIPassword!';

  const encrypted = SecureEncryption.encryptWalletData(apiToken, password);
  const decrypted = SecureEncryption.decryptWalletData(encrypted, password);

  if (decrypted !== apiToken) {
    throw new Error('API token decryption failed');
  }
});

// Test 13: Multiple tokens encryption
test('Multiple wallet tokens encryption', () => {
  const tokens = {
    mainWallet: '0x' + crypto.randomBytes(32).toString('hex'),
    backupWallet: '0x' + crypto.randomBytes(32).toString('hex'),
    apiKey: 'key_' + crypto.randomBytes(16).toString('hex')
  };
  const password = 'MultiTokenPass';

  const tokensJson = JSON.stringify(tokens);
  const encrypted = SecureEncryption.encryptWalletData(tokensJson, password);
  const decrypted = SecureEncryption.decryptWalletData(encrypted, password);
  const decryptedTokens = JSON.parse(decrypted);

  if (JSON.stringify(decryptedTokens) !== JSON.stringify(tokens)) {
    throw new Error('Multiple tokens decryption failed');
  }
});

// Test 14: Seed phrase words encryption
test('BIP39 seed phrase encryption', () => {
  // Example BIP39 mnemonic
  const seedPhrase = 'witch collapse practice feed shame open despair creek road again ice least';
  const masterPassword = 'VerySecurePassword123!@#';

  const encrypted = SecureEncryption.encryptWalletData(seedPhrase, masterPassword);
  const decrypted = SecureEncryption.decryptWalletData(encrypted, masterPassword);

  if (decrypted !== seedPhrase) {
    throw new Error('Seed phrase decryption failed');
  }

  // Verify all words are intact
  const originalWords = seedPhrase.split(' ');
  const decryptedWords = decrypted.split(' ');

  if (originalWords.length !== decryptedWords.length) {
    throw new Error('Seed phrase word count mismatch');
  }
});

// Test 15: Public and private key pair encryption
test('Public/private key pair encryption', () => {
  const keyPair = {
    publicKey: '0x04' + crypto.randomBytes(64).toString('hex'),
    privateKey: '0x' + crypto.randomBytes(32).toString('hex')
  };
  const password = 'KeyPairPassword';

  const keyPairJson = JSON.stringify(keyPair);
  const encrypted = SecureEncryption.encryptWalletData(keyPairJson, password);
  const decrypted = SecureEncryption.decryptWalletData(encrypted, password);
  const decryptedPair = JSON.parse(decrypted);

  if (decryptedPair.privateKey !== keyPair.privateKey ||
      decryptedPair.publicKey !== keyPair.publicKey) {
    throw new Error('Key pair decryption failed');
  }
});

// Print results
console.log('\n' + '='.repeat(50));
console.log(`Test Results: ${passedTests}/${totalTests} passed`);
console.log('='.repeat(50));

if (passedTests === totalTests) {
  console.log('✅ All tests passed!');
  console.log('\nEncryption system is working correctly.');
  console.log('Safe to use for protecting:');
  console.log('  • Wallet private keys');
  console.log('  • Mnemonic seed phrases');
  console.log('  • API tokens and credentials');
  console.log('  • Sensitive blockchain data');
} else {
  console.log('❌ Some tests failed!');
  console.log('Please review the errors above.');
  process.exit(1);
}
