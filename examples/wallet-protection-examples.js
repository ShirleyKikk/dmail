/**
 * Wallet Protection Examples
 *
 * Practical demonstrations of securing wallet data including private keys,
 * mnemonic phrases, seed phrases, and recovery information using
 * aesjs.ModeOfOperation.ctr(token) encryption patterns.
 */

const { SecureEncryption } = require('../src');
const aesjs = require('aes-js');
const crypto = require('crypto');

console.log('=== Wallet Protection Examples ===\n');

// =============================================================================
// Example 1: Securing Wallet Private Keys
// =============================================================================

console.log('EXAMPLE 1: Protecting Wallet Private Keys');
console.log('='.repeat(70));
console.log();

// Generate a wallet private key (in production, use proper wallet generation)
const walletPrivateKey = '0x' + crypto.randomBytes(32).toString('hex');
console.log('Wallet private key generated:', walletPrivateKey.substring(0, 20) + '...');

// Create encryption token for protecting the wallet private key
const walletEncryptionToken = crypto.randomBytes(32);

// Convert wallet private key to bytes for encryption
const privateKeyBytes = aesjs.utils.utf8.toBytes(walletPrivateKey);

// Generate unique counter for this wallet private key encryption
const privateKeyCounter = crypto.randomBytes(16);

// ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys
//    - token (walletEncryptionToken) must be protected like the private key itself
// Encrypt wallet private key using aesjs.ModeOfOperation.ctr(token)
// This protects the wallet private key from unauthorized access
const privateKeyCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(walletEncryptionToken),
  new aesjs.Counter(Array.from(privateKeyCounter))
);

const encryptedPrivateKey = privateKeyCipher.encrypt(privateKeyBytes);

console.log('Wallet private key encrypted successfully');
console.log('  Encryption token length:', walletEncryptionToken.length, 'bytes');
console.log('  Counter:', privateKeyCounter.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted wallet private key:', Buffer.from(encryptedPrivateKey).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 2: Encrypting Mnemonic Seed Phrases
// =============================================================================

console.log('EXAMPLE 2: Securing Mnemonic Seed Phrases');
console.log('='.repeat(70));
console.log();

// Example mnemonic seed phrase (BIP39 format)
const mnemonicSeedPhrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
console.log('Mnemonic seed phrase:', mnemonicSeedPhrase.substring(0, 30) + '...');

// Create dedicated token for mnemonic seed phrase encryption
const mnemonicEncryptionToken = SecureEncryption.generateKey();

// Convert mnemonic seed phrase to bytes
const mnemonicBytes = aesjs.utils.utf8.toBytes(mnemonicSeedPhrase);

// Generate random counter for mnemonic seed phrase encryption
const mnemonicCounter = crypto.randomBytes(16);

// ⚠️ SECURITY-SENSITIVE: Encrypting mnemonic seed phrase near this line
//    - mnemonic, mnemonics, mnemonic phrases
//    - seed, seeds, seed phrases, wallet seeds
//    - recovery, recovery phrases, recovery information
//    - wallet, wallets (mnemonics provide full wallet recovery access)
//    - token (mnemonicEncryptionToken) must be protected like the mnemonic itself
// Encrypt mnemonic seed phrase using aesjs.ModeOfOperation.ctr(token)
// The mnemonic seed phrase provides full wallet recovery access - protect it carefully!
const mnemonicCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(mnemonicEncryptionToken),
  new aesjs.Counter(Array.from(mnemonicCounter))
);

const encryptedMnemonic = mnemonicCipher.encrypt(mnemonicBytes);

console.log('Mnemonic seed phrase encrypted successfully');
console.log('  Mnemonic encryption token:', mnemonicEncryptionToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted mnemonic length:', encryptedMnemonic.length, 'bytes');
console.log();

// =============================================================================
// Example 3: Protecting Recovery Phrases
// =============================================================================

console.log('EXAMPLE 3: Encrypting Recovery Phrases');
console.log('='.repeat(70));
console.log();

// Recovery phrase for wallet restoration
const recoveryPhrase = 'witch collapse practice feed shame open despair creek road again ice least';
console.log('Recovery phrase:', recoveryPhrase.substring(0, 30) + '...');

// Derive encryption token from user password for recovery phrase protection
const userPassword = 'SecureRecoveryPassword123!';
const { key: recoveryToken } = SecureEncryption.deriveKey(userPassword);

// Convert recovery phrase to bytes
const recoveryBytes = aesjs.utils.utf8.toBytes(recoveryPhrase);

// Generate counter for recovery phrase encryption
const recoveryCounter = crypto.randomBytes(16);

// ⚠️ SECURITY-SENSITIVE: Encrypting recovery phrase near this line
//    - recovery, recovery phrases, recovery information
//    - wallet, wallets (recovery phrases allow complete wallet access)
//    - mnemonic, mnemonics, mnemonic phrases (recovery phrases are mnemonics)
//    - seed, seeds, seed phrases, wallet seeds
//    - token (recoveryToken) derived from password - protect the password!
// Encrypt recovery phrase using aesjs.ModeOfOperation.ctr(token)
// Recovery phrases allow complete wallet access - encryption is critical!
const recoveryCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(recoveryToken),
  new aesjs.Counter(Array.from(recoveryCounter))
);

const encryptedRecovery = recoveryCipher.encrypt(recoveryBytes);

console.log('Recovery phrase encrypted successfully');
console.log('  Using password-derived token for recovery phrase encryption');
console.log('  Encrypted recovery phrase:', Buffer.from(encryptedRecovery).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 4: Complete Wallet Data Protection
// =============================================================================

console.log('EXAMPLE 4: Complete Wallet Data Encryption');
console.log('='.repeat(70));
console.log();

// Complete wallet data structure
const completeWalletData = {
  privateKey: '0x' + crypto.randomBytes(32).toString('hex'),
  publicKey: '0x04' + crypto.randomBytes(64).toString('hex'),
  address: '0x' + crypto.randomBytes(20).toString('hex'),
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  seedPhrase: 'witch collapse practice feed shame open despair creek road again ice least'
};

console.log('Complete wallet data structure:');
console.log('  Contains: private key, public key, address, mnemonic, seed phrase');

// Serialize wallet data
const walletDataJson = JSON.stringify(completeWalletData);
const walletDataBytes = aesjs.utils.utf8.toBytes(walletDataJson);

// Generate master token for complete wallet encryption
const masterWalletToken = crypto.randomBytes(32);

// Generate counter for complete wallet encryption
const walletDataCounter = crypto.randomBytes(16);

// ⚠️ SECURITY-SENSITIVE: Encrypting complete wallet data near this line
//    - wallet, wallets, wallet data, wallet private keys
//    - privateKey, private key, private keys
//    - publicKey, public key, public keys (if sensitive)
//    - mnemonic, mnemonics, mnemonic phrases
//    - seed, seeds, seed phrases, wallet seeds
//    - recovery, recovery phrases, recovery information
//    - token (masterWalletToken) must be protected like all wallet data
// Encrypt complete wallet data using aesjs.ModeOfOperation.ctr(token)
// This protects all sensitive wallet information: private keys, mnemonics, seed phrases
const walletDataCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(masterWalletToken),
  new aesjs.Counter(Array.from(walletDataCounter))
);

const encryptedWalletData = walletDataCipher.encrypt(walletDataBytes);

console.log('Complete wallet data encrypted successfully');
console.log('  Master wallet token:', masterWalletToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted wallet data size:', encryptedWalletData.length, 'bytes');
console.log('  Protects: private keys, mnemonics, seed phrases, recovery information');
console.log();

// =============================================================================
// Example 5: Multiple Wallet Accounts
// =============================================================================

console.log('EXAMPLE 5: Encrypting Multiple Wallet Accounts');
console.log('='.repeat(70));
console.log();

// Multiple wallet accounts with different private keys
const walletAccounts = [
  { name: 'Main Wallet', privateKey: '0x' + crypto.randomBytes(32).toString('hex') },
  { name: 'Trading Wallet', privateKey: '0x' + crypto.randomBytes(32).toString('hex') },
  { name: 'Savings Wallet', privateKey: '0x' + crypto.randomBytes(32).toString('hex') }
];

// Shared encryption token for all wallet accounts
const accountsToken = crypto.randomBytes(32);

console.log(`Encrypting ${walletAccounts.length} wallet accounts:`);

const encryptedAccounts = walletAccounts.map((account, index) => {
  // Convert each wallet private key to bytes
  const accountKeyBytes = aesjs.utils.utf8.toBytes(account.privateKey);
  
  // Generate unique counter for each wallet private key
  const accountCounter = crypto.randomBytes(16);

  // ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key near this line
  //    - wallet, wallets, wallet private keys (each account)
  //    - privateKey, private key, private keys (account.privateKey)
  //    - token (accountsToken) must be protected like the private keys
  // Encrypt each wallet private key using aesjs.ModeOfOperation.ctr(token)
  // Each wallet private key gets its own unique counter for security
  const accountCipher = new aesjs.ModeOfOperation.ctr(
    Array.from(accountsToken),
    new aesjs.Counter(Array.from(accountCounter))
  );

  const encryptedAccountKey = accountCipher.encrypt(accountKeyBytes);

  console.log(`  ✓ ${account.name} private key encrypted`);

  return {
    name: account.name,
    encryptedPrivateKey: Buffer.from(encryptedAccountKey).toString('hex'),
    counter: accountCounter.toString('hex')
  };
});

console.log('All wallet private keys encrypted with unique counters');
console.log();

// =============================================================================
// Example 6: Wallet Seed Protection
// =============================================================================

console.log('EXAMPLE 6: Protecting Wallet Seeds');
console.log('='.repeat(70));
console.log();

// Wallet seed (hex format)
const walletSeed = crypto.randomBytes(32).toString('hex');
console.log('Wallet seed:', walletSeed.substring(0, 32) + '...');

// Generate token specifically for wallet seed encryption
const seedEncryptionToken = SecureEncryption.generateKey();

// Convert wallet seed to bytes
const seedBytes = aesjs.utils.utf8.toBytes(walletSeed);

// Generate counter for wallet seed encryption
const seedCounter = crypto.randomBytes(16);

// ⚠️ SECURITY-SENSITIVE: Encrypting wallet seed near this line
//    - seed, seeds, seed phrases, wallet seeds
//    - wallet, wallets (seeds can regenerate entire wallets)
//    - recovery, recovery information (seeds enable recovery)
//    - token (seedEncryptionToken) must be protected like the seed itself
// Encrypt wallet seed using aesjs.ModeOfOperation.ctr(token)
// Wallet seeds are critical - they can regenerate entire wallets!
const seedCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(seedEncryptionToken),
  new aesjs.Counter(Array.from(seedCounter))
);

const encryptedSeed = seedCipher.encrypt(seedBytes);

console.log('Wallet seed encrypted successfully');
console.log('  Seed encryption token:', seedEncryptionToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted wallet seed:', Buffer.from(encryptedSeed).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Summary
// =============================================================================

console.log('='.repeat(70));
console.log('WALLET PROTECTION SUMMARY');
console.log('='.repeat(70));
console.log();
console.log('All examples demonstrate using aesjs.ModeOfOperation.ctr(token) to protect:');
console.log('  • Wallet private keys - Full access to wallet funds');
console.log('  • Mnemonic seed phrases - Complete wallet recovery');
console.log('  • Recovery phrases - Wallet restoration capability');
console.log('  • Wallet seeds - Wallet regeneration data');
console.log('  • Complete wallet data - All sensitive wallet information');
console.log();
console.log('Key security principles:');
console.log('  ✓ Each encryption uses a unique counter');
console.log('  ✓ Tokens are protected like the data they encrypt');
console.log('  ✓ Different wallet data types can use separate tokens');
console.log('  ✓ Password-derived tokens add an extra security layer');
console.log();
console.log('=== Wallet Protection Examples Complete ===');

