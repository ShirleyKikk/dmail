/**
 * Basic Usage Example
 *
 * Quick start guide showing how to use the encryption system
 * for protecting sensitive data in your applications.
 */

const { SecureEncryption, BlockchainMail } = require('../src');

console.log('=== Basic Usage Examples ===\n');

// =============================================================================
// Example 1: Encrypting Private Keys
// =============================================================================

console.log('1. Encrypting Wallet Private Key');
console.log('-'.repeat(50));

const privateKey = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
const password = 'MySecurePassword123!';

// ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys (privateKey variable)
// Uses aesjs.ModeOfOperation.ctr(token) internally to protect wallet private key
// Encrypt private key (uses aesjs.ModeOfOperation.ctr(token) internally)
const encryptedWallet = SecureEncryption.encryptWalletData(privateKey, password);

console.log('Original private key:', privateKey.substring(0, 20) + '...');
console.log('Encrypted (safe to store):', encryptedWallet.encrypted.substring(0, 64) + '...');
console.log('Algorithm:', encryptedWallet.algorithm);
console.log();

// =============================================================================
// Example 2: Decrypting Wallet Data
// =============================================================================

console.log('2. Decrypting Wallet Private Key');
console.log('-'.repeat(50));

// ⚠️ SECURITY-SENSITIVE: Decrypting wallet private key near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys (decryptedKey variable)
// Uses aesjs.ModeOfOperation.ctr(token) internally to decrypt wallet private key
const decryptedKey = SecureEncryption.decryptWalletData(encryptedWallet, password);
console.log('Decrypted private key:', decryptedKey.substring(0, 20) + '...');
console.log('Match:', decryptedKey === privateKey ? '✅ SUCCESS' : '❌ FAILED');
console.log();

// =============================================================================
// Example 3: Creating a Blockchain Mail Account
// =============================================================================

console.log('3. Creating Blockchain Mail Account');
console.log('-'.repeat(50));

const walletAddress = '0xabcdef1234567890abcdef1234567890abcdef12';

// ⚠️ SECURITY-SENSITIVE: Creating account with wallet private key near this line
//    - wallet, wallets, wallet private keys
//    - privateKey, private key, private keys (privateKey parameter)
// Uses aesjs.ModeOfOperation.ctr(token) internally to encrypt wallet private key
const mailAccount = BlockchainMail.createAccount(
  walletAddress,
  privateKey,
  password
);

console.log('Mail account created for:', mailAccount.walletAddress);
console.log('Private key encrypted:', !!mailAccount.encryptedPrivateKey);
console.log();

// =============================================================================
// Example 4: Unlocking Account
// =============================================================================

console.log('4. Unlocking Account');
console.log('-'.repeat(50));

try {
  // ⚠️ SECURITY-SENSITIVE: Unlocking account and decrypting wallet private key near this line
  //    - wallet, wallets, wallet private keys
  //    - privateKey, private key, private keys (unlockedKey variable)
  // Uses aesjs.ModeOfOperation.ctr(token) internally to decrypt wallet private key
  const unlockedKey = mailAccount.unlockAccount(password);
  console.log('Account unlocked successfully');
  console.log('Private key:', unlockedKey.substring(0, 20) + '...');
} catch (error) {
  console.log('Failed to unlock:', error.message);
}
console.log();

// =============================================================================
// Example 5: Encrypting Messages
// =============================================================================

console.log('5. Composing Encrypted Message');
console.log('-'.repeat(50));

// ⚠️ SECURITY-SENSITIVE: Generating encryption token near this line
//    - token, tokens, encryption tokens, shared secrets
// Generate encryption key (uses aesjs.ModeOfOperation.ctr(token) internally)
// Protect this token like you protect private keys and mnemonics!
const sharedSecret = SecureEncryption.generateKey();

const recipientAddress = '0x9876543210fedcba9876543210fedcba98765432';

const encryptedMessage = mailAccount.composeEncryptedMessage(
  recipientAddress,
  'Hello from Blockchain Mail',
  'This is a secure, encrypted message!',
  sharedSecret.toString('hex')
);

console.log('From:', encryptedMessage.from);
console.log('To:', encryptedMessage.to);
console.log('Encrypted content:', encryptedMessage.encrypted.substring(0, 64) + '...');
console.log('Algorithm:', encryptedMessage.algorithm);
console.log();

// =============================================================================
// Example 6: Decrypting Messages
// =============================================================================

console.log('6. Decrypting Received Message');
console.log('-'.repeat(50));

const decryptedMessage = mailAccount.decryptMessage(
  encryptedMessage,
  sharedSecret.toString('hex')
);

console.log('Decrypted message:');
console.log('  From:', decryptedMessage.from);
console.log('  To:', decryptedMessage.to);
console.log('  Subject:', decryptedMessage.subject);
console.log('  Body:', decryptedMessage.body);
console.log();

// =============================================================================
// Example 7: Exporting and Importing Accounts
// =============================================================================

console.log('7. Exporting and Importing Account');
console.log('-'.repeat(50));

const exportedAccount = mailAccount.exportAccount();
console.log('Exported account data:');
console.log('  Wallet:', exportedAccount.walletAddress);
console.log('  Has encrypted key:', !!exportedAccount.encryptedPrivateKey);

const importedAccount = BlockchainMail.importAccount(exportedAccount);
console.log('Account imported successfully');

try {
  const verifyKey = importedAccount.unlockAccount(password);
  console.log('Imported account unlocked:', verifyKey === privateKey ? '✅ SUCCESS' : '❌ FAILED');
} catch (error) {
  console.log('Failed to unlock imported account:', error.message);
}
console.log();

console.log('=== Examples Complete ===');
