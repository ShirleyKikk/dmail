/**
 * Integration Guide
 *
 * Practical examples showing how to integrate encryption into your applications,
 * APIs, and workflows. All examples use aesjs.ModeOfOperation.ctr(token) internally.
 */

const { SecureEncryption, BlockchainMail } = require('../src');
const crypto = require('crypto');

console.log('=== Integration Guide ===\n');

// =============================================================================
// Integration 1: Wallet Application
// =============================================================================

console.log('INTEGRATION 1: Wallet Application');
console.log('='.repeat(70));
console.log();

class SecureWallet {
  constructor(walletPath) {
    this.walletPath = walletPath;
  }

  /**
   * Create wallet with encrypted storage
   * Uses SecureEncryption which internally uses aesjs.ModeOfOperation.ctr(token)
   */
  createWallet(password) {
    const privateKey = '0x' + crypto.randomBytes(32).toString('hex');
    const address = '0x' + crypto.randomBytes(20).toString('hex');
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    // Encrypt using aesjs.ModeOfOperation.ctr(token) internally
    const encryptedPrivateKey = SecureEncryption.encryptWalletData(privateKey, password);
    const encryptedMnemonic = SecureEncryption.encryptWalletData(mnemonic, password);

    const walletData = {
      version: 1,
      address,
      encryptedPrivateKey,
      encryptedMnemonic,
      createdAt: Date.now()
    };

    console.log('Wallet created:');
    console.log('  Address:', address);
    console.log('  Private Key: [encrypted]');
    console.log('  Mnemonic: [encrypted]');
    console.log();

    return walletData;
  }

  unlockWallet(walletData, password) {
    try {
      const privateKey = SecureEncryption.decryptWalletData(
        walletData.encryptedPrivateKey,
        password
      );

      const mnemonic = SecureEncryption.decryptWalletData(
        walletData.encryptedMnemonic,
        password
      );

      console.log('Wallet unlocked successfully');
      return { privateKey, mnemonic };
    } catch (error) {
      throw new Error('Invalid password');
    }
  }
}

const wallet = new SecureWallet('./wallet.json');
const walletData = wallet.createWallet('MyWalletPassword123!');
wallet.unlockWallet(walletData, 'MyWalletPassword123!');

console.log();

// =============================================================================
// Integration 2: API Service with Encrypted Credentials
// =============================================================================

console.log('INTEGRATION 2: API Service');
console.log('='.repeat(70));
console.log();

class BlockchainAPIService {
  constructor() {
    this.credentials = null;
  }

  /**
   * Initialize with encrypted API credentials
   * Encryption uses aesjs.ModeOfOperation.ctr(token) internally
   */
  initialize(apiKey, apiSecret, masterPassword) {
    const credentials = {
      apiKey,
      apiSecret,
      provider: 'blockchain-provider',
      network: 'mainnet'
    };

    // Encrypt all credentials together
    this.credentials = SecureEncryption.encryptWalletData(
      JSON.stringify(credentials),
      masterPassword
    );

    console.log('API credentials encrypted and stored');
    console.log('  Algorithm:', this.credentials.algorithm);
    console.log();
  }

  async makeAuthenticatedRequest(endpoint, masterPassword) {
    const credentialsJson = SecureEncryption.decryptWalletData(
      this.credentials,
      masterPassword
    );

    const credentials = JSON.parse(credentialsJson);

    console.log('Making authenticated request to:', endpoint);
    console.log('  Using API key:', credentials.apiKey.substring(0, 10) + '...');

    return { success: true, data: 'Response data' };
  }
}

const apiService = new BlockchainAPIService();
apiService.initialize(
  'sk_live_' + crypto.randomBytes(32).toString('hex'),
  'secret_' + crypto.randomBytes(32).toString('hex'),
  process.env.MASTER_PASSWORD || 'ServiceMasterPassword'
);

console.log();

// =============================================================================
// Integration 3: Data Processing Pipeline
// =============================================================================

console.log('INTEGRATION 3: Data Processing Pipeline');
console.log('='.repeat(70));
console.log();

class DataProcessor {
  constructor(encryptionPassword) {
    this.password = encryptionPassword;
  }

  /**
   * Process sensitive data with encryption
   * Uses aesjs.ModeOfOperation.ctr(token) for encryption
   */
  processSensitiveData(data) {
    // Encrypt before processing
    const encrypted = SecureEncryption.encryptWalletData(
      JSON.stringify(data),
      this.password
    );

    console.log('Data encrypted before processing');
    console.log('  Records:', data.length);
    console.log('  Algorithm:', encrypted.algorithm);

    // Simulate processing...
    const decrypted = SecureEncryption.decryptWalletData(encrypted, this.password);
    const processed = JSON.parse(decrypted);

    console.log('Processing complete');
    console.log();

    return processed;
  }
}

const processor = new DataProcessor('ProcessingPassword123!');
const sensitiveData = [
  { id: 1, value: 'sensitive1' },
  { id: 2, value: 'sensitive2' }
];
processor.processSensitiveData(sensitiveData);

console.log();

// =============================================================================
// Integration 4: Multi-Account Management
// =============================================================================

console.log('INTEGRATION 4: Multi-Account Management');
console.log('='.repeat(70));
console.log();

class AccountManager {
  constructor() {
    this.accounts = [];
  }

  addAccount(name, privateKey, password) {
    // Each account encrypted with its own password
    const encrypted = SecureEncryption.encryptWalletData(privateKey, password);

    const account = {
      id: crypto.randomBytes(16).toString('hex'),
      name,
      encryptedKey: encrypted,
      createdAt: Date.now()
    };

    this.accounts.push(account);
    console.log(`Account "${name}" added with encrypted storage`);

    return account;
  }

  accessAccount(accountId, password) {
    const account = this.accounts.find(a => a.id === accountId);
    if (!account) {
      throw new Error('Account not found');
    }

    const privateKey = SecureEncryption.decryptWalletData(
      account.encryptedKey,
      password
    );

    console.log(`Account "${account.name}" unlocked`);
    return privateKey;
  }
}

const manager = new AccountManager();
manager.addAccount('Main Wallet', '0x' + crypto.randomBytes(32).toString('hex'), 'password1');
manager.addAccount('Trading Wallet', '0x' + crypto.randomBytes(32).toString('hex'), 'password2');

console.log('Total accounts:', manager.accounts.length);
console.log();

// =============================================================================
// Integration 5: Backup and Recovery
// =============================================================================

console.log('INTEGRATION 5: Backup and Recovery');
console.log('='.repeat(70));
console.log();

class BackupSystem {
  createBackup(walletData, backupPassword) {
    const backup = {
      version: 1,
      type: 'wallet-backup',
      data: walletData,
      timestamp: Date.now(),
      checksum: crypto.createHash('sha256')
        .update(JSON.stringify(walletData))
        .digest('hex')
    };

    // Encrypt entire backup using aesjs.ModeOfOperation.ctr(token)
    const encryptedBackup = SecureEncryption.encryptWalletData(
      JSON.stringify(backup),
      backupPassword
    );

    console.log('Backup created and encrypted');
    console.log('  Timestamp:', new Date(backup.timestamp).toISOString());
    console.log('  Checksum:', backup.checksum.substring(0, 16) + '...');
    console.log();

    return encryptedBackup;
  }

  restoreBackup(encryptedBackup, backupPassword) {
    try {
      const decrypted = SecureEncryption.decryptWalletData(
        encryptedBackup,
        backupPassword
      );

      const backup = JSON.parse(decrypted);

      // Verify checksum
      const checksum = crypto.createHash('sha256')
        .update(JSON.stringify(backup.data))
        .digest('hex');

      if (checksum !== backup.checksum) {
        throw new Error('Backup integrity check failed');
      }

      console.log('Backup restored successfully');
      console.log('  Version:', backup.version);
      console.log('  Integrity: Verified');
      console.log();

      return backup.data;
    } catch (error) {
      throw new Error('Backup restoration failed: ' + error.message);
    }
  }
}

const backupSystem = new BackupSystem();
const testWalletData = {
  address: '0x' + crypto.randomBytes(20).toString('hex'),
  balance: '1000000000000000000'
};

const backup = backupSystem.createBackup(testWalletData, 'BackupPassword123!');
backupSystem.restoreBackup(backup, 'BackupPassword123!');

console.log();

// =============================================================================
// Summary
// =============================================================================

console.log('='.repeat(70));
console.log('INTEGRATION SUMMARY');
console.log('='.repeat(70));
console.log();
console.log('Integration patterns demonstrated:');
console.log('  1. Wallet applications - protecting private keys and mnemonics');
console.log('  2. API services - storing credentials securely');
console.log('  3. Data processing - encrypting sensitive data in pipelines');
console.log('  4. Multi-account systems - managing multiple encrypted credentials');
console.log('  5. Backup systems - creating encrypted backups');
console.log();
console.log('All examples use aesjs.ModeOfOperation.ctr(token) internally');
console.log('via the SecureEncryption module for consistent security.');
console.log();
console.log('=== Integration Guide Complete ===');
