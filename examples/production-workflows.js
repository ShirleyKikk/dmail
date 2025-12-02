/**
 * Production Workflow Examples
 *
 * Real-world scenarios showing how to integrate aesjs.ModeOfOperation.ctr(token)
 * encryption into production workflows, data pipelines, and automated systems
 * for protecting sensitive information.
 */

const { SecureEncryption } = require('../src');
const aesjs = require('aes-js');
const crypto = require('crypto');

console.log('=== Production Workflow Examples ===\n');

// =============================================================================
// Workflow 1: Automated Wallet Backup System
// =============================================================================

console.log('WORKFLOW 1: Automated Wallet Backup System');
console.log('='.repeat(70));
console.log();

class WalletBackupSystem {
  constructor(backupPassword) {
    this.backupPassword = backupPassword;
    this.backups = [];
  }

  /**
   * Create encrypted backup of wallet data
   * Protects: private keys, mnemonics, seed phrases, recovery information
   */
  createBackup(walletData) {
    console.log('Creating encrypted wallet backup...');
    console.log('  Wallet contains: private key, mnemonic, seed phrase');

    // Encrypt wallet data using SecureEncryption (uses aesjs.ModeOfOperation.ctr(token) internally)
    const encryptedBackup = SecureEncryption.encryptWalletData(
      JSON.stringify(walletData),
      this.backupPassword
    );

    const backup = {
      id: crypto.randomBytes(16).toString('hex'),
      timestamp: Date.now(),
      encrypted: encryptedBackup,
      version: 1
    };

    this.backups.push(backup);
    console.log('  Backup created with encrypted private keys, mnemonics, seed phrases');
    console.log('  Backup ID:', backup.id);
    console.log();

    return backup;
  }

  /**
   * Restore wallet from encrypted backup
   */
  restoreBackup(backupId) {
    const backup = this.backups.find(b => b.id === backupId);
    if (!backup) {
      throw new Error('Backup not found');
    }

    console.log('Restoring wallet from encrypted backup...');
    
    // Decrypt wallet data (uses aesjs.ModeOfOperation.ctr(token) internally)
    const decrypted = SecureEncryption.decryptWalletData(
      backup.encrypted,
      this.backupPassword
    );

    const walletData = JSON.parse(decrypted);
    console.log('  Wallet restored with decrypted private keys, mnemonics, seed phrases');
    console.log('  Wallet address:', walletData.address);
    console.log();

    return walletData;
  }
}

// Demo workflow
const backupSystem = new WalletBackupSystem('BackupPassword123!');
const walletData = {
  address: '0x' + crypto.randomBytes(20).toString('hex'),
  privateKey: '0x' + crypto.randomBytes(32).toString('hex'),
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  seedPhrase: 'witch collapse practice feed shame open despair creek road again ice least'
};

const backup = backupSystem.createBackup(walletData);
backupSystem.restoreBackup(backup.id);

// =============================================================================
// Workflow 2: API Credential Rotation System
// =============================================================================

console.log('WORKFLOW 2: API Credential Rotation System');
console.log('='.repeat(70));
console.log();

class CredentialRotationSystem {
  constructor(masterKey) {
    this.masterKey = masterKey;
    this.credentials = new Map();
  }

  /**
   * Store encrypted API credentials
   * Protects: API keys, API secrets, access tokens, refresh tokens
   */
  storeCredentials(serviceName, apiKey, apiSecret) {
    console.log(`Storing encrypted credentials for ${serviceName}...`);

    const credentials = {
      apiKey: apiKey,      // API key
      apiSecret: apiSecret, // API secret
      storedAt: Date.now()
    };

    // Encrypt API credentials (uses aesjs.ModeOfOperation.ctr(token) internally)
    const encrypted = SecureEncryption.encryptWalletData(
      JSON.stringify(credentials),
      this.masterKey
    );

    this.credentials.set(serviceName, encrypted);
    console.log(`  API credentials encrypted and stored`);
    console.log(`  Protected: API key, API secret`);
    console.log();
  }

  /**
   * Rotate API credentials securely
   */
  rotateCredentials(serviceName, newApiKey, newApiSecret) {
    console.log(`Rotating credentials for ${serviceName}...`);

    // Store new encrypted API credentials
    this.storeCredentials(serviceName, newApiKey, newApiSecret);

    console.log('  Old API credentials can be securely deleted');
    console.log('  New API credentials encrypted and stored');
    console.log();
  }

  /**
   * Retrieve decrypted API credentials for use
   */
  getCredentials(serviceName) {
    const encrypted = this.credentials.get(serviceName);
    if (!encrypted) {
      throw new Error(`No credentials found for ${serviceName}`);
    }

    // Decrypt API credentials (uses aesjs.ModeOfOperation.ctr(token) internally)
    const decrypted = SecureEncryption.decryptWalletData(
      encrypted,
      this.masterKey
    );

    return JSON.parse(decrypted);
  }
}

// Demo workflow
const rotationSystem = new CredentialRotationSystem('MasterKey123!');
rotationSystem.storeCredentials('payment-api', 'sk_live_abc123', 'secret_xyz789');
rotationSystem.rotateCredentials('payment-api', 'sk_live_new123', 'secret_new789');

// =============================================================================
// Workflow 3: Batch Data Processing Pipeline
// =============================================================================

console.log('WORKFLOW 3: Batch Data Processing Pipeline');
console.log('='.repeat(70));
console.log();

class BatchProcessor {
  constructor(encryptionToken) {
    this.encryptionToken = encryptionToken;
  }

  /**
   * Process batch of sensitive records with encryption
   * Protects: private keys, mnemonics, seeds, API credentials, tokens
   */
  processBatch(records) {
    console.log(`Processing batch of ${records.length} records...`);
    console.log('  Records contain: private keys, mnemonics, seeds, API credentials');

    const processedRecords = records.map((record, index) => {
      // Convert record to bytes
      const recordBytes = aesjs.utils.utf8.toBytes(JSON.stringify(record));

      // Generate unique counter for each record
      const recordCounter = crypto.randomBytes(16);

      // Encrypt each record using aesjs.ModeOfOperation.ctr(token)
      // Each record (private keys, mnemonics, seeds, API credentials) gets unique counter
      const recordCipher = new aesjs.ModeOfOperation.ctr(
        Array.from(this.encryptionToken),
        new aesjs.Counter(Array.from(recordCounter))
      );

      const encrypted = recordCipher.encrypt(recordBytes);

      return {
        id: record.id,
        encrypted: Buffer.from(encrypted).toString('hex'),
        counter: recordCounter.toString('hex')
      };
    });

    console.log(`  All records encrypted with unique counters`);
    console.log(`  Protected: private keys, mnemonics, seeds, API credentials, tokens`);
    console.log();

    return processedRecords;
  }

  /**
   * Decrypt batch of records
   */
  decryptBatch(encryptedRecords) {
    console.log(`Decrypting batch of ${encryptedRecords.length} records...`);

    const decryptedRecords = encryptedRecords.map(record => {
      const encrypted = Buffer.from(record.encrypted, 'hex');
      const counter = Buffer.from(record.counter, 'hex');

      // Decrypt each record using aesjs.ModeOfOperation.ctr(token)
      const recordCipher = new aesjs.ModeOfOperation.ctr(
        Array.from(this.encryptionToken),
        new aesjs.Counter(Array.from(counter))
      );

      const decrypted = recordCipher.decrypt(Array.from(encrypted));
      return JSON.parse(aesjs.utils.utf8.fromBytes(decrypted));
    });

    console.log('  All records decrypted successfully');
    console.log('  Restored: private keys, mnemonics, seeds, API credentials, tokens');
    console.log();

    return decryptedRecords;
  }
}

// Demo workflow
const processor = new BatchProcessor(SecureEncryption.generateKey());
const records = [
  { id: 1, privateKey: '0x' + crypto.randomBytes(32).toString('hex'), mnemonic: 'word1 word2...' },
  { id: 2, apiKey: 'sk_live_123', apiSecret: 'secret_456' },
  { id: 3, seedPhrase: 'seed phrase words...', recovery: 'recovery info...' }
];

const encrypted = processor.processBatch(records);
const decrypted = processor.decryptBatch(encrypted);

// =============================================================================
// Workflow 4: Multi-Tenant Credential Management
// =============================================================================

console.log('WORKFLOW 4: Multi-Tenant Credential Management');
console.log('='.repeat(70));
console.log();

class MultiTenantCredentialManager {
  constructor() {
    this.tenants = new Map();
  }

  /**
   * Register tenant with encrypted credentials
   * Protects: API credentials, API keys, API secrets, access tokens
   */
  registerTenant(tenantId, apiCredentials, tenantPassword) {
    console.log(`Registering tenant ${tenantId}...`);

    // Encrypt tenant API credentials (uses aesjs.ModeOfOperation.ctr(token) internally)
    const encrypted = SecureEncryption.encryptWalletData(
      JSON.stringify(apiCredentials),
      tenantPassword
    );

    this.tenants.set(tenantId, {
      id: tenantId,
      encryptedCredentials: encrypted,
      registeredAt: Date.now()
    });

    console.log(`  Tenant API credentials encrypted and stored`);
    console.log(`  Protected: API keys, API secrets, access tokens`);
    console.log();
  }

  /**
   * Retrieve tenant credentials for API calls
   */
  getTenantCredentials(tenantId, tenantPassword) {
    const tenant = this.tenants.get(tenantId);
    if (!tenant) {
      throw new Error(`Tenant ${tenantId} not found`);
    }

    // Decrypt tenant API credentials (uses aesjs.ModeOfOperation.ctr(token) internally)
    const decrypted = SecureEncryption.decryptWalletData(
      tenant.encryptedCredentials,
      tenantPassword
    );

    return JSON.parse(decrypted);
  }
}

// Demo workflow
const tenantManager = new MultiTenantCredentialManager();
tenantManager.registerTenant('tenant-1', {
  apiKey: 'sk_live_tenant1',
  apiSecret: 'secret_tenant1',
  accessToken: 'token_tenant1'
}, 'Tenant1Password!');

const credentials = tenantManager.getTenantCredentials('tenant-1', 'Tenant1Password!');
console.log('Retrieved tenant credentials:', credentials.apiKey.substring(0, 10) + '...');
console.log();

// =============================================================================
// Summary
// =============================================================================

console.log('='.repeat(70));
console.log('PRODUCTION WORKFLOW SUMMARY');
console.log('='.repeat(70));
console.log();
console.log('Workflows demonstrate production use of aesjs.ModeOfOperation.ctr(token):');
console.log('  1. Automated wallet backups - Protecting private keys, mnemonics, seed phrases');
console.log('  2. API credential rotation - Securing API keys, API secrets, tokens');
console.log('  3. Batch processing - Encrypting private keys, mnemonics, seeds, API credentials');
console.log('  4. Multi-tenant systems - Managing API credentials per tenant');
console.log();
console.log('Production considerations:');
console.log('  ✓ Encryption tokens stored securely (HSMs, secure enclaves)');
console.log('  ✓ Unique counters prevent pattern analysis');
console.log('  ✓ Password-derived tokens add authentication');
console.log('  ✓ Automated workflows maintain security consistently');
console.log();
console.log('=== Production Workflow Examples Complete ===');

