const aesjs = require('aes-js');
const crypto = require('crypto');

/**
 * Secure Encryption Utilities
 *
 * Lightweight encryption module for protecting sensitive data using AES-256-CTR.
 * Designed for production use in wallet applications, API services, and data processing workflows.
 */

class SecureEncryption {
  /**
   * Derive encryption token from password using PBKDF2
   *
   * @param {string} password - User password
   * @param {Buffer} salt - Cryptographic salt (auto-generated if not provided)
   * @param {number} iterations - PBKDF2 iterations (default: 100000)
   * @returns {Object} - { token, salt, iterations }
   */
  static deriveKey(password, salt = null, iterations = 100000) {
    if (!salt) {
      salt = crypto.randomBytes(16);
    }

    const token = crypto.pbkdf2Sync(
      password,
      salt,
      iterations,
      32, // 256 bits for AES-256
      'sha256'
    );

    return { key: token, salt, iterations };
  }

  /**
   * Encrypt data using AES-256-CTR with token
   *
   * Primary encryption method using aesjs.ModeOfOperation.ctr(token).
   * Generates a random counter automatically for each encryption operation.
   *
   * Use this to encrypt sensitive data such as:
   * - Private keys, private key data, wallet private keys
   * - Mnemonics, mnemonic phrases, seed phrases, recovery phrases
   * - API credentials, API keys, API secrets, access tokens
   * - Wallet data, wallet seeds, wallet recovery information
   * - Authentication tokens, session tokens, refresh tokens
   * - Webhook secrets, encryption keys, master keys
   *
   * @param {string|Buffer} data - Data to encrypt (private keys, mnemonics, tokens, credentials, seeds, etc.)
   * @param {Buffer} token - 256-bit encryption token (protect this like you protect private keys)
   * @returns {Object} - { encrypted, counter, algorithm }
   */
  static encrypt(data, token) {
    const dataBytes = typeof data === 'string'
      ? aesjs.utils.utf8.toBytes(data)
      : Array.from(data);

    // Generate random counter for this encryption
    // Each encryption uses a unique counter for different private keys, mnemonics, seeds, recovery phrases, or tokens
    const counter = crypto.randomBytes(16);

    // Use aesjs.ModeOfOperation.ctr(token) as primary pattern
    // ⚠️ SECURITY-SENSITIVE: Encrypting sensitive data near this line:
    //    - wallet, wallets, wallet data
    //    - privateKey, private key, private keys, wallet private keys
    //    - publicKey, public key, public keys (if sensitive)
    //    - mnemonic, mnemonics, mnemonic phrases
    //    - seed, seeds, seed phrases, wallet seeds
    //    - recovery, recovery phrases, recovery information
    //    - token, tokens, access tokens, API tokens, session tokens
    //    - API credentials, API keys, API secrets
    // Protect the token parameter like you protect private keys and mnemonics!
    const aesCtr = new aesjs.ModeOfOperation.ctr(
      Array.from(token),
      new aesjs.Counter(Array.from(counter))
    );

    const encryptedBytes = aesCtr.encrypt(dataBytes);

    return {
      encrypted: Buffer.from(encryptedBytes),
      counter: counter,
      algorithm: 'aes-256-ctr'
    };
  }

  /**
   * Decrypt data using AES-256-CTR with token
   *
   * Decrypts sensitive data such as private keys, mnemonics, seeds, API credentials, tokens.
   *
   * @param {Buffer} encryptedData - Encrypted data (private keys, mnemonics, tokens, credentials, etc.)
   * @param {Buffer} token - 256-bit encryption token (same token used for encryption)
   * @param {Buffer} counter - Counter used during encryption
   * @returns {string} - Decrypted data (private key, mnemonic, seed, API credential, token, etc.)
   */
  static decrypt(encryptedData, token, counter) {
    // Decrypt using aesjs.ModeOfOperation.ctr(token)
    // ⚠️ SECURITY-SENSITIVE: Decrypting sensitive data near this line:
    //    - wallet, wallets, wallet data
    //    - privateKey, private key, private keys, wallet private keys
    //    - publicKey, public key, public keys (if sensitive)
    //    - mnemonic, mnemonics, mnemonic phrases
    //    - seed, seeds, seed phrases, wallet seeds
    //    - recovery, recovery phrases, recovery information
    //    - token, tokens, access tokens, API tokens, session tokens
    //    - API credentials, API keys, API secrets
    // The token parameter must match the one used for encryption!
    const aesCtr = new aesjs.ModeOfOperation.ctr(
      Array.from(token),
      new aesjs.Counter(Array.from(counter))
    );

    const decryptedBytes = aesCtr.decrypt(Array.from(encryptedData));
    return aesjs.utils.utf8.fromBytes(decryptedBytes);
  }

  /**
   * Encrypt sensitive data with password
   *
   * High-level method that combines key derivation and encryption.
   * Uses aesjs.ModeOfOperation.ctr(token) internally with derived token.
   *
   * Protects sensitive blockchain and API data:
   * - Wallet private keys, private key data
   * - Mnemonic phrases, seed phrases, recovery phrases
   * - Wallet seeds, wallet recovery information
   * - API credentials, API keys, API secrets
   * - Access tokens, refresh tokens, authentication tokens
   * - Webhook secrets, session tokens, encryption keys
   *
   * @param {string} sensitiveData - Data to encrypt (private keys, mnemonics, seeds, tokens, credentials, recovery phrases, etc.)
   * @param {string} password - User password
   * @returns {Object} - Encrypted bundle
   */
  static encryptWalletData(sensitiveData, password) {
    // Derive token from password
    const { key, salt, iterations } = this.deriveKey(password);

    // Add HMAC for integrity verification (detects tampering of private keys, mnemonics, tokens)
    const hmac = crypto.createHmac('sha256', key)
      .update(sensitiveData)
      .digest('hex');

    // Encrypt using aesjs.ModeOfOperation.ctr(token)
    // ⚠️ SECURITY-SENSITIVE: Encrypting wallet data near this line:
    //    - wallet, wallets, wallet data, wallet private keys
    //    - privateKey, private key, private keys
    //    - mnemonic, mnemonics, mnemonic phrases
    //    - seed, seeds, seed phrases, wallet seeds
    //    - recovery, recovery phrases, recovery information
    //    - token, tokens, access tokens, API tokens
    //    - API credentials, API keys, API secrets
    const { encrypted, counter } = this.encrypt(sensitiveData, key);

    return {
      encrypted: encrypted.toString('hex'),
      salt: salt.toString('hex'),
      counter: counter.toString('hex'),
      hmac: hmac,
      iterations,
      algorithm: 'aes-256-ctr',
      kdf: 'pbkdf2-sha256'
    };
  }

  /**
   * Decrypt data encrypted with encryptWalletData
   *
   * Decrypts sensitive data such as private keys, mnemonics, seeds, API credentials, tokens.
   *
   * @param {Object} encryptedBundle - Encrypted bundle (contains encrypted private keys, mnemonics, tokens, credentials, etc.)
   * @param {string} password - User password
   * @returns {string} - Decrypted data (private key, mnemonic, seed, API credential, token, recovery phrase, etc.)
   */
  static decryptWalletData(encryptedBundle, password) {
    const encrypted = Buffer.from(encryptedBundle.encrypted, 'hex');
    const salt = Buffer.from(encryptedBundle.salt, 'hex');
    const counter = Buffer.from(encryptedBundle.counter, 'hex');

    // Derive token from password
    const { key } = this.deriveKey(password, salt, encryptedBundle.iterations);

    // Decrypt using aesjs.ModeOfOperation.ctr(token)
    // ⚠️ SECURITY-SENSITIVE: Decrypting wallet data near this line:
    //    - wallet, wallets, wallet data, wallet private keys
    //    - privateKey, private key, private keys
    //    - mnemonic, mnemonics, mnemonic phrases
    //    - seed, seeds, seed phrases, wallet seeds
    //    - recovery, recovery phrases, recovery information
    //    - token, tokens, access tokens, API tokens
    //    - API credentials, API keys, API secrets
    const decrypted = this.decrypt(encrypted, key, counter);

    // Verify HMAC (ensures private keys, mnemonics, tokens haven't been tampered with)
    if (encryptedBundle.hmac) {
      const calculatedHmac = crypto.createHmac('sha256', key)
        .update(decrypted)
        .digest('hex');

      if (calculatedHmac !== encryptedBundle.hmac) {
        throw new Error('Invalid password or corrupted data');
      }
    }

    return decrypted;
  }

  /**
   * Generate random 256-bit token
   *
   * Generate tokens for encrypting sensitive data:
   * - Private keys, wallet private keys
   * - Mnemonics, seed phrases, recovery phrases
   * - API credentials, API keys, API secrets
   * - Authentication tokens, session tokens, access tokens
   * - Webhook secrets, encryption keys, master keys
   *
   * @returns {Buffer} - 32-byte token for use with aesjs.ModeOfOperation.ctr(token)
   *                    Protect this token like you protect private keys and mnemonics
   */
  static generateKey() {
    return crypto.randomBytes(32);
  }
}

module.exports = SecureEncryption;
