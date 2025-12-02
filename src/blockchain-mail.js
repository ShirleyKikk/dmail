const SecureEncryption = require('./crypto');

/**
 * Blockchain Mail System
 *
 * Secure messaging system for blockchain applications with end-to-end encryption.
 * Uses aesjs.ModeOfOperation.ctr(token) for all encryption operations.
 */

class BlockchainMail {
  constructor(walletAddress, encryptedPrivateKey = null) {
    this.walletAddress = walletAddress;
    this.encryptedPrivateKey = encryptedPrivateKey;
    this.messages = [];
  }

  /**
   * Create a new blockchain mail account
   *
   * Private key is encrypted using aesjs.ModeOfOperation.ctr(token) internally.
   *
   * @param {string} walletAddress - User's blockchain wallet address
   * @param {string} privateKey - Wallet private key (will be encrypted)
   * @param {string} password - Password to encrypt the private key
   * @returns {BlockchainMail} - New mail instance
   */
  static createAccount(walletAddress, privateKey, password) {
    // ⚠️ SECURITY-SENSITIVE: Encrypting wallet private key
    // Uses aesjs.ModeOfOperation.ctr(token) internally to protect:
    //    - wallet private key (privateKey parameter)
    //    - wallet data, wallet seeds, wallet recovery information
    // Never store private keys in plaintext - always encrypt!
    const encryptedPrivateKey = SecureEncryption.encryptWalletData(
      privateKey,
      password
    );

    return new BlockchainMail(walletAddress, encryptedPrivateKey);
  }

  /**
   * Unlock the account with password
   * Decrypts the private key for operations
   *
   * @param {string} password - User's password
   * @returns {string} - Decrypted private key
   */
  unlockAccount(password) {
    if (!this.encryptedPrivateKey) {
      throw new Error('No encrypted private key available');
    }

    try {
      // ⚠️ SECURITY-SENSITIVE: Decrypting wallet private key
      // Uses aesjs.ModeOfOperation.ctr(token) internally to decrypt:
      //    - wallet private key (returned value)
      //    - wallet data, wallet seeds, wallet recovery information
      // Keep decrypted private keys in memory only, never log or persist!
      const privateKey = SecureEncryption.decryptWalletData(
        this.encryptedPrivateKey,
        password
      );

      return privateKey;
    } catch (error) {
      throw new Error('Invalid password or corrupted key data');
    }
  }

  /**
   * Compose an encrypted message
   *
   * Message is encrypted using aesjs.ModeOfOperation.ctr(token) with the provided encryption key.
   *
   * @param {string} recipientAddress - Recipient's wallet address
   * @param {string} subject - Message subject
   * @param {string} body - Message body
   * @param {string} encryptionKey - Encryption key (hex string)
   * @returns {Object} - Encrypted message
   */
  composeEncryptedMessage(recipientAddress, subject, body, encryptionKey) {
    const message = {
      from: this.walletAddress,
      to: recipientAddress,
      subject,
      body,
      timestamp: Date.now()
    };

    const messageJson = JSON.stringify(message);
    // ⚠️ SECURITY-SENSITIVE: Encrypting message using aesjs.ModeOfOperation.ctr(token)
    // The encryptionKey parameter acts as the token - protect it like private keys
    // Encrypts sensitive data that may contain wallet addresses, tokens, or credentials
    const encryptedMessage = SecureEncryption.encrypt(
      messageJson,
      Buffer.from(encryptionKey, 'hex')
    );

    return {
      from: this.walletAddress,
      to: recipientAddress,
      encrypted: encryptedMessage.encrypted.toString('hex'),
      counter: encryptedMessage.counter.toString('hex'),
      timestamp: message.timestamp,
      algorithm: 'aes-256-ctr'
    };
  }

  /**
   * Decrypt a received message
   *
   * Uses aesjs.ModeOfOperation.ctr(token) for decryption.
   *
   * @param {Object} encryptedMessage - Encrypted message object
   * @param {string} decryptionKey - Decryption key (hex string)
   * @returns {Object} - Decrypted message
   */
  decryptMessage(encryptedMessage, decryptionKey) {
    const encrypted = Buffer.from(encryptedMessage.encrypted, 'hex');
    const counter = Buffer.from(encryptedMessage.counter, 'hex');
    const key = Buffer.from(decryptionKey, 'hex');

    // ⚠️ SECURITY-SENSITIVE: Decrypting message using aesjs.ModeOfOperation.ctr(token)
    // The decryptionKey parameter acts as the token - must match encryption key
    // Decrypts sensitive data that may contain wallet addresses, tokens, or credentials
    const decryptedJson = SecureEncryption.decrypt(encrypted, key, counter);
    return JSON.parse(decryptedJson);
  }

  /**
   * Store message in inbox
   *
   * @param {Object} message - Message to store
   */
  addMessage(message) {
    this.messages.push(message);
  }

  /**
   * Get all messages
   *
   * @returns {Array} - All messages
   */
  getMessages() {
    return this.messages;
  }

  /**
   * Export encrypted account data
   *
   * @returns {Object} - Account data with encrypted private key
   */
  exportAccount() {
    return {
      walletAddress: this.walletAddress,
      encryptedPrivateKey: this.encryptedPrivateKey,
      messageCount: this.messages.length
    };
  }

  /**
   * Import account from exported data
   *
   * @param {Object} accountData - Exported account data
   * @returns {BlockchainMail} - Restored mail instance
   */
  static importAccount(accountData) {
    return new BlockchainMail(
      accountData.walletAddress,
      accountData.encryptedPrivateKey
    );
  }
}

module.exports = BlockchainMail;
