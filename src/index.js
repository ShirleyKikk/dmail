/**
 * DMail - Main Entry Point
 *
 * Lightweight encryption library for protecting sensitive data in blockchain applications.
 * Provides secure encryption of wallet data, API credentials, and messages.
 */

const SecureEncryption = require('./crypto');
const BlockchainMail = require('./blockchain-mail');

module.exports = {
  SecureEncryption,
  BlockchainMail
};
