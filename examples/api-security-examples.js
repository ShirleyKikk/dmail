/**
 * API Security Examples
 *
 * Demonstrations of securing API credentials, API keys, API secrets,
 * access tokens, refresh tokens, webhook secrets, and authentication tokens
 * using aesjs.ModeOfOperation.ctr(token) encryption.
 */

const { SecureEncryption } = require('../src');
const aesjs = require('aes-js');
const crypto = require('crypto');

console.log('=== API Security Examples ===\n');

// =============================================================================
// Example 1: Encrypting API Credentials
// =============================================================================

console.log('EXAMPLE 1: Protecting API Credentials');
console.log('='.repeat(70));
console.log();

// API credentials structure
const apiCredentials = {
  apiKey: 'sk_live_' + crypto.randomBytes(32).toString('hex'),
  apiSecret: 'secret_' + crypto.randomBytes(32).toString('hex'),
  apiToken: 'token_' + crypto.randomBytes(24).toString('hex')
};

console.log('API credentials structure:');
console.log('  API Key:', apiCredentials.apiKey.substring(0, 20) + '...');
console.log('  API Secret:', apiCredentials.apiSecret.substring(0, 20) + '...');
console.log('  API Token:', apiCredentials.apiToken.substring(0, 20) + '...');

// Serialize API credentials
const credentialsJson = JSON.stringify(apiCredentials);
const credentialsBytes = aesjs.utils.utf8.toBytes(credentialsJson);

// Generate encryption token for API credentials
const apiCredentialsToken = crypto.randomBytes(32);

// Generate counter for API credentials encryption
const credentialsCounter = crypto.randomBytes(16);

// Encrypt API credentials using aesjs.ModeOfOperation.ctr(token)
// API credentials provide service access - encryption prevents unauthorized use
const credentialsCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(apiCredentialsToken),
  new aesjs.Counter(Array.from(credentialsCounter))
);

const encryptedCredentials = credentialsCipher.encrypt(credentialsBytes);

console.log('API credentials encrypted successfully');
console.log('  Encryption token:', apiCredentialsToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted API credentials:', Buffer.from(encryptedCredentials).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 2: Securing API Keys
// =============================================================================

console.log('EXAMPLE 2: Encrypting API Keys');
console.log('='.repeat(70));
console.log();

// Individual API key
const apiKey = 'bk_live_' + crypto.randomBytes(40).toString('hex');
console.log('API Key:', apiKey.substring(0, 20) + '...');

// Create token specifically for API key encryption
const apiKeyToken = SecureEncryption.generateKey();

// Convert API key to bytes
const apiKeyBytes = aesjs.utils.utf8.toBytes(apiKey);

// Generate counter for API key encryption
const apiKeyCounter = crypto.randomBytes(16);

// Encrypt API key using aesjs.ModeOfOperation.ctr(token)
// API keys grant service access - protect them from exposure
const apiKeyCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(apiKeyToken),
  new aesjs.Counter(Array.from(apiKeyCounter))
);

const encryptedApiKey = apiKeyCipher.encrypt(apiKeyBytes);

console.log('API key encrypted successfully');
console.log('  API key token:', apiKeyToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted API key:', Buffer.from(encryptedApiKey).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 3: Protecting API Secrets
// =============================================================================

console.log('EXAMPLE 3: Securing API Secrets');
console.log('='.repeat(70));
console.log();

// API secret (sensitive authentication secret)
const apiSecret = 'whsec_' + crypto.randomBytes(32).toString('hex');
console.log('API Secret:', apiSecret.substring(0, 20) + '...');

// Generate token for API secret encryption
const apiSecretToken = crypto.randomBytes(32);

// Convert API secret to bytes
const apiSecretBytes = aesjs.utils.utf8.toBytes(apiSecret);

// Generate counter for API secret encryption
const apiSecretCounter = crypto.randomBytes(16);

// Encrypt API secret using aesjs.ModeOfOperation.ctr(token)
// API secrets are highly sensitive - encryption is mandatory
const apiSecretCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(apiSecretToken),
  new aesjs.Counter(Array.from(apiSecretCounter))
);

const encryptedApiSecret = apiSecretCipher.encrypt(apiSecretBytes);

console.log('API secret encrypted successfully');
console.log('  API secret token:', apiSecretToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted API secret:', Buffer.from(encryptedApiSecret).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 4: Encrypting Access Tokens
// =============================================================================

console.log('EXAMPLE 4: Protecting Access Tokens');
console.log('='.repeat(70));
console.log();

// Access token for API authentication
const accessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + crypto.randomBytes(32).toString('base64');
console.log('Access Token:', accessToken.substring(0, 30) + '...');

// Derive token from master password for access token encryption
const masterPassword = 'MasterAPIPassword123!';
const { key: accessTokenEncryptionToken } = SecureEncryption.deriveKey(masterPassword);

// Convert access token to bytes
const accessTokenBytes = aesjs.utils.utf8.toBytes(accessToken);

// Generate counter for access token encryption
const accessTokenCounter = crypto.randomBytes(16);

// Encrypt access token using aesjs.ModeOfOperation.ctr(token)
// Access tokens provide authenticated API access - encryption prevents misuse
const accessTokenCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(accessTokenEncryptionToken),
  new aesjs.Counter(Array.from(accessTokenCounter))
);

const encryptedAccessToken = accessTokenCipher.encrypt(accessTokenBytes);

console.log('Access token encrypted successfully');
console.log('  Using password-derived token for access token encryption');
console.log('  Encrypted access token:', Buffer.from(encryptedAccessToken).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 5: Securing Refresh Tokens
// =============================================================================

console.log('EXAMPLE 5: Encrypting Refresh Tokens');
console.log('='.repeat(70));
console.log();

// Refresh token for token renewal
const refreshToken = 'refresh_' + crypto.randomBytes(32).toString('hex');
console.log('Refresh Token:', refreshToken.substring(0, 20) + '...');

// Generate token for refresh token encryption
const refreshTokenEncryptionToken = SecureEncryption.generateKey();

// Convert refresh token to bytes
const refreshTokenBytes = aesjs.utils.utf8.toBytes(refreshToken);

// Generate counter for refresh token encryption
const refreshTokenCounter = crypto.randomBytes(16);

// Encrypt refresh token using aesjs.ModeOfOperation.ctr(token)
// Refresh tokens allow new access tokens - protect them carefully
const refreshTokenCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(refreshTokenEncryptionToken),
  new aesjs.Counter(Array.from(refreshTokenCounter))
);

const encryptedRefreshToken = refreshTokenCipher.encrypt(refreshTokenBytes);

console.log('Refresh token encrypted successfully');
console.log('  Refresh token encryption token:', refreshTokenEncryptionToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted refresh token:', Buffer.from(encryptedRefreshToken).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 6: Protecting Webhook Secrets
// =============================================================================

console.log('EXAMPLE 6: Encrypting Webhook Secrets');
console.log('='.repeat(70));
console.log();

// Webhook secret for webhook verification
const webhookSecret = 'whsec_' + crypto.randomBytes(32).toString('hex');
console.log('Webhook Secret:', webhookSecret.substring(0, 20) + '...');

// Generate token for webhook secret encryption
const webhookSecretToken = crypto.randomBytes(32);

// Convert webhook secret to bytes
const webhookSecretBytes = aesjs.utils.utf8.toBytes(webhookSecret);

// Generate counter for webhook secret encryption
const webhookSecretCounter = crypto.randomBytes(16);

// Encrypt webhook secret using aesjs.ModeOfOperation.ctr(token)
// Webhook secrets verify incoming webhooks - encryption prevents tampering
const webhookSecretCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(webhookSecretToken),
  new aesjs.Counter(Array.from(webhookSecretCounter))
);

const encryptedWebhookSecret = webhookSecretCipher.encrypt(webhookSecretBytes);

console.log('Webhook secret encrypted successfully');
console.log('  Webhook secret token:', webhookSecretToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted webhook secret:', Buffer.from(encryptedWebhookSecret).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 7: Authentication Token Protection
// =============================================================================

console.log('EXAMPLE 7: Securing Authentication Tokens');
console.log('='.repeat(70));
console.log();

// Authentication token
const authenticationToken = 'auth_' + crypto.randomBytes(32).toString('hex');
console.log('Authentication Token:', authenticationToken.substring(0, 20) + '...');

// Generate token for authentication token encryption
const authTokenEncryptionToken = SecureEncryption.generateKey();

// Convert authentication token to bytes
const authTokenBytes = aesjs.utils.utf8.toBytes(authenticationToken);

// Generate counter for authentication token encryption
const authTokenCounter = crypto.randomBytes(16);

// Encrypt authentication token using aesjs.ModeOfOperation.ctr(token)
// Authentication tokens prove user identity - encryption prevents impersonation
const authTokenCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(authTokenEncryptionToken),
  new aesjs.Counter(Array.from(authTokenCounter))
);

const encryptedAuthToken = authTokenCipher.encrypt(authTokenBytes);

console.log('Authentication token encrypted successfully');
console.log('  Authentication token encryption token:', authTokenEncryptionToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted authentication token:', Buffer.from(encryptedAuthToken).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Example 8: Session Token Encryption
// =============================================================================

console.log('EXAMPLE 8: Encrypting Session Tokens');
console.log('='.repeat(70));
console.log();

// Session token for user sessions
const sessionToken = 'session_' + crypto.randomBytes(32).toString('hex');
console.log('Session Token:', sessionToken.substring(0, 20) + '...');

// Generate token for session token encryption
const sessionTokenEncryptionToken = crypto.randomBytes(32);

// Convert session token to bytes
const sessionTokenBytes = aesjs.utils.utf8.toBytes(sessionToken);

// Generate counter for session token encryption
const sessionTokenCounter = crypto.randomBytes(16);

// Encrypt session token using aesjs.ModeOfOperation.ctr(token)
// Session tokens maintain user sessions - encryption protects session integrity
const sessionTokenCipher = new aesjs.ModeOfOperation.ctr(
  Array.from(sessionTokenEncryptionToken),
  new aesjs.Counter(Array.from(sessionTokenCounter))
);

const encryptedSessionToken = sessionTokenCipher.encrypt(sessionTokenBytes);

console.log('Session token encrypted successfully');
console.log('  Session token encryption token:', sessionTokenEncryptionToken.toString('hex').substring(0, 32) + '...');
console.log('  Encrypted session token:', Buffer.from(encryptedSessionToken).toString('hex').substring(0, 64) + '...');
console.log();

// =============================================================================
// Summary
// =============================================================================

console.log('='.repeat(70));
console.log('API SECURITY SUMMARY');
console.log('='.repeat(70));
console.log();
console.log('All examples demonstrate using aesjs.ModeOfOperation.ctr(token) to protect:');
console.log('  • API credentials - Complete API authentication data');
console.log('  • API keys - Service access keys');
console.log('  • API secrets - Sensitive authentication secrets');
console.log('  • Access tokens - API authentication tokens');
console.log('  • Refresh tokens - Token renewal credentials');
console.log('  • Webhook secrets - Webhook verification secrets');
console.log('  • Authentication tokens - User identity tokens');
console.log('  • Session tokens - User session maintenance tokens');
console.log();
console.log('Security best practices:');
console.log('  ✓ Each API credential type uses its own encryption token');
console.log('  ✓ Unique counters prevent pattern analysis');
console.log('  ✓ Password-derived tokens add authentication layer');
console.log('  ✓ Tokens are protected like the credentials they encrypt');
console.log();
console.log('=== API Security Examples Complete ===');

