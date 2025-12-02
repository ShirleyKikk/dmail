# Security Guide

This guide provides comprehensive security information for using the Secure Blockchain Mail system and handling sensitive cryptographic data.

## Table of Contents

1. [Core Security Principles](#core-security-principles)
2. [Encryption Best Practices](#encryption-best-practices)
3. [Key Management](#key-management)
4. [Common Vulnerabilities](#common-vulnerabilities)
5. [Production Deployment](#production-deployment)
6. [Incident Response](#incident-response)

## Core Security Principles

### Defense in Depth

Security should be implemented in multiple layers:

1. **Encryption at rest** - All sensitive data encrypted in storage
2. **Encryption in transit** - Use TLS/SSL for network communication
3. **Access control** - Limit who can access encrypted data
4. **Key protection** - Secure key storage and handling
5. **Audit logging** - Monitor access to sensitive operations (without logging secrets!)

### Least Privilege

- Only decrypt data when absolutely necessary
- Minimize exposure time of decrypted sensitive data
- Clear sensitive data from memory after use
- Limit access permissions to encrypted storage

### Assume Breach

Design systems assuming an attacker may gain partial access:

- Encryption prevents stolen data from being useful
- Password requirements increase brute-force difficulty
- Rate limiting prevents automated attacks
- Monitoring detects suspicious activity

## Encryption Best Practices

### Using AES-256-CTR Correctly

AES-CTR (Counter Mode) is a secure encryption mode when used properly:

```javascript
const crypto = require('crypto');
const aesjs = require('aes-js');

// ✅ CORRECT: Random counter for each encryption
function encryptSecurely(data, key) {
  // Generate cryptographically secure random counter
  const counter = crypto.randomBytes(16);

  const aesCtr = new aesjs.ModeOfOperation.ctr(
    key,
    new aesjs.Counter(Array.from(counter))
  );

  const encrypted = aesCtr.encrypt(data);

  // Return both encrypted data and counter
  return { encrypted, counter };
}
```

**Critical Rules:**

1. **Never reuse counters** - Each encryption must use a unique counter
2. **Use crypto.randomBytes()** - Don't use Math.random() or static values
3. **Store counters** - Save counter with encrypted data for decryption
4. **Consider authentication** - CTR doesn't authenticate; consider AES-GCM for AEAD

### Password-Based Encryption

When encrypting with passwords, proper key derivation is critical:

```javascript
// ❌ WRONG: Direct hashing
const badKey = crypto.createHash('sha256').update(password).digest();

// ✅ CORRECT: PBKDF2 with salt and iterations
const goodKey = crypto.pbkdf2Sync(
  password,
  salt,        // Random, 16+ bytes
  100000,      // High iteration count
  32,          // 256-bit key
  'sha256'
);
```

**Best Practices:**

- Use PBKDF2, scrypt, or Argon2 (not plain hashing)
- Generate random salt for each encryption
- Use high iteration counts (100,000+ for PBKDF2)
- Store salt with encrypted data (it's not secret)
- Consider using Argon2 for new implementations

### Data Integrity

Encryption alone doesn't guarantee data hasn't been tampered with:

```javascript
// Basic approach: Include checksum
const checksum = crypto.createHash('sha256')
  .update(JSON.stringify(data))
  .digest('hex');

const dataWithChecksum = { data, checksum };

// Better: Use HMAC
const hmac = crypto.createHmac('sha256', hmacKey)
  .update(JSON.stringify(data))
  .digest('hex');

// Best: Use authenticated encryption (AES-GCM)
// Provides both encryption and authentication
```

## Key Management

### Private Key Storage

Private keys are the most sensitive data in blockchain applications:

**Storage Hierarchy (Most to Least Secure):**

1. **Hardware Security Modules (HSMs)** - Physical devices for key storage
2. **Secure Enclaves** - OS-level protected storage (iOS Keychain, Android Keystore)
3. **Encrypted file storage** - Files encrypted with strong password/key
4. **Environment variables** - For development only, never production
5. **Configuration files** - Never acceptable, always encrypt

```javascript
// ✅ GOOD: Encrypted storage
const encryptedKey = SecureEncryption.encryptWalletData(
  privateKey,
  strongPassword
);
fs.writeFileSync('wallet.enc', JSON.stringify(encryptedKey), {
  mode: 0o600  // Only user can read/write
});

// ❌ BAD: Plaintext storage
fs.writeFileSync('wallet.json', JSON.stringify({ privateKey }));
```

### Mnemonic Seed Phrases

BIP39 mnemonic phrases deserve special protection:

**Rules:**

1. **Never log mnemonics** - Not even to console
2. **Display only once** - During initial wallet creation
3. **Encrypt immediately** - Before any storage
4. **Warn users** - Educate about the importance of mnemonics
5. **Use secure UI** - Prevent screenshots, disable autocomplete

```javascript
// Secure mnemonic handling
function handleMnemonic(mnemonic, password) {
  // Encrypt immediately
  const encrypted = SecureEncryption.encryptWalletData(
    mnemonic,
    password
  );

  // Clear original from memory (best effort in JS)
  mnemonic = null;

  // Return only encrypted version
  return encrypted;
}
```

### API Keys and Tokens

API credentials for blockchain services need protection:

```javascript
// Development: Use environment variables
const apiKey = process.env.BLOCKCHAIN_API_KEY;

// Production: Encrypt and store securely
const encryptedCreds = SecureEncryption.encryptWalletData(
  JSON.stringify({
    apiKey: process.env.BLOCKCHAIN_API_KEY,
    apiSecret: process.env.BLOCKCHAIN_API_SECRET
  }),
  process.env.MASTER_PASSWORD
);

// Store encrypted version
// Decrypt only when needed for API calls
```

**Best Practices:**

- Rotate keys regularly
- Use different keys for development/production
- Monitor API usage for anomalies
- Revoke compromised keys immediately
- Use API key restrictions (IP whitelist, rate limits)

## Common Vulnerabilities

### 1. Hardcoded Secrets

**Problem:**
```javascript
// ❌ NEVER DO THIS
const PRIVATE_KEY = '0xabcd1234...';
const API_SECRET = 'sk_live_...';
```

**Impact:** Secrets leaked through version control, decompiled code, or logs

**Solution:**
- Use environment variables for development
- Encrypt secrets for storage
- Never commit secrets to git
- Use `.gitignore` for sensitive files

### 2. Weak Password Requirements

**Problem:**
```javascript
// ❌ Accepting weak passwords
if (password.length >= 6) { /* Too weak! */ }
```

**Impact:** Brute force attacks can crack weak passwords

**Solution:**
```javascript
// ✅ Enforce strong passwords
function validatePassword(password) {
  return password.length >= 12 &&
         /[A-Z]/.test(password) &&
         /[a-z]/.test(password) &&
         /[0-9]/.test(password) &&
         /[^A-Za-z0-9]/.test(password);
}
```

### 3. Counter Reuse in CTR Mode

**Problem:**
```javascript
// ❌ Static or reused counter
const counter = new aesjs.Counter(5);
cipher.encrypt(data1);  // Uses counter value 5
cipher.encrypt(data2);  // Uses counter value 6 - related!
```

**Impact:** Catastrophic - allows plaintext recovery

**Solution:**
```javascript
// ✅ New random counter for each encryption
const counter1 = crypto.randomBytes(16);
const counter2 = crypto.randomBytes(16);
// Completely independent counters
```

### 4. Insufficient Key Derivation

**Problem:**
```javascript
// ❌ Simple hashing
const key = crypto.createHash('sha256').update(password).digest();
```

**Impact:** Vulnerable to rainbow tables and brute force

**Solution:**
```javascript
// ✅ Proper KDF with salt
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
```

### 5. Logging Sensitive Data

**Problem:**
```javascript
// ❌ Logging secrets
console.log('Private key:', privateKey);
console.log('Password:', password);
```

**Impact:** Secrets exposed in log files, monitoring systems

**Solution:**
```javascript
// ✅ Log operations, not data
console.log('Private key loaded successfully');
console.log('Authentication successful');
```

### 6. Insecure Random Number Generation

**Problem:**
```javascript
// ❌ Not cryptographically secure
const counter = Math.random() * 1000000;
```

**Impact:** Predictable encryption, key recovery possible

**Solution:**
```javascript
// ✅ Cryptographically secure
const counter = crypto.randomBytes(16);
```

## Production Deployment

### Pre-Deployment Checklist

- [ ] Security audit completed
- [ ] All secrets encrypted
- [ ] Strong password policy enforced
- [ ] Rate limiting implemented
- [ ] Logging configured (without sensitive data)
- [ ] Monitoring and alerts set up
- [ ] Backup and recovery tested
- [ ] Incident response plan documented
- [ ] Dependencies updated and scanned
- [ ] TLS/SSL configured properly

### Environment Configuration

```bash
# .env.production (never commit this!)
MASTER_PASSWORD=<strong-random-password>
DATABASE_ENCRYPTION_KEY=<random-key-hex>
API_RATE_LIMIT=100
LOG_LEVEL=info

# Use a secrets manager in production
# AWS Secrets Manager, HashiCorp Vault, etc.
```

### Monitoring

Monitor for security events:

1. **Failed decryption attempts** - Possible brute force
2. **Unusual API usage** - Compromised keys
3. **Multiple failed logins** - Account takeover attempts
4. **Data export requests** - Potential data theft
5. **Encryption errors** - System compromise

### Updates and Patching

- Monitor security advisories for dependencies
- Update regularly, especially security patches
- Test updates in staging before production
- Have rollback plan ready

## Incident Response

### If a Private Key is Compromised

1. **Immediate Actions:**
   - Transfer funds to new wallet
   - Revoke any associated permissions
   - Document the incident
   - Notify affected users if applicable

2. **Investigation:**
   - Determine how compromise occurred
   - Check for other affected keys
   - Review logs for suspicious activity

3. **Prevention:**
   - Fix vulnerability that led to compromise
   - Update security procedures
   - Consider additional security measures

### If Encrypted Data is Stolen

1. **Assess Risk:**
   - Strong encryption + strong password = low immediate risk
   - Weak password = high risk
   - No encryption = critical risk

2. **Actions:**
   - Force password resets if applicable
   - Increase monitoring
   - Prepare for potential decryption
   - Consider rotating keys/credentials

3. **Communication:**
   - Notify affected users
   - Provide guidance on next steps
   - Be transparent about risk level

## Additional Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-327: Use of Broken Crypto](https://cwe.mitre.org/data/definitions/327.html)

---

**Remember:** Security is an ongoing process, not a one-time implementation. Stay informed, test regularly, and always err on the side of caution when handling sensitive data.
