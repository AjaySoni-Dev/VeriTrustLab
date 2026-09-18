const crypto = require('crypto');

function encryptionKey(value) {
  const raw = String(value || '').trim();
  const key = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
  if (key.length !== 32) {
    const error = new Error('WEBHOOK_ENCRYPTION (or VERITRUST_WEBHOOK_ENCRYPTION_KEY) must be a 32-byte key encoded as hex or base64.');
    error.status = 500;
    error.code = 'SERVER_CONFIG_ERROR';
    throw error;
  }
  return key;
}

function encryptSecret(secret, keyValue) {
  const plaintext = Buffer.from(String(secret || ''), 'utf8');
  if (plaintext.length < 32) throw new Error('Webhook secret must contain at least 32 bytes.');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(keyValue), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext: ciphertext.toString('base64url'), iv: iv.toString('base64url'), auth_tag: cipher.getAuthTag().toString('base64url') };
}

function decryptSecret(row, keyValue) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(keyValue), Buffer.from(row.iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(row.auth_tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(row.ciphertext, 'base64url')), decipher.final()]).toString('utf8');
}

module.exports = { decryptSecret, encryptSecret, encryptionKey };
