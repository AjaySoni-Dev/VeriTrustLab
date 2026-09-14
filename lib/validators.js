const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/bmp']);
const MIN_PHISHING_TEXT_CHARS = 8;
const MAX_PHISHING_TEXT_CHARS = 12000;

function validationError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function detectedImageType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  if (buffer[0] === 0x42 && buffer[1] === 0x4d) return 'image/bmp';
  return null;
}

function validateImageUpload(upload, options = {}) {
  const maxBytes = Number(options.maxBytes || MAX_IMAGE_BYTES);
  const allowedTypes = options.allowedTypes || ALLOWED_IMAGE_TYPES;

  if (!upload) {
    throw validationError(400, 'IMAGE_REQUIRED', 'Upload an image using the image field.');
  }
  if (!upload.buffer || !Buffer.isBuffer(upload.buffer) || upload.buffer.length === 0) {
    throw validationError(400, 'IMAGE_EMPTY', 'Uploaded image is empty.');
  }
  if (upload.buffer.length > maxBytes || Number(upload.size || 0) > maxBytes) {
    throw validationError(413, 'IMAGE_TOO_LARGE', 'Image must be 4 MB or smaller for Vercel inference.');
  }

  const mimeType = String(upload.mimeType || '').toLowerCase();
  if (!mimeType || !allowedTypes.has(mimeType)) {
    throw validationError(400, 'IMAGE_TYPE_UNSUPPORTED', 'Unsupported image type. Use JPG, PNG, WEBP, or BMP.');
  }
  const detectedType = detectedImageType(upload.buffer);
  if (!detectedType || detectedType !== mimeType) {
    throw validationError(415, 'IMAGE_CONTENT_MISMATCH', 'The uploaded file content does not match its declared image type.');
  }

  return upload;
}

function hasExtremeCharacterRun(text) {
  return /(.)\1{80,}/u.test(text);
}

function hasLowVarietySpam(text) {
  const compact = text.replace(/\s+/g, '');
  if (compact.length < 80) return false;
  return new Set(compact.toLowerCase()).size <= 3;
}

function validatePhishingText(text) {
  const normalized = String(text || '').trim();
  if (!normalized) {
    throw validationError(400, 'TEXT_REQUIRED', 'Paste an email, SMS, URL, or message to analyze.');
  }
  if (normalized.length < MIN_PHISHING_TEXT_CHARS) {
    throw validationError(400, 'TEXT_TOO_SHORT', 'Message is too short to analyze reliably.');
  }
  if (normalized.length > MAX_PHISHING_TEXT_CHARS) {
    throw validationError(400, 'TEXT_TOO_LONG', 'Text payload is too long. Keep it under 12,000 characters.');
  }
  if (hasExtremeCharacterRun(normalized) || hasLowVarietySpam(normalized)) {
    throw validationError(400, 'TEXT_SPAM_PAYLOAD', 'Message payload appears malformed. Paste meaningful text to analyze.');
  }
  return normalized;
}

function validateModelKey(modelKey, models, label) {
  const normalized = String(modelKey || '').trim().toLowerCase();
  if (!normalized || !Object.prototype.hasOwnProperty.call(models, normalized)) {
    throw validationError(400, 'MODEL_UNKNOWN', `Unknown ${label} model.`);
  }
  return normalized;
}

function validateJsonContentType(req) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (!contentType.includes('application/json')) {
    throw validationError(415, 'CONTENT_TYPE_UNSUPPORTED', 'Use application/json for this endpoint.');
  }
}

module.exports = {
  ALLOWED_IMAGE_TYPES,
  MAX_IMAGE_BYTES,
  MAX_PHISHING_TEXT_CHARS,
  detectedImageType,
  validateImageUpload,
  validateJsonContentType,
  validateModelKey,
  validatePhishingText,
};
