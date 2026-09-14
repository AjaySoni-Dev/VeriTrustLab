const { HttpError } = require('../veritrust-api');

function detectedMime(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  if (buffer.subarray(0, 2).toString('ascii') === 'BM') return 'image/bmp';
  return null;
}

function validateImageBytes(buffer, declaredMime, maxBytes = 10 * 1024 * 1024) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) throw new HttpError(400, 'Stored image is empty.', { code: 'MEDIA_EMPTY' });
  if (buffer.length > maxBytes) throw new HttpError(413, 'Stored image exceeds the worker size limit.', { code: 'MEDIA_TOO_LARGE' });
  const actual = detectedMime(buffer);
  if (!actual) throw new HttpError(415, 'Stored image magic bytes are unsupported.', { code: 'MEDIA_MAGIC_INVALID' });
  if (declaredMime && actual !== String(declaredMime).toLowerCase()) throw new HttpError(415, 'Stored image content does not match its declared MIME type.', { code: 'MEDIA_MIME_MISMATCH' });
  return actual;
}

module.exports = { detectedMime, validateImageBytes };
