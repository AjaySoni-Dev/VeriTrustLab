const path = require('path');

const EXECUTABLE_OR_SCRIPT = new Set(['.exe', '.scr', '.com', '.js', '.jse', '.vbs', '.vbe', '.ps1', '.bat', '.cmd', '.hta', '.msi']);
const MACRO_OFFICE = new Set(['.docm', '.xlsm', '.xltm', '.pptm', '.potm', '.ppam', '.sldm']);
const DISK_OR_SHORTCUT = new Set(['.iso', '.img', '.lnk']);
const ARCHIVE = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz']);
const BIDI = /[\u202a-\u202e\u2066-\u2069]/u;

const MIME_BY_EXTENSION = new Map([
  ['.pdf', ['application/pdf']],
  ['.jpg', ['image/jpeg']], ['.jpeg', ['image/jpeg']], ['.png', ['image/png']], ['.gif', ['image/gif']],
  ['.txt', ['text/plain']], ['.csv', ['text/csv', 'application/csv']],
  ['.docx', ['application/vnd.openxmlformats-officedocument.wordprocessingml.document']],
  ['.xlsx', ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']],
  ['.pptx', ['application/vnd.openxmlformats-officedocument.presentationml.presentation']],
  ['.zip', ['application/zip', 'application/x-zip-compressed']],
]);

function filenameExtension(filename) {
  const safe = String(filename || '').trim().replace(/\\/gu, '/').split('/').pop() || '';
  return { safe, extension: path.extname(safe).toLowerCase() };
}

function hasDoubleExtension(filename) {
  const safe = String(filename || '').toLowerCase();
  const parts = safe.split('.').filter(Boolean);
  return parts.length >= 3 && parts.slice(-2).every((part) => /^[a-z0-9]{1,8}$/u.test(part));
}

function mimeMismatch(extension, declaredMime) {
  const expected = MIME_BY_EXTENSION.get(extension);
  if (!expected || !declaredMime) return false;
  return !expected.includes(String(declaredMime).toLowerCase().split(';')[0].trim());
}

function analyzeAttachmentMetadata(attachment = {}) {
  const { safe: filename, extension } = filenameExtension(attachment.filename);
  const declaredMime = String(attachment.declared_mime_type || '').toLowerCase().split(';')[0].trim() || null;
  const flags = [];

  if (filename && BIDI.test(filename)) flags.push({ code: 'BIDI_CONTROL_IN_FILENAME', severity: 'ELEVATED', explanation: 'The filename contains bidirectional text-control characters that can obscure how an extension appears.' });
  if (hasDoubleExtension(filename)) flags.push({ code: 'DOUBLE_EXTENSION', severity: 'ELEVATED', explanation: 'The filename contains multiple extensions and should be verified before opening.' });
  if (EXECUTABLE_OR_SCRIPT.has(extension)) flags.push({ code: 'EXECUTABLE_OR_SCRIPT_EXTENSION', severity: 'HIGH', explanation: 'The attachment uses an executable or script-oriented extension. VeriTrust does not execute it.' });
  if (MACRO_OFFICE.has(extension)) flags.push({ code: 'MACRO_ENABLED_OFFICE_EXTENSION', severity: 'ELEVATED', explanation: 'The attachment uses a macro-enabled Microsoft Office format.' });
  if (DISK_OR_SHORTCUT.has(extension)) flags.push({ code: 'DISK_IMAGE_OR_SHORTCUT_EXTENSION', severity: 'ELEVATED', explanation: 'The attachment is a disk-image or shortcut-oriented format that deserves manual review.' });
  if (ARCHIVE.has(extension)) flags.push({ code: 'ARCHIVE_ATTACHMENT', severity: 'INFO', explanation: 'The attachment is an archive; its contents are not executed by VeriTrust.' });
  if (mimeMismatch(extension, declaredMime)) flags.push({ code: 'DECLARED_MIME_EXTENSION_MISMATCH', severity: 'ELEVATED', explanation: 'The declared MIME type does not match the expected type for this filename extension.' });

  const rank = { INFO: 1, ELEVATED: 2, HIGH: 3 };
  const highest = flags.reduce((best, item) => rank[item.severity] > rank[best] ? item.severity : best, 'INFO');
  return {
    producer_version: 'mailgraph-attachment-metadata-1',
    state: 'METADATA_ONLY',
    filename_untrusted: filename || null,
    extension: extension || null,
    declared_mime_type: declaredMime,
    highest_severity: flags.length ? highest : 'NONE',
    flags,
    executable_content_processed: false,
    limitation: 'Metadata observations are supporting evidence only; attachment content is not executed or malware-sandboxed.',
  };
}

module.exports = { analyzeAttachmentMetadata, filenameExtension, hasDoubleExtension, mimeMismatch };
