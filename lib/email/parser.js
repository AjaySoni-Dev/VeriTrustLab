const crypto = require('crypto');
const { Readable } = require('stream');
const iconv = require('iconv-lite');
const { MailParser } = require('mailparser');
const {
  EMAIL_PARSER_VERSION,
  MAX_ATTACHMENT_BYTES,
  MAX_DECODED_BYTES,
  MAX_HEADER_BYTES,
  MAX_MIME_DEPTH,
  MAX_MIME_PARTS,
  MAX_NORMALIZED_HTML_BYTES,
  MAX_RAW_EML_BYTES,
  PARSER_TIMEOUT_MS,
} = require('./contracts');
const { safeTextFromHtml, sha256 } = require('./content');

function parserError(code, message, status = 400) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  return error;
}

function rawHeaderBlock(raw) {
  const crlf = raw.indexOf(Buffer.from('\r\n\r\n'));
  const lf = raw.indexOf(Buffer.from('\n\n'));
  const end = crlf >= 0 ? crlf + 4 : (lf >= 0 ? lf + 2 : raw.length);
  return raw.subarray(0, end);
}

function preflightMime(raw) {
  const headers = rawHeaderBlock(raw);
  if (headers.length > MAX_HEADER_BYTES) throw parserError('MALFORMED_LIMIT', 'The email header block exceeds 256 KiB.', 413);
  const latin = raw.toString('latin1');
  const partCount = (latin.match(/(?:^|\r?\n)content-type\s*:/giu) || []).length || 1;
  const multipartCount = (latin.match(/(?:^|\r?\n)content-type\s*:\s*multipart\//giu) || []).length;
  if (partCount > MAX_MIME_PARTS) throw parserError('PARTIAL_LIMIT', 'The email exceeds the MIME part budget.', 413);
  if (multipartCount > MAX_MIME_DEPTH) throw parserError('MALFORMED_LIMIT', 'The email exceeds the MIME nesting budget.', 413);
  const declaredCharsets = [...latin.matchAll(/\bcharset\s*=\s*(?:"([^"]+)"|'([^']+)'|([^;\s\r\n]+))/giu)]
    .map((match) => String(match[1] || match[2] || match[3] || '').trim().toLowerCase())
    .filter(Boolean);
  const unsupportedCharsets = [...new Set(declaredCharsets.filter((charset) => !iconv.encodingExists(charset)))];
  const boundaries = [...latin.matchAll(/content-type\s*:\s*multipart\/[^;\r\n]+;[^\r\n]*\bboundary\s*=\s*(?:"([^"]+)"|'([^']+)'|([^;\s\r\n]+))/giu)]
    .map((match) => match[1] || match[2] || match[3])
    .filter(Boolean);
  const unterminatedBoundaries = boundaries.filter((boundary) => !latin.includes(`--${boundary}--`));
  return { headerBytes: headers.length, estimatedPartCount: partCount, estimatedDepth: multipartCount, declaredCharsets, unsupportedCharsets, unterminatedBoundaries };
}

function addressValues(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.flatMap(addressValues);
  if (Array.isArray(value.value)) return value.value.map((item) => ({ name: item.name || '', address: item.address || '' }));
  if (value.address) return [{ name: value.name || '', address: value.address }];
  return [];
}

function headerDate(value) {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  const parsed = new Date(value || '');
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

async function parseEml(rawInput, options = {}) {
  const raw = Buffer.isBuffer(rawInput) ? rawInput : Buffer.from(rawInput || '');
  if (!raw.length) throw parserError('EMAIL_EMPTY', 'The raw email is empty.');
  if (raw.length > (options.maxRawBytes || MAX_RAW_EML_BYTES)) throw parserError('UNSUPPORTED_LIMIT', 'The raw email exceeds the 10 MiB endpoint limit.', 413);

  const rawSha256 = crypto.createHash('sha256').update(raw).digest('hex');
  const preflight = preflightMime(raw);
  const parser = options.parser || new MailParser({
    checksumAlgo: 'sha256',
    skipImageLinks: true,
    skipTextToHtml: true,
    maxHtmlLengthToParse: MAX_NORMALIZED_HTML_BYTES,
  });
  const attachments = [];
  const limitations = [
    ...(preflight.unsupportedCharsets.length ? ['UNSUPPORTED_CHARSET_DECLARATION'] : []),
    ...(preflight.unterminatedBoundaries.length ? ['MIME_TERMINATOR_MISSING'] : []),
  ];
  const malformed = [
    ...preflight.unsupportedCharsets.map((charset) => ({ code: 'UNSUPPORTED_CHARSET', charset })),
    ...preflight.unterminatedBoundaries.map((boundary) => ({ code: 'UNTERMINATED_MULTIPART', boundary_hash: sha256(boundary) })),
  ];
  let headers = new Map();
  let headerLines = [];
  let text = '';
  let html = '';
  let decodedBytes = 0;
  let mimePartCount = 0;
  let attachmentOrdinal = 0;
  let parseState = 'COMPLETED';
  let finished = false;

  const parsed = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      if (finished) return;
      const error = parserError('FAILED_TIMEOUT', 'Email parsing exceeded the wall-time budget.', 408);
      parser.destroy(error);
    }, options.timeoutMs ?? PARSER_TIMEOUT_MS);
    timeout.unref?.();

    parser.on('headers', (value) => { headers = value; });
    parser.on('headerLines', (value) => { headerLines = Array.isArray(value) ? value : []; });
    parser.on('data', (part) => {
      mimePartCount += 1;
      if (mimePartCount > MAX_MIME_PARTS) {
        parseState = 'PARTIAL_LIMIT';
        limitations.push('MIME_PART_LIMIT_REACHED');
      }
      if (part.type === 'attachment') {
        const index = attachmentOrdinal++;
        let size = 0;
        const digest = crypto.createHash('sha256');
        let overLimit = false;
        part.content.on('data', (chunk) => {
          size += chunk.length;
          decodedBytes += chunk.length;
          if (size <= MAX_ATTACHMENT_BYTES && decodedBytes <= MAX_DECODED_BYTES) digest.update(chunk);
          if (size > MAX_ATTACHMENT_BYTES) overLimit = true;
          if (decodedBytes > MAX_DECODED_BYTES) {
            parseState = 'PARTIAL_LIMIT';
            if (!limitations.includes('DECODED_BYTES_LIMIT_REACHED')) limitations.push('DECODED_BYTES_LIMIT_REACHED');
          }
        });
        part.content.once('error', (error) => {
          malformed.push({ code: 'ATTACHMENT_STREAM_ERROR', index, message: String(error.message || '').slice(0, 160) });
          part.release();
        });
        part.content.once('end', () => {
          if (overLimit) {
            parseState = 'PARTIAL_LIMIT';
            limitations.push(`ATTACHMENT_${index}_LIMIT_REACHED`);
          }
          attachments.push({
            part_index: index,
            filename: String(part.filename || '').slice(0, 512) || null,
            declared_mime_type: String(part.contentType || 'application/octet-stream').toLowerCase(),
            disposition: String(part.contentDisposition || 'attachment').toLowerCase(),
            content_id: part.contentId || null,
            decoded_size: size,
            sha256: overLimit || decodedBytes > MAX_DECODED_BYTES ? null : digest.digest('hex'),
            truncated: overLimit,
            media_authenticity: 'NOT_EVALUATED',
          });
          part.release();
        });
        part.content.resume();
        return;
      }
      if (part.type === 'text') {
        text = String(part.text || '');
        html = typeof part.html === 'string' ? part.html : '';
        const htmlBytes = Buffer.byteLength(html, 'utf8');
        if (htmlBytes > MAX_NORMALIZED_HTML_BYTES) {
          html = Buffer.from(html, 'utf8').subarray(0, MAX_NORMALIZED_HTML_BYTES).toString('utf8');
          parseState = 'TRUNCATED';
          limitations.push('NORMALIZED_HTML_TRUNCATED');
        }
        decodedBytes += Buffer.byteLength(text, 'utf8') + Buffer.byteLength(html, 'utf8');
        if (decodedBytes > MAX_DECODED_BYTES) {
          parseState = 'PARTIAL_LIMIT';
          limitations.push('DECODED_BYTES_LIMIT_REACHED');
        }
      }
    });
    parser.once('error', (error) => {
      finished = true;
      clearTimeout(timeout);
      reject(error);
    });
    parser.once('end', () => {
      finished = true;
      clearTimeout(timeout);
      resolve(true);
    });
    const source = typeof options.sourceFactory === 'function' ? options.sourceFactory(raw) : Readable.from(raw);
    source.pipe(parser);
  });
  if (!parsed) throw parserError('FAILED', 'Email parsing did not complete.', 422);

  const htmlText = safeTextFromHtml(html);
  const normalizedText = [text, htmlText && !text.includes(htmlText) ? htmlText : ''].filter(Boolean).join('\n\n').trim();
  const from = addressValues(headers.get('from'));
  const replyTo = addressValues(headers.get('reply-to'));
  const sender = addressValues(headers.get('sender'));
  const returnPath = addressValues(headers.get('return-path'));
  const singletonCounts = new Map();
  for (const row of headerLines) {
    const key = String(row.key || '').toLowerCase();
    if (['from', 'subject', 'message-id', 'sender', 'reply-to', 'return-path'].includes(key)) singletonCounts.set(key, (singletonCounts.get(key) || 0) + 1);
  }
  for (const [key, count] of singletonCounts) {
    if (count > 1) {
      malformed.push({ code: 'DUPLICATE_SINGLETON_HEADER', header: key, count });
      limitations.push('DUPLICATE_SINGLETON_HEADER');
    }
  }
  if (from.length !== 1) limitations.push(from.length ? 'AMBIGUOUS_MULTIPLE_FROM' : 'FROM_ADDRESS_UNAVAILABLE');

  return {
    rawSha256,
    rawBytes: raw.length,
    parserVersion: EMAIL_PARSER_VERSION,
    parseState,
    headerBytes: preflight.headerBytes,
    decodedBytes,
    mimePartCount: Math.max(mimePartCount, preflight.estimatedPartCount),
    mimeDepthEstimate: preflight.estimatedDepth,
    attachments: attachments.sort((a, b) => a.part_index - b.part_index),
    headers,
    headerLines,
    addresses: { from, replyTo, returnPath, sender },
    subject: String(headers.get('subject') || ''),
    messageId: String(headers.get('message-id') || '') || null,
    date: headerDate(headers.get('date')),
    text: normalizedText,
    html,
    bodyTextHash: sha256(normalizedText),
    bodyHtmlHash: sha256(html),
    subjectHash: sha256(String(headers.get('subject') || '')),
    limitations: [...new Set(limitations)],
    malformed,
  };
}

module.exports = {
  addressValues,
  parseEml,
  preflightMime,
  rawHeaderBlock,
};
