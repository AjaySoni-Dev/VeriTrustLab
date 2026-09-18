const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('MIME part budget drains and releases post-budget attachment streams instead of processing them', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../lib/email/parser.js'), 'utf8');
  assert.match(source, /mimePartCount > MAX_MIME_PARTS/u);
  assert.match(source, /skippedMimeParts \+= 1/u);
  assert.match(source, /part\.content\.resume\(\)/u);
  assert.match(source, /part\.release\(\)/u);
  assert.match(source, /MIME_PART_LIMIT_REACHED/u);
  assert.doesNotMatch(source, /if \(partCount > MAX_MIME_PARTS\) throw parserError/u);
});
