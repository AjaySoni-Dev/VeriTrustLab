const test = require('node:test');
const assert = require('node:assert/strict');
const { extractUrls } = require('../lib/email/content');

test('extractUrls tracks all ten clickable links and ignores image src resources', () => {
  const anchors = Array.from({ length: 10 }, (_, index) => `<a href="https://example${index}.com/path/${index}">Open ${index}</a>`).join('\n');
  const pixels = Array.from({ length: 20 }, (_, index) => `<img src="https://tracker.example/pixel/${index}.gif">`).join('\n');
  const result = extractUrls('', `${pixels}\n${anchors}`);
  assert.equal(result.urls.length, 10);
  assert.equal(result.observations.some((item) => item.code === 'URL_EXTRACTION_LIMIT_REACHED'), false);
  for (let index = 0; index < 10; index += 1) {
    assert.ok(result.urls.some((item) => item.url.includes(`example${index}.com/path/${index}`)));
  }
  assert.equal(result.urls.some((item) => item.url.includes('tracker.example')), false);
});

test('extractUrls accepts unquoted href, action, and formaction URLs', () => {
  const result = extractUrls('', '<a href=https://example.com/a>one</a><form action=https://example.org/submit><button formaction=https://example.net/confirm>Confirm</button></form>');
  assert.equal(result.urls.length, 3);
});
