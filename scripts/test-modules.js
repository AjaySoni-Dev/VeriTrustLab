const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'modules.js'), 'utf8');
const keys = ['phishing', 'deepfake', 'link', 'gateway'];

function loadWithConfig(config) {
  const target = { exports: {} };
  const localRequire = (request) => {
    if (request === '../config/modules.json') return config;
    throw new Error(`Unexpected require in module switch test: ${request}`);
  };
  new Function('require', 'module', 'exports', source)(localRequire, target, target.exports);
  return target.exports;
}

for (const disabled of keys) {
  const config = Object.fromEntries(keys.map((key) => [key, key !== disabled]));
  const modules = loadWithConfig(config);
  assert.equal(modules.isModuleEnabled(disabled), false);
  assert.throws(() => modules.requireModuleEnabled(disabled), (error) => error.code === 'NOT_FOUND' && error.status === 404);
  const sanitized = modules.sanitizeModuleData({ keep: 'ordinary value', remove: `Uses ${disabled} analysis` });
  assert.deepEqual(sanitized, { keep: 'ordinary value' });
}

console.log('Verified all four independent module-disabled states.');
