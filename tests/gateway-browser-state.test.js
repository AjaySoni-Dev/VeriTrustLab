const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const results = require('../assets/js/core/analysis-result');

class Element {
  constructor() {
    this.children = []; this.events = {}; this.dataset = {}; this.files = [];
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  get childElementCount() { return this.children.length; }
  setAttribute() {} removeAttribute() {} focus() {}
  querySelectorAll() { return this.children; }
  addEventListener(name, callback) { this.events[name] = callback; }
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test('a late Gateway poll cannot overwrite a newly selected history scan', async () => {
  const ids = new Map();
  const get = (id) => { if (!ids.has(id)) ids.set(id, new Element()); return ids.get(id); };
  const scanA = '12345678-1234-4123-8123-123456789012';
  const scanB = '12345678-1234-4123-8123-123456789013';
  let resolveA;
  const pendingA = new Promise((resolve) => { resolveA = resolve; });
  const api = {
    getSession: async () => ({ authenticated: true }),
    callAppApi: async (url) => {
      if (url.includes('?limit=')) return { scans: [{ id: scanB, created_at: new Date().toISOString(), status: 'failed' }] };
      if (url.endsWith(scanA)) return pendingA;
      if (url.endsWith(scanB)) return { scan_id: scanB, status: 'failed', decision: { risk: null } };
      throw new Error(`Unexpected endpoint: ${url}`);
    },
  };
  const window = { VeriTrustSupabase: api, VeriTrustAnalysisResult: results, location: { search: `?scan_id=${scanA}` } };
  vm.runInNewContext(fs.readFileSync('assets/js/pages/gateway.js', 'utf8'), {
    window, URLSearchParams, clearTimeout, setTimeout,
    document: { getElementById: get, querySelector: () => new Element(), createElement: () => new Element() },
  });
  await flush();
  const historyItem = get('gateway-history-list').children[0];
  await historyItem.events.click();
  assert.equal(get('gateway-status').textContent, 'failed');
  assert.equal(get('gateway-risk').textContent, 'Not available');
  resolveA({ scan_id: scanA, status: 'completed', decision: { risk: 0 } });
  await flush();
  assert.equal(get('gateway-status').textContent, 'failed');
  assert.equal(get('gateway-risk').textContent, 'Not available');
  assert.match(get('gateway-status-copy').textContent, /No safe conclusion/);
});
