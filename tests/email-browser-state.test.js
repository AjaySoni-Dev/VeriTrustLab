const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const results = require('../assets/js/core/analysis-result');

test('email mode changes cannot unlock an outstanding investigation or submit it twice', async () => {
  const nodes = new Map();
  function node(selector) {
    if (!nodes.has(selector)) nodes.set(selector, {
      value: '', dataset: {}, events: {}, attributes: {},
      classList: { add() {}, remove() {}, toggle() {} },
      setAttribute(name, value) { this.attributes[name] = value; },
      toggleAttribute() {}, focus() {},
      querySelectorAll() { return []; },
      addEventListener(name, callback) { this.events[name] = callback; },
    });
    return nodes.get(selector);
  }
  const tabs = [node('text-tab'), node('eml-tab')];
  tabs[0].dataset.emailMode = 'text'; tabs[1].dataset.emailMode = 'eml';
  let initialize;
  let resolveContext;
  let requests = 0;
  const context = new Promise((resolve) => { resolveContext = resolve; });
  vm.runInNewContext(fs.readFileSync('assets/js/pages/email-investigation.js', 'utf8'), {
    window: {
      VeriTrustAnalysisResult: results,
      VeriTrustAnalysisProgress: { create: () => ({ begin() {}, finish() {} }) },
      VeriTrustSupabase: { isConfigured: () => true, getSessionContext: () => { requests++; return context; } },
      addEventListener() {},
    },
    document: {
      querySelector: node,
      querySelectorAll: (selector) => selector.startsWith('[data-email-mode]') ? tabs : [],
      addEventListener: (name, callback) => { if (name === 'DOMContentLoaded') initialize = callback; },
    },
  });
  initialize();
  const submit = node('#phishingForm[data-email-workbench]').events.submit;
  const first = submit({ preventDefault() {} });
  assert.equal(node('#phishingSubmit').disabled, true);
  tabs[1].events.click();
  assert.equal(tabs[0].attributes['aria-selected'], 'true');
  assert.equal(node('#phishingSubmit').disabled, true);
  await submit({ preventDefault() {} });
  assert.equal(requests, 1);
  resolveContext(null);
  await first;
  assert.equal(node('#phishingSubmit').disabled, false);
});
