const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');
const { analysisProgress } = require('../lib/analysis-stream');
const { sendJson } = require('../lib/veritrust-api');
const { readResponse } = require('../assets/js/core/analysis-progress');

function responseSink() {
  const sink = new PassThrough();
  sink.headers = {};
  sink.setHeader = (name, value) => { sink.headers[name.toLowerCase()] = value; };
  sink.removeHeader = (name) => { delete sink.headers[name.toLowerCase()]; };
  return sink;
}

test('progress is opt-in and ordinary API clients keep the JSON contract', () => {
  const res = responseSink();
  const progress = analysisProgress({ headers: { accept: 'application/json' } }, res);
  progress('model', 'running', 'Waiting for model.');
  assert.equal(res.readableLength, 0);
  sendJson(res, 200, { ok: true, result: { label: 'Real' } });
  assert.equal(res.headers['content-type'], 'application/json; charset=utf-8');
  assert.equal(JSON.parse(res.read().toString()).result.label, 'Real');
});

test('stream events arrive before completion and preserve redaction and terminal errors', async () => {
  const res = responseSink();
  const progress = analysisProgress({ headers: { accept: 'application/x-ndjson' } }, res);
  progress('model', 'running', 'Requesting image analysis.');
  const first = JSON.parse(res.read().toString());
  assert.equal(first.type, 'progress');
  assert.equal(first.state, 'running');
  assert.equal(res.writableEnded, false);
  sendJson(res, 502, { ok: false, error: { code: 'MODEL_ERROR', message: 'Model unavailable.' }, provider_model: 'private-model' });
  const last = JSON.parse(res.read().toString());
  assert.equal(last.type, 'result');
  assert.equal(last.status, 502);
  assert.equal(last.payload.provider_model, undefined);
  await assert.rejects(readResponse(new Response(`${JSON.stringify(first)}\n${JSON.stringify(last)}\n`, { headers: { 'Content-Type': 'application/x-ndjson' } })), { code: 'MODEL_ERROR' });
});

test('fragmented UTF-8 frames render only received backend stages', async () => {
  const text = [
    { type: 'progress', sequence: 1, stage: 'model', state: 'running', message: 'Analyzing café content.' },
    { type: 'progress', sequence: 2, stage: 'model', state: 'completed', message: 'Scores received.' },
    { type: 'result', sequence: 3, status: 200, payload: { ok: true, scan_id: 'verified' } },
  ].map((item) => JSON.stringify(item)).join('\n');
  const bytes = new TextEncoder().encode(text);
  const stream = new ReadableStream({ start(controller) { for (const byte of bytes) controller.enqueue(Uint8Array.of(byte)); controller.close(); } });
  const events = [];
  const payload = await readResponse(new Response(stream, { headers: { 'content-type': 'application/x-ndjson' } }), (event) => events.push(event));
  assert.equal(payload.scan_id, 'verified');
  assert.equal(events.length, 2);
  assert.equal(events[0].message, 'Analyzing café content.');
});

test('a disconnected stream cannot produce a fabricated final report', async () => {
  const response = new Response(JSON.stringify({ type: 'progress', sequence: 1, stage: 'model', state: 'running', message: 'Waiting for model.' }) + '\n', { headers: { 'content-type': 'application/x-ndjson' } });
  await assert.rejects(readResponse(response), /before a final report/);
});

test('validation failures before streaming retain their HTTP status', () => {
  const res = responseSink();
  analysisProgress({ headers: { accept: 'application/x-ndjson' } }, res);
  sendJson(res, 401, { ok: false, error: { code: 'UNAUTHORIZED' } });
  assert.equal(res.statusCode, 401);
  assert.equal(res.headers['content-type'], 'application/json; charset=utf-8');
});
