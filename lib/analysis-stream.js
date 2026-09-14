// Opt-in progress on the same authenticated request; no process-local job store.
function analysisProgress(req, res) {
  if (!String(req.headers?.accept || '').split(',').some((type) => type.trim().split(';')[0] === 'application/x-ndjson')) return () => {};
  let started = false;
  let closed = false;
  let sequence = 0;
  res.on?.('close', () => { closed = true; });
  function write(event) {
    if (closed || res.writableEnded || res.destroyed) return;
    if (!started) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store, no-transform');
      res.setHeader('X-Accel-Buffering', 'no');
      res.removeHeader?.('Content-Length');
      started = true;
      res.flushHeaders?.();
    }
    res.write(`${JSON.stringify({ ...event, sequence: ++sequence, timestamp: new Date().toISOString() })}\n`);
  }
  res.analysisStream = {
    get started() { return started; },
    finish(status, payload) {
      write({ type: 'result', status, payload });
      if (!closed && !res.writableEnded) res.end();
      closed = true;
    },
  };
  return (stage, state, message) => {
    if (sequence < 150) write({ type: 'progress', stage, state, message });
  };
}

module.exports = { analysisProgress };
