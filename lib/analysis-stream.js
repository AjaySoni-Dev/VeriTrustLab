// Opt-in progress on the same authenticated request; no process-local job store.
function analysisProgress(req, res) {
  if (!String(req.headers?.accept || '').split(',').some((type) => type.trim().split(';')[0] === 'application/x-ndjson')) return () => {};
  let started = false;
  let closed = false;
  let sequence = 0;
  let heartbeat = null;

  function stopHeartbeat() {
    if (heartbeat) {
      clearInterval(heartbeat);
      heartbeat = null;
    }
  }

  res.on?.('close', () => {
    closed = true;
    stopHeartbeat();
  });

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
      heartbeat = setInterval(() => {
        if (closed || res.writableEnded || res.destroyed) {
          stopHeartbeat();
          return;
        }
        try { res.write('\n'); } catch { stopHeartbeat(); }
      }, 2000);
      if (typeof heartbeat?.unref === 'function') heartbeat.unref();
    }
    res.write(`${JSON.stringify({ ...event, sequence: ++sequence, timestamp: new Date().toISOString() })}\n`);
  }
  res.analysisStream = {
    get started() { return started; },
    finish(status, payload) {
      stopHeartbeat();
      write({ type: 'result', status, payload });
      if (!closed && !res.writableEnded) res.end();
      closed = true;
    },
  };
  return (stage, state, message, extra = null) => {
    if (sequence < 150) {
      const event = { type: 'progress', stage, state, message };
      if (extra && typeof extra === 'object' && extra.scan_id) event.scan_id = extra.scan_id;
      write(event);
    }
  };
}

module.exports = { analysisProgress };
