(function exposeAnalysisResult(root) {
  'use strict';

  function score(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) return null;
    return value;
  }

  function percent(value) {
    const normalized = score(value);
    return normalized === null ? 'Not available' : `${Math.round(normalized * 100)}%`;
  }

  const terminal = (status) => ['completed', 'failed', 'cancelled'].includes(status);
  const statusCopy = (status) => ({
    accepted: 'Submission accepted. Waiting for analysis.',
    queued: 'Waiting for an available analysis worker.',
    processing: 'Analysis is in progress.',
    partially_completed: 'Some checks finished. Remaining checks are still pending.',
    cancel_requested: 'Cancellation requested. Waiting for the worker to stop.',
    completed: 'Analysis finished. Review the decision and evidence coverage.',
    failed: 'Analysis failed. No safe conclusion can be drawn from missing checks.',
    cancelled: 'Analysis cancelled. Any available evidence may be incomplete.',
  }[status] || 'The scan status is unavailable. Refresh to check again.');

  async function withDeadline(operation, timeoutMs = 90000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try { return await operation(controller.signal); }
    catch (error) {
      if (controller.signal.aborted) throw new Error('The request timed out. The server may still be processing it; check scan history before submitting again.');
      throw error;
    } finally { clearTimeout(timer); }
  }

  function validateGatewayInput({ text = '', urls = [], files = [] }) {
    if (!text.trim() && !urls.length && !files.length) throw new Error('Add text, a URL, or a media file before analyzing.');
    if (text.trim().length > 12000) throw new Error('Keep gateway text at or below 12,000 characters.');
    if (urls.length > 20) throw new Error('Submit no more than 20 URLs per scan.');
    for (const value of urls) {
      let url;
      try { url = new URL(value); } catch { throw new Error('Each URL must be a complete HTTP or HTTPS address.'); }
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Use HTTP or HTTPS URLs without embedded credentials.');
    }
    if (files.length > 10) throw new Error('Choose no more than 10 media files.');
    const limits = { image: 10, audio: 25, video: 100 };
    const types = {
      image: ['image/jpeg', 'image/png', 'image/webp', 'image/bmp'],
      audio: ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4'],
      video: ['video/mp4', 'video/webm', 'video/quicktime'],
    };
    for (const file of files) {
      const kind = file.type.split('/')[0];
      if (!types[kind]?.includes(file.type)) throw new Error(`Unsupported media type for ${file.name}. Choose a supported image, audio, or video file.`);
      if (!file.size || file.size > limits[kind] * 1024 * 1024) throw new Error(`${file.name} must contain data and be no larger than ${limits[kind]} MiB.`);
    }
  }

  const api = Object.freeze({ score, percent, terminal, statusCopy, validateGatewayInput, withDeadline });
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.VeriTrustAnalysisResult = api;
}(typeof window === 'object' ? window : globalThis));
