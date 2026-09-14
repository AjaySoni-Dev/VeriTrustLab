(function initVeriTrustCli(global) {
  const mobileDevice = global.navigator.userAgentData?.mobile === true
    || /Android|iPhone|iPad|iPod|Mobile|IEMobile|Opera Mini/i.test(global.navigator.userAgent || '');
  if (mobileDevice || global.matchMedia('(max-width: 767px)').matches) {
    global.location.replace('detection.html?source=cli-mobile');
    return;
  }

  const core = global.VeriTrustCliCore;
  const client = global.VeriTrustSupabase;
  if (!core || !client) return;

  const apiConfig = global.VeriTrust_CONFIG?.api || {};
  const moduleEnabled = (name) => global.VeriTrustModules?.isEnabled(name) !== false;
  const scanChoices = () => [
    ...(moduleEnabled('link') ? ['link'] : []),
    ...(moduleEnabled('phishing') ? ['phishing'] : []),
    ...(moduleEnabled('gateway') ? ['gateway'] : []),
  ];
  const terminal = document.getElementById('cli-output');
  const form = document.getElementById('cli-form');
  const input = document.getElementById('cli-input');
  const submit = document.getElementById('cli-submit');
  const attachmentInput = document.getElementById('cli-file');
  const attachmentLabel = document.getElementById('cli-attachment-label');
  const busyLabel = document.getElementById('cli-busy');
  if (!terminal || !form || !input || !submit || !attachmentInput) return;

  const state = {
    attachment: null,
    commandHistory: [],
    historyIndex: 0,
    busy: false,
    abortController: null,
    sessionContext: null,
  };

  const helpOverview = [
    'VeriTrust CLI - allowlisted security commands in one authenticated shell.',
    '',
    'Core commands',
    ...(moduleEnabled('link') ? ['  scan link <url> [--context "text"] [--json]'] : []),
    ...(moduleEnabled('phishing') ? ['  scan phishing "message" [--model mailguard|cortex] [--json]'] : []),
    ...(moduleEnabled('gateway') ? ['  attach'] : []),
    ...(moduleEnabled('gateway') ? ['  scan gateway [--text "message"] [--url <url>]... [--no-wait] [--json]'] : []),
    '',
    'Workspace commands',
    '  status                    Show the signed-in workspace',
    '  models                    List available models',
    '  history [--limit 10]      Show recent saved scans',
    ...(moduleEnabled('gateway') ? ['  gateway get <scan-id>     Read a scan', '  gateway cancel <scan-id>  Request scan cancellation'] : []),
    ...(moduleEnabled('gateway') ? ['  detach                    Remove the current attachment'] : []),
    '  open gui [module]         Open an available graphical workflow',
    '  clear | version | exit',
    '',
    'Use quotes around text. Press Shift+Enter inside quotes for multiline content.',
    'Press Up/Down for command history, Tab for completion, Ctrl+L to clear, and Ctrl+C to cancel.',
  ].join('\n');
  const HELP = Object.freeze({
    overview: helpOverview,
    ...(moduleEnabled('link') ? { link: 'scan link <http-or-https-url> [--context "why this link was received"] [--model swift] [--json]' } : {}),
    ...(moduleEnabled('phishing') ? { phishing: 'scan phishing "message text" [--model mailguard|cortex] [--json]\nAlias: phish "message text"' } : {}),
    ...(moduleEnabled('gateway') ? { gateway: 'scan gateway [--text "message"] [--url <url>]... [--context general|credential|financial|identity] [--no-wait] [--json]' } : {}),
    history: 'history [--limit 10]\nLimit must be an integer from 1 to 50.',
    open: 'open gui [module]\nOpens an available graphical workflow.',
  });

  function write(message, tone = 'info', marker = '') {
    const line = document.createElement('div');
    line.className = `cli-line cli-line-${tone}`;
    const prefix = document.createElement('span');
    prefix.className = 'cli-line-marker';
    prefix.textContent = marker || ({ command: '$', success: '✓', error: '×', warning: '!', json: '{}', info: '›' }[tone] || '›');
    const content = document.createElement('pre');
    content.textContent = String(message ?? '');
    line.append(prefix, content);
    terminal.append(line);
    terminal.scrollTop = terminal.scrollHeight;
    return line;
  }

  function writeJson(value) {
    write(JSON.stringify(value, null, 2), 'json');
  }

  function clearTerminal() {
    terminal.replaceChildren();
  }

  function setBusy(busy, label = '') {
    state.busy = busy;
    submit.disabled = busy;
    form.setAttribute('aria-busy', String(busy));
    if (busyLabel) busyLabel.textContent = busy ? (label || 'Running command…') : 'Ready';
  }

  function updateAttachment(file) {
    state.attachment = file || null;
    if (!attachmentLabel) return;
    if (!file) {
      attachmentLabel.textContent = 'No attachment';
      attachmentLabel.classList.remove('has-file');
      return;
    }
    const size = file.size < 1024 * 1024
      ? `${Math.max(1, Math.round(file.size / 1024))} KB`
      : `${(file.size / (1024 * 1024)).toFixed(1)} MB`;
    attachmentLabel.textContent = `${file.name} · ${size}`;
    attachmentLabel.classList.add('has-file');
  }

  function openFilePicker() {
    attachmentInput.click();
    write('Choose an image, audio, or video file. After selection, run the scan command.', 'info');
  }

  async function sessionContext() {
    if (state.sessionContext) return state.sessionContext;
    state.sessionContext = await client.getSessionContext();
    return state.sessionContext;
  }

  function request(url, options = {}) {
    return client.callAppApi(url, {
      ...options,
      signal: state.abortController?.signal,
    });
  }

  function validateUrl(value) {
    let parsed;
    try {
      parsed = new URL(String(value || ''));
    } catch {
      throw new Error('Use a complete URL beginning with http:// or https://.');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only http:// and https:// URLs are supported.');
    }
    return parsed.href;
  }

  function percentage(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return `${Math.round(Math.max(0, Math.min(1, number)) * 100)}%`;
  }

  function printScanResult(data, label, raw = false) {
    const result = data?.result || {};
    const model = data?.model || {};
    const lines = [
      `${label} complete`,
      `Verdict    ${result.label || result.verdict || 'Unknown'}`,
      `Risk       ${result.risk_level || 'Unknown'}`,
      `Confidence ${percentage(result.confidence)}`,
      `Model      ${model.name || model.display_name || model.key || 'VeriTrust'}`,
      data?.scan_id ? `Scan ID    ${data.scan_id}` : '',
      result.summary || result.explanation ? `Summary    ${result.summary || result.explanation}` : '',
      result.disclaimer ? `Notice     ${result.disclaimer}` : '',
    ].filter(Boolean);
    write(lines.join('\n'), 'success');
    if (raw) writeJson(data);
  }

  function printGatewayResult(data, raw = false) {
    const decision = data?.decision || {};
    const lines = [
      `Evidence correlation ${data?.status || 'unknown'}`,
      `Scan ID        ${data?.scan_id || '—'}`,
      `Display ID     ${data?.display_id || '—'}`,
      `Verdict        ${decision.verdict || 'Pending'}`,
      `Risk           ${percentage(decision.risk)}`,
      `Recommendation ${decision.recommendation || 'Pending'}`,
      `Degraded       ${data?.degraded ? 'yes' : 'no'}`,
      Array.isArray(decision.reason_codes) && decision.reason_codes.length
        ? `Reasons        ${decision.reason_codes.join(', ')}`
        : '',
    ].filter(Boolean);
    write(lines.join('\n'), ['failed', 'cancelled'].includes(data?.status) ? 'warning' : 'success');
    if (raw) writeJson(data);
  }

  function wait(milliseconds) {
    return new Promise((resolve, reject) => {
      const signal = state.abortController?.signal;
      if (signal?.aborted) {
        reject(new DOMException('Command cancelled.', 'AbortError'));
        return;
      }
      const onAbort = () => {
        global.clearTimeout(timer);
        reject(new DOMException('Command cancelled.', 'AbortError'));
      };
      const timer = global.setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      }, milliseconds);
      signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  async function scanLink(parsed) {
    core.assertAllowedFlags(parsed, ['url', 'context', 'model', 'json']);
    const url = validateUrl(core.flagValue(parsed, 'url') || parsed.args[1]);
    const model = core.requireChoice(core.flagValue(parsed, 'model', 'swift'), ['swift'], 'Link model');
    const context = await sessionContext();
    const data = await request(apiConfig.linkCheck || '/api/link-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        context: core.flagValue(parsed, 'context'),
        text: url,
        model,
        org_id: context.organization.id,
      }),
    });
    printScanResult(data, 'Link scan', core.hasFlag(parsed, 'json'));
  }

  async function scanPhishing(parsed) {
    core.assertAllowedFlags(parsed, ['text', 'model', 'json']);
    const text = core.flagValue(parsed, 'text') || parsed.args.slice(1).join(' ');
    if (text.trim().length < 8) throw new Error('Phishing text must contain at least 8 characters.');
    if (text.length > 12000) throw new Error('Phishing text must not exceed 12,000 characters.');
    const model = core.requireChoice(core.flagValue(parsed, 'model', 'mailguard'), ['mailguard', 'cortex'], 'Phishing model');
    const context = await sessionContext();
    const data = await request(apiConfig.phishing || '/api/phishing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, model, org_id: context.organization.id }),
    });
    printScanResult(data, 'Phishing scan', core.hasFlag(parsed, 'json'));
  }


  function mediaKind(file) {
    if (file.type.startsWith('image/')) return 'image';
    if (file.type.startsWith('audio/')) return 'audio';
    if (file.type.startsWith('video/')) return 'video';
    throw new Error('Gateway attachments must be an image, audio, or video file.');
  }

  async function uploadGatewayAttachment(file) {
    if (file.size > 100 * 1024 * 1024) throw new Error('Gateway attachments must not exceed 100 MB.');
    const kind = mediaKind(file);
    write(`Registering private ${kind} upload…`, 'info');
    const registered = await request('/api/v1/gateway/uploads', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, mime_type: file.type, size_bytes: file.size }),
    });
    if (!registered?.signed_upload?.url) throw new Error('The gateway did not return a signed private upload URL.');
    const supabaseUrl = String(global.VeriTrust_CONFIG?.supabase?.url || '').replace(/\/$/, '');
    const signedUrl = /^https?:/i.test(registered.signed_upload.url)
      ? registered.signed_upload.url
      : `${supabaseUrl}/storage/v1${registered.signed_upload.url}`;
    const uploadResponse = await fetch(signedUrl, {
      method: 'PUT',
      headers: { 'Content-Type': file.type, 'x-upsert': 'false' },
      body: file,
      signal: state.abortController?.signal,
    });
    if (!uploadResponse.ok) throw new Error(`Private upload failed with status ${uploadResponse.status}.`);
    await request(`/api/v1/gateway/uploads/${registered.upload_id}/complete`, { method: 'POST' });
    write('Private attachment upload complete.', 'success');
    return { upload_id: registered.upload_id, kind };
  }

  async function pollGateway(scanId, raw) {
    let lastStatus = '';
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const data = await request(`/api/v1/gateway/scans/${encodeURIComponent(scanId)}`, { cache: 'no-store' });
      if (data.status !== lastStatus) {
        write(`Gateway status: ${data.status}`, 'info');
        lastStatus = data.status;
      }
      if (['completed', 'failed', 'cancelled'].includes(data.status)) {
        printGatewayResult(data, raw);
        return;
      }
      await wait(2000);
    }
    write(`Gateway scan ${scanId} is still running. Use "gateway get ${scanId}" to check it later.`, 'warning');
  }

  async function scanGateway(parsed) {
    core.assertAllowedFlags(parsed, ['text', 'url', 'context', 'no-wait', 'json']);
    const text = core.flagValue(parsed, 'text') || parsed.args.slice(1).join(' ');
    const urls = core.flagValues(parsed, 'url').map(validateUrl);
    const contextCategory = core.flagValue(parsed, 'context');
    if (contextCategory) core.requireChoice(contextCategory, ['general', 'credential', 'financial', 'identity'], 'Gateway context');
    if (!text && !urls.length && !state.attachment) {
      throw new Error('Provide --text, at least one --url, or attach a supported media file.');
    }

    const media = state.attachment ? [await uploadGatewayAttachment(state.attachment)] : [];
    const idempotencyKey = global.crypto?.randomUUID?.() || `web-cli-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const data = await request('/api/v1/gateway/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({
        source: { kind: 'web_cli' },
        content: { text: text || null, urls, media },
        processing_mode: media.length ? 'hybrid' : 'synchronous',
        metadata: { context_categories: contextCategory ? [contextCategory] : [] },
      }),
    });
    printGatewayResult(data, core.hasFlag(parsed, 'json'));
    if (!core.hasFlag(parsed, 'no-wait') && !['completed', 'failed', 'cancelled'].includes(data.status)) {
      await pollGateway(data.scan_id, core.hasFlag(parsed, 'json'));
    }
  }

  async function showStatus() {
    state.sessionContext = null;
    const context = await sessionContext();
    const lines = [
      'Authenticated workspace',
      `User   ${context.user?.email || context.profile?.email || context.user?.id || 'Signed in'}`,
      `Org    ${context.organization?.name || context.organization?.id || '—'}`,
      `Role   ${context.membership?.role || context.role || 'member'}`,
      `Plan   ${context.organization?.plan?.name || context.organization?.plans?.name || context.plan?.name || 'Current plan'}`,
    ];
    write(lines.join('\n'), 'success');
  }

  function showModels() {
    write([
      'Available models',
      ...(moduleEnabled('link') ? ['Link      swift       VeriTrust Swift'] : []),
      ...(moduleEnabled('phishing') ? ['Phishing  mailguard   VeriTrust MailGuard (fast classifier)', 'Phishing  cortex      VeriTrust Cortex (robust instruction model)'] : []),
      ...(moduleEnabled('gateway') ? ['Gateway   automatic   Routes applicable models and policy correlation'] : []),
    ].join('\n'), 'info');
  }

  async function showHistory(parsed) {
    core.assertAllowedFlags(parsed, ['limit', 'json']);
    const limit = core.integerFlag(parsed, 'limit', 10, { min: 1, max: 50 });
    const context = await sessionContext();
    const data = await client.getRecentScans(context.organization.id, limit);
    const scans = data?.scans || data?.items || [];
    if (!scans.length) {
      write('No saved scans were found in this workspace.', 'info');
      return;
    }
    const lines = scans.map((scan) => [
      String(scan.id || scan.scan_id || '—').slice(0, 12).padEnd(12),
      String(scan.scan_type || scan.type || 'scan').padEnd(10),
      String(scan.status || 'unknown').padEnd(12),
      String(scan.risk_level || scan.scan_results?.[0]?.risk_level || '—').padEnd(9),
      new Date(scan.created_at).toLocaleString(),
    ].join(' '));
    write(['Recent scans', 'ID           TYPE       STATUS       RISK      CREATED', ...lines].join('\n'), 'info');
    if (core.hasFlag(parsed, 'json')) writeJson(data);
  }

  async function gatewayCommand(parsed) {
    const action = String(parsed.args[0] || '').toLowerCase();
    if (!['get', 'cancel'].includes(action)) {
      await scanGateway({ ...parsed, name: 'scan', args: ['gateway', ...parsed.args] });
      return;
    }
    const scanId = parsed.args[1];
    if (!scanId) throw new Error(`gateway ${action} requires a scan ID.`);
    core.assertAllowedFlags(parsed, ['json']);
    if (action === 'get') {
      const data = await request(`/api/v1/gateway/scans/${encodeURIComponent(scanId)}`, { cache: 'no-store' });
      printGatewayResult(data, core.hasFlag(parsed, 'json'));
      return;
    }
    const data = await request(`/api/v1/gateway/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' });
    write(`Cancellation requested for gateway scan ${scanId}.`, 'success');
    if (core.hasFlag(parsed, 'json')) writeJson(data);
  }

  function openGui(parsed) {
    const rawTarget = String(parsed.args[0] || '').toLowerCase() === 'gui' ? parsed.args[1] : parsed.args[0];
    const target = String(rawTarget || 'detection').toLowerCase();
    const destinations = {
      detection: 'detection.html',
      gui: 'detection.html',
      ...(moduleEnabled('link') ? { link: 'link-check.html' } : {}),
      ...(moduleEnabled('phishing') ? { phishing: 'phishing.html' } : {}),
      ...(moduleEnabled('gateway') ? { gateway: 'gateway.html' } : {}),
    };
    if (!destinations[target]) throw new Error(`Unknown GUI module: ${target}.`);
    global.location.assign(destinations[target]);
  }

  async function execute(parsed) {
    const normalized = core.normalizeCommand(parsed);
    const { name, args } = normalized;
    if (!name) return;

    if (name === 'help') {
      const topic = String(args[0] || 'overview').toLowerCase();
      write(HELP[topic] || `No help topic named "${topic}". Run "help" for all commands.`, HELP[topic] ? 'info' : 'warning');
      return;
    }
    if (name === 'clear') {
      clearTerminal();
      return;
    }
    if (name === 'status') return showStatus();
    if (name === 'models') return showModels();
    if (name === 'attach') return openFilePicker();
    if (name === 'detach') {
      attachmentInput.value = '';
      updateAttachment(null);
      write('Attachment removed.', 'success');
      return;
    }
    if (name === 'history') return showHistory(normalized);
    if (name === 'open') return openGui(normalized);
    if (name === 'gateway' && moduleEnabled('gateway')) return gatewayCommand(normalized);
    if (name === 'version') {
      write('VeriTrust Web CLI 1.0.0\nCommand schema 1.0 · Gateway schema 1.0', 'info');
      return;
    }
    if (name === 'exit') {
      global.location.assign('dashboard.html');
      return;
    }
    if (name === 'scan') {
      const type = core.requireChoice(args[0], scanChoices(), 'Scan type');
      if (type === 'link') return scanLink(normalized);
      if (type === 'phishing') return scanPhishing(normalized);
      return scanGateway(normalized);
    }

    throw new Error(`Unknown command: ${name}. Run "help" to list supported commands.`);
  }

  function resizeInput() {
    input.style.height = 'auto';
    input.style.height = `${Math.min(132, Math.max(42, input.scrollHeight))}px`;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const raw = input.value.trim();
    if (!raw) return;
    if (state.busy) {
      write('A command is already running. Press Ctrl+C to cancel it.', 'warning');
      return;
    }

    state.commandHistory.push(raw);
    if (state.commandHistory.length > 100) state.commandHistory.shift();
    state.historyIndex = state.commandHistory.length;
    write(raw, 'command');
    input.value = '';
    resizeInput();
    state.abortController = new AbortController();
    setBusy(true, 'Running command…');

    try {
      await execute(core.parse(raw));
    } catch (error) {
      if (state.abortController?.signal.aborted || error?.name === 'AbortError') write('Command cancelled.', 'warning');
      else write(error?.message || 'The command could not be completed.', 'error');
    } finally {
      state.abortController = null;
      setBusy(false);
      input.focus();
    }
  });

  input.addEventListener('input', resizeInput);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      form.requestSubmit();
      return;
    }
    if (event.key === 'ArrowUp' && !input.value.includes('\n')) {
      event.preventDefault();
      state.historyIndex = Math.max(0, state.historyIndex - 1);
      input.value = state.commandHistory[state.historyIndex] || '';
      resizeInput();
      return;
    }
    if (event.key === 'ArrowDown' && !input.value.includes('\n')) {
      event.preventDefault();
      state.historyIndex = Math.min(state.commandHistory.length, state.historyIndex + 1);
      input.value = state.commandHistory[state.historyIndex] || '';
      resizeInput();
      return;
    }
    if (event.key === 'Tab' && !input.value.trim().includes(' ')) {
      const disabledCommands = new Set([
        ...(!moduleEnabled('link') ? ['link'] : []),
        ...(!moduleEnabled('phishing') ? ['phish'] : []),
        ...(!moduleEnabled('gateway') ? ['gateway', 'unified'] : []),
      ]);
      const candidates = core.completionCandidates(input.value).filter((candidate) => !disabledCommands.has(candidate));
      if (candidates.length === 1) {
        event.preventDefault();
        input.value = `${candidates[0]} `;
        resizeInput();
      }
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'l') {
      event.preventDefault();
      clearTerminal();
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'c') {
      event.preventDefault();
      if (state.abortController) state.abortController.abort();
      else {
        input.value = '';
        resizeInput();
      }
    }
  });

  attachmentInput.addEventListener('change', () => {
    const file = attachmentInput.files?.[0] || null;
    updateAttachment(file);
    if (file) write(`Attached ${file.name}. Run an available media scan.`, 'success');
    input.focus();
  });

  document.querySelectorAll('[data-cli-command]').forEach((button) => {
    const command = String(button.dataset.cliCommand || '').toLowerCase();
    if (command.includes('phishing')) button.dataset.module = 'phishing';
    else if (command.includes('gateway')) button.dataset.module = 'gateway';
    else if (command === 'attach') button.dataset.module = 'gateway';
    else if (command.includes('link')) button.dataset.module = 'link';
    button.addEventListener('click', () => {
      if (button.classList.contains('cli-attachment-action')) {
        openFilePicker();
        input.focus();
        return;
      }
      input.value = button.dataset.cliCommand || '';
      resizeInput();
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    });
  });

  async function boot() {
    const access = await global.VeriTrustPageAccess;
    if (!access?.allowed) return;
    write('VeriTrust Web CLI 1.0.0', 'success');
    write('One authenticated shell for the available security workflows. Run "help" to begin.', 'info');
    updateAttachment(null);
    resizeInput();
    input.focus();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once: true });
  else boot();
})(window);
