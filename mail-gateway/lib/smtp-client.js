const net = require('node:net');
const tls = require('node:tls');
const { normalizeForSmtpData } = require('./message');

class SmtpResponseError extends Error {
  constructor(message, code, lines = []) {
    super(message);
    this.name = 'SmtpResponseError';
    this.smtpCode = Number(code || 0);
    this.lines = lines;
  }
}

class LineReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.lines = [];
    this.waiters = [];
    this.error = null;
    this.onData = (chunk) => this.push(chunk);
    this.onError = (error) => this.fail(error);
    this.onClose = () => this.fail(new Error('SMTP connection closed unexpectedly.'));
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('close', this.onClose);
  }

  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onError);
    this.socket.off('close', this.onClose);
  }

  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline === -1) break;
      const line = this.buffer.subarray(0, newline + 1).toString('utf8').replace(/\r?\n$/u, '');
      this.buffer = this.buffer.subarray(newline + 1);
      const waiter = this.waiters.shift();
      if (waiter) waiter.resolve(line); else this.lines.push(line);
    }
  }

  fail(error) {
    if (this.error) return;
    this.error = error;
    while (this.waiters.length) this.waiters.shift().reject(error);
  }

  readLine(timeoutMs) {
    if (this.lines.length) return Promise.resolve(this.lines.shift());
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject };
      this.waiters.push(entry);
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(entry);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(new Error('SMTP response timed out.'));
      }, timeoutMs);
      timer.unref?.();
      entry.resolve = (value) => { clearTimeout(timer); resolve(value); };
      entry.reject = (error) => { clearTimeout(timer); reject(error); };
    });
  }
}

async function readResponse(reader, timeoutMs) {
  const lines = [];
  let code = 0;
  while (true) {
    const line = await reader.readLine(timeoutMs);
    lines.push(line);
    const match = line.match(/^(\d{3})([ -])(.*)$/u);
    if (!match) throw new Error(`Malformed SMTP response: ${line}`);
    code = Number(match[1]);
    if (match[2] === ' ') return { code, lines, text: lines.map((item) => item.slice(4)).join(' | ') };
  }
}

function writeCommand(socket, command) {
  socket.write(`${command}\r\n`, 'utf8');
}

async function expect(reader, allowed, timeoutMs) {
  const response = await readResponse(reader, timeoutMs);
  if (!allowed.includes(response.code)) throw new SmtpResponseError(response.text, response.code, response.lines);
  return response;
}

function capabilities(response) {
  return new Set(response.lines.map((line) => line.slice(4).trim().split(/\s+/u)[0].toUpperCase()).filter(Boolean));
}

function connectSocket(config) {
  return new Promise((resolve, reject) => {
    const options = { host: config.host, port: config.port };
    let socket;
    const onError = (error) => reject(error);
    const ready = () => {
      socket.off('error', onError);
      socket.setTimeout(config.timeoutMs, () => socket.destroy(new Error('Upstream SMTP connection timed out.')));
      resolve(socket);
    };
    if (config.secure) {
      socket = tls.connect({ ...options, servername: config.tlsServername || config.host, rejectUnauthorized: config.rejectUnauthorized });
      socket.once('error', onError);
      socket.once('secureConnect', ready);
    } else {
      socket = net.connect(options);
      socket.once('error', onError);
      socket.once('connect', ready);
    }
  });
}

async function upgradeStartTls(socket, reader, config) {
  reader.detach();
  return new Promise((resolve, reject) => {
    const secure = tls.connect({
      socket,
      servername: config.tlsServername || config.host,
      rejectUnauthorized: config.rejectUnauthorized,
    }, () => resolve(secure));
    secure.once('error', reject);
  });
}

async function authenticate(socket, reader, ehlo, config) {
  if (!config.username) return;
  const authLine = ehlo.lines.map((line) => line.slice(4).trim()).find((line) => /^AUTH\s/iu.test(line));
  const mechanisms = new Set(String(authLine || '').split(/\s+/u).slice(1).map((value) => value.toUpperCase()));
  if (mechanisms.has('PLAIN')) {
    const token = Buffer.from(`\u0000${config.username}\u0000${config.password}`, 'utf8').toString('base64');
    writeCommand(socket, `AUTH PLAIN ${token}`);
    await expect(reader, [235], config.timeoutMs);
    return;
  }
  if (mechanisms.has('LOGIN')) {
    writeCommand(socket, 'AUTH LOGIN');
    await expect(reader, [334], config.timeoutMs);
    writeCommand(socket, Buffer.from(config.username, 'utf8').toString('base64'));
    await expect(reader, [334], config.timeoutMs);
    writeCommand(socket, Buffer.from(config.password, 'utf8').toString('base64'));
    await expect(reader, [235], config.timeoutMs);
    return;
  }
  throw new Error('Upstream SMTP server does not advertise AUTH PLAIN or LOGIN.');
}

async function relayMessage(config, envelope, raw) {
  let socket = await connectSocket(config);
  let reader = new LineReader(socket);
  try {
    await expect(reader, [220], config.timeoutMs);
    writeCommand(socket, `EHLO ${config.ehloName}`);
    let ehlo = await expect(reader, [250], config.timeoutMs);
    let caps = capabilities(ehlo);

    if (!config.secure && config.startTls !== 'off') {
      if (caps.has('STARTTLS')) {
        writeCommand(socket, 'STARTTLS');
        await expect(reader, [220], config.timeoutMs);
        socket = await upgradeStartTls(socket, reader, config);
        reader = new LineReader(socket);
        writeCommand(socket, `EHLO ${config.ehloName}`);
        ehlo = await expect(reader, [250], config.timeoutMs);
        caps = capabilities(ehlo);
      } else if (config.startTls === 'required') {
        throw new Error('Upstream SMTP server does not offer STARTTLS.');
      }
    }

    await authenticate(socket, reader, ehlo, config);
    writeCommand(socket, `MAIL FROM:<${envelope.mailFrom || ''}>`);
    await expect(reader, [250], config.timeoutMs);
    for (const recipient of envelope.recipients) {
      writeCommand(socket, `RCPT TO:<${recipient}>`);
      await expect(reader, [250, 251], config.timeoutMs);
    }
    writeCommand(socket, 'DATA');
    await expect(reader, [354], config.timeoutMs);
    const data = normalizeForSmtpData(raw);
    socket.write(data);
    socket.write('.\r\n', 'ascii');
    const delivered = await expect(reader, [250], config.timeoutMs);
    writeCommand(socket, 'QUIT');
    await expect(reader, [221], Math.min(config.timeoutMs, 5000)).catch(() => null);
    return delivered;
  } finally {
    reader?.detach();
    if (!socket.destroyed) socket.end();
  }
}

module.exports = { LineReader, SmtpResponseError, relayMessage };
