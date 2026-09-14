const crypto = require('node:crypto');
const net = require('node:net');

function constantTimeEqual(leftValue, rightValue) {
  const left = Buffer.from(String(leftValue || ''), 'utf8');
  const right = Buffer.from(String(rightValue || ''), 'utf8');
  return left.length > 0 && left.length === right.length && crypto.timingSafeEqual(left, right);
}

function extractPath(command, keyword) {
  const expression = new RegExp(`^${keyword}\\s*:\\s*<([^>]*)>(?:\\s+.*)?$`, 'iu');
  const match = String(command || '').match(expression);
  return match ? match[1].trim() : null;
}

function decodeBase64(value) {
  try { return Buffer.from(String(value || ''), 'base64').toString('utf8'); } catch { return ''; }
}

class SmtpSession {
  constructor(socket, options) {
    this.socket = socket;
    this.options = options;
    this.buffer = Buffer.alloc(0);
    this.dataLines = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
    this.inData = false;
    this.processing = false;
    this.helo = '';
    this.authenticated = !options.requireAuth;
    this.authenticatedUser = null;
    this.authState = null;
    this.mailFrom = null;
    this.recipients = [];
    this.sessionId = crypto.randomUUID();
  }

  start() {
    if (this.options.isClientAllowed && !this.options.isClientAllowed(this.socket.remoteAddress || '')) {
      this.reply(554, '5.7.1 SMTP client address is not allowed');
      this.socket.end();
      return;
    }
    this.socket.setTimeout(this.options.connectionTimeoutMs || 5 * 60 * 1000);
    this.socket.on('timeout', () => this.close(421, '4.4.2 Connection timed out'));
    this.socket.on('error', (error) => this.options.onSessionError?.(error, this));
    this.socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.processBuffer().catch((error) => {
        this.options.onSessionError?.(error, this);
        this.close(451, '4.3.0 Gateway processing failure');
      });
    });
    this.reply(220, `${this.options.hostname} VeriTrust SMTP Gateway ready`);
  }

  reply(code, text) {
    if (!this.socket.destroyed) this.socket.write(`${code} ${text}\r\n`);
  }

  multiline(code, lines) {
    lines.forEach((line, index) => {
      const separator = index === lines.length - 1 ? ' ' : '-';
      this.socket.write(`${code}${separator}${line}\r\n`);
    });
  }

  close(code, text) {
    if (code) this.reply(code, text || 'Closing connection');
    this.socket.end();
  }

  resetTransaction() {
    this.mailFrom = null;
    this.recipients = [];
    this.dataLines = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
    this.inData = false;
  }

  async processBuffer() {
    if (this.processing) return;
    while (!this.processing) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline === -1) {
        if (!this.inData && this.buffer.length > 8192) {
          this.reply(500, '5.5.2 Command line too long');
          this.buffer = Buffer.alloc(0);
        }
        return;
      }
      const lineBuffer = this.buffer.subarray(0, newline + 1);
      this.buffer = this.buffer.subarray(newline + 1);
      if (this.inData) {
        await this.handleDataLine(lineBuffer);
      } else {
        const line = lineBuffer.toString('utf8').replace(/\r?\n$/u, '');
        await this.handleCommand(line);
      }
    }
  }

  async handleDataLine(lineBuffer) {
    const lineWithoutEnd = lineBuffer.toString('latin1').replace(/\r?\n$/u, '');
    if (lineWithoutEnd === '.') {
      this.inData = false;
      if (this.dataTooLarge) {
        this.reply(552, '5.3.4 Message exceeds VeriTrust maximum size');
        this.resetTransaction();
        return;
      }
      const raw = Buffer.concat(this.dataLines);
      this.processing = true;
      try {
        const result = await this.options.onMessage({
          raw,
          mailFrom: this.mailFrom || '',
          recipients: [...this.recipients],
          helo: this.helo,
          clientIp: this.socket.remoteAddress || '',
          authenticatedUser: this.authenticatedUser,
          receivedAt: new Date().toISOString(),
          sessionId: this.sessionId,
        });
        this.reply(Number(result?.code || 451), `${result?.enhanced || '4.3.0'} ${result?.message || 'Gateway did not return a delivery result'}`);
      } catch (error) {
        this.options.onSessionError?.(error, this);
        this.reply(451, '4.3.0 VeriTrust gateway could not process the message');
      } finally {
        this.resetTransaction();
        this.processing = false;
        await this.processBuffer();
      }
      return;
    }

    let stored = lineBuffer;
    if (lineWithoutEnd.startsWith('..')) stored = lineBuffer.subarray(1);
    this.dataBytes += stored.length;
    if (this.dataBytes > this.options.maxMessageBytes) {
      this.dataTooLarge = true;
      this.dataLines = [];
      return;
    }
    if (!this.dataTooLarge) this.dataLines.push(Buffer.from(stored));
  }

  async handleCommand(rawLine) {
    const line = String(rawLine || '');
    if (this.authState) return this.handleAuthContinuation(line);
    if (!line.trim()) return this.reply(500, '5.5.2 Empty command');
    const [verbRaw, ...rest] = line.split(/\s+/u);
    const verb = verbRaw.toUpperCase();
    const argument = rest.join(' ');

    if (verb === 'EHLO' || verb === 'HELO') {
      if (!argument || /[\r\n\u0000-\u001f\u007f]/u.test(argument) || argument.length > 255) return this.reply(501, '5.5.2 Invalid HELO name');
      this.helo = argument;
      this.resetTransaction();
      if (verb === 'HELO') return this.reply(250, this.options.hostname);
      const capabilities = [
        this.options.hostname,
        `SIZE ${this.options.maxMessageBytes}`,
        '8BITMIME',
      ];
      if (this.options.authUsername) capabilities.push('AUTH PLAIN LOGIN');
      return this.multiline(250, capabilities);
    }

    if (verb === 'NOOP') return this.reply(250, '2.0.0 OK');
    if (verb === 'RSET') { this.resetTransaction(); return this.reply(250, '2.0.0 Reset'); }
    if (verb === 'QUIT') return this.close(221, '2.0.0 Bye');
    if (verb === 'VRFY' || verb === 'EXPN') return this.reply(252, '2.5.2 Cannot verify user');
    if (verb === 'STARTTLS') return this.reply(454, '4.7.0 STARTTLS is not available on this listener');

    if (verb === 'AUTH') return this.handleAuth(argument);
    if (!this.helo) return this.reply(503, '5.5.1 Send HELO/EHLO first');
    if (this.options.requireAuth && !this.authenticated) return this.reply(530, '5.7.0 Authentication required');

    if (verb === 'MAIL') {
      const address = extractPath(line, 'MAIL FROM');
      if (address === null) return this.reply(501, '5.5.4 Use MAIL FROM:<address>');
      if (address.length > 320 || /[\r\n\u0000-\u001f\u007f]/u.test(address)) return this.reply(501, '5.1.7 Invalid reverse-path');
      this.mailFrom = address;
      this.recipients = [];
      return this.reply(250, '2.1.0 Sender OK');
    }

    if (verb === 'RCPT') {
      if (this.mailFrom === null) return this.reply(503, '5.5.1 MAIL FROM required first');
      const address = extractPath(line, 'RCPT TO');
      if (!address || address.length > 320 || /[\r\n\u0000-\u001f\u007f]/u.test(address)) return this.reply(501, '5.1.3 Invalid recipient');
      if (!this.options.isRecipientAllowed(address)) return this.reply(550, '5.7.1 Relay denied for this recipient');
      if (!this.recipients.includes(address)) this.recipients.push(address);
      return this.reply(250, '2.1.5 Recipient OK');
    }

    if (verb === 'DATA') {
      if (this.mailFrom === null || !this.recipients.length) return this.reply(503, '5.5.1 MAIL FROM and RCPT TO required first');
      this.inData = true;
      this.dataLines = [];
      this.dataBytes = 0;
      this.dataTooLarge = false;
      return this.reply(354, 'End data with <CR><LF>.<CR><LF>');
    }

    return this.reply(502, '5.5.1 Command not implemented');
  }

  handleAuth(argument) {
    if (!this.options.authUsername) return this.reply(502, '5.5.1 AUTH is not configured');
    const [mechanismRaw, initial = ''] = String(argument || '').split(/\s+/u);
    const mechanism = String(mechanismRaw || '').toUpperCase();
    if (mechanism === 'PLAIN') {
      if (!initial) {
        this.authState = { mechanism: 'PLAIN' };
        return this.reply(334, '');
      }
      return this.finishPlainAuth(initial);
    }
    if (mechanism === 'LOGIN') {
      this.authState = { mechanism: 'LOGIN_USER' };
      return this.reply(334, 'VXNlcm5hbWU6');
    }
    return this.reply(504, '5.5.4 Unsupported authentication mechanism');
  }

  handleAuthContinuation(line) {
    const state = this.authState;
    if (line === '*') {
      this.authState = null;
      return this.reply(501, '5.7.0 Authentication cancelled');
    }
    if (state.mechanism === 'PLAIN') return this.finishPlainAuth(line);
    if (state.mechanism === 'LOGIN_USER') {
      state.username = decodeBase64(line);
      state.mechanism = 'LOGIN_PASS';
      return this.reply(334, 'UGFzc3dvcmQ6');
    }
    if (state.mechanism === 'LOGIN_PASS') {
      const password = decodeBase64(line);
      this.authState = null;
      return this.finishCredentials(state.username, password);
    }
    this.authState = null;
    return this.reply(535, '5.7.8 Authentication failed');
  }

  finishPlainAuth(encoded) {
    this.authState = null;
    const decoded = decodeBase64(encoded);
    const parts = decoded.split('\u0000');
    const username = parts.length >= 3 ? parts[parts.length - 2] : '';
    const password = parts.length >= 2 ? parts[parts.length - 1] : '';
    return this.finishCredentials(username, password);
  }

  finishCredentials(username, password) {
    const valid = constantTimeEqual(username, this.options.authUsername) && constantTimeEqual(password, this.options.authPassword);
    if (!valid) {
      this.authenticated = false;
      this.authenticatedUser = null;
      return this.reply(535, '5.7.8 Authentication credentials invalid');
    }
    this.authenticated = true;
    this.authenticatedUser = username;
    return this.reply(235, '2.7.0 Authentication successful');
  }
}

function createSmtpServer(options) {
  const server = net.createServer((socket) => new SmtpSession(socket, options).start());
  server.maxConnections = options.maxConnections || 100;
  return server;
}

module.exports = { constantTimeEqual, createSmtpServer, extractPath };
