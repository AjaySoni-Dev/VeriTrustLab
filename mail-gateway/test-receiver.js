#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createSmtpServer } = require('./lib/smtp-server');

const host = process.env.VERITRUST_TEST_RECEIVER_HOST || '127.0.0.1';
const port = Number(process.env.VERITRUST_TEST_RECEIVER_PORT || 2526);
const output = path.resolve(process.env.VERITRUST_TEST_RECEIVER_OUTPUT || path.join(process.cwd(), 'veritrust-test-inbox'));
fs.mkdirSync(output, { recursive: true });

const server = createSmtpServer({
  hostname: process.env.VERITRUST_TEST_RECEIVER_ID || 'veritrust-test-receiver',
  maxMessageBytes: 10 * 1024 * 1024,
  connectionTimeoutMs: 300000,
  maxConnections: 20,
  requireAuth: false,
  authUsername: '',
  authPassword: '',
  isRecipientAllowed: () => true,
  onMessage: async (envelope) => {
    const id = `${Date.now()}-${crypto.randomUUID()}`;
    const file = path.join(output, `${id}.eml`);
    fs.writeFileSync(file, envelope.raw);
    process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), event: 'test_receiver.saved', file, mail_from: envelope.mailFrom, recipients: envelope.recipients })}\n`);
    return { code: 250, enhanced: '2.0.0', message: `Saved as ${path.basename(file)}` };
  },
  onSessionError: (error) => process.stderr.write(`${error.stack || error.message}\n`),
});

server.listen(port, host, () => process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), event: 'test_receiver.started', host, port, output })}\n`));
