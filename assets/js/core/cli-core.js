(function exposeCliCore(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.VeriTrustCliCore = api;
})(typeof window !== 'undefined' ? window : globalThis, () => {
  const COMMANDS = Object.freeze([
    'help',
    'clear',
    'status',
    'models',
    'attach',
    'detach',
    'scan',
    'link',
    'phish',
    'image',
    'gateway',
    'unified',
    'history',
    'open',
    'version',
    'exit',
  ]);
  const BOOLEAN_FLAGS = new Set(['json', 'no-wait']);

  function tokenize(input) {
    const source = String(input || '');
    const tokens = [];
    let current = '';
    let quote = null;
    let escaped = false;
    let tokenStarted = false;

    for (const character of source) {
      if (escaped) {
        const escapes = { n: '\n', r: '\r', t: '\t' };
        current += escapes[character] ?? character;
        escaped = false;
        tokenStarted = true;
        continue;
      }

      if (character === '\\') {
        escaped = true;
        tokenStarted = true;
        continue;
      }

      if (quote) {
        if (character === quote) quote = null;
        else current += character;
        tokenStarted = true;
        continue;
      }

      if (character === '"' || character === "'") {
        quote = character;
        tokenStarted = true;
        continue;
      }

      if (/\s/.test(character)) {
        if (tokenStarted) {
          tokens.push(current);
          current = '';
          tokenStarted = false;
        }
        continue;
      }

      current += character;
      tokenStarted = true;
    }

    if (escaped) current += '\\';
    if (quote) throw new Error(`Unterminated ${quote === '"' ? 'double' : 'single'} quote.`);
    if (tokenStarted) tokens.push(current);
    return tokens;
  }

  function addFlag(flags, key, value) {
    if (!Object.prototype.hasOwnProperty.call(flags, key)) {
      flags[key] = value;
      return;
    }
    flags[key] = Array.isArray(flags[key]) ? [...flags[key], value] : [flags[key], value];
  }

  function parse(input) {
    const tokens = tokenize(input);
    if (!tokens.length) return { name: '', args: [], flags: {}, raw: String(input || '') };

    const name = tokens.shift().toLowerCase();
    const args = [];
    const flags = {};

    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index];
      if (!token.startsWith('--') || token === '--') {
        args.push(token);
        continue;
      }

      const flagExpression = token.slice(2);
      if (!flagExpression) throw new Error('A flag name is required after --.');
      const equalsIndex = flagExpression.indexOf('=');
      if (equalsIndex >= 0) {
        const key = flagExpression.slice(0, equalsIndex).toLowerCase();
        if (!key) throw new Error('A flag name is required before =.');
        addFlag(flags, key, flagExpression.slice(equalsIndex + 1));
        continue;
      }

      const key = flagExpression.toLowerCase();
      const next = tokens[index + 1];
      if (!BOOLEAN_FLAGS.has(key) && next !== undefined && !next.startsWith('--')) {
        addFlag(flags, key, next);
        index += 1;
      } else {
        addFlag(flags, key, true);
      }
    }

    return { name, args, flags, raw: String(input || '') };
  }

  function flagValues(parsed, name) {
    const value = parsed?.flags?.[String(name || '').toLowerCase()];
    if (value === undefined) return [];
    return (Array.isArray(value) ? value : [value]).map((item) => String(item));
  }

  function flagValue(parsed, name, fallback = '') {
    const values = flagValues(parsed, name);
    return values.length ? values[values.length - 1] : fallback;
  }

  function hasFlag(parsed, name) {
    return Object.prototype.hasOwnProperty.call(parsed?.flags || {}, String(name || '').toLowerCase());
  }

  function integerFlag(parsed, name, fallback, { min = 1, max = 100 } = {}) {
    const raw = flagValue(parsed, name, String(fallback));
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new Error(`--${name} must be an integer from ${min} to ${max}.`);
    }
    return value;
  }

  function requireChoice(value, choices, label) {
    const normalized = String(value || '').toLowerCase();
    if (!choices.includes(normalized)) {
      throw new Error(`${label} must be one of: ${choices.join(', ')}.`);
    }
    return normalized;
  }

  function assertAllowedFlags(parsed, allowed) {
    const supported = new Set(allowed.map((flag) => String(flag).toLowerCase()));
    const unknown = Object.keys(parsed?.flags || {}).filter((flag) => !supported.has(flag));
    if (unknown.length) {
      throw new Error(`Unsupported flag${unknown.length === 1 ? '' : 's'}: ${unknown.map((flag) => `--${flag}`).join(', ')}.`);
    }
  }

  function normalizeCommand(parsed) {
    if (!parsed?.name) return parsed;
    const aliases = {
      link: 'link',
      phish: 'phishing',
      image: 'image',
      unified: 'gateway',
    };
    if (!Object.prototype.hasOwnProperty.call(aliases, parsed.name)) return parsed;
    return {
      ...parsed,
      name: 'scan',
      args: [aliases[parsed.name], ...(parsed.args || [])],
    };
  }

  function isMobileEnvironment({ width, userAgentMobile = false } = {}) {
    return Boolean(userAgentMobile) || Number(width) < 768;
  }

  function completionCandidates(prefix) {
    const normalized = String(prefix || '').trim().toLowerCase();
    return COMMANDS.filter((command) => command.startsWith(normalized));
  }

  return Object.freeze({
    COMMANDS,
    tokenize,
    parse,
    flagValues,
    flagValue,
    hasFlag,
    integerFlag,
    requireChoice,
    assertAllowedFlags,
    normalizeCommand,
    isMobileEnvironment,
    completionCandidates,
  });
});
