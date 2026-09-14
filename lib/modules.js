const rawModuleConfig = require('../config/modules.json');

const MODULE_KEYS = Object.freeze(['phishing', 'deepfake', 'link', 'gateway']);

function runtimeModuleConfig() {
  const raw = typeof process !== 'undefined' ? String(process.env?.VERITRUST_MODULES || '').trim() : '';
  if (!raw) return rawModuleConfig;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TypeError('VERITRUST_MODULES must be valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new TypeError('VERITRUST_MODULES must be a JSON object.');
  }
  return { ...rawModuleConfig, ...parsed };
}

const activeModuleConfig = runtimeModuleConfig();
const MODULE_CONFIG = Object.freeze(Object.fromEntries(MODULE_KEYS.map((key) => {
  if (typeof activeModuleConfig[key] !== 'boolean') {
    throw new TypeError(`Module configuration must define ${key} as true or false.`);
  }
  return [key, activeModuleConfig[key]];
})));

const SCAN_TYPE_MODULE = Object.freeze({
  deepfake: 'deepfake',
  deepfake_image: 'deepfake',
  phishing: 'phishing',
  link: 'link',
  gateway: 'gateway',
});
const MODULE_VALUE_PATTERNS = Object.freeze({
  deepfake: /deep[ _-]?fake|\bpixel\b|\bprism\b|synthetic[ _-]?media/iu,
  phishing: /phish|\bmailguard\b|\bcortex\b/iu,
  link: /link[ _-]?(?:analysis|check|scan|intelligence)|\bswift\b|\bsentinel\b|url[ _-]?(?:analysis|scan)/iu,
  gateway: /gateway|multimodal[ _-]?(?:scan|review)/iu,
});

function isModuleEnabled(moduleName) {
  return MODULE_CONFIG[String(moduleName || '').trim().toLowerCase()] === true;
}

function moduleForScanType(scanType) {
  return SCAN_TYPE_MODULE[String(scanType || '').trim().toLowerCase()] || null;
}

function isScanTypeEnabled(scanType) {
  const moduleName = moduleForScanType(scanType);
  return moduleName ? isModuleEnabled(moduleName) : true;
}

function moduleForScan(scan) {
  const metadata = scan?.metadata || {};
  if (metadata.logical_scan_type === 'link' || metadata.original_scan_type === 'link') return 'link';
  const inputs = Array.isArray(scan?.scan_inputs) ? scan.scan_inputs : [scan?.scan_inputs].filter(Boolean);
  if (inputs.some((input) => input?.input_kind === 'url'
    || input?.metadata?.logical_scan_type === 'link'
    || input?.metadata?.original_scan_type === 'link')) return 'link';
  return moduleForScanType(scan?.scan_type || scan?.type);
}

function requireModuleEnabled(moduleName) {
  if (!isModuleEnabled(moduleName)) {
    const error = new Error('The requested resource was not found.');
    error.status = 404;
    error.code = 'NOT_FOUND';
    throw error;
  }
}

function filterEnabledScans(scans) {
  return (Array.isArray(scans) ? scans : []).filter((scan) => {
    const moduleName = moduleForScan(scan);
    return !moduleName || isModuleEnabled(moduleName);
  });
}

function disabledModuleMention(value) {
  const text = String(value || '');
  return MODULE_KEYS.find((key) => !isModuleEnabled(key) && MODULE_VALUE_PATTERNS[key].test(text)) || null;
}

function sanitizeModuleData(value) {
  if (typeof value === 'string') return disabledModuleMention(value) ? null : value;
  if (Array.isArray(value)) return value.map(sanitizeModuleData).filter((item) => item !== null && item !== undefined);
  if (!value || typeof value !== 'object') return value;
  const sanitized = {};
  for (const [key, item] of Object.entries(value)) {
    if (disabledModuleMention(key)) continue;
    const clean = sanitizeModuleData(item);
    if (clean !== null && clean !== undefined) sanitized[key] = clean;
  }
  return sanitized;
}

module.exports = {
  MODULE_CONFIG,
  MODULE_KEYS,
  filterEnabledScans,
  isModuleEnabled,
  isScanTypeEnabled,
  moduleForScan,
  moduleForScanType,
  requireModuleEnabled,
  sanitizeModuleData,
};
