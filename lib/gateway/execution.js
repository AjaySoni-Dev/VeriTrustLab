function normalizedConcurrency(value, fallback = 2) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, 8);
}

async function mapWithConcurrency(items, concurrency, worker) {
  if (!Array.isArray(items)) throw new TypeError('items must be an array');
  if (typeof worker !== 'function') throw new TypeError('worker must be a function');
  if (!items.length) return [];

  const results = new Array(items.length);
  const limit = Math.min(items.length, normalizedConcurrency(concurrency));
  let cursor = 0;

  async function consume() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: limit }, () => consume()));
  return results;
}

function modelTimeoutMs(policy, prepared, synchronousBudgetMs) {
  const candidates = [
    Number(policy?.timeouts?.per_model_ms),
    Number(prepared?.version?.timeout_ms),
    Number(synchronousBudgetMs),
  ].filter((value) => Number.isFinite(value) && value > 0);
  if (!candidates.length) return 45000;
  return Math.max(1000, Math.min(...candidates));
}

module.exports = {
  mapWithConcurrency,
  modelTimeoutMs,
  normalizedConcurrency,
};
