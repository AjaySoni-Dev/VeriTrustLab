const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const testDir = path.join(root, 'tests');
const files = fs.existsSync(testDir)
  ? fs.readdirSync(testDir).filter((name) => name.endsWith('.test.js')).sort().map((name) => path.join(testDir, name))
  : [];

if (!files.length) {
  console.error('No committed regression tests were discovered. Failing the test command.');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], { cwd: root, stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
