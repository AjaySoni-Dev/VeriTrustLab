const contracts = require('../config/hf-model-contracts.canary.json');

const values = {
  runtime_source: 'bundled-pinned',
  module_contract_version: 'veritrust-module-command-1',
  models: contracts,
  required_secret: 'HF_TOKEN or HF_ACCESS_TOKEN',
};

console.log(JSON.stringify(values, null, 2));
