const DEFAULT_MODELS = Object.freeze({
  text: 'mailguard',
  url: 'swift',
  image: 'pixel',
});

function routeArtifacts(artifacts, policy) {
  const routing = policy.routing || {};
  return artifacts.flatMap((artifact) => {
    if (artifact.type === 'text') {
      return isModuleEnabled('phishing')
        ? [{ artifact, kind: 'phishing', modelKey: DEFAULT_MODELS.text, required: routing.text?.required?.includes('phishing') !== false, mode: 'fast' }]
        : [];
    }
    if (artifact.type === 'url') {
      return isModuleEnabled('link')
        ? [{ artifact, kind: 'link', modelKey: DEFAULT_MODELS.url, required: routing.url?.required?.includes('link') !== false, mode: 'fast' }]
        : [];
    }
    if (artifact.type === 'image') {
      return isModuleEnabled('deepfake')
        ? [{ artifact, kind: 'deepfake_image', modelKey: DEFAULT_MODELS.image, required: routing.image?.required?.includes('deepfake_image') !== false, mode: 'heavy' }]
        : [];
    }
    return isModuleEnabled('deepfake')
      ? [{ artifact, kind: `deepfake_${artifact.type}`, modelKey: null, required: false, mode: 'unsupported' }]
      : [];
  });
}

module.exports = {
  DEFAULT_MODELS,
  routeArtifacts,
};
const { isModuleEnabled } = require('../modules');
