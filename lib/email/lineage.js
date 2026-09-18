const { HttpError } = require('../veritrust-api');

const ACQUISITION_STAGE_INDEX = Object.freeze({
  plain_text: 0,
  raw_eml: 1,
  trusted_receiver_event: 2,
});
const EMAIL_SCAN_SOURCES = new Set(['phishing-v2', 'trusted-receiver-v2']);

function acquisitionStageIndex(mode) {
  return Object.prototype.hasOwnProperty.call(ACQUISITION_STAGE_INDEX, mode)
    ? ACQUISITION_STAGE_INDEX[mode]
    : -1;
}

function validateLineageParentReport(parentReport, currentMode) {
  const scan = parentReport?.scan || null;
  if (!scan?.id) {
    throw new HttpError(404, 'The parent email investigation was not found in this workspace.', { code: 'EMAIL_LINEAGE_PARENT_NOT_FOUND' });
  }
  if (!EMAIL_SCAN_SOURCES.has(String(scan.source || ''))) {
    throw new HttpError(409, 'The parent scan is not an email-v2 investigation and cannot be used as evidence lineage.', { code: 'EMAIL_LINEAGE_PARENT_TYPE_INVALID' });
  }
  if (String(scan.status || '').toLowerCase() !== 'completed') {
    throw new HttpError(409, 'The parent email investigation must be completed before it can be linked as an evidence upgrade.', { code: 'EMAIL_LINEAGE_PARENT_INCOMPLETE' });
  }
  const parentMode = String(scan.metadata?.input_mode || '');
  const parentIndex = acquisitionStageIndex(parentMode);
  const currentIndex = acquisitionStageIndex(currentMode);
  if (parentIndex < 0 || currentIndex < 0) {
    throw new HttpError(409, 'The evidence acquisition stage is not valid for lineage.', { code: 'EMAIL_LINEAGE_STAGE_INVALID' });
  }
  if (currentIndex <= parentIndex) {
    throw new HttpError(409, 'Evidence lineage must move to a stronger acquisition stage.', {
      code: 'EMAIL_LINEAGE_STAGE_NOT_MONOTONIC',
      meta: { parent_stage: parentMode, current_stage: currentMode },
    });
  }
  return { parentScanId: scan.id, parentMode };
}

async function resolveLineageParent({ orgId, parentScanId, currentMode, loadScan }) {
  if (!parentScanId) return null;
  try {
    const report = await loadScan(orgId, parentScanId);
    return validateLineageParentReport(report, currentMode);
  } catch (error) {
    if (error?.code === 'GATEWAY_SCAN_NOT_FOUND' || Number(error?.status || 0) === 404) {
      throw new HttpError(404, 'The parent email investigation was not found in this workspace.', { code: 'EMAIL_LINEAGE_PARENT_NOT_FOUND' });
    }
    throw error;
  }
}

function investigationLineage({ parentScanId = null, currentScanId = null, mode, parentMode = null }) {
  return {
    parent_scan_id: parentScanId || null,
    current_scan_id: currentScanId || null,
    acquisition_stage: mode,
    parent_acquisition_stage: parentMode || null,
    relationship: parentScanId ? 'user_linked_evidence_upgrade' : null,
    same_message_verified: parentScanId ? false : null,
  };
}

module.exports = {
  ACQUISITION_STAGE_INDEX,
  acquisitionStageIndex,
  investigationLineage,
  resolveLineageParent,
  validateLineageParentReport,
};
