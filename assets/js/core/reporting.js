(function initVeriTrustReporting(global) {
  const REPORT_TEMPLATE_VERSION = '20260804';

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[char]));
  }

  function clamp01(value) {
    return Math.max(0, Math.min(1, Number(value) || 0));
  }

  function formatPercent(value) {
    return `${Math.round(clamp01(value) * 100)}%`;
  }

  function titleCase(value) {
    const text = String(value || '').trim();
    if (!text) return 'Unknown';
    return text.charAt(0).toUpperCase() + text.slice(1).toLowerCase();
  }

  function titleWords(value) {
    return String(value || '').replace(/\w\S*/g, (word) => (
      word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    ));
  }

  function modelDisplayName(model = {}) {
    const raw = String(model.name || model.key || 'VeriTrust').trim();
    return raw
      .split(/\s+/)
      .map((part) => {
        if (/^veritrust$/i.test(part)) return 'VeriTrust';
        return titleWords(part);
      })
      .join(' ');
  }

  function modelKeyLabel(value) {
    return titleWords(String(value || 'N/A').replace(/[-_]+/g, ' '));
  }

  function isRobustModel(model = {}) {
    const key = String(model.key || '').toLowerCase();
    const name = String(model.name || '').toLowerCase();
    return key === 'prism' || name.includes('prism');
  }

  function asList(value) {
    if (Array.isArray(value)) return value;
    return value ? [value] : [];
  }

  function assetUrl(path, cacheKey = '') {
    try {
      const url = new URL(path, global.location.href);
      if (cacheKey) url.searchParams.set('v', cacheKey);
      return url.href;
    } catch {
      return path;
    }
  }

  function normalizeReportData(data = {}) {
    const result = data.result || {};
    const report = data.report || {};
    const scanType = data.scan_type || data.type || report.scan_type || 'scan';
    const model = data.model || report.model || {};

    return {
      title: report.title || data.title || 'VeriTrust Scan Report',
      scan_id: data.scan_id || data.scan?.id || report.scan_id || null,
      scan_type: scanType,
      created_at: data.created_at || report.created_at || new Date().toISOString(),
      model: {
        key: model.key || '',
        name: modelDisplayName(model),
        fallback_used: Boolean(model.fallback_used || model.fallback_from),
        fallback_from: model.fallback_from || null,
      },
      result: {
        ...result,
        risk_level: titleCase(result.risk_level || 'Low'),
        confidence_band: result.confidence_band || 'N/A',
        summary: result.summary || result.explanation || 'AI-assisted assessment completed.',
        disclaimer:
          result.disclaimer ||
          report.disclaimer ||
          'AI-assisted result. Not legal, forensic, cybersecurity, or final proof.',
      },
      scores: data.scores || report.scores || [],
      report: {
        title: report.title || data.title || 'VeriTrust Scan Report',
        disclaimer:
          report.disclaimer ||
          result.disclaimer ||
          'AI-assisted result. Not legal, forensic, cybersecurity, or final proof.',
        exportable: report.exportable !== false,
      },
    };
  }

  function riskClass(level) {
    const normalized = String(level || 'low').toLowerCase();
    if (normalized === 'critical') return 'critical';
    if (normalized === 'high') return 'high';
    if (normalized === 'medium') return 'medium';
    return 'low';
  }

  function visibleVisualUrl(url) {
    return String(url || '').trim();
  }

  function sanitizeVisualsForJson(visuals = {}) {
    const normalUrl = (url) => {
      const value = String(url || '').trim();
      return value && !value.startsWith('data:') && !value.startsWith('blob:') ? value : '';
    };

    return {
      available: Boolean(visuals.available),
      selected_face_index: visuals.selected_face_index != null && Number.isFinite(Number(visuals.selected_face_index))
        ? Number(visuals.selected_face_index)
        : null,
      analyzed_image_url: normalUrl(visuals.analyzed_image_url),
      cropped_image_url: normalUrl(visuals.cropped_image_url),
      annotated_image_url: normalUrl(visuals.annotated_image_url),
    };
  }

  function truncate(value, maxLength = 96) {
    const text = String(value || '').replace(/\s+/g, ' ').trim();
    return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
  }

  function evidenceItems(result) {
    return asList(result.evidence || result.indicators).slice(0, 4).map((item) => {
      if (typeof item === 'string') {
        return { title: item, description: '', severity: 'Medium' };
      }

      return {
        title: item?.title || item?.type || 'Signal',
        description: item?.description || item?.detail || item?.reason || item?.message || '',
        severity: item?.severity || 'Medium',
      };
    });
  }

  function hasValue(value) {
    return value !== null && value !== undefined && value !== '';
  }

  function detectionDetails(report, result, isDeepfake, isLink = false) {
    const details = [
      ['Scan type', titleCase(report.scan_type)],
      ['Scan ID', report.scan_id || 'Not available'],
      ['Model', report.model.name, isRobustModel(report.model) ? 'Alternate image model' : ''],
      ['Model key', modelKeyLabel(report.model.key)],
      ['Fallback', report.model.fallback_used ? `Used${report.model.fallback_from ? ` from ${report.model.fallback_from}` : ''}` : 'Not used'],
      ['Confidence band', result.confidence_band || 'N/A'],
    ];

    if (isDeepfake) {
      if (hasValue(result.fake_score)) details.push(['Fake score', formatPercent(result.fake_score)]);
      if (hasValue(result.real_score)) details.push(['Real score', formatPercent(result.real_score)]);
    } else if (isLink) {
      if (hasValue(result.link_score)) details.push(['Link score', formatPercent(result.link_score)]);
      if (hasValue(result.model_score)) details.push(['Model score', formatPercent(result.model_score)]);
      if (hasValue(result.rule_score)) details.push(['Rule score', formatPercent(result.rule_score)]);
    } else if (hasValue(result.phishing_score)) {
      details.push(['Phishing score', formatPercent(result.phishing_score)]);
    }

    if (Array.isArray(report.scores) && report.scores.length) {
      report.scores.slice(0, 2).forEach((score, index) => {
        const label = score?.label || score?.name || `Score ${index + 1}`;
        const value = hasValue(score?.score) ? formatPercent(score.score) : score?.value;
        if (hasValue(value)) details.push([label, value]);
      });
    }

    return details.slice(0, 10);
  }

  function renderDetectionDetails(details) {
    return `
      <section class="report-section detail-section">
        <div class="section-heading">
          <h2>Detection Details</h2>
          <span>Complete available scan metadata</span>
        </div>
        <div class="detail-panel">
          ${details.map(([label, value, badge]) => `
            <div class="detail-item">
              <span>${escapeHtml(label)}</span>
              <strong class="truncate">
                ${escapeHtml(value)}
                ${badge ? `<em class="model-tag">${escapeHtml(badge)}</em>` : ''}
              </strong>
            </div>
          `).join('')}
        </div>
      </section>
    `;
  }

  function extractedGroups(result) {
    const extracted = result.extracted || {};
    return ['urls', 'domains', 'emails', 'phones']
      .map((key) => [key, asList(extracted[key]).slice(0, 2)])
      .filter(([, values]) => values.length);
  }

  function renderVisualCard(title, url, fallback) {
    const src = visibleVisualUrl(url);

    return `
      <div class="visual-card">
        <div class="mini-label">${escapeHtml(title)}</div>
        ${
          src
            ? `<img src="${escapeHtml(src)}" alt="${escapeHtml(title)}">`
            : `<div class="visual-fallback">${escapeHtml(fallback)}</div>`
        }
      </div>
    `;
  }

  function renderDeepfakeVisuals(visuals = {}) {
    const faceNumber = Number.isFinite(Number(visuals.selected_face_index))
      ? Number(visuals.selected_face_index) + 1
      : null;
    const hasAnnotated = Boolean(visibleVisualUrl(visuals.annotated_image_url));
    const hasCrop = Boolean(visibleVisualUrl(visuals.cropped_image_url));
    const analyzedImageUrl = visibleVisualUrl(visuals.analyzed_image_url);
    const hasAnalyzed = Boolean(analyzedImageUrl);
    const cards = [];

    if (hasAnnotated || hasCrop) {
      if (hasAnnotated) {
        cards.push(renderVisualCard('Annotated Full Image', visuals.annotated_image_url, 'Annotated image not available.'));
      } else if (hasAnalyzed) {
        cards.push(renderVisualCard('Analyzed Image', analyzedImageUrl, 'Analyzed image not available.'));
      }

      if (hasCrop) {
        cards.push(renderVisualCard('Selected Face Crop', visuals.cropped_image_url, 'Cropped face not available.'));
      } else if (hasAnalyzed) {
        cards.push(renderVisualCard('Analyzed Image', analyzedImageUrl, 'Analyzed image not available.'));
      }
    } else {
      cards.push(renderVisualCard('Analyzed Image', analyzedImageUrl, 'Analyzed image not available.'));
    }

    if (!cards.length) {
      cards.push(renderVisualCard('Annotated Full Image', visuals.annotated_image_url, 'Annotated image not available.'));
    }

    return `
      <section class="report-section visual-section">
        <div class="section-heading">
          <h2>Image Preview</h2>
          <span>${
            hasAnnotated && hasCrop
              ? `Annotated image and crop included${faceNumber ? `, face ${faceNumber}` : ''}`
              : hasCrop && faceNumber
                ? `Selected face ${faceNumber}`
                : hasAnalyzed
                  ? 'Analyzed image included'
                  : 'Image evidence unavailable'
          }</span>
        </div>

        <div class="visual-grid${cards.length === 1 ? ' single' : ''}">
          ${cards.slice(0, 2).join('')}
        </div>
      </section>
    `;
  }

  function renderExtractedEntities(result) {
    const groups = extractedGroups(result);

    if (!groups.length) {
      return `
        <section class="report-section">
          <div class="section-heading"><h2>Extracted Entities</h2></div>
          <p class="muted compact">No URLs, domains, emails, or phone numbers were extracted.</p>
        </section>
      `;
    }

    return `
      <section class="report-section">
        <div class="section-heading"><h2>Extracted Entities</h2></div>
        <div class="entity-list">
          ${groups.map(([key, values]) => `
            <div class="entity-row">
              <span>${escapeHtml(key)}</span>
              <strong class="truncate">${escapeHtml(values.join(', '))}</strong>
            </div>
          `).join('')}
        </div>
      </section>
    `;
  }

  function renderLinkExtractedDetails(result) {
    const extracted = result.extracted || {};
    const rows = [
      ['Extracted URL', extracted.normalized_url || extracted.input_url],
      ['Hostname', extracted.hostname],
      ['Domain', extracted.domain],
      ['Scheme', extracted.scheme],
      ['Path', extracted.path],
      ['Query present', extracted.query_present ? 'Yes' : 'No'],
    ].filter(([, value]) => hasValue(value));

    if (!rows.length) {
      return `
        <section class="report-section">
          <div class="section-heading"><h2>Extracted URL</h2></div>
          <p class="muted compact">No URL structure details were returned.</p>
        </section>
      `;
    }

    return `
      <section class="report-section">
        <div class="section-heading"><h2>Extracted URL</h2></div>
        <div class="entity-list">
          ${rows.map(([label, value]) => `
            <div class="entity-row">
              <span>${escapeHtml(label)}</span>
              <strong class="truncate">${escapeHtml(value)}</strong>
            </div>
          `).join('')}
        </div>
      </section>
    `;
  }

  function reportHtml(data, options = {}) {
    const report = normalizeReportData(data);
    const result = report.result || {};
    const isDeepfake = String(report.scan_type).toLowerCase() === 'deepfake';
    const isLink = String(report.scan_type).toLowerCase() === 'link';
    const risk = riskClass(result.risk_level);
    const evidence = evidenceItems(result);
    const visuals = options.visuals || {};
    const details = detectionDetails(report, result, isDeepfake, isLink);
    const created = new Date(report.created_at);
    const createdLabel = Number.isNaN(created.getTime())
      ? String(report.created_at || '')
      : created.toLocaleString();

    const logoUrl = options.logoUrl || assetUrl('/assets/images/logo.png', REPORT_TEMPLATE_VERSION);
    const brandUrl = options.brandUrl || assetUrl('/assets/images/brand.png', REPORT_TEMPLATE_VERSION);

    return `
      <!doctype html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
        <title>${escapeHtml(report.title)}</title>
        <style>
          @page {
            size: A4 portrait;
            margin: 0;
          }

          html,
          body {
            width: 210mm;
            height: 297mm;
            max-width: 210mm;
            max-height: 297mm;
            margin: 0;
            padding: 0;
            overflow: hidden;
            background: #111111 !important;
            color-scheme: dark;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
          }

          * {
            box-sizing: border-box;
          }

          body {
            color: #f4f7fb;
            font-family: Inter, Arial, Helvetica, sans-serif;
            line-height: 1.28;
          }

          .report-sheet {
            width: 210mm;
            height: 297mm;
            max-height: 297mm;
            overflow: hidden;
            padding: 7mm;
            background:
              radial-gradient(circle at top left, rgba(255, 255, 255, 0.06), transparent 34%),
              radial-gradient(circle at bottom right, rgba(255, 255, 255, 0.035), transparent 34%),
              #111111 !important;
            page-break-before: avoid;
            page-break-after: avoid;
            page-break-inside: avoid;
            break-inside: avoid;
          }

          .report-frame {
            width: 100%;
            height: 100%;
            overflow: hidden;
            display: grid;
            grid-template-rows: auto auto auto auto auto;
            align-content: start;
            gap: 4.2mm;
            padding: 6mm;
            border: 1px solid rgba(255, 255, 255, 0.13);
            border-radius: 10px;
            background: linear-gradient(145deg, #171717 0%, #121214 52%, #0f0f10 100%) !important;
            box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.035);
          }

          .report-header {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 10px;
            align-items: start;
            padding-bottom: 4mm;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
          }

          .brand {
            display: grid;
            gap: 5px;
            justify-items: start;
          }

          .brand-lockup {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            min-height: 28px;
            margin-bottom: 2px;
          }

          .brand-logo {
            width: 27px;
            height: 27px;
            flex: 0 0 auto;
            object-fit: contain;
            filter: drop-shadow(0 1px 5px rgba(0, 0, 0, 0.35));
          }

          .brand-word {
            width: 124px;
            max-height: 18px;
            object-fit: contain;
            filter: drop-shadow(0 1px 5px rgba(0, 0, 0, 0.35));
          }

          h1 {
            margin: 2px 0 0;
            font-size: 17px;
            line-height: 1;
            letter-spacing: 0;
          }

          .subtitle,
          .muted {
            color: #9ca3af;
          }

          .subtitle {
            margin: 2px 0 0;
            font-size: 9px;
          }

          .scan-meta {
            display: grid;
            gap: 2px;
            min-width: 54mm;
            color: #9ca3af;
            font-size: 8.4px;
            text-align: right;
          }

          .truncate {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }

          .hero-result {
            display: grid;
            grid-template-columns: 1.15fr 0.72fr 0.72fr 0.72fr;
            gap: 6px;
          }

          .metric-card,
          .detail-panel,
          .visual-card,
          .summary-card,
          .evidence-card,
          .entity-row,
          .disclaimer {
            border: 1px solid rgba(255, 255, 255, 0.105);
            border-radius: 8px;
            background: #1a1a1b !important;
          }

          .metric-card,
          .summary-card,
          .evidence-card,
          .entity-row {
            padding: 6.5px;
          }

          .detail-panel {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 5px 9px;
            padding: 7px 8px;
          }

          .mini-label {
            margin-bottom: 3px;
            color: #8f8f98;
            font-size: 7.8px;
            font-weight: 800;
            letter-spacing: 0.045em;
            text-transform: uppercase;
          }

          .metric-card strong {
            display: block;
            font-size: 15.5px;
            line-height: 1.05;
          }

          .risk-pill {
            width: fit-content;
            min-height: 22px;
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            padding: 0 8px;
            font-size: 11.5px;
            font-weight: 900;
          }

          .risk-low {
            color: #bbf7d0;
            background: rgba(34, 197, 94, 0.13);
            border: 1px solid rgba(34, 197, 94, 0.38);
          }

          .risk-medium {
            color: #01afaf;
            background: rgba(1, 175, 175, 0.13);
            border: 1px solid rgba(1, 175, 175, 0.38);
          }

          .risk-high,
          .risk-critical {
            color: #fecaca;
            background: rgba(239, 68, 68, 0.14);
            border: 1px solid rgba(239, 68, 68, 0.46);
          }

          .detail-item strong,
          .entity-row strong {
            display: flex;
            min-width: 0;
            align-items: center;
            gap: 4px;
            color: #f9fafb;
            font-size: 8.9px;
          }

          .detail-item span,
          .entity-row span {
            display: block;
            color: #8f8f98;
            font-size: 7.6px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.04em;
          }

          .model-tag {
            flex: 0 0 auto;
            display: inline-flex;
            align-items: center;
            min-height: 13px;
            padding: 0 5px;
            border: 1px solid rgba(96, 165, 250, 0.45);
            border-radius: 999px;
            color: #bfdbfe;
            background: rgba(37, 99, 235, 0.16);
            font-size: 6.8px;
            font-style: normal;
            font-weight: 900;
            letter-spacing: 0.04em;
            text-transform: uppercase;
          }

          .report-main {
            min-height: 0;
            display: grid;
            gap: 3mm;
            align-content: start;
            overflow: hidden;
          }

          .report-section {
            min-width: 0;
          }

          .section-heading {
            min-height: 15px;
            display: flex;
            justify-content: space-between;
            gap: 8px;
            align-items: center;
            margin-bottom: 4px;
          }

          h2 {
            margin: 0;
            font-size: 11.8px;
            line-height: 1;
          }

          .section-heading span {
            color: #8f8f98;
            font-size: 8px;
          }

          .visual-grid {
            display: grid;
            grid-template-columns: 1.42fr 1fr;
            gap: 7px;
          }

          .visual-grid.single {
            grid-template-columns: 1fr;
          }

          .visual-card {
            min-height: 82mm;
            padding: 6px;
            background: #181819 !important;
          }

          .visual-card img {
            width: 100%;
            height: 75mm;
            object-fit: contain;
            border-radius: 6px;
            background: #0b0b0c !important;
          }

          .visual-fallback {
            height: 75mm;
            display: grid;
            place-items: center;
            border: 1px dashed rgba(255, 255, 255, 0.13);
            border-radius: 6px;
            color: #8f8f98;
            font-size: 9px;
            text-align: center;
            background: #121213 !important;
          }

          .visual-grid.single .visual-card {
            min-height: 96mm;
          }

          .visual-grid.single .visual-card img,
          .visual-grid.single .visual-fallback {
            height: 89mm;
          }

          .summary-card p,
          .compact {
            margin: 0;
            font-size: 9.4px;
          }

          .summary-card p {
            display: -webkit-box;
            overflow: hidden;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
          }

          .evidence-list {
            display: grid;
            gap: 4px;
          }

          .evidence-card {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 7px;
            align-items: center;
          }

          .evidence-card strong {
            font-size: 9.3px;
          }

          .evidence-copy {
            min-width: 0;
            display: grid;
            gap: 1px;
          }

          .evidence-copy p {
            display: -webkit-box;
            margin: 0;
            overflow: hidden;
            color: #a7aab2;
            font-size: 8px;
            line-height: 1.25;
            -webkit-line-clamp: 1;
            -webkit-box-orient: vertical;
          }

          .severity {
            border: 1px solid rgba(255, 255, 255, 0.13);
            border-radius: 999px;
            padding: 2px 6px;
            color: #f9fafb;
            font-size: 7.4px;
            font-weight: 900;
          }

          .entity-list {
            display: grid;
            gap: 4px;
          }

          .entity-row {
            display: grid;
            grid-template-columns: 23mm minmax(0, 1fr);
            gap: 7px;
            align-items: center;
          }

          .disclaimer {
            padding: 6px 8px;
            color: #9ca3af;
            font-size: 8.4px;
            line-height: 1.25;
            background: #151516 !important;
          }

          @media print {
            html,
            body {
              width: 210mm !important;
              height: 297mm !important;
              max-height: 297mm !important;
              overflow: hidden !important;
              background: #111111 !important;
            }

            .report-sheet {
              page-break-before: avoid;
              page-break-after: avoid;
              page-break-inside: avoid;
              break-inside: avoid;
              background-color: #111111 !important;
            }
          }
        </style>
      </head>

      <body>
        <main class="report-sheet" data-report-template="${REPORT_TEMPLATE_VERSION}">
          <div class="report-frame">
            <header class="report-header">
              <div>
                <div class="brand">
                  <div class="brand-lockup">
                    <img class="brand-logo" src="${escapeHtml(logoUrl)}" alt="VeriTrust logo">
                    <img class="brand-word" src="${escapeHtml(brandUrl)}" alt="VeriTrust">
                  </div>
                  <h1>Scan Report</h1>
                  <p class="subtitle">AI-assisted digital trust verification</p>
                </div>
              </div>

              <div class="scan-meta">
                <span class="truncate">Type: ${escapeHtml(titleCase(report.scan_type))}</span>
                <span class="truncate">Date: ${escapeHtml(createdLabel)}</span>
                <span class="truncate">Scan ID: ${escapeHtml(report.scan_id || 'Not available')}</span>
              </div>
            </header>

            <section class="hero-result">
              <div class="metric-card">
                <div class="mini-label">Verdict</div>
                <strong class="truncate">${escapeHtml(result.label || 'Unknown')}</strong>
              </div>

              <div class="metric-card">
                <div class="mini-label">Risk</div>
                <span class="risk-pill risk-${risk}">${escapeHtml(result.risk_level || 'Low')}</span>
              </div>

              <div class="metric-card">
                <div class="mini-label">Confidence</div>
                <strong>${escapeHtml(formatPercent(result.confidence))}</strong>
              </div>

              <div class="metric-card">
                <div class="mini-label">Band</div>
                <strong class="truncate">${escapeHtml(result.confidence_band || 'N/A')}</strong>
              </div>
            </section>

            ${renderDetectionDetails(details)}

            <div class="report-main">
              ${isDeepfake ? renderDeepfakeVisuals(visuals) : (isLink ? renderLinkExtractedDetails(result) : renderExtractedEntities(result))}

              <section class="report-section">
                <div class="section-heading"><h2>Summary</h2></div>
                <div class="summary-card">
                  <p>${escapeHtml(truncate(result.summary || result.explanation || 'No summary available.', 280))}</p>
                </div>
              </section>

              <section class="report-section">
                <div class="section-heading">
                  <h2>${isDeepfake ? 'Score Details' : 'Indicators'}</h2>
                  <span>Top ${Math.min(4, evidence.length)} shown</span>
                </div>

                ${
                  evidence.length
                    ? `
                      <div class="evidence-list">
                        ${evidence.map((item) => `
                          <div class="evidence-card">
                            <div class="evidence-copy">
                              <strong class="truncate">${escapeHtml(item.title)}</strong>
                              ${item.description ? `<p>${escapeHtml(truncate(item.description, 120))}</p>` : ''}
                            </div>
                            <span class="severity">${escapeHtml(item.severity)}</span>
                          </div>
                        `).join('')}
                      </div>
                    `
                    : '<p class="muted compact">No additional evidence or indicators were returned.</p>'
                }
              </section>
            </div>

            <footer class="disclaimer">
              ${escapeHtml(result.disclaimer || report.report.disclaimer || 'AI-assisted result. Not legal, forensic, cybersecurity, or final proof.')}
            </footer>
          </div>
        </main>
      </body>
      </html>
    `;
  }

  function waitForReportImages(printWindow, timeoutMs = 2500) {
    const images = Array.from(printWindow.document.images || []);
    if (!images.length) return Promise.resolve();

    const imagePromises = images.map((image) => new Promise((resolve) => {
      if (image.complete) {
        resolve();
        return;
      }

      const done = () => resolve();
      image.addEventListener('load', done, { once: true });
      image.addEventListener('error', done, { once: true });
    }));

    return Promise.race([
      Promise.all(imagePromises),
      new Promise((resolve) => setTimeout(resolve, timeoutMs)),
    ]);
  }

  async function printReport(data, options = {}) {
    const printWindow = global.open('', '_blank', 'width=900,height=700');

    if (!printWindow) {
      global.print();
      return;
    }

    printWindow.document.open();
    printWindow.document.write(reportHtml(data, options));
    printWindow.document.close();
    printWindow.focus();

    await waitForReportImages(printWindow, options.timeoutMs || 2500);
    printWindow.print();
  }

  global.VeriTrustReporting = {
    REPORT_TEMPLATE_VERSION,
    normalizeReportData,
    printReport,
    reportHtml,
    sanitizeVisualsForJson,
    waitForReportImages,
  };
})(window);
