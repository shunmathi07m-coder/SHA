/**
 * Which One Did I Send? — Content Script
 * Injected on web pages to intercept file uploads, compute fingerprints,
 * scan for privacy leaks, detect outdated versions, and display the in-page guard modal.
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__FILEGUARD_CONTENT_SCRIPT_INITIALIZED__) return;
  window.__FILEGUARD_CONTENT_SCRIPT_INITIALIZED__ = true;

  console.log('[FileGuard] Content script activated on:', window.location.origin);

  const Crypto = window.FileGuardCrypto;
  const PrivacyShield = window.PrivacyLeakShield;
  const FileGuard = window.FileGuardEngine;
  const Storage = window.FileGuardStorage;

  // Intercept file selection changes
  document.addEventListener('change', async (event) => {
    const target = event.target;
    if (!target || target.tagName !== 'INPUT' || target.type !== 'file') return;
    if (!target.files || target.files.length === 0) return;

    // Check if target has our skip flag (e.g. user chose Continue Anyway)
    if (target.dataset.fileguardBypass === 'true') {
      delete target.dataset.fileguardBypass;
      return;
    }

    const file = target.files[0];
    await handleFileUploadInspection(file, target);
  }, true);

  /**
   * Main inspection pipeline for selected file
   */
  async function handleFileUploadInspection(file, inputElement) {
    try {
      const settings = await Storage.getSettings();
      if (!settings.fileGuardEnabled && !settings.privacyShieldEnabled) {
        return; // Protection disabled
      }

      // 1. Calculate SHA-256 Fingerprint
      const sha256 = await Crypto.sha256Hex(file);

      // 2. Scan Privacy Leak Shield if enabled
      let leakResult = { supported: false, hasFindings: false, findings: [] };
      if (settings.privacyShieldEnabled) {
        leakResult = await PrivacyShield.scanFile(file);
      }

      // 3. Scan FileGuard Version Heuristics if enabled
      let fgResult = { status: 'CLEAN' };
      if (settings.fileGuardEnabled) {
        const history = await Storage.getHistory();
        const versionLinks = await Storage.getVersionLinks();
        const fileMeta = {
          name: file.name,
          size: file.size,
          sha256: sha256,
          lastModified: file.lastModified
        };
        fgResult = FileGuard.analyzeFile(fileMeta, history, versionLinks);
      }

      const hasPrivacyRisk = leakResult.hasFindings;
      const isOutdated = fgResult.status === 'POTENTIAL_OUTDATED';
      const isDuplicate = fgResult.status === 'EXACT_DUPLICATE';

      // If an issue is flagged, trigger the FileGuard in-page warning modal
      if (hasPrivacyRisk || isOutdated || isDuplicate) {
        showFileGuardModal({
          file,
          inputElement,
          sha256,
          leakResult,
          fgResult,
          origin: window.location.origin
        });
      } else {
        // Safe upload: log activity silently and let user proceed
        await Storage.recordFileActivity({
          filename: file.name,
          fileSize: file.size,
          fileType: file.type || 'application/octet-stream',
          lastModified: file.lastModified,
          sha256: sha256,
          origin: window.location.origin,
          recipient: detectProbableRecipient(),
          source: 'web_integration',
          eventStage: Storage.EVENT_STAGES.UPLOAD_SELECTED,
          status: 'Selected for Upload',
          actionType: 'web_file_input',
          fileGuardStatus: 'CLEAN',
          leakShieldResult: leakResult,
          notes: 'Safe document selected for upload.'
        });
      }
    } catch (err) {
      console.error('[FileGuard] Error during file inspection:', err);
    }
  }

  /**
   * Display floating modal alert
   */
  function showFileGuardModal({ file, inputElement, sha256, leakResult, fgResult, origin }) {
    // Remove existing modal if any
    const existing = document.getElementById('fileguard-modal-root');
    if (existing) existing.remove();

    const root = document.createElement('div');
    root.id = 'fileguard-modal-root';

    const isLeak = leakResult && leakResult.hasFindings;
    const isOutdated = fgResult && fgResult.status === 'POTENTIAL_OUTDATED';
    const isDupe = fgResult && fgResult.status === 'EXACT_DUPLICATE';

    let headerClass = 'fg-alert-leak';
    let icon = '🛡️';
    let title = 'PRIVACY LEAK SHIELD ALERT';
    let subtitle = 'Potentially sensitive information detected in this document.';

    if (isLeak && isOutdated) {
      title = 'FILEGUARD & PRIVACY LEAK SHIELD WARNING';
      subtitle = 'Both sensitive information and a newer version were detected.';
    } else if (isOutdated) {
      headerClass = 'fg-alert-outdated';
      icon = '⚠️';
      title = 'FILEGUARD WARNING';
      subtitle = 'A potentially newer version may exist.';
    } else if (isDupe) {
      headerClass = 'fg-alert-outdated';
      icon = '⚡';
      title = 'FILEGUARD DUPLICATE NOTICE';
      subtitle = 'You have previously shared this identical file content.';
    }

    let findingsHtml = '';
    if (isLeak) {
      findingsHtml = `
        <div class="fg-findings-list">
          <div style="font-weight: 700; color: #fb7185; font-size: 12px;">Detected Sensitive Information:</div>
          ${leakResult.findings.map(f => `
            <div class="fg-finding-item">
              <div class="fg-finding-title">• [${escapeHtml(f.severity.toUpperCase())}] ${escapeHtml(f.name)}</div>
              <div class="fg-finding-snip">${escapeHtml(f.snippet)}</div>
            </div>
          `).join('')}
        </div>
      `;
    }

    let comparisonHtml = '';
    if (isOutdated && fgResult.suggestedFile) {
      comparisonHtml = `
        <div class="fg-comparison-box">
          <div style="font-weight: 700; color: #fbbf24;">Version Comparison:</div>
          <div><strong>Selected File:</strong> ${escapeHtml(file.name)}</div>
          <div><strong>Possible Newer Version:</strong> ${escapeHtml(fgResult.suggestedFile.name)}</div>
          <div style="color: #94a3b8; font-size: 11px; margin-top: 4px;">Reason: ${escapeHtml(fgResult.reason)}</div>
        </div>
      `;
    } else if (isDupe && fgResult.matchedRecord) {
      comparisonHtml = `
        <div class="fg-comparison-box">
          <div style="font-weight: 700; color: #fbbf24;">Duplicate Details:</div>
          <div>Exact identical content previously sent as: <strong>"${escapeHtml(fgResult.matchedRecord.filename)}"</strong></div>
          <div style="color: #94a3b8; font-size: 11px;">Sent on: ${fgResult.matchedRecord.timestamp} to ${escapeHtml(fgResult.matchedRecord.origin)}</div>
        </div>
      `;
    }

    root.innerHTML = `
      <div class="fg-modal-card ${headerClass}">
        <div class="fg-modal-header">
          <div class="fg-icon-box">${icon}</div>
          <div class="fg-header-text">
            <h3>${escapeHtml(title)}</h3>
            <p>${escapeHtml(subtitle)}</p>
          </div>
        </div>
        <div class="fg-modal-body">
          <div class="fg-info-box">
            <div class="fg-info-row">
              <span class="fg-info-label">Selected File:</span>
              <span class="fg-info-val">${escapeHtml(file.name)}</span>
            </div>
            <div class="fg-info-row">
              <span class="fg-info-label">SHA-256:</span>
              <span class="fg-info-val">${Crypto.formatShortHash(sha256, 8, 6)}</span>
            </div>
          </div>
          ${findingsHtml}
          ${comparisonHtml}
        </div>
        <div class="fg-modal-footer">
          <button class="fg-btn fg-btn-danger" id="fgBtnCancel">Cancel Sharing</button>
          <button class="fg-btn fg-btn-secondary" id="fgBtnDetails">Compare Details</button>
          <button class="fg-btn fg-btn-subtle" id="fgBtnContinue">Continue Anyway</button>
        </div>
      </div>
    `;

    document.body.appendChild(root);

    // 1. Cancel Sharing Action
    document.getElementById('fgBtnCancel').addEventListener('click', async () => {
      // Clear file input to prevent accidental send
      if (inputElement) {
        inputElement.value = '';
      }
      root.remove();

      // Record Cancelled outcome in history chain
      await Storage.recordFileActivity({
        filename: file.name,
        fileSize: file.size,
        fileType: file.type || 'text/plain',
        lastModified: file.lastModified,
        sha256: sha256,
        origin: origin,
        recipient: detectProbableRecipient(),
        source: 'web_integration',
        eventStage: Storage.EVENT_STAGES.UPLOAD_CANCELLED,
        status: 'Upload Cancelled (Blocked)',
        actionType: 'web_file_input',
        fileGuardStatus: fgResult.status,
        leakShieldResult: leakResult,
        notes: 'User cancelled upload after shield warning.'
      });
    });

    // 2. Compare Details Action
    document.getElementById('fgBtnDetails').addEventListener('click', () => {
      const detailsUrl = chrome && chrome.runtime && chrome.runtime.getURL
        ? chrome.runtime.getURL('dashboard/dashboard.html')
        : '/dashboard/dashboard.html';
      window.open(detailsUrl, '_blank');
    });

    // 3. Continue Anyway Action
    document.getElementById('fgBtnContinue').addEventListener('click', async () => {
      root.remove();
      // Set bypass flag on the element so re-triggering doesn't open loop
      if (inputElement) {
        inputElement.dataset.fileguardBypass = 'true';
      }

      // Record Continued outcome in history chain
      await Storage.recordFileActivity({
        filename: file.name,
        fileSize: file.size,
        fileType: file.type || 'text/plain',
        lastModified: file.lastModified,
        sha256: sha256,
        origin: origin,
        recipient: detectProbableRecipient(),
        source: 'web_integration',
        eventStage: Storage.EVENT_STAGES.UPLOAD_CONTINUED,
        status: 'Upload Continued (Override)',
        actionType: 'web_file_input',
        fileGuardStatus: fgResult.status,
        leakShieldResult: leakResult,
        notes: 'User explicitly authorized upload despite warning.'
      });
    });
  }

  /**
   * Best-effort recipient detection from page context
   */
  function detectProbableRecipient() {
    // Check Gmail "To" field or common input fields
    const toField = document.querySelector('input[name="to"], [aria-label="To recipients"], [aria-label="To"]');
    if (toField) {
      const text = toField.value || toField.textContent;
      if (text) return text.trim().slice(0, 50);
    }
    return null;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

})();
