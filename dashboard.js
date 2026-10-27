/**
 * Which One Did I Send? — Dashboard Controller
 * Operates on the unified shared real-file history and version linkages.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const Crypto = window.FileGuardCrypto;
  const Storage = window.FileGuardStorage;

  // DOM Elements
  const integrityBanner = document.getElementById('integrityBanner');
  const bannerIcon = document.getElementById('bannerIcon');
  const bannerTitle = document.getElementById('bannerTitle');
  const bannerDesc = document.getElementById('bannerDesc');
  const btnReaudit = document.getElementById('btnReaudit');
  const btnVerifyChain = document.getElementById('btnVerifyChain');
  const btnExportJson = document.getElementById('btnExportJson');
  const btnClearHistory = document.getElementById('btnClearHistory');

  const btnImportFiles = document.getElementById('btnImportFiles');
  const bulkImportInput = document.getElementById('bulkImportInput');
  const btnOpenLinkModal = document.getElementById('btnOpenLinkModal');

  const metricTotal = document.getElementById('metricTotal');
  const metricDuplicates = document.getElementById('metricDuplicates');
  const metricVersions = document.getElementById('metricVersions');
  const metricLeaks = document.getElementById('metricLeaks');

  const searchInput = document.getElementById('searchInput');
  const filterStage = document.getElementById('filterStage');
  const filterPrivacy = document.getElementById('filterPrivacy');
  const filterVersion = document.getElementById('filterVersion');

  const tableBody = document.getElementById('tableBody');
  const tableEmpty = document.getElementById('tableEmpty');

  const detailsModal = document.getElementById('detailsModal');
  const modalBody = document.getElementById('modalBody');
  const btnCloseModal = document.getElementById('btnCloseModal');
  const btnCloseModalBtn = document.getElementById('btnCloseModalBtn');

  const linkVersionModal = document.getElementById('linkVersionModal');
  const selectOlderRecord = document.getElementById('selectOlderRecord');
  const selectNewerRecord = document.getElementById('selectNewerRecord');
  const btnCloseLinkModal = document.getElementById('btnCloseLinkModal');
  const btnCancelLinkModal = document.getElementById('btnCancelLinkModal');
  const btnConfirmLinkVersion = document.getElementById('btnConfirmLinkVersion');

  const confirmClearModal = document.getElementById('confirmClearModal');
  const btnCancelClear = document.getElementById('btnCancelClear');
  const btnCancelClearBtn = document.getElementById('btnCancelClearBtn');
  const btnConfirmClearBtn = document.getElementById('btnConfirmClearBtn');

  let allRecords = [];

  // 1. Initial Load & Audit
  async function loadDashboard() {
    allRecords = await Storage.getHistory();
    await runChainAudit();
    updateMetrics(allRecords);
    renderTable();
  }

  // 2. Cryptographic Chain Audit
  async function runChainAudit() {
    const audit = await Storage.verifyHistoryChain();

    if (audit.isValid) {
      integrityBanner.className = 'integrity-banner banner-success';
      bannerIcon.textContent = '🛡️';
      bannerTitle.textContent = 'Cryptographic Chain Verified';
      bannerDesc.textContent = audit.count === 0
        ? 'No records stored yet. Ready to index real files.'
        : `All ${audit.count} real-file records are mathematically chained and intact via SHA-256. No tampering detected.`;
    } else {
      integrityBanner.className = 'integrity-banner banner-warning';
      bannerIcon.textContent = '⚠️';
      bannerTitle.textContent = 'History Integrity Warning';
      bannerDesc.textContent = audit.reason || 'One or more records may have been modified!';
    }
  }

  // 3. Compute Metrics
  function updateMetrics(records) {
    metricTotal.textContent = records.length;

    let dupes = 0;
    let versionsCount = 0;
    let leaks = 0;

    records.forEach(r => {
      if (r.fileGuardStatus === 'EXACT_DUPLICATE') dupes++;
      if (r.explicitlyLinked || r.linkedNewerVersionId || r.isNewerThanId || r.fileGuardStatus === 'POTENTIAL_OUTDATED') {
        versionsCount++;
      }
      if (r.privacyStatus === 'SENSITIVE_DETECTED' || (r.leakShieldResult && r.leakShieldResult.hasFindings)) {
        leaks++;
      }
    });

    metricDuplicates.textContent = dupes;
    metricVersions.textContent = versionsCount;
    metricLeaks.textContent = leaks;
  }

  // 4. Render Table with Filters
  function renderTable() {
    const query = searchInput.value.trim().toLowerCase();
    const stageVal = filterStage.value;
    const privacyVal = filterPrivacy.value;
    const versionVal = filterVersion.value;

    const filtered = allRecords.filter(r => {
      // Query filter (filename, recipient, fingerprint, notes)
      if (query) {
        const nameMatch = r.filename && r.filename.toLowerCase().includes(query);
        const recipientMatch = r.recipient && r.recipient.toLowerCase().includes(query);
        const hashMatch = r.sha256 && r.sha256.toLowerCase().includes(query);
        const originMatch = r.origin && r.origin.toLowerCase().includes(query);
        if (!nameMatch && !recipientMatch && !hashMatch && !originMatch) return false;
      }

      // Event Stage filter
      if (stageVal !== 'ALL') {
        if (r.eventStage !== stageVal) return false;
      }

      // Privacy filter
      if (privacyVal !== 'ALL') {
        if (r.privacyStatus !== privacyVal) return false;
      }

      // Version filter
      if (versionVal !== 'ALL') {
        if (versionVal === 'EXPLICIT_LINK' && !r.explicitlyLinked && !r.linkedNewerVersionId && !r.isNewerThanId) return false;
        if (versionVal === 'POTENTIAL_OUTDATED' && r.fileGuardStatus !== 'POTENTIAL_OUTDATED') return false;
        if (versionVal === 'EXACT_DUPLICATE' && r.fileGuardStatus !== 'EXACT_DUPLICATE') return false;
        if (versionVal === 'CLEAN' && (r.fileGuardStatus !== 'CLEAN' || r.explicitlyLinked)) return false;
      }

      return true;
    });

    tableBody.innerHTML = '';

    if (filtered.length === 0) {
      tableEmpty.classList.remove('hidden');
      return;
    }

    tableEmpty.classList.add('hidden');

    filtered.slice().reverse().forEach((r) => {
      const tr = document.createElement('tr');

      const dateStr = formatDateTime(new Date(r.processedAt || r.timestamp));
      const shortHash = Crypto.formatShortHash(r.sha256, 8, 6);
      const sizeStr = formatBytes(r.fileSize);

      // Event Stage Badge
      let stageBadge = '<span class="badge badge-info">Scanned</span>';
      if (r.eventStage === 'IMPORTED') {
        stageBadge = '<span class="badge badge-info">Imported / Indexed</span>';
      } else if (r.eventStage === 'UPLOAD_SELECTED') {
        stageBadge = '<span class="badge badge-info">Upload Selected</span>';
      } else if (r.eventStage === 'UPLOAD_CANCELLED') {
        stageBadge = '<span class="badge badge-danger">Upload Cancelled</span>';
      } else if (r.eventStage === 'UPLOAD_CONTINUED') {
        stageBadge = '<span class="badge badge-warn">Upload Override</span>';
      } else if (r.eventStage === 'UPLOAD_INITIATED' || r.eventStage === 'UPLOAD_CONFIRMED') {
        stageBadge = '<span class="badge badge-clean">Shared / Confirmed</span>';
      }

      // Version Relationship Badge
      let versionBadge = '<span class="badge badge-clean">Clean</span>';
      if (r.linkedNewerFilename || r.linkedNewerVersionId) {
        versionBadge = `<span class="badge badge-warn" title="Newer version exists: ${escapeHtml(r.linkedNewerFilename || 'Linked')}">🔗 Newer: ${escapeHtml(r.linkedNewerFilename || 'Linked')}</span>`;
      } else if (r.isNewerThanFilename || r.isNewerThanId) {
        versionBadge = `<span class="badge badge-clean" title="Supersedes: ${escapeHtml(r.isNewerThanFilename || 'Older')}">🔗 Supersedes: ${escapeHtml(r.isNewerThanFilename || 'Older')}</span>`;
      } else if (r.fileGuardStatus === 'POTENTIAL_OUTDATED') {
        versionBadge = '<span class="badge badge-warn">Outdated Heuristic</span>';
      } else if (r.fileGuardStatus === 'EXACT_DUPLICATE') {
        versionBadge = '<span class="badge badge-warn">Duplicate Fingerprint</span>';
      }

      // Privacy Badge
      let privacyBadge = '<span class="badge badge-clean">Clean</span>';
      if (r.privacyStatus === 'SENSITIVE_DETECTED') {
        const catList = r.detectedCategories && r.detectedCategories.length > 0 ? r.detectedCategories.join(', ') : 'Exposed data';
        privacyBadge = `<span class="badge badge-danger" title="${escapeHtml(catList)}">Sensitive (${r.detectedCategories ? r.detectedCategories.length : 1})</span>`;
      } else if (r.privacyStatus === 'UNSUPPORTED_FORMAT') {
        privacyBadge = '<span class="badge badge-subtle" title="Content scan unavailable for this file type.">Unsupported Format</span>';
      } else if (r.privacyStatus === 'NOT_SCANNED') {
        privacyBadge = '<span class="badge badge-subtle">Not Scanned</span>';
      }

      tr.innerHTML = `
        <td>${dateStr}</td>
        <td>
          <div class="file-cell">
            <span class="file-name">${escapeHtml(r.filename)}</span>
            <span class="file-size">${sizeStr} • ${escapeHtml(r.fileType || 'unknown')}</span>
          </div>
        </td>
        <td>
          <div class="hash-cell">
            <span class="mono-tag" title="${escapeHtml(r.sha256)}">${escapeHtml(shortHash)}</span>
            <button class="btn-copy" data-hash="${escapeHtml(r.sha256)}" title="Copy full SHA-256">📋</button>
          </div>
        </td>
        <td>${stageBadge}</td>
        <td>${versionBadge}</td>
        <td>${privacyBadge}</td>
        <td>${escapeHtml(r.origin || 'Local Preflight')}</td>
        <td>
          <button class="btn btn-sm btn-outline btn-inspect" data-id="${escapeHtml(r.id)}">Inspect</button>
        </td>
      `;

      tableBody.appendChild(tr);
    });

    // Wire copy buttons
    document.querySelectorAll('.btn-copy').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const hash = e.currentTarget.getAttribute('data-hash');
        navigator.clipboard.writeText(hash).then(() => {
          const original = e.currentTarget.textContent;
          e.currentTarget.textContent = '✓';
          setTimeout(() => e.currentTarget.textContent = original, 1200);
        });
      });
    });

    // Wire inspect buttons
    document.querySelectorAll('.btn-inspect').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-id');
        const record = allRecords.find(item => item.id === id);
        if (record) showRecordInspection(record);
      });
    });
  }

  // 5. Real File Import / Indexing Workflow
  btnImportFiles.addEventListener('click', () => {
    bulkImportInput.click();
  });

  bulkImportInput.addEventListener('change', async (e) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const files = Array.from(e.target.files);
    btnImportFiles.disabled = true;
    btnImportFiles.textContent = `Indexing ${files.length} file(s)...`;

    try {
      const imported = await Storage.importFiles(files, {
        source: 'bulk_import',
        origin: 'User Local Drive'
      });
      alert(`✅ Successfully imported and fingerprinted ${imported.length} real file(s) into your persistent database.`);
      await loadDashboard();
    } catch (err) {
      alert(`Import error: ${err.message}`);
    } finally {
      btnImportFiles.disabled = false;
      btnImportFiles.innerHTML = `<span class="icon">📁</span> Import / Index Real Files`;
      bulkImportInput.value = '';
    }
  });

  // 6. Explicit Version Linking Workflow
  btnOpenLinkModal.addEventListener('click', () => {
    if (allRecords.length < 2) {
      alert('Please import or process at least two real files before creating version links.');
      return;
    }

    selectOlderRecord.innerHTML = '<option value="">Select older document...</option>';
    selectNewerRecord.innerHTML = '<option value="">Select newer document...</option>';

    allRecords.forEach(r => {
      const opt1 = document.createElement('option');
      opt1.value = r.id;
      opt1.textContent = `${r.filename} (${formatDateTime(new Date(r.processedAt || r.timestamp))})`;
      selectOlderRecord.appendChild(opt1);

      const opt2 = document.createElement('option');
      opt2.value = r.id;
      opt2.textContent = `${r.filename} (${formatDateTime(new Date(r.processedAt || r.timestamp))})`;
      selectNewerRecord.appendChild(opt2);
    });

    linkVersionModal.classList.remove('hidden');
  });

  btnCloseLinkModal.addEventListener('click', () => linkVersionModal.classList.add('hidden'));
  btnCancelLinkModal.addEventListener('click', () => linkVersionModal.classList.add('hidden'));

  btnConfirmLinkVersion.addEventListener('click', async () => {
    const olderId = selectOlderRecord.value;
    const newerId = selectNewerRecord.value;

    if (!olderId || !newerId) {
      alert('Please select both the older and newer files to establish the version link.');
      return;
    }

    if (olderId === newerId) {
      alert('A file cannot be linked as a newer version of itself.');
      return;
    }

    try {
      await Storage.linkVersions(olderId, newerId);
      linkVersionModal.classList.add('hidden');
      alert('✅ Version relationship confirmed and permanently saved in persistent history.');
      await loadDashboard();
    } catch (err) {
      alert(`Error linking versions: ${err.message}`);
    }
  });

  // 7. Record Inspection Modal
  function showRecordInspection(record) {
    let leakHtml = '<p class="text-muted">No privacy leaks detected (clean text).</p>';
    if (record.privacyStatus === 'UNSUPPORTED_FORMAT') {
      leakHtml = '<p class="text-muted">Content scan unavailable for this file type (binary format).</p>';
    } else if (record.privacyStatus === 'SENSITIVE_DETECTED' && record.leakShieldResult) {
      leakHtml = (record.leakShieldResult.findings || []).map(f => `
        <div class="prop-box" style="border-left: 3px solid #f43f5e; margin-bottom: 6px;">
          <strong>[${escapeHtml((f.severity || 'REVIEW').toUpperCase())}] ${escapeHtml(f.name || f.category)}</strong>
          <div style="font-family: var(--font-mono); font-size: 11px; margin-top: 4px; color: #fca5a5;">
            ${escapeHtml(f.snippet || f.maskedValue || 'Masked')}
          </div>
        </div>
      `).join('');
    }

    let versionLinkHtml = '<p class="text-muted">No explicit version linkage recorded for this file.</p>';
    if (record.linkedNewerFilename || record.linkedNewerVersionId) {
      versionLinkHtml = `
        <div class="prop-box" style="border-left: 3px solid #f59e0b;">
          <strong>🔗 Superseded by Newer Version:</strong> ${escapeHtml(record.linkedNewerFilename || record.linkedNewerVersionId)}
          <p class="text-muted mt-2" style="font-size: 11px;">FileGuard will alert whenever this file is selected in an upload flow.</p>
        </div>
      `;
    } else if (record.isNewerThanFilename || record.isNewerThanId) {
      versionLinkHtml = `
        <div class="prop-box" style="border-left: 3px solid #10b981;">
          <strong>🔗 Registered Replacement For:</strong> ${escapeHtml(record.isNewerThanFilename || record.isNewerThanId)}
          <p class="text-muted mt-2" style="font-size: 11px;">This file is confirmed as the official newer version.</p>
        </div>
      `;
    }

    modalBody.innerHTML = `
      <div class="prop-group">
        <span class="prop-label">Real File Identity & Fingerprint</span>
        <div class="prop-box">
          <div><strong>Filename:</strong> ${escapeHtml(record.filename)}</div>
          <div><strong>File Size:</strong> ${formatBytes(record.fileSize)} (${record.fileSize} bytes)</div>
          <div><strong>MIME Type:</strong> ${escapeHtml(record.fileType)}</div>
          <div><strong>File Last-Modified:</strong> ${record.lastModified || 'Not reported by browser'}</div>
          <div><strong>Local Reference:</strong> ${escapeHtml(record.localRef || '—')}</div>
          <div style="margin-top: 6px;">
            <strong>SHA-256 Fingerprint:</strong><br>
            <span class="mono-tag" style="word-break: break-all;">${escapeHtml(record.sha256)}</span>
          </div>
        </div>
      </div>

      <div class="prop-group">
        <span class="prop-label">Truthful Lifecycle & Event Context</span>
        <div class="prop-box">
          <div><strong>Event Stage:</strong> <span class="badge badge-info">${escapeHtml(record.eventStage || 'SCANNED')}</span></div>
          <div><strong>Source:</strong> ${escapeHtml(record.source || 'manual')}</div>
          <div><strong>Recorded Date:</strong> ${record.processedAt || record.timestamp}</div>
          <div><strong>Origin / Website:</strong> ${escapeHtml(record.origin)}</div>
          <div><strong>Recipient:</strong> ${escapeHtml(record.recipient || 'Not detected (None invented)')}</div>
          <div><strong>FileGuard Status:</strong> ${escapeHtml(record.fileGuardStatus)}</div>
          <div><strong>Notes:</strong> ${escapeHtml(record.notes || '—')}</div>
        </div>
      </div>

      <div class="prop-group">
        <span class="prop-label">Version Relationship Information</span>
        ${versionLinkHtml}
      </div>

      <div class="prop-group">
        <span class="prop-label">Privacy Leak Shield Inspection</span>
        ${leakHtml}
      </div>

      <div class="prop-group">
        <span class="prop-label">Tamper-Evident Hash Chain</span>
        <div class="chain-box">
          <div class="chain-item">
            <span class="label">Previous Hash (prevHash):</span>
            <span class="val">${escapeHtml(record.prevHash)}</span>
          </div>
          <div class="chain-item">
            <span class="label">Record Hash (recordHash):</span>
            <span class="val">${escapeHtml(record.recordHash)}</span>
          </div>
        </div>
      </div>
    `;

    detailsModal.classList.remove('hidden');
  }

  // 8. Modal Listeners
  btnCloseModal.addEventListener('click', () => detailsModal.classList.add('hidden'));
  btnCloseModalBtn.addEventListener('click', () => detailsModal.classList.add('hidden'));

  // Clear History Modal
  btnClearHistory.addEventListener('click', () => confirmClearModal.classList.remove('hidden'));
  btnCancelClear.addEventListener('click', () => confirmClearModal.classList.add('hidden'));
  btnCancelClearBtn.addEventListener('click', () => confirmClearModal.classList.add('hidden'));

  btnConfirmClearBtn.addEventListener('click', async () => {
    await Storage.clearHistory();
    confirmClearModal.classList.add('hidden');
    await loadDashboard();
  });

  // Export JSON
  btnExportJson.addEventListener('click', () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(allRecords, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `fileguard_real_history_${Date.now()}.json`);
    dlAnchor.click();
  });

  // Re-audit buttons
  btnReaudit.addEventListener('click', runChainAudit);
  btnVerifyChain.addEventListener('click', async () => {
    await runChainAudit();
    alert('Cryptographic hash-chain audit completed.');
  });

  // Filter Listeners
  searchInput.addEventListener('input', renderTable);
  filterStage.addEventListener('change', renderTable);
  filterPrivacy.addEventListener('change', renderTable);
  filterVersion.addEventListener('change', renderTable);

  // Formatting helpers
  function formatDateTime(d) {
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
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

  // Run on startup
  await loadDashboard();
});
