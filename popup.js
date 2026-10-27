/**
 * Which One Did I Send? — Popup Controller
 * Connects to unified shared real-file history and honest lifecycle event stages.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const Crypto = window.FileGuardCrypto;
  const PrivacyShield = window.PrivacyLeakShield;
  const FileGuard = window.FileGuardEngine;
  const Storage = window.FileGuardStorage;

  // DOM Elements
  const toggleFileGuard = document.getElementById('toggleFileGuard');
  const togglePrivacyShield = document.getElementById('togglePrivacyShield');
  const globalStatus = document.getElementById('globalStatus');

  const statTotalFiles = document.getElementById('statTotalFiles');
  const statDuplicates = document.getElementById('statDuplicates');
  const statOutdated = document.getElementById('statOutdated');
  const statLeaks = document.getElementById('statLeaks');

  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');

  const scanResultCard = document.getElementById('scanResultCard');
  const resultFilename = document.getElementById('resultFilename');
  const resultBadge = document.getElementById('resultBadge');
  const resultSha256 = document.getElementById('resultSha256');
  const resultFileGuard = document.getElementById('resultFileGuard');
  const resultPrivacyShield = document.getElementById('resultPrivacyShield');
  const findingsBox = document.getElementById('findingsBox');
  const btnLogPreflight = document.getElementById('btnLogPreflight');
  const btnResetScan = document.getElementById('btnResetScan');

  const activityList = document.getElementById('activityList');
  const btnOpenDashboard = document.getElementById('btnOpenDashboard');
  const btnOpenDashboardLink = document.getElementById('btnOpenDashboardLink');
  const btnOpenDemo = document.getElementById('btnOpenDemo');

  let currentScannedData = null;

  // 1. Load Initial Settings & Data
  async function refreshDashboardStats() {
    const settings = await Storage.getSettings();
    toggleFileGuard.checked = settings.fileGuardEnabled;
    togglePrivacyShield.checked = settings.privacyShieldEnabled;

    const history = await Storage.getHistory();
    statTotalFiles.textContent = history.length;

    let duplicatesCount = 0;
    let outdatedCount = 0;
    let leaksCount = 0;

    history.forEach(r => {
      if (r.fileGuardStatus === 'EXACT_DUPLICATE') duplicatesCount++;
      if (r.fileGuardStatus === 'POTENTIAL_OUTDATED' || r.linkedNewerVersionId) outdatedCount++;
      if (r.privacyStatus === 'SENSITIVE_DETECTED' || (r.leakShieldResult && r.leakShieldResult.hasFindings)) leaksCount++;
    });

    statDuplicates.textContent = duplicatesCount;
    statOutdated.textContent = outdatedCount;
    statLeaks.textContent = leaksCount;

    renderRecentActivity(history);
  }

  function renderRecentActivity(history) {
    activityList.innerHTML = '';
    if (!history || history.length === 0) {
      activityList.innerHTML = '<div class="empty-state">No real files tracked yet. Try the preflight scanner above!</div>';
      return;
    }

    const recent = history.slice(-3).reverse();
    recent.forEach(r => {
      const item = document.createElement('div');
      item.className = 'activity-item';

      let badgeClass = 'badge-clean';
      let badgeLabel = r.eventStage === 'IMPORTED' ? 'Imported' : 'Scanned';

      if (r.privacyStatus === 'SENSITIVE_DETECTED' || (r.leakShieldResult && r.leakShieldResult.hasFindings)) {
        badgeClass = 'badge-danger';
        badgeLabel = 'Leak Shielded';
      } else if (r.linkedNewerVersionId || r.fileGuardStatus === 'POTENTIAL_OUTDATED') {
        badgeClass = 'badge-warning';
        badgeLabel = 'Outdated';
      } else if (r.fileGuardStatus === 'EXACT_DUPLICATE') {
        badgeClass = 'badge-warning';
        badgeLabel = 'Duplicate';
      }

      const timeAgo = formatTimeAgo(new Date(r.processedAt || r.timestamp));

      item.innerHTML = `
        <div class="activity-main">
          <span class="activity-filename" title="${escapeHtml(r.filename)}">${escapeHtml(r.filename)}</span>
          <span class="activity-meta">${timeAgo} • ${escapeHtml(r.eventStage || 'Scanned')}</span>
        </div>
        <span class="badge ${badgeClass}">${badgeLabel}</span>
      `;
      activityList.appendChild(item);
    });
  }

  // 2. Settings Toggles
  toggleFileGuard.addEventListener('change', async (e) => {
    await Storage.updateSettings({ fileGuardEnabled: e.target.checked });
  });

  togglePrivacyShield.addEventListener('change', async (e) => {
    await Storage.updateSettings({ privacyShieldEnabled: e.target.checked });
  });

  // 3. Drop Zone and File Selection
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  // 4. File Analysis Execution on Real User File
  async function handleFileSelected(file) {
    if (!file) return;

    resultFilename.textContent = file.name;
    resultSha256.textContent = 'Calculating SHA-256...';
    resultFileGuard.textContent = 'Checking stored versions...';
    resultPrivacyShield.textContent = 'Scanning file contents...';
    findingsBox.classList.add('hidden');
    findingsBox.innerHTML = '';
    scanResultCard.classList.remove('hidden');

    try {
      // 1. Calculate Real SHA-256
      const sha256 = await Crypto.sha256Hex(file);
      resultSha256.textContent = Crypto.formatShortHash(sha256, 10, 8);
      resultSha256.title = sha256;

      // 2. Run Privacy Leak Shield on real contents
      const leakResult = await PrivacyShield.scanFile(file);
      let leakStatusText = 'No sensitive data detected';
      let hasLeaks = false;

      if (!leakResult.supported) {
        leakStatusText = 'Content scan unavailable for this file type.';
      } else if (leakResult.hasFindings) {
        hasLeaks = true;
        leakStatusText = `⚠️ ${leakResult.totalFindings} issue(s) detected (${leakResult.highestSeverity.toUpperCase()})`;

        findingsBox.classList.remove('hidden');
        leakResult.findings.forEach(f => {
          const div = document.createElement('div');
          div.className = 'finding-item';
          div.innerHTML = `
            <div class="finding-title">[${escapeHtml(f.severity.toUpperCase())}] ${escapeHtml(f.name)}</div>
            <div class="finding-snippet">${escapeHtml(f.snippet)}</div>
          `;
          findingsBox.appendChild(div);
        });
      }
      resultPrivacyShield.textContent = leakStatusText;

      // 3. Run FileGuard against real history & explicit version links
      const history = await Storage.getHistory();
      const versionLinks = await Storage.getVersionLinks();
      const fileData = {
        name: file.name,
        size: file.size,
        sha256: sha256,
        lastModified: file.lastModified
      };
      const fgResult = FileGuard.analyzeFile(fileData, history, versionLinks);

      let fgStatusText = 'No known newer version was found in your recorded file history.';
      if (fgResult.status === 'EXACT_DUPLICATE') {
        fgStatusText = `⚠️ Duplicate: identical content previously recorded (${fgResult.matchedRecord.filename})`;
      } else if (fgResult.status === 'POTENTIAL_OUTDATED') {
        const linkTag = fgResult.isExplicitLink ? '[Explicit Link] ' : '';
        fgStatusText = `⚠️ Newer version exists: ${linkTag}"${fgResult.suggestedFile.name}"`;
      }
      resultFileGuard.textContent = fgStatusText;

      // 4. Update overall Result Badge
      if (hasLeaks) {
        resultBadge.className = 'result-badge badge-danger';
        resultBadge.textContent = 'PRIVACY RISK';
      } else if (fgResult.status === 'POTENTIAL_OUTDATED') {
        resultBadge.className = 'result-badge badge-warning';
        resultBadge.textContent = 'OUTDATED';
      } else if (fgResult.status === 'EXACT_DUPLICATE') {
        resultBadge.className = 'result-badge badge-warning';
        resultBadge.textContent = 'DUPLICATE';
      } else {
        resultBadge.className = 'result-badge badge-clean';
        resultBadge.textContent = 'SAFE / CLEAN';
      }

      currentScannedData = {
        filename: file.name,
        fileSize: file.size,
        fileType: file.type || 'text/plain',
        lastModified: file.lastModified,
        sha256: sha256,
        source: 'manual_preflight',
        eventStage: Storage.EVENT_STAGES.SCANNED,
        status: hasLeaks ? 'Preflight (Sensitive Detected)' : (fgResult.status === 'POTENTIAL_OUTDATED' ? 'Preflight (Outdated Version)' : 'Preflight Checked (Clean)'),
        origin: 'Local Extension Preflight',
        fileGuardStatus: fgResult.status,
        leakShieldResult: leakResult,
        notes: 'Preflight scanned via popup'
      };

    } catch (err) {
      console.error('Scan error:', err);
      resultBadge.className = 'result-badge badge-danger';
      resultBadge.textContent = 'ERROR';
      resultSha256.textContent = 'Error computing fingerprint';
      resultFileGuard.textContent = err.message;
    }
  }

  // 5. Log preflight record into persistent shared history chain
  btnLogPreflight.addEventListener('click', async () => {
    if (!currentScannedData) return;
    btnLogPreflight.disabled = true;
    btnLogPreflight.textContent = 'Recording...';

    await Storage.recordFileActivity(currentScannedData);
    await refreshDashboardStats();

    btnLogPreflight.textContent = 'Recorded ✓';
    setTimeout(() => {
      btnLogPreflight.disabled = false;
      btnLogPreflight.textContent = 'Record in History';
    }, 1500);
  });

  btnResetScan.addEventListener('click', () => {
    scanResultCard.classList.add('hidden');
    fileInput.value = '';
    currentScannedData = null;
  });

  // 6. Navigation Actions
  function openDashboardPage() {
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html') });
    } else {
      window.open('../dashboard/dashboard.html', '_blank');
    }
  }

  btnOpenDashboard.addEventListener('click', openDashboardPage);
  btnOpenDashboardLink.addEventListener('click', openDashboardPage);

  btnOpenDemo.addEventListener('click', () => {
    const demoUrl = 'http://localhost:3000/demo/index.html';
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: demoUrl });
    } else {
      window.open('../demo/index.html', '_blank');
    }
  });

  // Helper formatting utilities
  function formatTimeAgo(date) {
    if (isNaN(date.getTime())) return 'Recently';
    const now = new Date();
    const sec = Math.floor((now - date) / 1000);
    if (sec < 60) return 'Just now';
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hours = Math.floor(min / 60);
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
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

  // Initial load
  await refreshDashboardStats();
});
