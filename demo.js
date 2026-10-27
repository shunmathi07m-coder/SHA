/**
 * Which One Did I Send? — Real-File Demonstration Controller
 * All 4 scenarios use real files, real SHA-256 fingerprints,
 * real content scanning, and the central shared persistent history.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const Crypto = window.FileGuardCrypto;
  const PrivacyShield = window.PrivacyLeakShield;
  const FileGuard = window.FileGuardEngine;
  const Storage = window.FileGuardStorage;

  // DOM Elements
  const btnRunSafe = document.getElementById('btnRunSafe');
  const btnRunOutdated = document.getElementById('btnRunOutdated');
  const btnRunSensitive = document.getElementById('btnRunSensitive');
  const btnRunDuplicate = document.getElementById('btnRunDuplicate');

  const btnDemoBulkImport = document.getElementById('btnDemoBulkImport');
  const demoBulkImportInput = document.getElementById('demoBulkImportInput');
  const btnDemoLinkVersions = document.getElementById('btnDemoLinkVersions');

  const demoDropZone = document.getElementById('demoDropZone');
  const demoFileInput = document.getElementById('demoFileInput');
  const recipientInput = document.getElementById('recipientInput');
  const fileStatusPreview = document.getElementById('fileStatusPreview');
  const previewFilename = document.getElementById('previewFilename');
  const previewSize = document.getElementById('previewSize');
  const previewLastModified = document.getElementById('previewLastModified');
  const previewHash = document.getElementById('previewHash');
  const btnSimulateShare = document.getElementById('btnSimulateShare');
  const btnResetForm = document.getElementById('btnResetForm');

  const verdictBadge = document.getElementById('verdictBadge');
  const verdictSummary = document.getElementById('verdictSummary');
  const demoFindingsContainer = document.getElementById('demoFindingsContainer');
  const demoFindingsList = document.getElementById('demoFindingsList');
  const demoVersionContainer = document.getElementById('demoVersionContainer');
  const demoComparisonDetails = document.getElementById('demoComparisonDetails');
  const demoOutcomeBox = document.getElementById('demoOutcomeBox');
  const demoOutcomeText = document.getElementById('demoOutcomeText');

  const demoTableBody = document.getElementById('demoTableBody');
  const historyCounter = document.getElementById('historyCounter');
  const demoSearchInput = document.getElementById('demoSearchInput');
  const btnRefreshDemoTable = document.getElementById('btnRefreshDemoTable');
  const btnDemoClearHistory = document.getElementById('btnDemoClearHistory');

  const demoLinkModal = document.getElementById('demoLinkModal');
  const demoSelectOlder = document.getElementById('demoSelectOlder');
  const demoSelectNewer = document.getElementById('demoSelectNewer');
  const btnCloseDemoLink = document.getElementById('btnCloseDemoLink');
  const btnCancelDemoLink = document.getElementById('btnCancelDemoLink');
  const btnConfirmDemoLink = document.getElementById('btnConfirmDemoLink');

  let activeRealFile = null;
  let activeAnalysis = null;

  // 1. Initial Load from Persistent Storage
  await refreshActivityTable();

  /**
   * Helper to fetch an actual sample file from disk as a real File object
   */
  async function fetchRealSampleFile(samplePath, filename) {
    const res = await fetch(samplePath);
    if (!res.ok) {
      throw new Error(`Failed to load real sample file at ${samplePath}`);
    }
    const blob = await res.blob();
    return new File([blob], filename, {
      type: blob.type || 'text/plain',
      lastModified: Date.now()
    });
  }

  // 2. Scenario 1: Normal File Processing (Real Safe File)
  btnRunSafe.addEventListener('click', async () => {
    try {
      btnRunSafe.disabled = true;
      btnRunSafe.textContent = 'Loading real file...';
      const file = await fetchRealSampleFile('samples/safe_meeting_notes.txt', 'safe_meeting_notes.txt');
      recipientInput.value = 'team-sync@company.internal';
      await loadAndAnalyzeFile(file, 'Scenario 1: Normal File Processing');
    } catch (err) {
      alert(`Error loading real sample: ${err.message}`);
    } finally {
      btnRunSafe.disabled = false;
      btnRunSafe.textContent = 'Load Real Safe Sample';
    }
  });

  // 3. Scenario 2: FileGuard Version Detection (Real Versioned Files)
  btnRunOutdated.addEventListener('click', async () => {
    try {
      btnRunOutdated.disabled = true;
      btnRunOutdated.textContent = 'Indexing real files...';

      // 1. Fetch real Assignment_v2_final.txt from disk
      const v2File = await fetchRealSampleFile('samples/Assignment_v2_final.txt', 'Assignment_v2_final.txt');
      const v2Hash = await Crypto.sha256Hex(v2File);

      // Check if v2 is already in history, otherwise index it
      let v2Record = await Storage.findByFingerprint(v2Hash);
      if (!v2Record) {
        v2Record = await Storage.recordFileActivity({
          filename: 'Assignment_v2_final.txt',
          fileSize: v2File.size,
          fileType: 'text/plain',
          lastModified: v2File.lastModified,
          sha256: v2Hash,
          origin: window.location.origin,
          recipient: 'professor@university.edu',
          source: 'real_file_import',
          eventStage: Storage.EVENT_STAGES.IMPORTED,
          status: 'Imported (Final Version)',
          fileGuardStatus: 'CLEAN',
          notes: 'Real final version indexed in persistent database'
        });
      }

      // 2. Fetch real Assignment_v1_draft.txt from disk
      const v1File = await fetchRealSampleFile('samples/Assignment_v1_draft.txt', 'Assignment_v1_draft.txt');
      recipientInput.value = 'professor@university.edu';

      // Load and analyze the draft file against real history
      await loadAndAnalyzeFile(v1File, 'Scenario 2: Real FileGuard Version Check');
      await refreshActivityTable();
    } catch (err) {
      alert(`Error running version scenario: ${err.message}`);
    } finally {
      btnRunOutdated.disabled = false;
      btnRunOutdated.textContent = 'Test Real Version Check';
    }
  });

  // 4. Scenario 3: Privacy Leak Shield (Real Sensitive File)
  btnRunSensitive.addEventListener('click', async () => {
    try {
      btnRunSensitive.disabled = true;
      btnRunSensitive.textContent = 'Loading real file...';
      const file = await fetchRealSampleFile('samples/sensitive_credentials.txt', 'sensitive_credentials.txt');
      recipientInput.value = 'external-partner@cloud-vendor.org';
      await loadAndAnalyzeFile(file, 'Scenario 3: Privacy Leak Shield');
    } catch (err) {
      alert(`Error loading real sensitive file: ${err.message}`);
    } finally {
      btnRunSensitive.disabled = false;
      btnRunSensitive.textContent = 'Load Real Sensitive Sample';
    }
  });

  // 5. Scenario 4: Exact Duplicate Fingerprint
  btnRunDuplicate.addEventListener('click', async () => {
    try {
      btnRunDuplicate.disabled = true;
      btnRunDuplicate.textContent = 'Processing real duplicate...';

      // 1. Fetch real safe_meeting_notes.txt as original
      const originalFile = await fetchRealSampleFile('samples/safe_meeting_notes.txt', 'safe_meeting_notes.txt');
      const hash = await Crypto.sha256Hex(originalFile);

      // Ensure original is registered in persistent database
      let originalRecord = await Storage.findByFingerprint(hash);
      if (!originalRecord) {
        originalRecord = await Storage.recordFileActivity({
          filename: 'safe_meeting_notes.txt',
          fileSize: originalFile.size,
          fileType: 'text/plain',
          lastModified: originalFile.lastModified,
          sha256: hash,
          origin: window.location.origin,
          recipient: 'team-sync@company.internal',
          source: 'real_file_import',
          eventStage: Storage.EVENT_STAGES.IMPORTED,
          status: 'Imported (Original Document)',
          fileGuardStatus: 'CLEAN',
          notes: 'Original document registered'
        });
      }

      // 2. Create second File object with identical real content but renamed
      const renamedFile = new File([await originalFile.text()], 'safe_meeting_notes_COPY_RENAMED.txt', {
        type: 'text/plain',
        lastModified: Date.now()
      });
      recipientInput.value = 'department-head@company.internal';

      await loadAndAnalyzeFile(renamedFile, 'Scenario 4: Duplicate Content Hash Check');
      await refreshActivityTable();
    } catch (err) {
      alert(`Error running duplicate scenario: ${err.message}`);
    } finally {
      btnRunDuplicate.disabled = false;
      btnRunDuplicate.textContent = 'Test Duplicate Fingerprint';
    }
  });

  // 6. Bulk Import Real Files from User Computer
  btnDemoBulkImport.addEventListener('click', () => {
    demoBulkImportInput.click();
  });

  demoBulkImportInput.addEventListener('change', async (e) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const files = Array.from(e.target.files);
    btnDemoBulkImport.disabled = true;
    btnDemoBulkImport.textContent = `Indexing ${files.length} real file(s)...`;

    try {
      const imported = await Storage.importFiles(files, {
        source: 'demo_page_import',
        origin: 'User Local Drive'
      });
      alert(`✅ Successfully imported and fingerprinted ${imported.length} real file(s) into persistent shared storage.`);
      await refreshActivityTable();
    } catch (err) {
      alert(`Import error: ${err.message}`);
    } finally {
      btnDemoBulkImport.disabled = false;
      btnDemoBulkImport.innerHTML = `<span class="icon">📁</span> Import / Index Real Files`;
      demoBulkImportInput.value = '';
    }
  });

  // 7. Explicit Version Linking on Demo Page
  btnDemoLinkVersions.addEventListener('click', async () => {
    const history = await Storage.getHistory();
    if (history.length < 2) {
      alert('Please import or process at least two real files before establishing version links.');
      return;
    }

    demoSelectOlder.innerHTML = '<option value="">Select older document...</option>';
    demoSelectNewer.innerHTML = '<option value="">Select newer document...</option>';

    history.forEach(r => {
      const opt1 = document.createElement('option');
      opt1.value = r.id;
      opt1.textContent = `${r.filename} (${new Date(r.processedAt || r.timestamp).toLocaleTimeString()})`;
      demoSelectOlder.appendChild(opt1);

      const opt2 = document.createElement('option');
      opt2.value = r.id;
      opt2.textContent = `${r.filename} (${new Date(r.processedAt || r.timestamp).toLocaleTimeString()})`;
      demoSelectNewer.appendChild(opt2);
    });

    demoLinkModal.classList.remove('hidden');
  });

  btnCloseDemoLink.addEventListener('click', () => demoLinkModal.classList.add('hidden'));
  btnCancelDemoLink.addEventListener('click', () => demoLinkModal.classList.add('hidden'));

  btnConfirmDemoLink.addEventListener('click', async () => {
    const olderId = demoSelectOlder.value;
    const newerId = demoSelectNewer.value;

    if (!olderId || !newerId) {
      alert('Please select both the older and newer files.');
      return;
    }
    if (olderId === newerId) {
      alert('A file cannot be linked as a newer version of itself.');
      return;
    }

    try {
      await Storage.linkVersions(olderId, newerId);
      demoLinkModal.classList.add('hidden');
      alert('✅ Version relationship linked and saved in persistent shared history.');
      await refreshActivityTable();
    } catch (err) {
      alert(`Error linking versions: ${err.message}`);
    }
  });

  // 8. Real-File Selection via Picker or Drag & Drop
  demoDropZone.addEventListener('click', () => demoFileInput.click());

  demoDropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    demoDropZone.classList.add('dragover');
  });

  demoDropZone.addEventListener('dragleave', () => {
    demoDropZone.classList.remove('dragover');
  });

  demoDropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    demoDropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await loadAndAnalyzeFile(e.dataTransfer.files[0], 'User Dropped Real File');
    }
  });

  demoFileInput.addEventListener('change', async (e) => {
    if (e.target.files && e.target.files.length > 0) {
      await loadAndAnalyzeFile(e.target.files[0], 'User Selected Real File');
    }
  });

  // 9. Core Real-File Inspection Pipeline
  async function loadAndAnalyzeFile(file, sourceLabel = 'Real File') {
    activeRealFile = file;

    // Update form preview
    previewFilename.textContent = file.name;
    previewSize.textContent = formatBytes(file.size);
    previewLastModified.textContent = file.lastModified
      ? new Date(file.lastModified).toLocaleString()
      : 'Not reported by browser';
    fileStatusPreview.classList.remove('hidden');
    previewHash.textContent = 'Calculating real SHA-256 fingerprint via Web Crypto...';

    // Reset verdict boxes
    demoFindingsContainer.classList.add('hidden');
    demoFindingsList.innerHTML = '';
    demoVersionContainer.classList.add('hidden');
    demoComparisonDetails.innerHTML = '';
    demoOutcomeBox.classList.add('hidden');

    // 1. Calculate Real SHA-256
    const sha256 = await Crypto.sha256Hex(file);
    previewHash.textContent = `SHA-256: ${sha256}`;

    // 2. Scan Privacy Leak Shield on actual file content
    const leakResult = await PrivacyShield.scanFile(file);

    // 3. Scan FileGuard against persistent shared history & explicit version links
    const history = await Storage.getHistory();
    const versionLinks = await Storage.getVersionLinks();
    const fileMeta = {
      name: file.name,
      size: file.size,
      sha256: sha256,
      lastModified: file.lastModified
    };
    const fgResult = FileGuard.analyzeFile(fileMeta, history, versionLinks);

    activeAnalysis = {
      file,
      sha256,
      leakResult,
      fgResult,
      sourceLabel
    };

    renderVerdict(activeAnalysis);
  }

  function renderVerdict({ file, sha256, leakResult, fgResult }) {
    const hasLeaks = leakResult.hasFindings;
    const isOutdated = fgResult.status === 'POTENTIAL_OUTDATED';
    const isDupe = fgResult.status === 'EXACT_DUPLICATE';

    if (!leakResult.supported) {
      verdictBadge.className = 'badge badge-info';
      verdictBadge.textContent = 'UNSUPPORTED FORMAT';
      verdictSummary.innerHTML = `ℹ️ <strong>Format Note:</strong> Content scan unavailable for this file type (${escapeHtml(file.type || 'binary')}). Fingerprinting and version tracking remain fully active.`;
    } else if (hasLeaks) {
      verdictBadge.className = 'badge badge-danger';
      verdictBadge.textContent = `LEAK DETECTED (${leakResult.highestSeverity.toUpperCase()})`;
      verdictSummary.innerHTML = `⚠️ <strong>Privacy Leak Shield Triggered:</strong> Found ${leakResult.totalFindings} sensitive item(s) in actual file contents. Values are safely masked below.`;

      demoFindingsContainer.classList.remove('hidden');
      demoFindingsList.innerHTML = leakResult.findings.map(f => `
        <div class="finding-row">
          <div class="finding-name">• [${escapeHtml(f.severity.toUpperCase())}] ${escapeHtml(f.name)}</div>
          <div class="finding-code">${escapeHtml(f.snippet)}</div>
        </div>
      `).join('');
    } else if (isOutdated) {
      verdictBadge.className = 'badge badge-warn';
      verdictBadge.textContent = 'OUTDATED VERSION';
      const linkTag = fgResult.isExplicitLink ? '<strong>[Confirmed Link]</strong> ' : '';
      verdictSummary.innerHTML = `⚠️ <strong>FileGuard Warning:</strong> ${linkTag}A newer version was found in your recorded history: <em>${escapeHtml(fgResult.suggestedFile.name)}</em>.`;

      demoVersionContainer.classList.remove('hidden');
      demoComparisonDetails.innerHTML = `
        <div><strong>Selected File:</strong> ${escapeHtml(file.name)} (${formatBytes(file.size)})</div>
        <div><strong>Recorded Newer Version:</strong> ${escapeHtml(fgResult.suggestedFile.name)} (${formatBytes(fgResult.suggestedFile.size)})</div>
        <div style="margin-top: 4px; color: #fde68a;"><strong>Detection Reason:</strong> ${escapeHtml(fgResult.reason)}</div>
      `;
    } else if (isDupe) {
      verdictBadge.className = 'badge badge-warn';
      verdictBadge.textContent = 'EXACT DUPLICATE';
      verdictSummary.innerHTML = `⚡ <strong>Duplicate Content Detected:</strong> Identical content was already recorded as <em>"${escapeHtml(fgResult.matchedRecord.filename)}"</em> on ${new Date(fgResult.matchedRecord.processedAt || fgResult.matchedRecord.timestamp).toLocaleString()}.`;
    } else {
      verdictBadge.className = 'badge badge-clean';
      verdictBadge.textContent = 'SAFE / VERIFIED';
      verdictSummary.innerHTML = `✅ <strong>All Checks Passed:</strong> Real SHA-256 fingerprint verified. No sensitive leaks detected in text content, and no known newer version was found in your recorded file history.`;
    }
  }

  // 10. Simulated Sharing / Processing Execution
  btnSimulateShare.addEventListener('click', async () => {
    if (!activeRealFile || !activeAnalysis) {
      alert('Please select or load a real document first.');
      return;
    }

    const { file, sha256, leakResult, fgResult } = activeAnalysis;
    const recipient = recipientInput.value.trim() || null;
    const hasIssue = leakResult.hasFindings || fgResult.status === 'POTENTIAL_OUTDATED' || fgResult.status === 'EXACT_DUPLICATE';

    if (hasIssue) {
      const issueType = leakResult.hasFindings ? 'Sensitive Information Leaks' : 'FileGuard Warning (Duplicate or Outdated Version)';
      const userChoice = confirm(`⚠️ [WHICH ONE DID I SEND? WARNING]\n\nIssues were detected in this document:\n- ${issueType}\n\nDo you want to CANCEL sharing (Recommended)?\n\nClick OK to CANCEL sharing.\nClick Cancel to CONTINUE ANYWAY.`);

      if (userChoice) {
        // User CANCELLED
        await recordAction(
          Storage.EVENT_STAGES.UPLOAD_CANCELLED,
          'Upload Cancelled (Blocked)',
          'User cancelled sharing following shield warning.'
        );
        demoOutcomeBox.classList.remove('hidden');
        demoOutcomeBox.style.background = 'rgba(244, 63, 94, 0.15)';
        demoOutcomeBox.style.borderColor = 'rgba(244, 63, 94, 0.4)';
        demoOutcomeText.innerHTML = `🛑 <strong>Upload Cancelled:</strong> Sharing was halted. Stored in persistent history with stage <code>UPLOAD_CANCELLED</code>.`;
        return;
      } else {
        // User CONTINUED
        await recordAction(
          Storage.EVENT_STAGES.UPLOAD_CONTINUED,
          'Upload Continued (Override)',
          'User explicitly continued sharing despite warning.'
        );
        demoOutcomeBox.classList.remove('hidden');
        demoOutcomeBox.style.background = 'rgba(245, 158, 11, 0.15)';
        demoOutcomeBox.style.borderColor = 'rgba(245, 158, 11, 0.4)';
        demoOutcomeText.innerHTML = `⚠️ <strong>Upload Continued:</strong> User authorized sharing with override. Stored in persistent history with stage <code>UPLOAD_CONTINUED</code>.`;
        return;
      }
    }

    // Clean File Shared
    await recordAction(
      Storage.EVENT_STAGES.UPLOAD_INITIATED,
      'Upload Initiated (Clean)',
      'Clean file sharing simulated successfully.'
    );
    demoOutcomeBox.classList.remove('hidden');
    demoOutcomeBox.style.background = 'rgba(16, 185, 129, 0.15)';
    demoOutcomeBox.style.borderColor = 'rgba(16, 185, 129, 0.4)';
    demoOutcomeText.innerHTML = `✅ <strong>Action Processed:</strong> Real document successfully recorded in persistent shared history.`;
  });

  async function recordAction(stage, statusLabel, notes) {
    const { file, sha256, leakResult, fgResult } = activeAnalysis;
    await Storage.recordFileActivity({
      filename: file.name,
      fileSize: file.size,
      fileType: file.type || 'text/plain',
      lastModified: file.lastModified,
      sha256: sha256,
      origin: window.location.origin,
      recipient: recipientInput.value.trim() || null,
      source: 'demo_workflow',
      eventStage: stage,
      status: statusLabel,
      fileGuardStatus: fgResult.status,
      leakShieldResult: leakResult,
      notes: notes
    });
    await refreshActivityTable();
  }

  // 11. Reset Form
  btnResetForm.addEventListener('click', () => {
    activeRealFile = null;
    activeAnalysis = null;
    demoFileInput.value = '';
    recipientInput.value = '';
    fileStatusPreview.classList.add('hidden');
    demoFindingsContainer.classList.add('hidden');
    demoVersionContainer.classList.add('hidden');
    demoOutcomeBox.classList.add('hidden');
    verdictBadge.className = 'badge';
    verdictBadge.textContent = 'Ready';
    verdictSummary.textContent = 'Choose a real file from your computer or click one of the real sample scenarios above to run live analysis.';
  });

  // 12. Refresh Shared Persistent Activity Table
  async function refreshActivityTable() {
    const history = await Storage.getHistory();
    historyCounter.textContent = `(${history.length} records in shared database)`;

    const query = demoSearchInput ? demoSearchInput.value.trim().toLowerCase() : '';

    const filtered = history.filter(r => {
      if (!query) return true;
      const nameMatch = r.filename && r.filename.toLowerCase().includes(query);
      const hashMatch = r.sha256 && r.sha256.toLowerCase().includes(query);
      const stageMatch = r.eventStage && r.eventStage.toLowerCase().includes(query);
      return nameMatch || hashMatch || stageMatch;
    });

    demoTableBody.innerHTML = '';

    if (filtered.length === 0) {
      demoTableBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No records match your search filter.</td></tr>';
      return;
    }

    filtered.slice().reverse().slice(0, 15).forEach(r => {
      const tr = document.createElement('tr');
      const timeStr = new Date(r.processedAt || r.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const shortHash = Crypto.formatShortHash(r.sha256, 8, 6);

      let stageBadge = '<span class="badge badge-info">Scanned</span>';
      if (r.eventStage === 'IMPORTED') stageBadge = '<span class="badge badge-info">Imported</span>';
      else if (r.eventStage === 'UPLOAD_SELECTED') stageBadge = '<span class="badge badge-info">Selected</span>';
      else if (r.eventStage === 'UPLOAD_CANCELLED') stageBadge = '<span class="badge badge-danger">Cancelled</span>';
      else if (r.eventStage === 'UPLOAD_CONTINUED') stageBadge = '<span class="badge badge-warn">Overridden</span>';
      else if (r.eventStage === 'UPLOAD_INITIATED' || r.eventStage === 'UPLOAD_CONFIRMED') stageBadge = '<span class="badge badge-clean">Shared</span>';

      let vBadge = '<span class="badge badge-clean">Clean</span>';
      if (r.linkedNewerFilename || r.linkedNewerVersionId) vBadge = `<span class="badge badge-warn">🔗 Newer Exists</span>`;
      else if (r.isNewerThanFilename || r.isNewerThanId) vBadge = `<span class="badge badge-clean">🔗 Supersedes</span>`;
      else if (r.fileGuardStatus === 'POTENTIAL_OUTDATED') vBadge = '<span class="badge badge-warn">Outdated</span>';
      else if (r.fileGuardStatus === 'EXACT_DUPLICATE') vBadge = '<span class="badge badge-warn">Duplicate</span>';

      let pBadge = '<span class="badge badge-clean">Clean</span>';
      if (r.privacyStatus === 'SENSITIVE_DETECTED') pBadge = '<span class="badge badge-danger">Sensitive</span>';
      else if (r.privacyStatus === 'UNSUPPORTED_FORMAT') pBadge = '<span class="badge badge-subtle">Unsupported</span>';

      tr.innerHTML = `
        <td>${timeStr}</td>
        <td><strong>${escapeHtml(r.filename)}</strong></td>
        <td><code style="color: #93c5fd;">${escapeHtml(shortHash)}</code></td>
        <td>${stageBadge}</td>
        <td>${vBadge}</td>
        <td>${pBadge}</td>
        <td>${escapeHtml(r.recipient || '—')}</td>
      `;
      demoTableBody.appendChild(tr);
    });
  }

  btnRefreshDemoTable.addEventListener('click', refreshActivityTable);
  if (demoSearchInput) demoSearchInput.addEventListener('input', refreshActivityTable);

  // Clear History
  btnDemoClearHistory.addEventListener('click', async () => {
    if (confirm('Are you sure you want to delete all records from the shared persistent history?')) {
      await Storage.clearHistory();
      await refreshActivityTable();
      alert('Persistent history cleared.');
    }
  });

  // Formatting helpers
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
});
