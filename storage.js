/**
 * Which One Did I Send? — Central File-History Storage Service
 * Manages persistent real-file records, version relationships,
 * privacy scan results, lifecycle event stages, and tamper-evident hash chaining.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    const crypto = require('./crypto');
    module.exports = factory(crypto);
  } else {
    root.FileGuardStorage = factory(root.FileGuardCrypto);
  }
})(typeof self !== 'undefined' ? self : this, function (Crypto) {
  'use strict';

  const STORAGE_KEY_HISTORY = 'fileguard_history_records';
  const STORAGE_KEY_SETTINGS = 'fileguard_user_settings';
  const STORAGE_KEY_VERSION_LINKS = 'fileguard_version_links';

  // Event Stages (Truthful lifecycle tracking)
  const EVENT_STAGES = {
    IMPORTED: 'IMPORTED',                   // File imported or indexed into database
    SCANNED: 'SCANNED',                     // File processed or preflight scanned
    UPLOAD_SELECTED: 'UPLOAD_SELECTED',     // File selected in an upload or attachment workflow
    UPLOAD_CANCELLED: 'UPLOAD_CANCELLED',   // Upload action cancelled by user after warning
    UPLOAD_CONTINUED: 'UPLOAD_CONTINUED',   // Upload continued with user override
    UPLOAD_INITIATED: 'UPLOAD_INITIATED',   // Upload or sharing action initiated
    UPLOAD_CONFIRMED: 'UPLOAD_CONFIRMED'    // Successful upload visibly confirmed by website
  };

  // Privacy Scan Statuses
  const PRIVACY_STATUS = {
    NOT_SCANNED: 'NOT_SCANNED',
    UNSUPPORTED_FORMAT: 'UNSUPPORTED_FORMAT',
    CLEAN: 'CLEAN',
    SENSITIVE_DETECTED: 'SENSITIVE_DETECTED'
  };

  const DEFAULT_SETTINGS = {
    fileGuardEnabled: true,
    privacyShieldEnabled: true,
    autoScanSupportedTypes: true,
    showInPageModal: true
  };

  /**
   * Universal storage adapter abstraction
   */
  const adapter = {
    async get(key) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise((resolve) => {
          chrome.storage.local.get([key], (result) => resolve(result[key]));
        });
      }
      if (typeof localStorage !== 'undefined') {
        const item = localStorage.getItem(key);
        try {
          return item ? JSON.parse(item) : null;
        } catch (e) {
          return null;
        }
      }
      if (!adapter._memoryStore) adapter._memoryStore = {};
      return adapter._memoryStore[key] || null;
    },

    async set(key, value) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise((resolve) => {
          chrome.storage.local.set({ [key]: value }, resolve);
        });
      }
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(key, JSON.stringify(value));
        return;
      }
      if (!adapter._memoryStore) adapter._memoryStore = {};
      adapter._memoryStore[key] = value;
    },

    async remove(key) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise((resolve) => {
          chrome.storage.local.remove([key], resolve);
        });
      }
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem(key);
        return;
      }
      if (adapter._memoryStore) delete adapter._memoryStore[key];
    }
  };

  /**
   * Get user settings
   */
  async function getSettings() {
    const stored = await adapter.get(STORAGE_KEY_SETTINGS);
    return Object.assign({}, DEFAULT_SETTINGS, stored || {});
  }

  /**
   * Save user settings
   */
  async function updateSettings(newSettings) {
    const current = await getSettings();
    const updated = Object.assign({}, current, newSettings);
    await adapter.set(STORAGE_KEY_SETTINGS, updated);
    return updated;
  }

  /**
   * Retrieve all recorded history entries
   */
  async function getHistory() {
    const records = await adapter.get(STORAGE_KEY_HISTORY);
    return Array.isArray(records) ? records : [];
  }

  /**
   * Retrieve explicit version linkages
   * Format: { [olderRecordId]: newerRecordId }
   */
  async function getVersionLinks() {
    const links = await adapter.get(STORAGE_KEY_VERSION_LINKS);
    return links && typeof links === 'object' ? links : {};
  }

  /**
   * Explicitly link two records in history as older -> newer version
   */
  async function linkVersions(olderRecordId, newerRecordId, userNote = '') {
    if (!olderRecordId || !newerRecordId || olderRecordId === newerRecordId) {
      throw new Error('Valid, distinct older and newer record IDs are required.');
    }

    const history = await getHistory();
    const olderRecord = history.find(r => r.id === olderRecordId);
    const newerRecord = history.find(r => r.id === newerRecordId);

    if (!olderRecord || !newerRecord) {
      throw new Error('One or both records could not be found in history.');
    }

    // Persist in version links dictionary
    const links = await getVersionLinks();
    links[olderRecordId] = newerRecordId;
    await adapter.set(STORAGE_KEY_VERSION_LINKS, links);

    // Update the records' embedded version relationship metadata
    olderRecord.linkedNewerVersionId = newerRecordId;
    olderRecord.linkedNewerFilename = newerRecord.filename;
    olderRecord.explicitlyLinked = true;

    newerRecord.isNewerThanId = olderRecordId;
    newerRecord.isNewerThanFilename = olderRecord.filename;
    newerRecord.explicitlyLinked = true;

    // Re-seal the modified records' hashes
    await recomputeHistoryChain(history);
    await adapter.set(STORAGE_KEY_HISTORY, history);

    return {
      success: true,
      olderFilename: olderRecord.filename,
      newerFilename: newerRecord.filename,
      links
    };
  }

  /**
   * Recompute hash chain across entire history array (used after linking or migrations)
   */
  async function recomputeHistoryChain(history) {
    let prevHash = Crypto.GENESIS_PREV_HASH;
    for (let i = 0; i < history.length; i++) {
      const record = history[i];
      record.prevHash = prevHash;
      record.recordHash = await Crypto.computeRecordHash(prevHash, record);
      prevHash = record.recordHash;
    }
    return history;
  }

  /**
   * Append or update a file activity record with real metadata and cryptographic chaining
   */
  async function recordFileActivity(recordData) {
    const history = await getHistory();
    const versionLinks = await getVersionLinks();

    // Determine previous record hash
    let prevHash = Crypto.GENESIS_PREV_HASH;
    if (history.length > 0) {
      const lastRecord = history[history.length - 1];
      prevHash = lastRecord.recordHash || Crypto.GENESIS_PREV_HASH;
    }

    const id = recordData.id || ('rec_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8));
    const processedAt = recordData.processedAt || new Date().toISOString();

    // Check if an explicit newer version was already registered for this file or record
    const linkedNewerId = recordData.linkedNewerVersionId || versionLinks[id] || null;

    // Normalize privacy scan findings: NEVER store raw secrets
    let safeLeakResult = null;
    let privacyStatus = PRIVACY_STATUS.NOT_SCANNED;
    let detectedCategories = [];

    if (recordData.leakShieldResult) {
      const lr = recordData.leakShieldResult;
      if (!lr.supported) {
        privacyStatus = PRIVACY_STATUS.UNSUPPORTED_FORMAT;
        safeLeakResult = {
          supported: false,
          reason: lr.reason || 'Binary format (content scan unavailable)',
          hasFindings: false,
          findings: []
        };
      } else if (lr.hasFindings) {
        privacyStatus = PRIVACY_STATUS.SENSITIVE_DETECTED;
        detectedCategories = Array.from(new Set(lr.findings.map(f => f.name || f.category)));
        safeLeakResult = {
          supported: true,
          hasFindings: true,
          highestSeverity: lr.highestSeverity,
          totalFindings: lr.totalFindings,
          detectedCategories: detectedCategories,
          findings: lr.findings.map(f => ({
            name: f.name,
            category: f.category,
            severity: f.severity,
            maskedValue: f.maskedValue,
            snippet: f.snippet,
            location: f.location
          }))
        };
      } else {
        privacyStatus = PRIVACY_STATUS.CLEAN;
        safeLeakResult = {
          supported: true,
          hasFindings: false,
          findings: []
        };
      }
    }

    // Build the complete, truthful record object
    const record = {
      id: id,
      filename: recordData.filename || 'unnamed_file',
      fileSize: typeof recordData.fileSize === 'number' ? recordData.fileSize : 0,
      fileType: recordData.fileType || 'application/octet-stream',
      lastModified: recordData.lastModified ? new Date(recordData.lastModified).toISOString() : null,
      sha256: recordData.sha256 || null,
      processedAt: processedAt,
      timestamp: processedAt, // For backwards compatibility
      source: recordData.source || 'manual_selection',
      eventStage: recordData.eventStage || EVENT_STAGES.SCANNED,
      status: recordData.status || 'Processed',
      localRef: recordData.localRef || (recordData.filename ? `local://${recordData.filename}` : null),
      origin: recordData.origin || (typeof window !== 'undefined' ? window.location.origin : 'localhost'),
      recipient: recordData.recipient || null,
      fileGuardStatus: recordData.fileGuardStatus || 'CLEAN',
      linkedNewerVersionId: linkedNewerId,
      isNewerThanId: recordData.isNewerThanId || null,
      explicitlyLinked: !!(linkedNewerId || recordData.isNewerThanId),
      privacyStatus: recordData.privacyStatus || privacyStatus,
      detectedCategories: detectedCategories,
      leakShieldResult: safeLeakResult,
      notes: recordData.notes || '',
      prevHash: prevHash
    };

    // Compute tamper-evident hash
    record.recordHash = await Crypto.computeRecordHash(prevHash, record);

    history.push(record);
    await adapter.set(STORAGE_KEY_HISTORY, history);

    return record;
  }

  /**
   * Bulk import / index real files into history
   * Each file is processed using its real metadata and SHA-256 fingerprint.
   */
  async function importFiles(fileList, options = {}) {
    if (!fileList || fileList.length === 0) return [];
    const results = [];

    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      const sha256 = await Crypto.sha256Hex(file);

      // Check if identical fingerprint already exists
      const existing = await findByFingerprint(sha256);

      const recordData = {
        filename: file.name,
        fileSize: file.size,
        fileType: file.type || 'text/plain',
        lastModified: file.lastModified,
        sha256: sha256,
        source: options.source || 'bulk_import',
        eventStage: EVENT_STAGES.IMPORTED,
        status: existing ? 'Imported (Duplicate Hash)' : 'Imported / Indexed',
        origin: options.origin || (typeof window !== 'undefined' ? window.location.origin : 'local_machine'),
        recipient: options.recipient || null,
        fileGuardStatus: existing ? 'EXACT_DUPLICATE' : 'CLEAN',
        notes: options.notes || 'Imported via user file selector'
      };

      const record = await recordFileActivity(recordData);
      results.push(record);
    }

    return results;
  }

  /**
   * Find an existing record by exact SHA-256 fingerprint
   */
  async function findByFingerprint(sha256) {
    if (!sha256) return null;
    const history = await getHistory();
    return history.find(r => r.sha256 === sha256) || null;
  }

  /**
   * Verify the integrity of the hash chain across all stored records
   */
  async function verifyHistoryChain() {
    const history = await getHistory();

    if (history.length === 0) {
      return {
        isValid: true,
        count: 0,
        message: 'No records stored yet. The genesis chain is ready.'
      };
    }

    let expectedPrevHash = Crypto.GENESIS_PREV_HASH;

    for (let i = 0; i < history.length; i++) {
      const record = history[i];

      if (record.prevHash !== expectedPrevHash) {
        return {
          isValid: false,
          count: history.length,
          brokenIndex: i,
          recordId: record.id,
          reason: `Broken chain link at record #${i + 1} (${record.filename}). Expected prevHash "${expectedPrevHash.slice(0, 10)}...", found "${(record.prevHash || '').slice(0, 10)}...".`
        };
      }

      const computedHash = await Crypto.computeRecordHash(record.prevHash, record);
      if (record.recordHash !== computedHash) {
        return {
          isValid: false,
          count: history.length,
          brokenIndex: i,
          recordId: record.id,
          reason: `Integrity check failed at record #${i + 1} (${record.filename}). Stored hash "${(record.recordHash || '').slice(0, 10)}..." does not match recalculated hash "${computedHash.slice(0, 10)}...". Data was altered.`
        };
      }

      expectedPrevHash = record.recordHash;
    }

    return {
      isValid: true,
      count: history.length,
      lastHash: expectedPrevHash,
      message: `History integrity verified: all ${history.length} records intact and mathematically linked via SHA-256.`
    };
  }

  /**
   * Search and filter history records
   */
  async function queryHistory({
    query = '',
    fingerprint = '',
    origin = '',
    eventStage = 'ALL',
    privacyStatus = 'ALL',
    dateFrom = null,
    dateTo = null
  } = {}) {
    const history = await getHistory();
    const cleanQuery = query.trim().toLowerCase();
    const cleanFp = fingerprint.trim().toLowerCase();
    const cleanOrigin = origin.trim().toLowerCase();

    return history.filter(record => {
      if (cleanQuery) {
        const nameMatch = record.filename && record.filename.toLowerCase().includes(cleanQuery);
        const recipientMatch = record.recipient && record.recipient.toLowerCase().includes(cleanQuery);
        const hashMatch = record.sha256 && record.sha256.toLowerCase().includes(cleanQuery);
        const noteMatch = record.notes && record.notes.toLowerCase().includes(cleanQuery);
        if (!nameMatch && !recipientMatch && !hashMatch && !noteMatch) return false;
      }

      if (cleanFp) {
        if (!record.sha256 || !record.sha256.toLowerCase().includes(cleanFp)) return false;
      }

      if (cleanOrigin) {
        if (!record.origin || !record.origin.toLowerCase().includes(cleanOrigin)) return false;
      }

      if (eventStage && eventStage !== 'ALL') {
        if (record.eventStage !== eventStage) return false;
      }

      if (privacyStatus && privacyStatus !== 'ALL') {
        if (record.privacyStatus !== privacyStatus) return false;
      }

      if (dateFrom && new Date(record.processedAt || record.timestamp) < new Date(dateFrom)) return false;
      if (dateTo && new Date(record.processedAt || record.timestamp) > new Date(dateTo)) return false;

      return true;
    });
  }

  /**
   * Clear all records and links
   */
  async function clearHistory() {
    await adapter.remove(STORAGE_KEY_HISTORY);
    await adapter.remove(STORAGE_KEY_VERSION_LINKS);
    return true;
  }

  return {
    EVENT_STAGES,
    PRIVACY_STATUS,
    getSettings,
    updateSettings,
    getHistory,
    getVersionLinks,
    linkVersions,
    recordFileActivity,
    importFiles,
    findByFingerprint,
    verifyHistoryChain,
    queryHistory,
    clearHistory
  };
});
