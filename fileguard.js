/**
 * Which One Did I Send? — FileGuard Engine
 * Wrong-version prevention & duplicate detection using real shared history.
 * 
 * - Exact duplicate matching via SHA-256 fingerprints
 * - Explicitly linked newer version resolution
 * - Heuristic version relationship detection (v1 vs v2, draft vs final, timestamps)
 * - Honest messaging when no newer version is known
 * - Text/metadata comparison for candidate inspection
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.FileGuardEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Version rank weights for common status keywords
  const KEYWORD_RANKS = {
    'initial': 10,
    'draft': 15,
    'wip': 15,
    'preview': 20,
    'review': 25,
    'v1': 30,
    'ver1': 30,
    'version1': 30,
    'v2': 40,
    'ver2': 40,
    'version2': 40,
    'v3': 50,
    'ver3': 50,
    'version3': 50,
    'final': 60,
    'corrected': 65,
    'revised': 70,
    'updated': 75,
    'latest': 80
  };

  /**
   * Parse a filename into base stem, version number, keywords, extension
   */
  function parseFilenameMeta(filename) {
    if (!filename || typeof filename !== 'string') {
      return { stem: '', ext: '', versionNum: null, keywordRank: 0, normalizedStem: '' };
    }

    const lastDot = filename.lastIndexOf('.');
    const ext = lastDot > 0 ? filename.slice(lastDot + 1).toLowerCase() : '';
    const nameWithoutExt = lastDot > 0 ? filename.slice(0, lastDot) : filename;

    // Check for explicit version numbering e.g., v1, v2, v2.1, _1, _2
    let versionNum = null;
    const vMatch = nameWithoutExt.match(/[._-\s]v(?:er(?:sion)?)?(\d+(?:\.\d+)?)\b/i);
    if (vMatch) {
      versionNum = parseFloat(vMatch[1]);
    }

    // Check for keywords
    let keywordRank = 0;
    let foundKeyword = null;
    const tokens = nameWithoutExt.toLowerCase().split(/[._\-\s]+/);
    for (const token of tokens) {
      if (KEYWORD_RANKS[token] !== undefined) {
        if (KEYWORD_RANKS[token] > keywordRank) {
          keywordRank = KEYWORD_RANKS[token];
          foundKeyword = token;
        }
      }
    }

    // Normalize stem by replacing separators with spaces, then stripping keywords and dates
    const normalizedStem = nameWithoutExt
      .toLowerCase()
      .replace(/[._-\s]+/g, ' ')
      .replace(/\bv(?:er(?:sion)?)?\d+(?:\.\d+)?\b/gi, '')
      .replace(/\b(initial|draft|wip|preview|review|final|corrected|revised|updated|latest)\b/gi, '')
      .replace(/\b\d{4}[- ]\d{2}[- ]\d{2}\b/g, '') // strip YYYY-MM-DD
      .replace(/\s+/g, ' ')
      .trim();

    return {
      raw: filename,
      nameWithoutExt,
      ext,
      versionNum,
      keywordRank,
      foundKeyword,
      normalizedStem
    };
  }

  /**
   * Check if two files share a common base project/document stem
   */
  function isSameDocumentFamily(metaA, metaB) {
    if (!metaA.normalizedStem || !metaB.normalizedStem) return false;
    // Same exact normalized stem
    if (metaA.normalizedStem === metaB.normalizedStem) return true;
    // Substring match if sufficiently long
    if (metaA.normalizedStem.length >= 4 && metaB.normalizedStem.length >= 4) {
      if (metaA.normalizedStem.startsWith(metaB.normalizedStem) || metaB.normalizedStem.startsWith(metaA.normalizedStem)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Analyze a selected file against real history records
   * @param {object} selectedFile - { name, size, sha256, lastModified }
   * @param {Array} historyRecords - Array of recorded history items
   * @param {object} versionLinks - Optional explicit { [olderId]: newerId } map
   * @returns {object} Analysis result
   */
  function analyzeFile(selectedFile, historyRecords = [], versionLinks = {}) {
    if (!selectedFile) {
      return {
        status: 'UNKNOWN',
        message: 'No file specified for analysis.'
      };
    }

    const { name, size, sha256 } = selectedFile;
    const selectedMeta = parseFilenameMeta(name);

    // 1. Check for Explicitly Linked Newer Version
    // If this file has already been recorded or linked by the user to a newer version
    for (const record of historyRecords) {
      if (record.filename === name || (sha256 && record.sha256 === sha256)) {
        const newerId = record.linkedNewerVersionId || versionLinks[record.id];
        if (newerId) {
          const newerRecord = historyRecords.find(r => r.id === newerId);
          if (newerRecord) {
            return {
              status: 'POTENTIAL_OUTDATED',
              confidence: 'HIGH',
              isExplicitLink: true,
              title: 'FileGuard Warning: Confirmed Newer Version Exists',
              message: `A confirmed newer version exists in your history: "${newerRecord.filename}".`,
              reason: 'User-confirmed version relationship',
              selectedFile: {
                name: name,
                size: size,
                sha256: sha256,
                lastModified: selectedFile.lastModified
              },
              suggestedFile: {
                id: newerRecord.id,
                name: newerRecord.filename,
                size: newerRecord.fileSize,
                sha256: newerRecord.sha256,
                timestamp: newerRecord.processedAt || newerRecord.timestamp,
                origin: newerRecord.origin
              }
            };
          }
        }
      }
    }

    // Also check if any record in history explicitly declares itself as superseding this filename
    const supersedingRecord = historyRecords.find(r => r.isNewerThanFilename === name);
    if (supersedingRecord) {
      return {
        status: 'POTENTIAL_OUTDATED',
        confidence: 'HIGH',
        isExplicitLink: true,
        title: 'FileGuard Warning: Confirmed Newer Version Exists',
        message: `"${supersedingRecord.filename}" was registered as superseding "${name}".`,
        reason: 'User-confirmed version relationship',
        selectedFile: {
          name: name,
          size: size,
          sha256: sha256,
          lastModified: selectedFile.lastModified
        },
        suggestedFile: {
          id: supersedingRecord.id,
          name: supersedingRecord.filename,
          size: supersedingRecord.fileSize,
          sha256: supersedingRecord.sha256,
          timestamp: supersedingRecord.processedAt || supersedingRecord.timestamp,
          origin: supersedingRecord.origin
        }
      };
    }

    // 2. Exact Content Match (SHA-256 fingerprint)
    if (sha256) {
      const exactMatches = historyRecords.filter(r => r.sha256 === sha256);
      if (exactMatches.length > 0) {
        const latestMatch = exactMatches[exactMatches.length - 1];
        const isSameName = latestMatch.filename === name;
        return {
          status: 'EXACT_DUPLICATE',
          confidence: 'HIGH',
          title: 'Exact Content Match Detected',
          message: isSameName
            ? `You have already processed/sent this exact file (${name}) previously.`
            : `Identical file content previously recorded under the name "${latestMatch.filename}".`,
          matchedRecord: latestMatch,
          selectedFile: selectedFile,
          details: {
            sha256,
            previouslyRecordedDate: latestMatch.processedAt || latestMatch.timestamp,
            origin: latestMatch.origin || 'Unknown website',
            recipient: latestMatch.recipient || 'Not specified'
          }
        };
      }
    }

    // 3. Version Relationship Heuristics (FileGuard)
    let bestNewerCandidate = null;
    let candidateConfidence = 'LOW';
    let reason = '';

    for (const record of historyRecords) {
      // Don't compare with exact self if same name and identical timestamp
      if (record.filename === name && record.sha256 === sha256) continue;

      const recordMeta = parseFilenameMeta(record.filename);

      if (isSameDocumentFamily(selectedMeta, recordMeta)) {
        let isNewer = false;
        let confidence = 'LOW';
        let candidateReason = '';

        // Check explicit numeric versions (e.g. Assignment_v1 vs Assignment_v2)
        if (selectedMeta.versionNum !== null && recordMeta.versionNum !== null) {
          if (recordMeta.versionNum > selectedMeta.versionNum) {
            isNewer = true;
            confidence = 'HIGH';
            candidateReason = `Higher version number detected in history (v${recordMeta.versionNum} vs v${selectedMeta.versionNum})`;
          }
        }

        // Check keyword ranks (e.g. draft vs final, final vs latest/updated)
        if (!isNewer && recordMeta.keywordRank > selectedMeta.keywordRank && recordMeta.keywordRank > 0) {
          isNewer = true;
          confidence = 'HIGH';
          candidateReason = `Status upgrade detected in history ("${recordMeta.foundKeyword}" vs "${selectedMeta.foundKeyword || 'unmarked'}")`;
        }

        // Check timestamps if version numbers/keywords are equal or absent
        if (!isNewer && record.lastModified && selectedFile.lastModified) {
          const recordMod = new Date(record.lastModified).getTime();
          const selectedMod = new Date(selectedFile.lastModified).getTime();
          if (recordMod > selectedMod) {
            isNewer = true;
            confidence = 'MEDIUM';
            candidateReason = `Recorded file has a more recent last-modified timestamp`;
          }
        }

        if (isNewer) {
          if (!bestNewerCandidate || (confidence === 'HIGH' && candidateConfidence !== 'HIGH')) {
            bestNewerCandidate = record;
            candidateConfidence = confidence;
            reason = candidateReason;
          }
        }
      }
    }

    if (bestNewerCandidate) {
      return {
        status: 'POTENTIAL_OUTDATED',
        confidence: candidateConfidence,
        isExplicitLink: false,
        title: 'FileGuard Warning: Newer Version May Exist',
        message: `A potentially newer version was previously recorded: "${bestNewerCandidate.filename}".`,
        reason: reason,
        selectedFile: {
          name: name,
          size: size,
          sha256: sha256,
          lastModified: selectedFile.lastModified
        },
        suggestedFile: {
          id: bestNewerCandidate.id,
          name: bestNewerCandidate.filename,
          size: bestNewerCandidate.fileSize,
          sha256: bestNewerCandidate.sha256,
          timestamp: bestNewerCandidate.processedAt || bestNewerCandidate.timestamp,
          origin: bestNewerCandidate.origin
        }
      };
    }

    // 4. Clean / No newer version known
    return {
      status: 'CLEAN',
      confidence: 'NORMAL',
      title: 'No Conflicts Detected',
      message: 'No known newer version was found in your recorded file history.',
      selectedFile: selectedFile
    };
  }

  /**
   * Basic line-by-line comparison between two text strings
   */
  function compareTextContents(textA, textB) {
    if (typeof textA !== 'string' || typeof textB !== 'string') {
      return {
        supported: false,
        reason: 'Full text comparison unavailable for this format (binary/unparsed).'
      };
    }

    const linesA = textA.split(/\r?\n/);
    const linesB = textB.split(/\r?\n/);

    return {
      supported: true,
      linesCountA: linesA.length,
      linesCountB: linesB.length,
      isIdentical: textA === textB,
      sizeDiff: textB.length - textA.length
    };
  }

  return {
    KEYWORD_RANKS,
    parseFilenameMeta,
    isSameDocumentFamily,
    analyzeFile,
    compareTextContents
  };
});
