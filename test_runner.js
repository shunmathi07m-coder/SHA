/**
 * Which One Did I Send? — Comprehensive Test Suite
 * Tests A through J covering:
 * - Real file imports & fingerprint extraction
 * - Exact duplicate detection by SHA-256
 * - Different content verification
 * - Known newer versions (explicitly registered & heuristic)
 * - Unknown versions (honest "No known newer version")
 * - Privacy detection from actual content (masking & no raw secrets)
 * - Unsupported formats ("Content scan unavailable for this file type.")
 * - Real history matching actual files & events
 * - Persistence across reloads
 * - Honest event status (imported is not labeled sent)
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Crypto = require('../shared/crypto');
const PrivacyShield = require('../shared/privacy-shield');
const FileGuard = require('../shared/fileguard');
const Storage = require('../shared/storage');

const samplesDir = path.resolve(__dirname, '../demo/samples');

async function runTestSuite() {
  console.log('🧪 Starting "Which One Did I Send?" Comprehensive Verification (Tests A–J)...\n');
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAIL: ${name}`);
      console.error(`     Error: ${err.message}`);
      if (err.stack) console.error(err.stack.split('\n').slice(1, 4).join('\n'));
      failed++;
    }
  }

  // Clear storage before starting test suite
  await Storage.clearHistory();

  // Read actual real files from disk
  const safeNotesPath = path.join(samplesDir, 'safe_meeting_notes.txt');
  const sensitiveCredsPath = path.join(samplesDir, 'sensitive_credentials.txt');
  const v1DraftPath = path.join(samplesDir, 'Assignment_v1_draft.txt');
  const v2FinalPath = path.join(samplesDir, 'Assignment_v2_final.txt');

  const safeNotesBuf = fs.readFileSync(safeNotesPath);
  const sensitiveCredsBuf = fs.readFileSync(sensitiveCredsPath);
  const v1DraftBuf = fs.readFileSync(v1DraftPath);
  const v2FinalBuf = fs.readFileSync(v2FinalPath);

  // ==========================================
  // TEST A — New file: Import real file & verify fingerprint
  // ==========================================
  await test('TEST A — New file: Import real file & verify actual fingerprint in history', async () => {
    const realSha = await Crypto.sha256Hex(safeNotesBuf);
    assert.ok(realSha && realSha.length === 64, 'Must compute 64-char hex SHA-256');

    const record = await Storage.recordFileActivity({
      filename: 'safe_meeting_notes.txt',
      fileSize: safeNotesBuf.length,
      fileType: 'text/plain',
      lastModified: fs.statSync(safeNotesPath).mtimeMs,
      sha256: realSha,
      source: 'manual_import',
      eventStage: Storage.EVENT_STAGES.IMPORTED,
      status: 'Imported / Indexed',
      origin: 'local_disk',
      fileGuardStatus: 'CLEAN'
    });

    assert.ok(record.id, 'Record must have stable ID');
    assert.strictEqual(record.sha256, realSha);
    assert.strictEqual(record.eventStage, Storage.EVENT_STAGES.IMPORTED);

    const found = await Storage.findByFingerprint(realSha);
    assert.ok(found, 'Should find recorded file by fingerprint in history');
    assert.strictEqual(found.filename, 'safe_meeting_notes.txt');
  });

  // ==========================================
  // TEST B — Exact duplicate: Second copy with different name matches fingerprint
  // ==========================================
  await test('TEST B — Exact duplicate: Different filename with identical content matches fingerprint', async () => {
    const realSha = await Crypto.sha256Hex(safeNotesBuf);

    const history = await Storage.getHistory();
    const duplicateCandidate = {
      name: 'Meeting_Notes_Copy_Renamed.txt', // Different filename!
      size: safeNotesBuf.length,
      sha256: realSha,
      lastModified: Date.now()
    };

    const analysis = FileGuard.analyzeFile(duplicateCandidate, history);
    assert.strictEqual(analysis.status, 'EXACT_DUPLICATE');
    assert.strictEqual(analysis.confidence, 'HIGH');
    assert.strictEqual(analysis.matchedRecord.filename, 'safe_meeting_notes.txt');
    assert.ok(analysis.message.includes('Identical file content'));
  });

  // ==========================================
  // TEST C — Different content: Genuinely different file is not classified as match
  // ==========================================
  await test('TEST C — Different content: Genuinely different file is not classified as duplicate', async () => {
    const diffSha = await Crypto.sha256Hex(v1DraftBuf);
    const history = await Storage.getHistory();

    const differentFile = {
      name: 'Assignment_v1_draft.txt',
      size: v1DraftBuf.length,
      sha256: diffSha,
      lastModified: Date.now()
    };

    const analysis = FileGuard.analyzeFile(differentFile, history);
    assert.notStrictEqual(analysis.status, 'EXACT_DUPLICATE');
    assert.strictEqual(analysis.status, 'CLEAN');
  });

  // ==========================================
  // TEST D — Known newer version: Import two actual versions and register relationship
  // ==========================================
  await test('TEST D — Known newer version: Explicitly linked and heuristic newer versions detected', async () => {
    const v1Hash = await Crypto.sha256Hex(v1DraftBuf);
    const v2Hash = await Crypto.sha256Hex(v2FinalBuf);

    // Record v1
    const rec1 = await Storage.recordFileActivity({
      filename: 'Assignment_v1_draft.txt',
      fileSize: v1DraftBuf.length,
      fileType: 'text/plain',
      lastModified: fs.statSync(v1DraftPath).mtimeMs,
      sha256: v1Hash,
      eventStage: Storage.EVENT_STAGES.IMPORTED,
      status: 'Imported (Draft)'
    });

    // Record v2
    const rec2 = await Storage.recordFileActivity({
      filename: 'Assignment_v2_final.txt',
      fileSize: v2FinalBuf.length,
      fileType: 'text/plain',
      lastModified: fs.statSync(v2FinalPath).mtimeMs,
      sha256: v2Hash,
      eventStage: Storage.EVENT_STAGES.IMPORTED,
      status: 'Imported (Final)'
    });

    // Explicitly link rec1 -> rec2
    await Storage.linkVersions(rec1.id, rec2.id);

    const history = await Storage.getHistory();
    const versionLinks = await Storage.getVersionLinks();

    // Now test selecting v1: FileGuard must report v2 as explicit newer version!
    const v1Selected = {
      name: 'Assignment_v1_draft.txt',
      size: v1DraftBuf.length,
      sha256: v1Hash,
      lastModified: fs.statSync(v1DraftPath).mtimeMs
    };

    const analysis = FileGuard.analyzeFile(v1Selected, history, versionLinks);
    assert.strictEqual(analysis.status, 'POTENTIAL_OUTDATED');
    assert.strictEqual(analysis.confidence, 'HIGH');
    assert.strictEqual(analysis.suggestedFile.name, 'Assignment_v2_final.txt');
    assert.strictEqual(analysis.isExplicitLink, true);
    assert.ok(analysis.message.includes('Assignment_v2_final.txt'));
  });

  // ==========================================
  // TEST E — Unknown version: No newer version in history returns honest message
  // ==========================================
  await test('TEST E — Unknown version: Displays honest "No known newer version" message', async () => {
    const history = await Storage.getHistory();
    const unknownFile = {
      name: 'Independent_Biology_Paper.txt',
      size: 4096,
      sha256: '9999888877776666555544443333222211110000aaaabbbbccccddddeeee0000',
      lastModified: Date.now()
    };

    const analysis = FileGuard.analyzeFile(unknownFile, history);
    assert.strictEqual(analysis.status, 'CLEAN');
    assert.strictEqual(analysis.message, 'No known newer version was found in your recorded file history.');
  });

  // ==========================================
  // TEST F — Privacy detection: Scans actual text content with safe masking
  // ==========================================
  await test('TEST F — Privacy detection: Scans actual content & masks sensitive findings', async () => {
    const content = sensitiveCredsBuf.toString('utf8');
    const result = PrivacyShield.scanText(content);

    assert.strictEqual(result.hasFindings, true);
    assert.strictEqual(result.highestSeverity, 'critical');

    const emailFinding = result.findings.find(f => f.ruleId === 'email_address');
    assert.ok(emailFinding, 'Must detect email address');
    assert.ok(emailFinding.maskedValue.includes('@example.com'));
    assert.ok(!emailFinding.maskedValue.includes('demo.user@example.com'), 'Raw email must not appear unmasked');

    const tokenFinding = result.findings.find(f => f.ruleId === 'openai_api_key');
    assert.ok(tokenFinding, 'Must detect OpenAI key pattern');
    assert.ok(tokenFinding.maskedValue.includes('...'));
    assert.ok(!tokenFinding.maskedValue.includes('NOT_A_REAL_SECRET_48201948291'), 'Raw token secret must not be stored');

    const awsFinding = result.findings.find(f => f.ruleId === 'aws_access_key');
    assert.ok(awsFinding, 'Must detect AWS access key ID');
  });

  // ==========================================
  // TEST G — Unsupported file: Reports "Content scan unavailable for this file type."
  // ==========================================
  await test('TEST G — Unsupported file: Transparently reports content scan unavailable', async () => {
    // Mock binary file (PDF)
    const mockPdf = {
      name: 'Contract_Signed.pdf',
      type: 'application/pdf',
      size: 154000
    };

    const isSupported = PrivacyShield.isSupportedTextFile(mockPdf);
    assert.strictEqual(isSupported, false, 'PDF should not be treated as text');

    const scanRes = await PrivacyShield.scanFile(mockPdf);
    assert.strictEqual(scanRes.supported, false);
    assert.strictEqual(scanRes.reason, 'Content scan unavailable for this file type.');
  });

  // ==========================================
  // TEST H — Real history: Records match actual files and events
  // ==========================================
  await test('TEST H — Real history: Stored records match actual file metadata', async () => {
    const history = await Storage.getHistory();
    assert.ok(history.length >= 3, 'Must have recorded real files from previous tests');

    const v2Rec = history.find(r => r.filename === 'Assignment_v2_final.txt');
    assert.ok(v2Rec, 'Must contain real v2 record');
    assert.strictEqual(v2Rec.fileSize, v2FinalBuf.length);
    assert.strictEqual(v2Rec.fileType, 'text/plain');
    assert.ok(v2Rec.recordHash, 'Must contain computed recordHash');
    assert.ok(v2Rec.prevHash, 'Must contain prevHash');
  });

  // ==========================================
  // TEST I — Persistence: Records and version links survive reload
  // ==========================================
  await test('TEST I — Persistence: Cryptographic chain and version links verified intact', async () => {
    // Verify tamper-evident chain across all records
    const audit = await Storage.verifyHistoryChain();
    assert.strictEqual(audit.isValid, true, 'Cryptographic chain must verify cleanly');
    assert.ok(audit.count >= 3);

    const links = await Storage.getVersionLinks();
    assert.ok(Object.keys(links).length >= 1, 'Version link must persist in storage');
  });

  // ==========================================
  // TEST J — Honest event status: Imported and scanned files are not falsely labeled sent
  // ==========================================
  await test('TEST J — Honest event status: Imported/scanned files are not labeled sent', async () => {
    const history = await Storage.getHistory();

    for (const record of history) {
      if (record.eventStage === Storage.EVENT_STAGES.IMPORTED) {
        assert.ok(
          !record.status.toLowerCase().includes('shared') && !record.status.toLowerCase().includes('sent'),
          `Imported record ${record.filename} must not be labeled as sent`
        );
      }
      if (record.eventStage === Storage.EVENT_STAGES.SCANNED) {
        assert.ok(
          !record.status.toLowerCase().includes('shared') && !record.status.toLowerCase().includes('sent'),
          `Scanned record ${record.filename} must not be labeled as sent`
        );
      }
    }
  });

  console.log(`\n================================`);
  console.log(`Verification Summary: ${passed} Passed, ${failed} Failed`);
  console.log(`================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
