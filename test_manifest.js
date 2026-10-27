/**
 * Manifest V3 Validator Test
 * Checks:
 * - Valid JSON format
 * - manifest_version === 3
 * - Referenced icons exist on disk
 * - Background service worker exists on disk
 * - Content script files exist on disk
 * - Action popup exists on disk
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const manifestPath = path.join(rootDir, 'manifest.json');

console.log('🔍 Validating Chrome Extension Manifest V3 configuration...\n');

assert.ok(fs.existsSync(manifestPath), 'manifest.json must exist');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

// 1. Version checks
assert.strictEqual(manifest.manifest_version, 3, 'Must be Manifest V3');
assert.ok(manifest.name, 'Extension name must be set');
assert.ok(manifest.version, 'Extension version must be set');

// 2. Icon existence
assert.ok(manifest.icons, 'icons object must exist');
for (const [size, iconRelPath] of Object.entries(manifest.icons)) {
  const iconFullPath = path.join(rootDir, iconRelPath);
  assert.ok(fs.existsSync(iconFullPath), `Icon size ${size} at ${iconRelPath} must exist on disk`);
}

// 3. Action popup
assert.ok(manifest.action, 'action object must exist');
assert.ok(manifest.action.default_popup, 'default_popup must be defined');
assert.ok(fs.existsSync(path.join(rootDir, manifest.action.default_popup)), 'default_popup HTML file must exist');

// 4. Background Service Worker
assert.ok(manifest.background, 'background object must exist');
assert.ok(manifest.background.service_worker, 'background.service_worker must be defined');
assert.ok(fs.existsSync(path.join(rootDir, manifest.background.service_worker)), 'service_worker file must exist');

// 5. Content scripts
if (manifest.content_scripts) {
  for (const cs of manifest.content_scripts) {
    if (cs.js) {
      for (const scriptPath of cs.js) {
        assert.ok(fs.existsSync(path.join(rootDir, scriptPath)), `Content script ${scriptPath} must exist`);
      }
    }
    if (cs.css) {
      for (const cssPath of cs.css) {
        assert.ok(fs.existsSync(path.join(rootDir, cssPath)), `Content css ${cssPath} must exist`);
      }
    }
  }
}

console.log('✅ Manifest V3 and file integrity checks passed 100%!\n');
