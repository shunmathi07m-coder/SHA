# 🛡️ Which One Did I Send?
> *"Git tracks source changes. Which One Did I Send? tracks what you send."*  
> **Tagline:** Know what you sent. Catch mistakes before you send.

A lightweight, zero-dependency **Chrome Extension MVP (Manifest V3)** designed to prevent wrong-version document uploads, shield accidental leaks of sensitive credentials, and maintain a tamper-evident, cryptographically chained audit history of all files shared via browser workflows.

---

## 🚀 60-Second Quick Start

### 1. Load the Chrome Extension (Unpacked)
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked** in the top left.
4. Select the project directory (`c:\Users\vijim\OneDrive\Desktop\SHA`).
5. Pin the **Which One Did I Send?** extension (`🛡️`) to your Chrome toolbar.

### 2. Start the Localhost Demo Server
In your terminal, run:
```bash
node server.js
```
*(Or `npm start`)*

Open your browser to:
👉 **[http://localhost:3000/demo/index.html](http://localhost:3000/demo/index.html)**

### 3. Run Automated Tests
```bash
npm test
```
*(Runs both the Manifest V3 integrity validator and the full cryptographic/privacy test suite).*

---

## 🏆 Hackathon Presentation: 3 Demo Scenarios

The demo page at `http://localhost:3000/demo/index.html` includes **1-Click Judge Buttons** for rapid demonstration:

### Scenario 1: Safe File Sharing
* **Action:** Click **"Test Safe File"** (`Project_Meeting_Notes.txt`).
* **Result:** SHA-256 fingerprint is calculated instantly via Web Crypto. Privacy Leak Shield verifies clean contents. FileGuard confirms no conflicts.
* **Demonstration Point:** Zero friction for safe documents. Logs activity cleanly to local history.

### Scenario 2: Privacy Leak Shield
* **Action:** Click **"Test Sensitive Leak"** (`Staging_Secrets_Config.txt`).
* **Result:** Privacy Leak Shield triggers a **Critical/High** alert!
* **Demonstration Point:** Detects exposed mock OpenAI keys (`sk-test...`), AWS keys (`AKIA...`), email addresses, and phone numbers. Shows masked snippets (`sk-te...8291`) so raw secrets are never leaked in UI or storage.
* **Judges Actions:**
  * **Cancel Sharing:** Blocks upload, resets form, and logs "Cancelled (User blocked)".
  * **Continue Anyway:** Allows explicit override, recording the decision in the tamper-evident audit log.

### Scenario 3: FileGuard (Wrong-Version Prevention)
* **Action:** Click **"Test Outdated File"**.
* **Result:** Simulates a user selecting `Assignment_v1_draft.txt` when `Assignment_v2_final.txt` was previously registered.
* **Demonstration Point:** FileGuard recognizes the filename stem relationship and version upgrade, warning: *"A potentially newer version was previously registered: Assignment_v2_final.txt"*.
* **Judges Actions:** Compare details side-by-side (filenames, timestamps, fingerprints) to prevent submitting outdated assignments.

### Bonus Scenario 4: Exact Content Duplicate Detection
* **Action:** Click **"Test Duplicate Hash"**.
* **Result:** Demonstrates that even if a file is renamed (e.g. `Quarterly_Report_Copy_Renamed.txt`), matching SHA-256 fingerprints identify identical content with mathematical confidence.

---

## 🧩 Architectural Components

```
SHA/
├── manifest.json              # Chrome Manifest V3 with minimal permissions
├── CHROMEWEBSTORE.md          # Store listing, permission justification, privacy policy
├── server.js                  # Zero-dependency localhost demo server (Node http)
├── package.json               # Test and run scripts
├── icons/                     # Extension icons (16px, 48px, 128px)
├── shared/
│   ├── crypto.js              # Web Crypto API SHA-256 fingerprinting & canonical hash chaining
│   ├── privacy-shield.js      # Regex tokenizers for secrets, keys, emails, phones + masking
│   ├── fileguard.js           # Version heuristics (v1/v2, draft/final, timestamps) & duplicate matcher
│   └── storage.js             # chrome.storage.local abstraction with fallback & tamper-evident chaining
├── background/
│   └── service-worker.js      # Manifest V3 service worker managing badges and storage events
├── popup/
│   ├── popup.html             # Clean popup with quick preflight scanner & toggles
│   ├── popup.css              # Dark theme, high-contrast, accessible CSS
│   └── popup.js               # Preflight scan controller and badge updates
├── dashboard/
│   ├── dashboard.html         # Full history dashboard with search, filter, and audit verification
│   ├── dashboard.css          # Professional dashboard layout
│   └── dashboard.js           # Chain verification auditor, metrics, JSON exporter
├── content/
│   ├── content.js             # In-page file input interceptor & floating alert modal
│   └── content.css            # Scoped modal styles with maximum z-index
├── demo/
│   ├── index.html             # Interactive demo page for judges
│   ├── demo.css               # Demo interface styles
│   ├── demo.js                # 1-click test scenarios and simulated sharing workflow
│   └── samples/               # Synthetic test files (Safe notes, Credentials, v1 draft, v2 final)
└── test/
    ├── test_manifest.js       # Manifest V3 validator test
    └── test_runner.js         # Automated crypto, privacy, versioning, and chain tests
```

---

## 🔒 Security & Privacy Guarantees

1. **100% Local Processing:** Document fingerprints and privacy scans are computed in browser memory using the **Web Crypto API** (`crypto.subtle`). No document content is ever sent over the network.
2. **Masked Secrets:** Detected API keys, credentials, and PII are masked by default (e.g. `sk-test_****...291`) in all UI modals, previews, and persistent storage records.
3. **Tamper-Evident Hash Chaining:** Every logged record calculates:
   $$\text{recordHash} = \text{SHA-256}(\text{prevHash} + \text{"::"} + \text{canonicalJson}(\text{recordData}))$$
   The dashboard audits the entire chain upon loading. If any record or metadata is mutated, a red warning highlights the exact tampered index.
4. **Minimum Permissions:** Declares only `storage` and `activeTab`. Zero broad host access.

---

## ⚠️ Transparent Limitations & Honest Boundaries

- **Binary Files (PDF / DOCX):** Deep content inspection currently supports text-based files (`.txt`, `.csv`, `.json`, `.md`, `.env`, source code). For binary files without an embedded local parser, the UI transparently states: *"Binary file format; content scan unavailable; SHA-256 fingerprinting & FileGuard active"*.
- **Upload Interception:** Browser extensions cannot reliably block 100% of custom drag-and-drop React/Wasm canvas upload widgets on arbitrary third-party web apps without deep site-specific content scripts. The extension provides a reliable **Manual Preflight Scanner** in the popup as a universal fallback for any file before sharing.
- **Pure Local Hash Chain:** A purely local hash chain detects tampering of individual records, but a user or process with full disk access could theoretically rewrite the entire chain. True non-repudiation in production would anchor periodic chain roots to an external ledger or signed timestamping authority.
