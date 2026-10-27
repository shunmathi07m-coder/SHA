# Chrome Web Store Listing — Which One Did I Send?

**Last Updated:** 2026-10-09  
**Version:** 1.0.0

---

## 1. Store Listing Metadata

- **Extension Name:** Which One Did I Send?
- **Short Name:** WhichOneDidISend
- **Summary / Tagline:** Know what you sent. Catch mistakes before you send. Version tracking, duplicate detection, and privacy leak shield.
- **Category:** Productivity / Developer Tools
- **Language:** English

### Detailed Description

"Git tracks source changes. Which One Did I Send? tracks what you send."

Ever sent the wrong version of your resume, assignment, or report through Gmail, an LMS, or browser upload portal? Or worried you accidentally included a sensitive API token or personal contact information?

"Which One Did I Send?" is your browser copilot for file sharing. It operates entirely locally on your device with zero cloud tracking:

1. **FileGuard (Wrong-Version Prevention):**
   Automatically warns you if you are uploading an older or outdated draft (e.g. `Resume_final.pdf` when `Resume_latest.pdf` exists) and prevents accidental duplicate sends.

2. **Privacy Leak Shield:**
   Scans text documents locally for exposed API keys, private tokens, passwords, emails, and phone numbers before they leave your browser.

3. **Tamper-Evident History Dashboard:**
   Logs all shared file fingerprints using cryptographically linked SHA-256 hash chains, providing a verifiable audit log of exactly what you sent and when.

---

## 2. Permissions Justification

| Permission | Justification |
| :--- | :--- |
| `storage` | Required to securely store local file metadata, user protection preferences, and tamper-evident history records directly on your machine. |
| `activeTab` | Required to provide in-page protection warnings and inspect file input events on the active tab without accessing your broader browsing history. |

---

## 3. Privacy & Data Use Disclosures

- **Remote Data Transmission:** NONE. 100% local processing.
- **File Content Uploads:** NO file contents are ever uploaded to any external or cloud servers.
- **Personally Identifiable Information:** Stored only locally in your browser storage; masked by default in all logs and popups.
- **Analytics / Tracking:** Zero third-party trackers, zero cookies, zero external telemetry.
