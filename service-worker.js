/**
 * Which One Did I Send? — Background Service Worker (Manifest V3)
 * Handles cross-component messaging, badge updates, and history coordination.
 */

// Import shared modules in Service Worker scope
importScripts(
  '../shared/crypto.js',
  '../shared/privacy-shield.js',
  '../shared/fileguard.js',
  '../shared/storage.js'
);

/**
 * Update the extension icon badge with the number of recorded files or recent warnings
 */
async function updateBadge() {
  try {
    const history = await self.FileGuardStorage.getHistory();
    const count = history.length;
    const text = count > 0 ? String(count > 99 ? '99+' : count) : '';
    await chrome.action.setBadgeText({ text });
    await chrome.action.setBadgeBackgroundColor({ color: '#2563EB' });
  } catch (err) {
    console.error('[FileGuard SW] Failed to update badge:', err);
  }
}

// Lifecycle events
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[FileGuard SW] Extension installed/updated:', details.reason);
  await updateBadge();
});

chrome.runtime.onStartup.addListener(async () => {
  await updateBadge();
});

// Central message dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  (async () => {
    try {
      switch (message.type) {
        case 'GET_SETTINGS': {
          const settings = await self.FileGuardStorage.getSettings();
          sendResponse({ success: true, settings });
          break;
        }

        case 'UPDATE_SETTINGS': {
          const settings = await self.FileGuardStorage.updateSettings(message.settings);
          sendResponse({ success: true, settings });
          break;
        }

        case 'GET_HISTORY': {
          const history = await self.FileGuardStorage.getHistory();
          sendResponse({ success: true, history });
          break;
        }

        case 'RECORD_FILE_ACTIVITY': {
          const record = await self.FileGuardStorage.recordFileActivity(message.recordData);
          await updateBadge();
          sendResponse({ success: true, record });
          break;
        }

        case 'VERIFY_CHAIN': {
          const result = await self.FileGuardStorage.verifyHistoryChain();
          sendResponse({ success: true, result });
          break;
        }

        case 'CLEAR_HISTORY': {
          await self.FileGuardStorage.clearHistory();
          await updateBadge();
          sendResponse({ success: true });
          break;
        }

        case 'OPEN_DASHBOARD': {
          const dashboardUrl = chrome.runtime.getURL('dashboard/dashboard.html');
          await chrome.tabs.create({ url: dashboardUrl });
          sendResponse({ success: true });
          break;
        }

        default:
          sendResponse({ success: false, error: `Unknown message type: ${message.type}` });
      }
    } catch (err) {
      console.error('[FileGuard SW] Message error:', err);
      sendResponse({ success: false, error: err.message });
    }
  })();

  return true; // Keep message channel open for async response
});
