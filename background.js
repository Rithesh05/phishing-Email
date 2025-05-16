// Listen for installation
chrome.runtime.onInstalled.addListener(() => {
  // Initialize storage with default values
  chrome.storage.sync.set({
    localScan: true,
    scannedCount: 0,
    threatCount: 0
  });
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'updateStats') {
    updateStats(request.data);
  }
  return true;
});

// Update extension badge with threat count
async function updateStats(data) {
  const stats = await chrome.storage.sync.get(['scannedCount', 'threatCount']);
  await chrome.storage.sync.set({
    scannedCount: stats.scannedCount + 1,
    threatCount: stats.threatCount + (data.isPhishing ? 1 : 0)
  });
}