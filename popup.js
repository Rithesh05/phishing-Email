document.addEventListener('DOMContentLoaded', async () => {
  // Load saved settings
  const settings = await chrome.storage.sync.get([
    'localScan',
    'scannedCount',
    'threatCount'
  ]);

  // Update UI with saved settings
  document.getElementById('local-scan').checked = settings.localScan !== false;
  document.getElementById('scanned-count').textContent = settings.scannedCount || 0;
  document.getElementById('threat-count').textContent = settings.threatCount || 0;

  // Toggle settings
  document.getElementById('local-scan').addEventListener('change', async (e) => {
    await chrome.storage.sync.set({ localScan: e.target.checked });
  });
});