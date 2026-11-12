// Stage C background service worker (Manifest V3).
//
// Responsibilities are kept deliberately small:
//   * open the side panel when the toolbar icon is clicked
//   * relay "read open email" requests from the side panel to the Gmail
//     content script and back
//
// It performs no network calls itself and holds no secrets. The pairing nonce
// lives only in the side panel's chrome.storage.local after the operator pastes
// it, and is never logged.

// Keep the side panel open for the Gmail tab so the sidebar is usable.
chrome.tabs.query({ url: "https://mail.google.com/*" }, (tabs) => {
  for (const tab of tabs) {
    if (tab.id != null) {
      chrome.sidePanel.setOptions({ tabId: tab.id, path: "sidepanel.html", enabled: true });
    }
  }
});

// Open the side panel when the toolbar icon is clicked.
chrome.action.onClicked.addListener((tab) => {
  if (tab.id != null) {
    chrome.sidePanel.open({ tabId: tab.id });
  } else {
    chrome.sidePanel.open({ windowId: tab.windowId });
  }
});

// Relay a read-only request from the side panel to the Gmail content script.
// The content script only reads the DOM; it never mutates anything.
// Shared state for inert previews only (never used to authorize sends).
const state = {
  openEmail: null,
  confirmedRecipient: null,
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "read-open-email") {
    return; // not ours
  }
  // Accept an optional recipient hint from the side panel for inert previews.
  state.confirmedRecipient = message.recipientHint || state.confirmedRecipient || null;

  chrome.tabs.query({ active: true, url: "https://mail.google.com/*" }, (tabs) => {
    const tab = tabs[0];
    if (!tab || tab.id == null) {
      sendResponse({ ok: false, error: "No active Gmail tab found." });
      return;
    }
    chrome.tabs.sendMessage(tab.id, { type: "read-open-email", recipientHint: state.confirmedRecipient }, (resp) => {
      if (chrome.runtime.lastError) {
        sendResponse({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      sendResponse(resp);
    });
  });

  return true; // keep the message channel open for the async sendResponse
});
