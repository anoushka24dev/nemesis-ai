// Stage C Gmail content script.
//
// READ-ONLY by contract. It reads the currently open email's subject, sender,
// and body text out of the Gmail DOM and returns them to the side panel. It
// never clicks buttons, never submits forms, never calls the Gmail API, and
// never mutates the page. Proposed actions are computed and returned as
// *simulation text only*; nothing here executes them.

(() => {
  "use strict";

  // Read the visible email's subject from the DOM.
  function readSubject() {
    const el =
      document.querySelector("h2[data-thread-perm-id]") ||
      document.querySelector("h2.hP") ||
      document.querySelector("[data-testid='message-subject']");
    return el ? el.textContent.trim() : "";
  }

  // Read the sender display name / address.
  function readSender() {
    const el =
      document.querySelector("span.gD") ||
      document.querySelector("[data-hovercard-id]");
    if (!el) return "";
    const name = (el.textContent || "").trim();
    const email = el.getAttribute("email") || el.getAttribute("data-hovercard-id") || "";
    return email && email !== name ? `${name} <${email}>`.trim() : name;
  }

  // Read the email body text. Prefer the expanded message body.
  function readBody() {
    const el =
      document.querySelector("div.a3s.aiL") ||
      document.querySelector("div[dir='ltr']") ||
      document.querySelector(".ii.gt");
    return el ? el.textContent.trim().slice(0, 20000) : "";
  }

  function readOpenEmail(recipientHint) {
    const subject = readSubject();
    const sender = readSender();
    const body = readBody();
    const hasEmail = Boolean(subject || sender || body);

    // Derived inert suggestions only (never executed).
    const concerns = [];
    if (recipientHint && recipientHint.toLowerCase().trim() !== sender.toLowerCase().trim()) {
      concerns.push(`Proposed recipient ${"you@example.com"} does not match the sender shown in the open email.`);
    }

    const simulatedActions = [
      `Propose send to ${"you@example.com"} (inert preview only)`,
      'Propose reply to ' + (sender || '<no sender shown>') + ' -- SIMULATION ONLY (inert preview, never executed)',
      `Propose forward to ${"you@example.com"} (inert preview only)`,
      ...concerns,
    ].filter(Boolean);

    return {
      ok: true,
      present: hasEmail,
      subject,
      sender,
      bodyText: body,
      simulatedActions,
    };
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || message.type !== "read-open-email") {
      return; // not ours
    }
    try {
      sendResponse(readOpenEmail(message.recipientHint));
    } catch (err) {
      sendResponse({ ok: false, error: String(err) });
    }
    return false; // synchronous response
  });
})();
