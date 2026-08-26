/*
 * Own Vault extension — page fill script.
 *
 * Injected everywhere but completely passive: it holds no state, reads
 * nothing, and touches the page only when a fill message arrives — which
 * only the popup sends, only on the user's explicit click, and only to the
 * active tab. Credentials pass through here transiently and are not kept.
 *
 * Filling is done via the native value setter + input/change events so
 * framework-controlled forms (React and friends track the setter, not the
 * attribute) see the change as if typed.
 */
"use strict";

(function () {
  function visible(el) {
    if (!el) return false;
    var r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  function setValue(input, value) {
    var proto = Object.getPrototypeOf(input);
    var desc = Object.getOwnPropertyDescriptor(proto, "value") ||
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (desc && desc.set) desc.set.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // The password field anchors everything: take the first visible one, then
  // look for the nearest preceding visible text/email input in the same form
  // (or the whole document on formless pages) as the username. Covers the
  // overwhelming common case; username-first two-step logins get the
  // username only, which is still a fill.
  function findFields() {
    var pws = Array.prototype.filter.call(
      document.querySelectorAll('input[type="password"]'),
      visible
    );
    var pw = pws[0] || null;
    var scope = (pw && pw.form) || document;
    var candidates = Array.prototype.filter.call(
      scope.querySelectorAll(
        'input[type="text"], input[type="email"], input:not([type])'
      ),
      visible
    );
    var user = null;
    if (pw) {
      // last text-ish input positioned before the password field
      var pos = pw.compareDocumentPosition.bind(pw);
      for (var i = 0; i < candidates.length; i++) {
        if (pos(candidates[i]) & Node.DOCUMENT_POSITION_PRECEDING) user = candidates[i];
      }
    } else {
      user = candidates[0] || null;
    }
    return { user: user, pw: pw };
  }

  chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (!msg || msg.type !== "ov:fill") return false;
    var f = findFields();
    var filled = [];
    if (f.user && msg.username) {
      setValue(f.user, msg.username);
      filled.push("username");
    }
    if (f.pw && msg.password) {
      setValue(f.pw, msg.password);
      filled.push("password");
    }
    sendResponse({ ok: true, filled: filled });
    return false; // responded synchronously
  });
})();
