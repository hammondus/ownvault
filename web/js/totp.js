/*
 * Own Vault — TOTP code generation (RFC 6238 over WebCrypto HMAC-SHA1).
 *
 * DOM-free and stateless, like vault.js, so the same module can back a
 * browser extension later. The TOTP secret is just another encrypted payload
 * field; this module only turns it into the current 6-digit code.
 *
 * Parameters are fixed at 6 digits / 30-second period / SHA-1 (and one
 * matching bound in normalize()): authenticator apps assume those values and
 * most ignore otpauth:// parameters that claim otherwise, so a knob here
 * would only generate codes no verifier accepts. An otpauth:// URI declaring
 * different parameters is rejected outright rather than stored and silently
 * wrong every 30 seconds.
 */
window.Totp = (function () {
  "use strict";

  var B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var PERIOD = 30; // seconds
  var DIGITS = 6;

  function b32decode(s) {
    var value = 0;
    var bits = 0;
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var idx = B32_ALPHABET.indexOf(s.charAt(i));
      if (idx < 0) throw new Error("Authenticator key has invalid characters.");
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  // Pull the secret out of an otpauth:// URI (the text behind the QR code).
  // Rejects anything this module can't generate correct codes for.
  function secretFromUri(uri) {
    if (/^otpauth:\/\/hotp\//i.test(uri)) {
      throw new Error("Counter-based (HOTP) keys aren't supported — only time-based (TOTP).");
    }
    if (!/^otpauth:\/\/totp\//i.test(uri)) {
      throw new Error("Unrecognised otpauth link.");
    }
    var query = uri.split("?")[1] || "";
    var params = {};
    query.split("&").forEach(function (pair) {
      var eq = pair.indexOf("=");
      if (eq < 0) return;
      var k = decodeURIComponent(pair.slice(0, eq)).toLowerCase();
      params[k] = decodeURIComponent(pair.slice(eq + 1));
    });
    var alg = (params.algorithm || "SHA1").toUpperCase();
    var digits = parseInt(params.digits || "6", 10);
    var period = parseInt(params.period || "30", 10);
    if (alg !== "SHA1" || digits !== DIGITS || period !== PERIOD) {
      throw new Error(
        "This key needs " + alg + "/" + digits + " digits/" + period +
          "s codes; only the standard SHA1/6/30 is supported."
      );
    }
    if (!params.secret) throw new Error("The otpauth link has no secret.");
    return params.secret;
  }

  // Turn whatever the user pasted (bare base32, with spaces/dashes/padding,
  // or a full otpauth:// URI) into canonical base32, or throw with a message
  // fit to show the user. Empty input returns "".
  function normalize(input) {
    var s = (input || "").trim();
    if (!s) return "";
    if (/^otpauth:/i.test(s)) s = secretFromUri(s);
    s = s.replace(/[\s-]/g, "").toUpperCase().replace(/=+$/, "");
    if (!s) return "";
    if (!/^[A-Z2-7]+$/.test(s)) {
      throw new Error("Authenticator key isn't valid base32 (letters A–Z and digits 2–7).");
    }
    if (s.length < 8) {
      throw new Error("Authenticator key is too short — check for a missed part.");
    }
    return s;
  }

  // Current code for a normalized base32 secret. Resolves
  // {code, secondsLeft}; rejects if the secret doesn't decode.
  function code(secret, nowMs) {
    var bytes;
    try {
      bytes = b32decode(secret);
    } catch (e) {
      return Promise.reject(e);
    }
    var step = Math.floor(nowMs / 1000 / PERIOD);
    // 8-byte big-endian counter. Arithmetic, not shifts: JS bitwise ops
    // truncate to 32 bits and the counter is 64.
    var counter = new Uint8Array(8);
    var v = step;
    for (var i = 7; i >= 0; i--) {
      counter[i] = v % 256;
      v = Math.floor(v / 256);
    }
    return window.crypto.subtle
      .importKey("raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"])
      .then(function (key) {
        return window.crypto.subtle.sign("HMAC", key, counter);
      })
      .then(function (mac) {
        // Dynamic truncation (RFC 4226 §5.3): low nibble of the last byte
        // picks a 4-byte window; mask the sign bit; take the low 6 digits.
        var h = new Uint8Array(mac);
        var off = h[h.length - 1] & 0x0f;
        var bin =
          ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
        var c = String(bin % Math.pow(10, DIGITS));
        while (c.length < DIGITS) c = "0" + c;
        return {
          code: c,
          secondsLeft: PERIOD - (Math.floor(nowMs / 1000) % PERIOD)
        };
      });
  }

  return {
    normalize: normalize,
    code: code,
    PERIOD: PERIOD
  };
})();
