/*
 * Own Vault — small password-strength estimator (zxcvbn-style, no deps).
 *
 * Estimates entropy the way an attacker guesses, not by raw character-pool
 * math: repeated and sequential characters are nearly free, keyboard runs are
 * cheap, and a password built on a breach-list word falls at the speed of a
 * dictionary, however long it looks. The real zxcvbn ships megabytes of
 * dictionaries; this is the ~150-line version that catches the same big
 * mistakes and stays auditable.
 *
 * DOM-free: exposes PwStrength.score(pw) -> {score 0..4, label, bits,
 * crackTime, feedback}. UI wiring lives in vaultui.js. The 12-character
 * minimum stays the only hard rule — this meter only informs.
 */
window.PwStrength = (function () {
  "use strict";

  // Top of the public breach-corpus lists, normalised (lowercase, no l33t).
  // A match anywhere in the password devalues the characters it covers.
  var COMMON = [
    "password", "passwort", "passw0rd", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwertyuiop", "azerty", "abc123", "letmein",
    "welcome", "monkey", "dragon", "master", "shadow", "superman", "batman",
    "trustno1", "iloveyou", "sunshine", "princess", "football", "baseball",
    "soccer", "charlie", "michael", "jordan", "harley", "ranger", "hunter",
    "buster", "thomas", "robert", "soccer", "killer", "hockey", "george",
    "andrew", "jennifer", "joshua", "pepper", "daniel", "access", "computer",
    "cookie", "summer", "winter", "secret", "flower", "orange", "banana",
    "cheese", "ginger", "hannah", "maggie", "ashley", "nicole", "chelsea",
    "biteme", "matrix", "freedom", "whatever", "starwars", "internet",
    "corvette", "mercedes", "ferrari", "yamaha", "mustang", "camaro",
    "pokemon", "pikachu", "gandalf", "merlin", "diamond", "silver", "golden",
    "purple", "yellow", "admin", "administrator", "root", "login", "guest",
    "changeme", "default", "godzilla", "asdfgh", "zxcvbn", "qazwsx",
    "password1", "password123", "hello123", "test123", "ownvault", "vault"
  ];

  // Runs read off these in either direction count as sequences.
  var SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "0123456789"
  ];

  var LEET = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i"
  };

  function normalize(pw) {
    var out = "";
    var lower = pw.toLowerCase();
    for (var i = 0; i < lower.length; i++) {
      out += LEET[lower[i]] || lower[i];
    }
    return out;
  }

  function log2(n) {
    return Math.log(n) / Math.LN2;
  }

  // Is b one step from a along any sequence row (either direction)?
  function isSequential(a, b) {
    a = a.toLowerCase();
    b = b.toLowerCase();
    for (var i = 0; i < SEQUENCES.length; i++) {
      var row = SEQUENCES[i];
      var at = row.indexOf(a);
      if (at === -1) continue;
      if (row[at + 1] === b || row[at - 1] === b) return true;
    }
    return false;
  }

  function score(pw) {
    pw = String(pw || "");
    if (!pw) {
      return { score: 0, label: "", bits: 0, crackTime: "", feedback: "" };
    }

    // Per-character entropy from the pool of character classes actually
    // present — mixing classes earns the whole password a bigger pool, the
    // way an attacker's mask actually widens. The penalties below claw back
    // the classic gaming of this estimate (P@ssw0rd1-style).
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    var perChar = log2(pool || 26);

    var bits = 0;
    var cheapRun = 0; // chars devalued as repeats/sequences
    for (var i = 0; i < pw.length; i++) {
      if (i > 0 && pw[i] === pw[i - 1]) {
        bits += 1; // repeat continuation is nearly free to guess
        cheapRun++;
        continue;
      }
      if (i > 0 && isSequential(pw[i - 1], pw[i])) {
        bits += 1.5; // sequence/keyboard-run continuation
        cheapRun++;
        continue;
      }
      bits += perChar;
    }

    // Breach-list words: the covered characters cost the attacker roughly a
    // dictionary rank, not their pool entropy. Longest match wins.
    var norm = normalize(pw);
    var hitWord = "";
    for (var w = 0; w < COMMON.length; w++) {
      var word = COMMON[w];
      if (word.length > hitWord.length && norm.indexOf(word) !== -1) {
        hitWord = word;
      }
    }
    if (hitWord) {
      bits = Math.max(bits - hitWord.length * perChar + log2(COMMON.length), 1);
    }

    // A 4-digit year is one guess in ~200, not four digits of entropy.
    if (/(19|20)\d\d/.test(pw)) {
      bits = Math.max(bits - (4 * log2(10) - log2(200)), 1);
    }

    var s;
    if (bits < 28) s = 0;
    else if (bits < 40) s = 1;
    else if (bits < 55) s = 2;
    else if (bits < 70) s = 3;
    else s = 4;

    var labels = ["very weak", "weak", "fair", "good", "strong"];

    var feedback = "";
    if (hitWord) {
      feedback = "Contains a very common password (“" + hitWord + "”).";
    } else if (cheapRun >= pw.length / 3) {
      feedback = "Avoid repeated characters and keyboard runs.";
    } else if (s < 3) {
      feedback = "Longer is stronger — a few random words work well.";
    }

    return {
      score: s,
      label: labels[s],
      bits: Math.round(bits),
      crackTime: crackTime(bits),
      feedback: feedback
    };
  }

  // Honest framing for THIS app: a stolen backup or server DB is attacked
  // offline through PBKDF2-SHA256 at 600k iterations. A serious GPU rig
  // manages on the order of 1e6 such guesses/second; average success at half
  // the keyspace. Returns a full phrase ("in about 3 days") so the UI never
  // has to guess at grammar.
  function crackTime(bits) {
    var seconds = Math.pow(2, bits - 1) / 1e6;
    if (seconds < 60) return "instantly";
    if (seconds < 3600) return "in about " + Math.round(seconds / 60) + " minutes";
    if (seconds < 86400) return "in about " + Math.round(seconds / 3600) + " hours";
    if (seconds < 31557600) return "in about " + Math.round(seconds / 86400) + " days";
    var years = seconds / 31557600;
    if (years < 1000) return "in about " + Math.round(years) + " years";
    if (years < 1e6) return "in centuries";
    return "in millions of years";
  }

  return { score: score };
})();
