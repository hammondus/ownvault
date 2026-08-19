# TODO

(Nothing pending.)

## Done

- Argon2id key derivation (vendored argon2-browser WASM, 64 MiB / 3 passes)
  for all new wrapped-key records; v1 PBKDF2 records still unlock and migrate
  to Argon2id on the next password change or full re-encrypt. Provenance and
  the CSP change in DESIGN-DECISIONS.md.

- Full re-encrypt (Settings): fresh vault key + new master password, every
  entry re-encrypted, committed in one atomic IndexedDB transaction (a crash
  leaves the vault entirely on the old key). Rotates the server write-auth
  claim; other devices auto-lock and re-unlock with the new password. Also
  rebinds any legacy pre-AAD ciphertexts.
- Per-vault write auth: a credential derived from the vault key
  (unlock = proof of write rights, nothing extra to copy between devices),
  claimed hash-stored on first write (TOFU) and required on every write after.
  Co-tenants can no longer overwrite each other's ciphertext. See
  DESIGN-DECISIONS.md for why it's derived rather than minted.
- Password strength meter on the create and change-password forms
  (pwstrength.js, ~150 lines, no dependency): pool entropy discounted for
  repeats/sequences/keyboard runs, a l33t-normalised common-password list, and
  crack time framed at offline PBKDF2 rates. Advisory only — the 12-character
  floor stays the hard rule.
- CSV import (Settings): header-mapped support for Chrome/Edge, Firefox,
  Safari/Apple Passwords, Bitwarden, LastPass, 1Password, and KeePass exports.
  Parse-then-confirm (count shown before anything is written), bulk insert in
  one transaction, TOTP columns preserved in notes.
- Hamburger button defaults to bottom-right (floating-action-button spot)
  instead of top-left, where it covered the search field; dragging still
  overrides it.
- Double-tap the hamburger to pin the drawer open (900px+ screens; content
  moves aside). Single tap releases. Persisted across reloads.
- Rate-limit failed `/api/*` token auth: per-IP failure counter in front of
  `auth()` (429 after 10 failures per 15 min, refused before the compare so a
  blocked guess learns nothing), plus a 16-character minimum on `-token` at
  startup. See DESIGN-DECISIONS.md for the IP-bucketing reasoning.
- Install-as-PWA prompt on the welcome step and in Settings (the browser's own install control is easy to miss); iOS gets Add-to-Home-Screen instructions since it has no install prompt.
- Themed confirm dialogs for destructive actions (delete entry, restore backup, print recovery sheet) — replaced the out-of-place browser `window.confirm`.
- Name a vault at creation ("Home", "Work"); the name labels the installed PWA icon (client-side manifest, so it never touches the server) and the lock screen.
- Vault name syncs end-to-end encrypted: a new device connecting to a Vault ID inherits the name on first unlock, and renaming on any device propagates to all of them.
- Fixed iOS unlock doing nothing: `crypto.subtle` is unavailable over plain HTTP (non-secure context), so unlock failed silently. Now detects it and shows a clear "needs HTTPS" message; unlock rejections can no longer fail silently. (Serve iOS over HTTPS — mkcert on LAN, or a reverse proxy.)

