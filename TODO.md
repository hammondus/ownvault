# TODO

- CSV import
- fix the stupid default position of hamburger menu
- have the option of double clicking the hamburber button to keep the menu open. Useful when on a larger screen.

## Security (future hardening)

- Argon2id key derivation (via a small WASM module) in place of PBKDF2 — far
  more resistant to GPU cracking. WebCrypto has no native support, hence WASM.
  Needs a KDF field in the wrapped-key record (`v` is there for this) and a
  migrate-on-password-change path.
- Per-vault write tokens, so co-tenants on a shared server can't overwrite each
  other's ciphertext (today the single server token gates all writes).
- Password strength meter (zxcvbn-style) on the create/change screens, beyond
  the current 12-character floor.
- "Full re-encrypt" action for suspected compromise (new vault key, every entry
  re-encrypted) — see CLAUDE.md caveat under the crypto design. Would also
  rebind any remaining legacy (pre-AAD) ciphertexts in one sweep.

## Done

- Rate-limit failed `/api/*` token auth: per-IP failure counter in front of
  `auth()` (429 after 10 failures per 15 min, refused before the compare so a
  blocked guess learns nothing), plus a 16-character minimum on `-token` at
  startup. See DESIGN-DECISIONS.md for the IP-bucketing reasoning.
- Install-as-PWA prompt on the welcome step and in Settings (the browser's own install control is easy to miss); iOS gets Add-to-Home-Screen instructions since it has no install prompt.
- Themed confirm dialogs for destructive actions (delete entry, restore backup, print recovery sheet) — replaced the out-of-place browser `window.confirm`.
- Name a vault at creation ("Home", "Work"); the name labels the installed PWA icon (client-side manifest, so it never touches the server) and the lock screen.
- Vault name syncs end-to-end encrypted: a new device connecting to a Vault ID inherits the name on first unlock, and renaming on any device propagates to all of them.
- Fixed iOS unlock doing nothing: `crypto.subtle` is unavailable over plain HTTP (non-secure context), so unlock failed silently. Now detects it and shows a clear "needs HTTPS" message; unlock rejections can no longer fail silently. (Serve iOS over HTTPS — mkcert on LAN, or a reverse proxy.)

