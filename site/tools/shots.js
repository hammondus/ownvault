// Regenerates the app screenshots used on the website. Run it with
// `make shots` from site/, with the vault app running on :8080
// (`go run . -dev` in the repository root).
//
// The screenshots are of the real app, filled with invented logins. The
// vault is created fresh in a throwaway browser profile each run and the
// entries go in through Vault.put — the same API the add form calls, and far
// more reliable than driving that form eight times.
//
// Playwright is a dev-only tool, installed on demand by `make shots`. The
// site itself has no JavaScript and no node_modules.

const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const path = require('path');

const OUT = process.argv[2] || 'web/img';
const APP = process.env.OV_APP_URL || 'http://localhost:8080';
const PW = 'correct horse battery staple';

// Rendered at 3x and downscaled to 700px wide: the site shows them at roughly
// 350 CSS px, so this stays sharp on a retina screen without shipping a 1200px
// PNG for every one.
const VIEWPORT = { width: 400, height: 860 };
const SCALE = 3;
const FINAL_WIDTH = 700;

const ENTRIES = [
  { title: 'GitHub', username: 'craig@example.com', password: 'r7Kq-2mZv-9TbL-wX4e',
    url: 'https://github.com', totp: 'JBSWY3DPEHPK3PXP',
    notes: 'Recovery codes are in the safe.' },
  { title: 'Fastmail', username: 'craig@example.com', password: 'Hd3p!vQn8sYt2Lc',
    url: 'https://app.fastmail.com', notes: '' },
  { title: 'AWS console', username: 'ops-admin', password: 'Zk9%tR4wLp1Vn6Qs',
    url: 'https://console.aws.amazon.com', critical: true, totp: 'KRSXG5CTMVRXEZLU',
    notes: 'Root account. Billing alerts go to the ops alias.' },
  { title: 'Bendigo Bank', username: '4471 9903', password: 'Mq2#dFj7xNb5',
    url: 'https://banking.bendigobank.com.au', critical: true,
    notes: 'Card PIN is not stored here.' },
  { title: 'Hetzner Cloud', username: 'craig@example.com', password: 'Wt6&yUe1oPa3Kd',
    url: 'https://console.hetzner.cloud', notes: 'arm64 box running the sync server.' },
  { title: 'Netflix', username: 'family@example.com', password: 'Jr8*mCx4bTz0',
    url: 'https://netflix.com', notes: '' },
  { title: 'Namecheap', username: 'hammondus', password: 'Vb5$nQw9rEy2Ax',
    url: 'https://ap.www.namecheap.com', notes: 'Domain renewals, October.' },
  { title: 'Home router', username: 'admin', password: 'Ls3!kGh6dJm8',
    url: 'https://192.168.1.1', notes: 'Guest WiFi password is on the fridge.' }
];

const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: SCALE });

  // Sync off, so the lock gate opens on "create a vault" rather than the
  // connect step, and nothing is pushed to whatever server is on :8080.
  await ctx.addInitScript(() => localStorage.setItem('syncEnabled', '0'));

  const page = await ctx.newPage();
  const shot = name => page.screenshot({ path: path.join(OUT, name + '.png') })
    .then(() => console.log('  ' + name + '.png'));

  await page.goto(APP + '/');
  await page.waitForSelector('#create-form:not([hidden])', { timeout: 20000 });

  await page.fill('#create-name', 'Home');
  await page.fill('#create-pw', PW);
  await page.fill('#create-pw2', PW);
  await page.click('#create-form button[type=submit]');

  // Argon2id at 64 MiB is deliberately slow; give it room.
  await page.waitForSelector('#welcome-continue', { state: 'visible', timeout: 60000 });
  await page.click('#welcome-continue');
  await page.waitForSelector('#pw-list', { state: 'attached', timeout: 20000 });

  await page.evaluate(async entries => {
    for (const e of entries) await window.Vault.put(e);
  }, ENTRIES);
  await wait(1200);
  await shot('list');

  await page.fill('#pw-search', 'example');
  await wait(500);
  await shot('search');
  await page.fill('#pw-search', '');
  await wait(400);

  // The record modal, on the entry that has an authenticator key.
  await page.click('#pw-list li:has-text("AWS console")');
  await page.waitForSelector('#record-modal:not([hidden])', { timeout: 10000 });
  await wait(1200);
  await shot('record');
  await page.keyboard.press('Escape');
  await wait(500);

  await page.click('#menu-btn');
  await wait(500);
  await page.click('a[hx-push-url="/settings"]');
  await page.waitForSelector('#main .screen', { timeout: 10000 });
  await wait(900);
  await shot('settings');

  // Reload to get the plain unlock gate, then crop away the empty space above
  // and below the centred form.
  await page.reload();
  await page.waitForSelector('#unlock-form:not([hidden])', { timeout: 20000 });
  await wait(600);
  await shot('unlock');

  await browser.close();

  // sips is macOS-only and part of the base system, which suits a step run by
  // hand on the dev machine. On another platform, resize these by whatever
  // means is at hand — only the pixel dimensions matter.
  const p = n => path.join(OUT, n + '.png');
  execFileSync('sips', ['-c', String(VIEWPORT.height * SCALE * 0.58),
                        String(VIEWPORT.width * SCALE), p('unlock')], { stdio: 'ignore' });
  for (const n of ['list', 'search', 'record', 'settings', 'unlock']) {
    execFileSync('sips', ['--resampleWidth', String(FINAL_WIDTH), p(n)], { stdio: 'ignore' });
  }
  console.log('done');
})().catch(e => { console.error(e); process.exit(1); });
