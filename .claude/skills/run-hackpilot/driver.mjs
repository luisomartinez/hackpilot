#!/usr/bin/env node
// Minimal chromium-cli-shaped REPL driver for HackPilot's web dashboard.
// chromium-cli isn't available in this environment, so this adapts the
// run-skill-generator's documented fallback: Playwright's `chromium`
// (not `_electron`) launched headless, driven by line commands piped
// over stdin. Commands (one per line):
//
//   nav <url>
//   wait-for text=<substring>        (also accepts a raw CSS selector)
//   wait-for sel=<css selector>
//   click <css selector>
//   fill <css selector> <text...>
//   press <key>
//   screenshot [name]                -> screenshots/<name|auto>.png (full page)
//   screenshot-visible [name]        -> same, viewport only (no scroll) -
//                                       use for a centered modal on a page
//                                       that scrolls for miles
//   console                          -> prints captured console/page errors
//   eval <js expression>
//   quit
//
// Usage:
//   node driver.mjs <<'EOF'
//   nav http://admin:PASSWORD@localhost:8080/
//   wait-for text=Dashboard Overview
//   screenshot home
//   EOF
//
// Screenshots land in ./screenshots/ next to this file.

import { chromium } from 'playwright';
import { createInterface } from 'node:readline';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCREEN_DIR = path.join(__dirname, 'screenshots');
mkdirSync(SCREEN_DIR, { recursive: true });

const consoleLog = [];

const browser = await chromium.launch({ headless: true });
const contextOptions = { ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } };
// Basic Auth: Chromium aborts navigation on user:pass@host URLs, so pass
// credentials via the context instead of embedding them in `nav`'s URL.
if (process.env.BASIC_AUTH_USER) {
  contextOptions.httpCredentials = {
    username: process.env.BASIC_AUTH_USER,
    password: process.env.BASIC_AUTH_PASS || '',
  };
}
const context = await browser.newContext(contextOptions);
const page = await context.newPage();

page.on('console', (msg) => consoleLog.push({ type: msg.type(), text: msg.text() }));
page.on('pageerror', (err) => consoleLog.push({ type: 'pageerror', text: String(err) }));

let shotCounter = 0;

function parseWaitTarget(arg) {
  if (arg.startsWith('text=')) return { kind: 'text', value: arg.slice(5) };
  if (arg.startsWith('sel=')) return { kind: 'sel', value: arg.slice(4) };
  return { kind: 'sel', value: arg };
}

async function runCommand(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return;
  const [cmd, ...rest] = trimmed.split(/\s+/);
  const argLine = trimmed.slice(cmd.length).trim();

  switch (cmd) {
    case 'nav': {
      await page.goto(argLine, { waitUntil: 'domcontentloaded', timeout: 30000 });
      console.log(`[nav] ${argLine} -> ${page.url()} (status via network not tracked)`);
      break;
    }
    case 'wait-for': {
      const target = parseWaitTarget(argLine);
      if (target.kind === 'text') {
        await page.getByText(target.value, { exact: false }).first().waitFor({ timeout: 15000 });
      } else {
        await page.locator(target.value).first().waitFor({ timeout: 15000 });
      }
      console.log(`[wait-for] found: ${argLine}`);
      break;
    }
    case 'click': {
      await page.locator(argLine).first().click({ timeout: 10000 });
      console.log(`[click] ${argLine}`);
      break;
    }
    case 'fill': {
      const [sel, ...text] = rest;
      await page.locator(sel).first().fill(text.join(' '));
      console.log(`[fill] ${sel} = "${text.join(' ')}"`);
      break;
    }
    case 'press': {
      await page.keyboard.press(argLine);
      console.log(`[press] ${argLine}`);
      break;
    }
    case 'screenshot': {
      const name = argLine || `shot-${++shotCounter}`;
      const out = path.join(SCREEN_DIR, `${name}.png`);
      await page.screenshot({ path: out, fullPage: true });
      console.log(`[screenshot] ${out}`);
      break;
    }
    case 'screenshot-visible': {
      // Viewport-only (not fullPage) - use for a centered modal/dialog on a
      // page whose body scrolls for miles (a findings table with 100+ rows
      // makes a fullPage shot nearly unreadable).
      const name = argLine || `shot-${++shotCounter}`;
      const out = path.join(SCREEN_DIR, `${name}.png`);
      await page.screenshot({ path: out, fullPage: false });
      console.log(`[screenshot-visible] ${out}`);
      break;
    }
    case 'eval': {
      const result = await page.evaluate(argLine);
      console.log(`[eval] ${JSON.stringify(result)}`);
      break;
    }
    case 'console': {
      const errors = consoleLog.filter(e => e.type === 'error' || e.type === 'pageerror');
      console.log(`[console] ${consoleLog.length} total, ${errors.length} error(s)`);
      for (const e of errors) console.log(`  [${e.type}] ${e.text}`);
      break;
    }
    case 'quit': {
      await browser.close();
      process.exit(0);
    }
    default:
      console.log(`[?] unknown command: ${cmd}`);
  }
}

// Readline fires 'line' events as fast as stdin produces them, without
// waiting for an async handler to finish - piping a whole heredoc in one
// shot meant 'close' (EOF) fired and closed the browser while the first
// `nav` was still in flight, aborting it. Queue commands and run them
// strictly one at a time instead.
let queue = Promise.resolve();
let closed = false;

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  queue = queue.then(async () => {
    if (closed) return;
    try {
      await runCommand(line);
    } catch (err) {
      console.log(`[error] ${err.message}`);
    }
  });
});
rl.on('close', () => {
  queue = queue.then(async () => {
    if (closed) return;
    closed = true;
    await browser.close();
    process.exit(0);
  });
});
