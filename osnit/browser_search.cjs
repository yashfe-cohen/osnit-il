#!/usr/bin/env node
/* No-API web discovery through the pre-installed headless Chromium (Playwright), driven as a subprocess — the way
 * Burp/Acunetix use a real browser instead of shipping a scraper. Reads ONE JSON request on stdin, launches
 * Chromium ONCE, loads a single search-engine results page, returns the outbound result URLs (and any document
 * links) as ONE JSON object on stdout. Logs go to stderr. It never throws to the shell: a missing browser, a
 * blocked/consent page, or a navigation failure is reported as {ok:false, code:...} so the Python side degrades
 * to [] instead of crashing. No login walls, no captcha solving — a challenge page returns code:"blocked".
 *
 * Request  (stdin JSON): {query, engine:"bing"|"duckduckgo"|"brave", limit, user_agent, nav_timeout_ms,
 *                         proxy, headful}
 * Response (stdout JSON): {ok:true, urls:[...], doc_links:[...], engine, note}
 *                    or   {ok:false, code:"no-browser"|"nav-failed"|"blocked"|"bad-request"|"timeout", error}
 */
'use strict';

const DOC_EXT = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt', '.json', '.vcf', '.xml', '.rtf'];

const ENGINES = {
  bing: { url: q => `https://www.bing.com/search?setlang=he&count=30&q=${encodeURIComponent(q)}`,
          sel: 'li.b_algo h2 a, li.b_algo a.tilk' },
  duckduckgo: { url: q => `https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`,
                sel: 'a.result__a' },
  brave: { url: q => `https://search.brave.com/search?q=${encodeURIComponent(q)}`,
           sel: 'a.result-header, #results a[href^="http"]' },
};

function out(obj) { process.stdout.write(JSON.stringify(obj)); }

function readStdin() {
  return new Promise(resolve => {
    let s = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', d => { s += d; });
    process.stdin.on('end', () => resolve(s));
    setTimeout(() => resolve(s), 2000);   // a caller that forgets to close stdin still proceeds
  });
}

function unwrap(href) {
  // Bing and others wrap outbound links in a redirector; recover the real destination from ?u=/&url=.
  try {
    const u = new URL(href);
    for (const k of ['u', 'url', 'uddg', 'r']) {
      let v = u.searchParams.get(k);
      if (v) {
        if (/^a1/.test(v)) { try { v = Buffer.from(v.slice(2), 'base64').toString('utf8'); } catch (e) {} }
        if (/^https?:\/\//.test(v)) return v;
      }
    }
    return href;
  } catch (e) { return href; }
}

const BLOCKED_HOST = /(^|\.)(bing|duckduckgo|google|brave|microsoft|msn|yahoo)\.com$/i;
const CONSENT = /\/sorry\/|consent\.|captcha|unusual traffic|verify you are human/i;

async function main() {
  let req;
  try { req = JSON.parse(await readStdin()); } catch (e) { return out({ ok: false, code: 'bad-request', error: 'stdin is not JSON' }); }
  if (!req || !req.query) return out({ ok: false, code: 'bad-request', error: 'no query' });
  const eng = ENGINES[req.engine] || ENGINES.bing;

  let chromium;
  try { ({ chromium } = require('playwright')); }
  catch (e) {
    try { ({ chromium } = require('/opt/node-tools/node_modules/playwright')); }
    catch (e2) { return out({ ok: false, code: 'no-browser', error: 'playwright not installed' }); }
  }

  let browser;
  try {
    const launch = { headless: !req.headful, args: ['--no-sandbox', '--disable-dev-shm-usage'] };
    if (req.proxy) launch.proxy = { server: req.proxy };
    browser = await chromium.launch(launch);
  } catch (e) {
    return out({ ok: false, code: 'no-browser', error: String(e && e.message || e).slice(0, 300) });
  }

  try {
    const ctx = await browser.newContext({
      userAgent: req.user_agent || undefined,
      ignoreHTTPSErrors: true, locale: 'he-IL',
    });
    const page = await ctx.newPage();
    const nav = Math.max(5000, req.nav_timeout_ms || 25000);
    let resp;
    try { resp = await page.goto(eng.url(req.query), { waitUntil: 'domcontentloaded', timeout: nav }); }
    catch (e) { await browser.close(); return out({ ok: false, code: 'nav-failed', error: String(e && e.message || e).slice(0, 300) }); }

    const bodyText = (await page.content()).slice(0, 4000);
    const curUrl = page.url();
    if (CONSENT.test(curUrl) || CONSENT.test(bodyText)) {
      await browser.close();
      return out({ ok: false, code: 'blocked', error: 'consent/captcha wall' });
    }

    let hrefs = [];
    try { hrefs = await page.$$eval(eng.sel, as => as.map(a => a.href).filter(Boolean)); } catch (e) {}
    if (!hrefs.length) {
      try { hrefs = await page.$$eval('a[href^="http"]', as => as.map(a => a.href)); } catch (e) {}
    }
    await browser.close();

    const seen = new Set(), urls = [], docs = [];
    for (let h of hrefs) {
      h = unwrap(h);
      let host;
      try { host = new URL(h).hostname; } catch (e) { continue; }
      if (!/^https?:$/.test(new URL(h).protocol) || BLOCKED_HOST.test(host)) continue;
      if (seen.has(h)) continue;
      seen.add(h);
      const path = new URL(h).pathname.toLowerCase();
      if (DOC_EXT.some(x => path.endsWith(x))) docs.push(h);
      urls.push(h);
      if (urls.length >= (req.limit || 20) * 2) break;
    }
    return out({ ok: true, urls: urls.slice(0, (req.limit || 20)), doc_links: docs, engine: req.engine || 'bing' });
  } catch (e) {
    try { await browser.close(); } catch (e2) {}
    return out({ ok: false, code: 'nav-failed', error: String(e && e.message || e).slice(0, 300) });
  }
}

main().catch(e => out({ ok: false, code: 'nav-failed', error: String(e && e.message || e).slice(0, 300) }));
