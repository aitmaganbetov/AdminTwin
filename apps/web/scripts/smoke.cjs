// Playwright smoke-тест AdminTwin Web UI против локального ядра (ADMINTWIN_DEV_AUTH=true, ADMINTWIN_SIMULATOR=true,
// ADMINTWIN_FIXTURES=infra/dev/fixtures.yaml). Запуск: `node scripts/smoke.cjs` (UI на WEB_URL, по умолчанию :3000).
/* eslint-disable @typescript-eslint/no-require-imports */
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require("playwright");

const BASE = process.env.WEB_URL || "http://localhost:3000";
const OUT = path.join(__dirname, "..", "docs", "screenshots");
const TENANT_A = "11111111-1111-4111-8111-111111111111";
const DOCKER_WEB = "a0000000-0000-4000-8000-000000000002";
const APP_LINUX = "a0000000-0000-4000-8000-000000000003";

const results = [];
const consoleErrors = [];
function step(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function shot(page, name) {
  fs.mkdirSync(OUT, { recursive: true });
  const p = path.join(OUT, `${name}.png`);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: p, fullPage: true });
  return p;
}

async function newPage(browser, opts) {
  const ctx = await browser.newContext({ deviceScaleFactor: 1, ...opts });
  const page = await ctx.newPage();
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource: the server responded with a status of (404|403|409|422)/.test(m.text())) {
      consoleErrors.push(m.text());
    }
  });
  page.on("pageerror", (e) => consoleErrors.push(`pageerror: ${e.message}`));
  return { ctx, page };
}

async function devLogin(page, { actor = "alice", roles = ["tenant_admin"], scopes = [] } = {}) {
  await page.goto(`${BASE}/`);
  await page.waitForURL(/\/login/);
  await page.selectOption("[data-testid=dev-tenant]", TENANT_A);
  await page.fill("#dev-actor", actor);
  for (const box of await page.$$('input[name="roles"]')) {
    const v = await box.getAttribute("value");
    if (roles.includes(v) !== (await box.isChecked())) await box.click();
  }
  for (const box of await page.$$('input[name="scopes"]')) {
    const v = await box.getAttribute("value");
    if (scopes.includes(v) !== (await box.isChecked())) await box.click();
  }
  await page.click("[data-testid=dev-login-submit]");
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.waitForSelector("header.header");
}

async function createChange(page, { runbook, asset, params, reason }) {
  await page.goto(`${BASE}/changes/new`);
  await page.waitForSelector("[data-testid=cf-runbook]");
  await page.selectOption("[data-testid=cf-runbook]", runbook);
  await page.selectOption("[data-testid=cf-asset]", asset);
  for (const [k, v] of Object.entries(params)) {
    const sel = `[data-testid=param-${k}]`;
    await page.waitForSelector(sel);
    const tag = await page.$eval(sel, (el) => el.tagName);
    if (tag === "SELECT") await page.selectOption(sel, v);
    else await page.fill(sel, v);
  }
  await page.fill("[data-testid=cf-reason]", reason);
  const key = await page.textContent("[data-testid=idem-key]");
  await page.click("[data-testid=cf-submit]");
  await page.waitForURL(/\/changes\/[0-9a-f-]{36}/, { timeout: 15000 });
  return { url: page.url(), idemKey: key };
}

async function waitStatus(page, status, timeout = 15000) {
  await page.waitForFunction(
    (s) => document.querySelector("[data-testid=change-status]")?.textContent?.trim() === s,
    status,
    { timeout },
  );
}

(async () => {
  const browser = await chromium.launch();
  try {
    // ---------- desktop, light ----------
    const { ctx, page } = await newPage(browser, { viewport: { width: 1366, height: 900 }, colorScheme: "light" });
    await page.goto(`${BASE}/`);
    await page.waitForURL(/\/login/);
    step("unauthenticated user is redirected to DEV login", true, page.url());
    await shot(page, "01-login-light");

    await devLogin(page);
    step("dev login (Tenant A, alice, tenant_admin)", true);
    await page.waitForSelector("[data-testid=cc-kill-state]");
    await shot(page, "02-command-center-light");

    await page.goto(`${BASE}/assets`);
    await page.waitForSelector("[data-testid=assets-table] tbody tr");
    const rows = await page.$$eval("[data-testid=assets-table] tbody tr", (r) => r.length);
    const hasLegalHold = await page.isVisible("text=legal hold");
    step("assets list renders", rows === 5 && hasLegalHold, `${rows} rows, legal hold badge: ${hasLegalHold}`);
    await shot(page, "03-assets-light");

    // docker.container.restart → closed (operator mode, low risk → auto_ok)
    const c1 = await createChange(page, {
      runbook: "docker.container.restart",
      asset: DOCKER_WEB,
      params: { container_id: "3f2a9c1b7d4e" },
      reason: "smoke: restart app-api",
    });
    await waitStatus(page, "closed");
    const evidence = await page.textContent("[data-testid=evidence-id]");
    step("docker.container.restart reaches closed", true, `${c1.url} idem=${c1.idemKey} evidence=${evidence}`);
    await shot(page, "04-change-closed-light");

    // linux.logs.rotate_cleanup → waiting_approval; author approves → 403 separation-of-duties
    const c2 = await createChange(page, {
      runbook: "linux.logs.rotate_cleanup",
      asset: APP_LINUX,
      params: { directory: "/var/log/nginx" },
      reason: "smoke: rotate nginx logs",
    });
    await waitStatus(page, "waiting_approval");
    step("linux.logs.rotate_cleanup shows waiting_approval", true, c2.url);
    const authorWarn = await page.isVisible("text=Вы — автор этого запроса");
    await page.fill("[data-testid=approval-comment]", "self-approve attempt");
    await page.click("[data-testid=approve]");
    await page.waitForSelector("[data-testid=approval-error] [data-problem-code]");
    const code = await page.getAttribute("[data-testid=approval-error] [data-problem-code]", "data-problem-code");
    const rid = await page.textContent("[data-testid=approval-error] [data-testid=request-id]");
    step("author approval → 403 separation-of-duties shown", code === "separation-of-duties" && !!rid, `code=${code} request_id=${rid} authorWarning=${authorWarn}`);
    await shot(page, "05-approval-sod-light");

    // invalid params → 422 field errors mapped to the form (client validation bypassed by valid-looking pattern)
    await page.goto(`${BASE}/changes/new?runbook=docker.container.restart&asset=${DOCKER_WEB}`);
    // До загрузки CMDB поле — текст с подсказкой pattern; после — select из объектов актива.
    const sel = await page.waitForSelector("select[data-testid=param-container_id]", { timeout: 10000 }).catch(() => null);
    const opts = sel ? await sel.$$eval("option", (o) => o.map((x) => x.textContent)) : [];
    step("param form generated from schema (inventory select)", !!sel && opts.some((o) => /0a1b2c3d4e5f \(/.test(o)), opts.join(" | "));

    // Stage 1 modules not served yet → graceful "module not available"
    for (const p of ["/incidents", "/collaboration", "/ai"]) {
      await page.goto(`${BASE}${p}`);
      await page.waitForSelector("[data-testid=module-unavailable]", { timeout: 10000 });
    }
    step("incidents / agent collaboration / AI degrade to 'module not available'", true);
    await page.goto(`${BASE}/incidents`);
    await page.waitForSelector("[data-testid=module-unavailable]");
    await shot(page, "06-incidents-unavailable-light");

    await page.goto(`${BASE}/topology?asset=${APP_LINUX}`);
    await page.waitForSelector("[data-testid=blast-table] tbody tr");
    step("topology + blast radius highlight", await page.isVisible(".topo-node.is-impacted"));
    await shot(page, "07-topology-light");

    await page.goto(`${BASE}/audit`);
    await page.waitForSelector("[data-testid=integrity] .notice");
    step("audit integrity check", await page.isVisible("text=Hash chain цела"));

    // Kill switch toggle (on → banner → change rejected → off)
    await page.goto(`${BASE}/settings`);
    await page.waitForSelector("[data-testid=kill-state]");
    await page.click("[data-testid=kill-toggle]");
    await page.fill("[data-testid=kill-reason]", "smoke drill");
    await page.check("[data-testid=kill-ack]");
    await page.click("[data-testid=kill-confirm]");
    await page.waitForFunction(() => document.querySelector("[data-testid=kill-state]")?.textContent === "АКТИВЕН");
    await page.waitForSelector("[data-testid=kill-banner]");
    step("kill switch activated (tenant), banner shown", true);
    await shot(page, "08-kill-switch-active-light");

    await page.goto(`${BASE}/changes/new`);
    await createChange(page, { runbook: "docker.container.restart", asset: DOCKER_WEB, params: { container_id: "9b8c7d6e5f4a" }, reason: "smoke: must be rejected" }).catch(() => null);
    const killCode = await page.getAttribute("[data-problem-code]", "data-problem-code").catch(() => null);
    step("new change rejected with kill-switch-active", killCode === "kill-switch-active", `code=${killCode}`);
    await shot(page, "09-kill-switch-rejected-light");

    await page.goto(`${BASE}/settings`);
    await page.waitForSelector("[data-testid=kill-state]");
    await page.click("[data-testid=kill-toggle]");
    await page.fill("[data-testid=kill-reason]", "drill finished");
    await page.click("[data-testid=kill-confirm]");
    await page.waitForFunction(() => document.querySelector("[data-testid=kill-state]")?.textContent === "не активен");
    step("kill switch deactivated", !(await page.isVisible("[data-testid=kill-banner]")));

    // ---------- dark theme toggle + kk ----------
    // Kill switch отзывает открытые согласования (§11.7): c2 больше не ждёт согласования.
    await page.goto(c2.url);
    await waitStatus(page, "rejected");
    step("kill switch revoked the open approval (waiting_approval → rejected)", true);
    await page.click("[data-testid=theme-toggle]");
    const theme = await page.getAttribute("html", "data-theme");
    step("theme toggle → dark", theme === "dark", `data-theme=${theme}`);
    await shot(page, "10-change-revoked-dark");
    await createChange(page, { runbook: "linux.logs.rotate_cleanup", asset: APP_LINUX, params: { directory: "/var/log/app" }, reason: "smoke: dark view" });
    await waitStatus(page, "waiting_approval");
    await shot(page, "10b-change-waiting-dark");
    await page.goto(`${BASE}/`);
    await page.selectOption("[data-testid=lang-select]", "kk");
    await page.waitForSelector("text=Басқару орталығы");
    const lang = await page.getAttribute("html", "lang");
    step("language switch → kk (Cyrillic Kazakh)", lang === "kk", `lang=${lang}`);
    await shot(page, "11-command-center-dark-kk");
    await page.selectOption("[data-testid=lang-select]", "en");
    await page.goto(`${BASE}/runbooks`);
    await page.waitForSelector('[data-testid="runbook-linux.logs.rotate_cleanup"]');
    await shot(page, "12-runbooks-dark-en");
    await page.goto(`${BASE}/capabilities`);
    await page.waitForSelector("[data-testid=capabilities-table] tbody tr");
    await page.click("button:has-text('P1a')");
    await page.waitForTimeout(300);
    step("capabilities tier filter + 'reference ≠ certification' notice", await page.isVisible("text=Reference to a standard ≠ certification"));
    await ctx.close();

    // ---------- phone width ----------
    const phone = await newPage(browser, { viewport: { width: 390, height: 844 }, colorScheme: "dark", isMobile: true, hasTouch: true });
    await devLogin(phone.page);
    await phone.page.waitForSelector("[data-testid=cc-kill-state]");
    const overflow = await phone.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    step("phone width: no horizontal page scroll (command center)", overflow <= 0, `overflow=${overflow}px`);
    await shot(phone.page, "13-phone-command-center-dark");
    await phone.page.click("button[aria-controls=primary-nav]");
    await phone.page.waitForSelector(".sidebar[data-open=true]");
    await phone.page.screenshot({ path: path.join(OUT, "14-phone-menu-dark.png") });
    await phone.page.keyboard.press("Escape");
    await phone.page.goto(c1.url);
    await waitStatus(phone.page, "closed");
    const overflow2 = await phone.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    step("phone width: no horizontal page scroll (change detail)", overflow2 <= 0, `overflow=${overflow2}px`);
    await shot(phone.page, "15-phone-change-dark");
    await phone.ctx.close();

    const phoneLight = await newPage(browser, { viewport: { width: 390, height: 844 }, colorScheme: "light", isMobile: true, hasTouch: true });
    await devLogin(phoneLight.page);
    await phoneLight.page.goto(`${BASE}/assets`);
    await phoneLight.page.waitForSelector("[data-testid=assets-table] tbody tr");
    const overflow3 = await phoneLight.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    step("phone width: no horizontal page scroll (assets)", overflow3 <= 0, `overflow=${overflow3}px`);
    await shot(phoneLight.page, "16-phone-assets-light");
    // keyboard: skip link is the first focusable element and visible on focus
    await phoneLight.page.keyboard.press("Tab");
    const focused = await phoneLight.page.evaluate(() => document.activeElement?.className);
    step("keyboard: skip link receives first focus", focused === "skip-link", `focused=${focused}`);
    await phoneLight.ctx.close();
  } catch (e) {
    step("unexpected error", false, e && e.stack ? e.stack.split("\n").slice(0, 3).join(" | ") : String(e));
  } finally {
    await browser.close();
  }
  step("no unexpected console errors", consoleErrors.length === 0, consoleErrors.slice(0, 5).join(" || "));
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed; screenshots in ${OUT}`);
  process.exit(failed.length ? 1 : 0);
})();
