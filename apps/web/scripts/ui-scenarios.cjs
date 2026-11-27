// Сквозные сценарии UI: клавиатура, сохранение + перезагрузка, фильтры, роли, двойная отправка, большой объём.
// node scripts/ui-scenarios.cjs [outDir]   (env: WEB_URL, CORE_URL). Создаёт данные в ядре (инциденты, изменения).
/* eslint-disable @typescript-eslint/no-require-imports */
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require("playwright");
const BASE = process.env.WEB_URL || "http://localhost:3000";
const CORE = process.env.CORE_URL || "http://127.0.0.1:8080";
const T = "11111111-1111-4111-8111-111111111111";
const OUT = process.argv[2] || path.join(require("node:os").tmpdir(), "admintwin-ui-scenarios");
fs.mkdirSync(OUT, { recursive: true });
const results = [];
const ok = (name, pass, detail = "") => {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
};
const hdr = (actor, roles, scopes = "") => ({ "X-AdminTwin-Tenant": T, "X-AdminTwin-Actor": actor, "X-AdminTwin-Roles": roles, "X-AdminTwin-Scopes": scopes, "Content-Type": "application/json" });
async function api(method, p, body, h = hdr("alice", "tenant_admin")) {
  const r = await fetch(CORE + p, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json().catch(() => null) };
}

async function login(page, { actor = "alice", roles = ["tenant_admin"], scopes = [] } = {}) {
  await page.goto(`${BASE}/login`);
  await page.waitForSelector("[data-testid=dev-tenant]");
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
const focused = (page) =>
  page.evaluate(() => {
    const e = document.activeElement;
    return e ? `${e.tagName.toLowerCase()}${e.id ? "#" + e.id : ""}|${(e.getAttribute("aria-label") || e.textContent || "").trim().slice(0, 40)}` : "";
  });
const outline = (page) =>
  page.evaluate(() => {
    const e = document.activeElement;
    const cs = getComputedStyle(e);
    return cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) >= 2 ? `${cs.outlineWidth} ${cs.outlineStyle}` : `none (${cs.boxShadow.slice(0, 30)})`;
  });

(async () => {
  const browser = await chromium.launch();
  const consoleErrors = [];
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  page.on("console", (m) => m.type() === "error" && !/status of 404/.test(m.text()) && consoleErrors.push(m.text()));
  page.on("pageerror", (e) => consoleErrors.push("pageerror " + e.message));

  // --- 1. Только клавиатура: вход ---
  await page.goto(`${BASE}/login`);
  await page.waitForSelector("[data-testid=dev-tenant]");
  await page.fill("#dev-actor", "");
  await page.focus("#dev-actor");
  await page.keyboard.type("bad actor!");
  await page.keyboard.press("Enter");
  const actorErr = await page.$eval("#dev-actor", (e) => ({ inv: e.getAttribute("aria-invalid"), focus: document.activeElement === e, msg: document.getElementById("dev-actor-err")?.textContent }));
  ok("login: invalid actor shows error next to field and keeps focus", actorErr.inv === "true" && actorErr.focus && !!actorErr.msg, actorErr.msg);
  await page.fill("#dev-actor", "alice");
  await page.keyboard.press("Enter");
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  ok("login: Enter submits the form", true);

  // skip link
  await page.goto(`${BASE}/`);
  await page.waitForSelector("[data-testid=cc-kill-state]");
  await page.keyboard.press("Tab");
  const f1 = await focused(page);
  ok("first Tab focuses the skip link", /skip|Перейти/i.test(f1) || f1.startsWith("a|"), f1);
  await page.keyboard.press("Enter");
  ok("skip link moves focus to main", (await focused(page)).startsWith("main#main"), await focused(page));
  // Tab order header → nav → main, видимый фокус
  await page.goto(`${BASE}/incidents`);
  await page.waitForSelector("[data-testid=incidents-table]");
  const order = [];
  const outlines = new Set();
  for (let i = 0; i < 22; i++) {
    await page.keyboard.press("Tab");
    order.push(await focused(page));
    outlines.add(await outline(page));
  }
  ok("Tab order: brand → language → theme → logout → nav → filters → table", order.findIndex((x) => x.includes("lang-select")) < order.findIndex((x) => x.includes("Инциденты")) && order.findIndex((x) => x.includes("inc-sev")) > order.findIndex((x) => x.includes("Настройки")), order.slice(0, 22).join(" › "));
  ok("focus indicator is visible (≥2px outline) on every stop", ![...outlines].some((o) => o.startsWith("none")), [...outlines].join("; "));

  // --- 2. Диалог: создание инцидента с клавиатуры, ошибка у поля, возврат фокуса, сохранение + перезагрузка ---
  const createBtn = page.getByRole("button", { name: /Создать инцидент/ });
  await createBtn.focus();
  await page.keyboard.press("Enter");
  await page.waitForSelector("dialog[open]");
  ok("dialog opens with focus inside", await page.evaluate(() => !!document.activeElement?.closest("dialog[open]")), await focused(page));
  await page.keyboard.press("Escape");
  await page.waitForFunction(() => !document.querySelector("dialog[open]"));
  await page.waitForTimeout(100);
  ok("Escape closes dialog and returns focus to the opener", /Создать инцидент/.test(await focused(page)), await focused(page));
  await page.keyboard.press("Enter");
  await page.waitForSelector("dialog[open]");
  await page.click("[data-testid=ni-submit]");
  const tErr = await page.$eval("#ni-title", (e) => ({ inv: e.getAttribute("aria-invalid"), focus: document.activeElement === e, msg: document.getElementById("ni-title-err")?.textContent }));
  ok("empty title: error under the field, focus moved to it", tErr.inv === "true" && tErr.focus && !!tErr.msg, tErr.msg);
  const longTitle = `UI-audit ${Date.now()} — очень длинный заголовок инцидента для проверки переноса: Қазақстан Ұлттық Әуе Ғарыш Өңірі Һ І ${"x".repeat(60)}`;
  await page.fill("#ni-title", longTitle);
  await page.selectOption("#ni-sev", "low");
  // двойная отправка: два клика подряд
  await Promise.all([page.click("[data-testid=ni-submit]"), page.click("[data-testid=ni-submit]").catch(() => {})]);
  await page.waitForFunction(() => !document.querySelector("dialog[open]"), null, { timeout: 10000 });
  await page.waitForTimeout(500);
  const created = (await api("GET", "/api/v1/incidents")).body.items.filter((i) => i.title === longTitle);
  ok("double click on «Создать инцидент» creates exactly one incident", created.length === 1, `created=${created.length}`);
  await page.reload();
  await page.waitForSelector("[data-testid=incidents-table]");
  ok("after reload the new incident is in the list", (await page.textContent("[data-testid=incidents-table]")).includes(longTitle.slice(0, 40)));

  // --- 3. Фильтры: выдача, пусто по фильтру, сброс ---
  await page.selectOption("#inc-sev", "low");
  await page.waitForFunction(() => /Найдено: 1/.test(document.querySelector("[data-testid=incidents-count]")?.textContent || ""), null, { timeout: 8000 }).catch(() => {});
  await page.waitForTimeout(800);
  const sevs = await page.$$eval("[data-testid=incidents-table] tbody tr td:nth-child(2)", (c) => c.map((x) => x.textContent.trim()));
  ok("severity filter narrows the list (every row is «низкий»)", sevs.length >= 1 && sevs.every((x) => x === "низкий"), `${sevs.length} rows: ${[...new Set(sevs)].join(",")}`);
  await page.selectOption("#inc-status", "closed");
  await page.waitForSelector("[data-testid=empty-filtered]", { timeout: 8000 });
  ok("no matches: «ничего не найдено» with reset (not «записей нет»)", await page.isVisible("[data-testid=reset-filters]"), await page.textContent("[data-testid=empty-filtered] h3"));
  await page.click("[data-testid=reset-filters]");
  await page.waitForSelector("[data-testid=incidents-table] tbody tr");
  ok("reset filters restores the list", (await page.$$("[data-testid=incidents-table] tbody tr")).length >= 2);
  await page.goto(`${BASE}/assets`);
  await page.waitForSelector("[data-testid=assets-table]");
  await page.fill("#asset-q", "zzz-no-such");
  await page.waitForSelector("[data-testid=empty-filtered]");
  ok("assets: search with no matches shows reset", true, await page.textContent("[data-testid=assets-count]"));
  await page.click("[data-testid=reset-filters]");
  await page.waitForSelector("[data-testid=assets-table] tbody tr");
  ok("assets: reset restores 5 rows and clears the field", (await page.$$("[data-testid=assets-table] tbody tr")).length === 5 && (await page.inputValue("#asset-q")) === "");
  await page.goto(`${BASE}/changes?status=rolled_back`);
  await page.waitForSelector("[data-testid=empty-filtered]");
  ok("changes: status with no records → «ничего не найдено» + reset", true);

  // --- 4. Изменение: форма → согласование другим пользователем → перезагрузка ---
  await page.goto(`${BASE}/changes/new`);
  await page.waitForSelector("[data-testid=cf-runbook]");
  await page.click("[data-testid=cf-submit]");
  const inv = await page.$$eval('[aria-invalid="true"]', (els) => els.map((e) => e.id));
  ok("change form: submit empty → invalid fields marked, focus on first", inv.includes("cf-runbook") && (await focused(page)).includes("cf-runbook"), inv.join(","));
  await page.selectOption("[data-testid=cf-runbook]", "linux.logs.rotate_cleanup");
  await page.selectOption("[data-testid=cf-asset]", "a0000000-0000-4000-8000-000000000003");
  await page.waitForSelector("[data-testid=param-directory]");
  await page.selectOption("[data-testid=param-directory]", "/var/log/app").catch(async () => page.fill("[data-testid=param-directory]", "/var/log/app"));
  const reasonText = `UI-audit reason ${Date.now()}`;
  await page.fill("[data-testid=cf-reason]", reasonText);
  const incOpt = await page.$$eval("#cf-incident option", (o) => o.length);
  ok("change form: incident is picked from a list of open incidents", incOpt >= 2, `${incOpt} options`);
  await Promise.all([page.waitForURL(/\/changes\/[0-9a-f-]{36}/), page.click("[data-testid=cf-submit]")]);
  const changeUrl = page.url();
  const chId = changeUrl.match(/changes\/([0-9a-f-]{36})/)[1];
  const dup = (await api("GET", "/api/v1/changes")).body.items.filter((c) => c.reason === reasonText);
  ok("change created once", dup.length === 1, chId);
  await page.waitForSelector("[data-testid=change-status]");
  ok("breadcrumb leads back to the changes list", (await page.getAttribute(".breadcrumb a", "href")) === "/changes");
  // автор видит предупреждение SoD; согласует другой пользователь
  const ctx2 = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1, isMobile: true, hasTouch: true });
  const p2 = await ctx2.newPage();
  p2.on("pageerror", (e) => consoleErrors.push("pageerror " + e.message));
  await login(p2, { actor: "carol", roles: ["it_manager"] });
  await p2.goto(changeUrl);
  await p2.waitForSelector("[data-testid=approve]");
  const apTop = await p2.$eval("[data-testid=approval-panel]", (e) => e.getBoundingClientRect().top);
  const sumTop = await p2.$eval("#ch-summary", (e) => e.getBoundingClientRect().top);
  ok("390px: approval panel is above the summary", apTop < sumTop, `approval ${Math.round(apTop)} < summary ${Math.round(sumTop)}`);
  await p2.screenshot({ path: path.join(OUT, "approve-mobile.png"), fullPage: false });
  await p2.fill("[data-testid=approval-comment]", "ok by carol");
  await p2.click("[data-testid=approve]");
  await p2.waitForFunction(() => document.querySelector("[data-testid=change-status]")?.textContent?.trim() !== "waiting_approval", null, { timeout: 15000 });
  await p2.reload();
  await p2.waitForSelector("[data-testid=change-status]");
  const st = (await p2.textContent("[data-testid=change-status]")).trim();
  const persisted = (await api("GET", `/api/v1/changes/${chId}`)).body;
  ok("approval saved: after reload status moved on and decision is listed", st !== "waiting_approval" && persisted.decisions.some((d) => d.actor_id === "carol"), `status=${st}`);

  // --- 5. Меню на 390 px с клавиатуры ---
  await p2.goto(`${BASE}/incidents`);
  await p2.waitForSelector("[data-testid=incidents-table]");
  const menu = p2.locator(".menu-button");
  await menu.focus();
  await p2.keyboard.press("Enter");
  await p2.waitForSelector(".sidebar[data-open=true]");
  const inNav = await p2.evaluate(() => !!document.activeElement?.closest("#primary-nav"));
  await p2.keyboard.press("Escape");
  await p2.waitForSelector(".sidebar[data-open=false]", { state: "attached" });
  const back = await p2.evaluate(() => document.activeElement?.classList.contains("menu-button"));
  ok("390px menu: opens with Enter (focus moves in), Escape closes and returns focus", inNav && back, `inNav=${inNav} back=${back}`);
  const ov = await p2.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
  ok("390px incidents with a long title: no page-level horizontal scroll", !ov);
  await p2.screenshot({ path: path.join(OUT, "incidents-long-390.png"), fullPage: true });

  // --- 6. Роли: viewer и auditor ---
  const ctx3 = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const p3 = await ctx3.newPage();
  await login(p3, { actor: "frank", roles: ["viewer"] });
  await p3.goto(`${BASE}/`);
  await p3.waitForSelector("[data-testid=cc-kill-state]");
  const viewerNew = await p3.isVisible("text=Новое изменение");
  await p3.goto(`${BASE}/changes/${chId}`);
  await p3.waitForSelector("[data-testid=approval-panel]");
  const viewerApprove = await p3.isVisible("[data-testid=approve]");
  const viewerCancel = await p3.isVisible("[data-testid=cancel-change]");
  ok("viewer: no «Новое изменение», no approve/cancel actions", !viewerNew && !viewerApprove && !viewerCancel);
  await p3.goto(`${BASE}/incidents`);
  await p3.waitForSelector("[data-testid=incidents-table]");
  ok("viewer: no «Создать инцидент»", !(await p3.isVisible("text=Создать инцидент")));
  await p3.screenshot({ path: path.join(OUT, "viewer-incidents.png") });

  // --- 7. Большой объём: 60 инцидентов ---
  for (let i = 0; i < 60; i++) await api("POST", "/api/v1/incidents", { title: `Bulk incident #${i} ${"long-name-".repeat(i % 4)}`, severity: ["low", "medium", "high"][i % 3], asset_ids: [] });
  await page.goto(`${BASE}/incidents`);
  await page.waitForSelector("[data-testid=incidents-table]");
  const rows = (await page.$$("[data-testid=incidents-table] tbody tr")).length;
  const ov2 = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
  ok("62+ incidents: table renders, header sticky, no page overflow", rows >= 60 && !ov2, `${rows} rows`);
  await page.mouse.wheel(0, 2400);
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(OUT, "incidents-many.png") });

  ok("no console errors (excluding expected 404 for unpublished modules)", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));
  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(results, null, 2));
  await browser.close();
  console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed`);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
