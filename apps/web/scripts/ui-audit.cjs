// UI-аудит: каждый маршрут × ширины 1440/1024/768/390; скриншоты, переполнение, axe, ошибки консоли.
// node scripts/ui-audit.cjs <outDir> [routesFilter]   (env: WEB_URL, CORE_URL, WIDTHS, THEME=light|dark, LOCALE=ru|kk|en)
// Требует запущенные ядро (dev-auth, симулятор, данные) и UI. ID инцидента/изменений берутся из API ядра.
/* eslint-disable @typescript-eslint/no-require-imports */
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require("playwright");

const BASE = process.env.WEB_URL || "http://localhost:3000";
const OUT = process.argv[2];
const FILTER = process.argv[3] ? new RegExp(process.argv[3]) : null;
const TENANT_A = "11111111-1111-4111-8111-111111111111";
const AXE = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const CORE = process.env.CORE_URL || "http://127.0.0.1:8080";
const WIDTHS = (process.env.WIDTHS || "1440,1024,768,390").split(",").map(Number);
async function routes() {
  const h = { "X-AdminTwin-Tenant": TENANT_A, "X-AdminTwin-Actor": "alice", "X-AdminTwin-Roles": "tenant_admin" };
  const get = async (p) => (await fetch(CORE + p, { headers: h })).json().catch(() => ({ items: [] }));
  const inc = ((await get("/api/v1/incidents")).items || [])[0];
  const chs = (await get("/api/v1/changes")).items || [];
  const waiting = chs.find((c) => c.status === "waiting_approval");
  const closed = chs.find((c) => c.status === "closed");
  return [
    { name: "login", path: "/login" },
    { name: "command-center", path: "/", full: true },
    { name: "incidents", path: "/incidents" },
    inc && { name: "incident-detail", path: `/incidents/${inc.id}`, full: true },
    { name: "collaboration", path: "/collaboration", full: true, wait: 1500 },
    { name: "changes", path: "/changes" },
    { name: "change-new", path: "/changes/new", full: true },
    waiting && { name: "change-waiting", path: `/changes/${waiting.id}`, full: true },
    closed && { name: "change-closed", path: `/changes/${closed.id}`, full: true },
    { name: "assets", path: "/assets" },
    { name: "topology", path: "/topology", full: true },
    { name: "runbooks", path: "/runbooks", full: true },
    { name: "capabilities", path: "/capabilities", full: true },
    { name: "ai", path: "/ai", full: true },
    { name: "audit", path: "/audit" },
    { name: "health", path: "/health", full: true },
    { name: "settings", path: "/settings", full: true },
  ].filter(Boolean);
}

async function login(page, roles = ["tenant_admin"], actor = "alice", scopes = []) {
  await page.goto(`${BASE}/login`);
  await page.waitForSelector("[data-testid=dev-tenant]");
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
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const report = [];
  const theme = process.env.THEME || "light";
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: theme, deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  if (process.env.LOCALE) await page.addInitScript((l) => { try { localStorage.setItem("admintwin.locale", l); } catch {} }, process.env.LOCALE);
  await login(page);
  for (const r of await routes()) {
    if (FILTER && !FILTER.test(r.name)) continue;
    for (const w of WIDTHS) {
      errors.length = 0;
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(`${BASE}${r.path}`);
      await page.waitForLoadState("networkidle").catch(() => {});
      await page.waitForTimeout(r.wait || 600);
      const m = await page.evaluate(() => {
        const vw = document.documentElement.clientWidth;
        const off = [];
        for (const el of document.querySelectorAll("main *, header *")) {
          const b = el.getBoundingClientRect();
          if (b.width === 0 || b.height === 0) continue;
          if (el.closest(".table-wrap, .topo-wrap, pre, .stream, dialog:not([open])")) continue;
          if (b.right > vw + 1 || b.left < -1) off.push(`${el.tagName.toLowerCase()}.${String(el.className).slice(0, 40)} "${(el.textContent || "").trim().slice(0, 30)}" r=${Math.round(b.right)}`);
        }
        // обрезанный текст в кнопках/ячейках
        const clipped = [];
        for (const el of document.querySelectorAll("button, .btn, th, .badge, .nav-link, label")) {
          if (el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflow !== "visible") clipped.push(`${el.tagName.toLowerCase()} "${(el.textContent || "").trim().slice(0, 30)}"`);
        }
        return {
          pageOverflow: document.documentElement.scrollWidth > vw + 1,
          scrollWidth: document.documentElement.scrollWidth,
          vw,
          off: [...new Set(off)].slice(0, 8),
          clipped: clipped.slice(0, 8),
          h1: [...document.querySelectorAll("h1")].map((h) => h.textContent.trim()),
        };
      });
      let axe = null;
      if (w === 1440 || w === 390) {
        await page.evaluate(AXE);
        axe = await page.evaluate(async () => {
          const res = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] } });
          return res.violations.map((v) => ({ id: v.id, impact: v.impact, n: v.nodes.length, sample: v.nodes.slice(0, 3).map((n) => n.target.join(" ") + " :: " + (n.failureSummary || "").split("\n").slice(1, 2).join("")) }));
        });
      }
      const file = `${r.name}-${w}.png`;
      await page.screenshot({ path: path.join(OUT, file), fullPage: w !== 1440 ? true : !!r.full });
      report.push({ route: r.name, path: r.path, width: w, ...m, axe, errors: [...errors] });
      console.log(`${r.name}@${w}: overflow=${m.pageOverflow} off=${m.off.length} clipped=${m.clipped.length} axe=${axe ? axe.map((a) => a.id + ":" + a.n).join(",") : "-"} err=${errors.length}`);
    }
  }
  fs.writeFileSync(path.join(OUT, "report.json"), JSON.stringify(report, null, 2));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
