// visual.js — open every GUI page in a real browser and fail on visible breakage.
//
//   node tests/gui/visual.js [--out <dir>]      (CHROME=<path to chrome or chromium>)
//
// Starts serve.py (the GUI files with recorded API answers), then opens every
// page in pages.json at a phone and a desktop width, in light and dark, in
// both skins, and fails when a page:
//   - throws a script error, or logs one to the console;
//   - never shows what it is for (pages.json "ready");
//   - asks the API for something not recorded (record the fixtures again);
//   - is wider than the screen, naming the elements that stick out.
// Every view is kept as a screenshot in --out (default tests/gui/out/) with
// an index.html to look through them, which CI keeps as an artifact.
const { chromium } = require("playwright-core");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const OUT = path.resolve(args.includes("--out") ? args[args.indexOf("--out") + 1] : path.join(__dirname, "out"));
const PORT = 8431;
const BASE = `http://127.0.0.1:${PORT}`;
const CHROME = process.env.CHROME || ["/usr/bin/chromium", "/usr/bin/google-chrome", "/usr/bin/chromium-browser"].find((p) => fs.existsSync(p));
const PAGES = JSON.parse(fs.readFileSync(path.join(__dirname, "pages.json"), "utf8")).pages;
const LOOKS = [
  { name: "light", width: 390, height: 844, mode: "light", skin: "" },
  { name: "light", width: 1440, height: 900, mode: "light", skin: "" },
  { name: "dark", width: 390, height: 844, mode: "dark", skin: "" },
  { name: "dark", width: 1440, height: 900, mode: "dark", skin: "" },
  { name: "arcade-light", width: 1440, height: 900, mode: "light", skin: "arcade" },
  { name: "arcade-dark", width: 390, height: 844, mode: "dark", skin: "arcade" },
];

function startServer() {
  return new Promise((resolve, reject) => {
    const srv = spawn("python3", [path.join(__dirname, "serve.py"), "--port", String(PORT)], { stdio: ["ignore", "pipe", "inherit"] });
    srv.stdout.on("data", (d) => { if (String(d).includes("serving")) resolve(srv); });
    srv.on("exit", (c) => reject(new Error(`serve.py exited (${c})`)));
  });
}

async function misses() {
  return (await (await fetch(`${BASE}/__misses`)).json()).length;
}

// Visible elements whose right edge is past the screen, outside any scroller
// that is meant to hold them. Named by tag#id.class so the log says where.
function overflowing() {
  const w = document.documentElement.clientWidth;
  const out = [];
  for (const el of document.querySelectorAll("body *")) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0 || r.right <= w + 1) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === "hidden" || cs.position === "fixed") continue;
    let clipped = false;
    for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
      const o = getComputedStyle(a).overflowX;
      if (o === "auto" || o === "scroll" || o === "hidden" || o === "clip") { clipped = true; break; }
    }
    if (clipped) continue;
    if (el.parentElement && el.parentElement.getBoundingClientRect().right > w + 1 && out.length) continue;
    const name = el.tagName.toLowerCase() + (el.id ? `#${el.id}` : "") +
      (typeof el.className === "string" && el.className.trim() ? "." + el.className.trim().split(/\s+/).join(".") : "");
    out.push(`${name} (right edge ${Math.round(r.right)}px)`);
    if (out.length >= 5) break;
  }
  return { pageWidth: document.documentElement.scrollWidth, screen: w, out };
}

(async () => {
  if (!CHROME) { console.error("no Chrome or Chromium found: set CHROME=<path>"); process.exit(2); }
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });
  const srv = await startServer();
  const browser = await chromium.launch({ executablePath: CHROME });
  const failures = [];
  const shots = [];
  try {
    for (const look of LOOKS) {
      const ctx = await browser.newContext({ viewport: { width: look.width, height: look.height }, colorScheme: look.mode });
      await ctx.addInitScript(([mode, skin]) => {
        localStorage.setItem("agenti-gui-theme", mode);
        if (skin) localStorage.setItem("agenti-gui-skin", skin); else localStorage.removeItem("agenti-gui-skin");
      }, [look.mode, look.skin]);
      for (const pg of PAGES) {
        await ctx.clearCookies();
        if (pg.as === "signed-in") await ctx.addCookies([{ name: "gui-test", value: "signed-in", url: BASE }]);
        const view = `${pg.name} [${look.name} ${look.width}px]`;
        const errors = [];
        const p = await ctx.newPage();
        p.on("pageerror", (e) => errors.push(`script error: ${e.message}`));
        p.on("console", (m) => {
          if (m.type() === "error" && !/^Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`);
        });
        const before = await misses();
        await p.goto(BASE + pg.path, { waitUntil: "networkidle" });
        for (const sel of [].concat(pg.click || [])) { await p.click(sel); await p.waitForLoadState("networkidle"); }
        const ready = await p.waitForSelector(pg.ready, { state: "visible", timeout: 8000 }).then(() => true, () => false);
        await p.waitForTimeout(300);
        if (!ready) errors.push(`never showed ${pg.ready}`);
        const missed = (await misses()) - before;
        if (missed) errors.push(`${missed} API call(s) not recorded (see GET /__misses; run record.js again)`);
        const o = await p.evaluate(overflowing);
        if (o.pageWidth > o.screen + 1) errors.push(`wider than the screen (${o.pageWidth}px on ${o.screen}px): ${o.out.join(", ") || "no single element found"}`);
        const file = `${look.name}-${look.width}/${pg.name}.png`;
        fs.mkdirSync(path.join(OUT, path.dirname(file)), { recursive: true });
        await p.screenshot({ path: path.join(OUT, file), fullPage: true });
        shots.push({ view, file, ok: errors.length === 0 });
        for (const e of errors) failures.push(`${view}: ${e}`);
        console.log(`${errors.length ? "FAIL" : " ok "} ${view}${errors.length ? "\n       " + errors.join("\n       ") : ""}`);
        await p.close();
      }
      await ctx.close();
    }
  } finally {
    await browser.close();
    srv.kill();
  }
  const rows = shots.map((s) => `<figure class="${s.ok ? "" : "bad"}"><figcaption>${s.ok ? "" : "FAIL "}${s.view}</figcaption><a href="${s.file}"><img loading="lazy" src="${s.file}"></a></figure>`).join("\n");
  fs.writeFileSync(path.join(OUT, "index.html"), `<!doctype html><meta charset="utf-8"><title>Agenti GUI views</title>
<style>body{font:14px system-ui;margin:16px}figure{display:inline-block;vertical-align:top;margin:8px;width:300px}img{width:300px;border:1px solid #ccc}.bad figcaption{color:#c00;font-weight:bold}</style>
<h1>${shots.length} views, ${failures.length} problem(s)</h1>\n${rows}\n`);
  console.log(`\n${shots.length} views, ${failures.length} problem(s). Screenshots: ${path.relative(process.cwd(), OUT)}/index.html`);
  process.exit(failures.length ? 1 : 0);
})().catch((e) => { console.error(e.stack || e.message); process.exit(1); });
