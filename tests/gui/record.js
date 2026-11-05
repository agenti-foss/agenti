// record.js — capture the API answers the visual check replays (fixtures/).
//
//   node tests/gui/record.js <https://box:8420> <admin user> <password file> <totp secret file> \
//        [--scrub <text>=<replacement> ...]
//
// Signs in to a live Agenti (a TEST box, never one holding client data),
// opens every page in pages.json, and keeps each answer the pages got from
// the API. Then every --scrub text is replaced, and the result is refused if
// anything still looks like a private address: these files are committed to
// a public repo. Give the box's own address, e.g. --scrub 10.1.2.3=198.51.100.5.
const { chromium } = require("playwright-core");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);
const [base, user, pwFile, totpFile] = args;
if (!totpFile) {
  console.error("usage: node record.js <base url> <admin user> <password file> <totp secret file> [--scrub a=b ...]");
  process.exit(2);
}
const scrubs = [];
for (let i = 4; i < args.length; i++) {
  if (args[i] === "--scrub" && args[i + 1] && args[i + 1].includes("=")) {
    const [from, to] = args[++i].split(/=(.*)/s);
    scrubs.push([from, to]);
  }
}
const browserPath = process.env.CHROME || "/usr/bin/chromium";
const pages = JSON.parse(fs.readFileSync(path.join(__dirname, "pages.json"), "utf8")).pages;

function totp(b32) {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of b32.replace(/[\s=]/g, "").toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac("sha1", key).update(ctr).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}

// Anything that looks like it came from a private network or a person.
const PRIVATE = /\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|sk-ant-[A-Za-z0-9_-]+)\b/;
const repo = path.join(__dirname, "..", "..");
const EXAMPLES = ["docs/help", "shared/gui", "shared/gui/js"].flatMap((d) =>
  fs.readdirSync(path.join(repo, d)).filter((f) => /\.(md|html|js)$/.test(f))
    .map((f) => fs.readFileSync(path.join(repo, d, f), "utf8"))).join("\n");

async function visit(ctx, list, answers) {
  const p = await ctx.newPage();
  p.on("response", async (r) => {
    const u = new URL(r.url());
    const ct = r.headers()["content-type"] || "";
    if (u.origin !== new URL(base).origin || !ct.includes("application/json")) return;
    const key = `${r.request().method()} ${u.pathname}${u.search}`;
    try { answers[key] = { status: r.status(), body: await r.json() }; } catch (e) { /* not JSON after all */ }
  });
  for (const pg of list) {
    await p.goto(base + pg.path, { waitUntil: "networkidle" });
    for (const sel of [].concat(pg.click || [])) { await p.click(sel); await p.waitForLoadState("networkidle"); }
    await p.waitForTimeout(1500);
  }
  await p.close();
}

(async () => {
  const browser = await chromium.launch({ executablePath: browserPath });
  const out = { "signed-out": {}, "signed-in": {} };

  const anon = await browser.newContext({ ignoreHTTPSErrors: true });
  await visit(anon, pages.filter((p) => p.as === "signed-out"), out["signed-out"]);
  await anon.close();

  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const p = await ctx.newPage();
  await p.goto(base + "/login.html", { waitUntil: "networkidle" });
  await p.fill("#login-form input[autocomplete=username], #login-form input[type=text]", user);
  await p.fill("#login-form input[type=password]", fs.readFileSync(pwFile, "utf8").trim());
  await p.click("#login-btn");
  await p.waitForTimeout(1500);
  const box = await p.$("input[autocomplete=one-time-code]:visible");
  if (box) { await box.fill(totp(fs.readFileSync(totpFile, "utf8").trim())); await p.keyboard.press("Enter"); }
  await p.waitForURL(/dashboard/, { timeout: 15000 });
  await p.close();
  await visit(ctx, pages.filter((p) => p.as === "signed-in"), out["signed-in"]);
  await browser.close();

  for (const who of Object.keys(out)) {
    let text = JSON.stringify(Object.fromEntries(Object.keys(out[who]).sort().map((k) => [k, out[who][k]])));
    for (const [from, to] of scrubs) text = text.split(from).join(to);
    // An address the shipped docs or code already use as an example is fine;
    // anything else private is the box's own, or someone's.
    const leak = [...text.matchAll(new RegExp(PRIVATE, "g"))].map((m) => m[0]).find((m) => !EXAMPLES.includes(m));
    if (leak) {
      console.error(`REFUSING to write fixtures/${who}.json: it still contains '${leak}'. Add --scrub ${leak}=198.51.100.5 (or similar).`);
      process.exit(1);
    }
    const file = path.join(__dirname, "fixtures", `${who}.json`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({
      _about: "Recorded by tests/gui/record.js from a test box; replayed by serve.py. Record again when a page calls something new.",
      answers: JSON.parse(text),
    }, null, 1) + "\n");
    console.log(`wrote ${path.relative(process.cwd(), file)}: ${Object.keys(out[who]).length} answers`);
  }
})().catch((e) => { console.error(e.message); process.exit(1); });
