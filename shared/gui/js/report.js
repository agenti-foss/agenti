// report.js — one report, full page, readable, exportable.
//
//   report.html?agent=[&copy=][&file=<name>][&user=][#print]
//   report.html?team=[&user=][#print]       (the team document)
// ?user= is another user's report, opened from their dashboard by an admin
// (CLAUDE.md §4 item 71); ?embed=1 when inside the Settings pop-up.
//
// The report is the Markdown the agent wrote (GET /agents/{a}/report, the same
// text `agenti ... report` prints), rendered by markdown.js. Two exports:
//   - PDF: the browser's own print dialog (window.print) with the print
//     stylesheet in theme.css — every desktop and phone browser offers
//     "Save as PDF" there, and it typesets better than anything the API
//     could produce without a dependency. Opening with #print goes straight
//     to that dialog once the report has rendered.
//   - Word: GET /agents/{a}/report.docx (shared/api/docx.py), the same file
//     selection, as a download.
// The <select> lists every report for this agent (GET /agents/{a}/reports) so
// an older run's report can be opened without leaving the page.
//
// A team's document (?team= instead of ?agent=) has no picker — it is
// assembled fresh on every read (cmd_team_report, deterministic, no
// stored file to choose between) from GET /teams/{team}/report — but
// gets the exact same render/PDF/docx path as a per-agent report, since
// both sides already speak the identical {report_markdown} shape and
// AgentiMarkdown.render()/docx.py's grammar.

document.addEventListener("DOMContentLoaded", async function () {
  const esc = Agenti.esc;
  const params = new URLSearchParams(location.search);
  const agent = params.get("agent") || "";
  const team = params.get("team") || "";
  const copy = params.get("copy") || "";
  const viewUser = params.get("user") || "";
  const embed = params.get("embed") === "1";
  if (embed) document.body.classList.add("embedded");
  else renderNav("dashboard");
  let file = params.get("file") || "";
  const enc = encodeURIComponent;
  // Which run's reports (copy) and whose (user) ride on every request; the
  // view (user, embed) rides on every link.
  const runParams = () => {
    const p = new URLSearchParams();
    if (copy && !team) p.set("copy", copy);
    if (viewUser) p.set("user", viewUser);
    return p;
  };
  const viewQS = viewUser ? `&user=${enc(viewUser)}${embed ? "&embed=1" : ""}` : "";
  const base = team
    ? `teams/${encodeURIComponent(team)}`
    : `agents/${encodeURIComponent(agent)}`;
  const body = document.getElementById("report-body");
  const banner = document.getElementById("rp-banner");
  const sel = document.getElementById("rp-file");
  const raw = document.getElementById("rp-raw-body");

  if (!agent && !team) {
    body.innerHTML = `<p class="report-empty">No agent or team named in the URL.</p>`;
    body.dataset.rendered = "1";
    return;
  }
  document.getElementById("rp-back").href = (team
    ? `team.html?team=${enc(team)}`
    : `agent.html?agent=${enc(agent)}${copy ? `&copy=${enc(copy)}` : ""}`) + viewQS;
  document.title = team ? `${team} team report — Agenti` : `${agent} report — Agenti`;

  const q = () => {
    const p = runParams();
    if (file && !team) p.set("file", file);   // a team document has one version
    const s = p.toString();
    return s ? `?${s}` : "";
  };

  // The list of reports, newest first, for the picker. `reports` answers
  // with [{name, bytes, status}].
  // A team has no such listing — its document is generated fresh each time.
  let noReports = false;   // the listing answered, and it was empty
  if (team) {
    sel.hidden = true;
  } else {
    try {
      const rq = runParams().toString();
      const r = await Agenti.get(`${base}/reports${rq ? `?${rq}` : ""}`);
      const names = (r.reports || []).map((x) => x.name).filter((n) => /\.md$/.test(n));
      if (names.length) {
        sel.innerHTML = names.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
        if (file && names.includes(file)) sel.value = file;
        else { file = names[0]; sel.value = file; }
      } else {
        sel.hidden = true;
        noReports = true;
      }
    } catch (e) { sel.hidden = true; }   // fall through: load() shows the real error
  }
  sel.addEventListener("change", () => {
    file = sel.value;
    const sb = document.getElementById("rp-send");
    if (sb) sb.dataset.sendPre = file ? `report:${file}` : "";
    const u = new URL(location.href); u.searchParams.set("file", file); u.hash = "";
    history.replaceState(null, "", u.toString());
    load();
  });

  let markdown = "";
  async function load() {
    // Nothing to fetch: say so plainly instead of asking for a report that
    // doesn't exist (which the API answers with a 400 and an error banner).
    if (noReports) {
      body.innerHTML = `<p class="report-empty">No reports yet. An agent writes its report when a run ends — finished, stopped, or interrupted.</p>`;
      for (const id of ["rp-print", "rp-docx"]) { const el = document.getElementById(id); if (el) el.hidden = true; }
      body.dataset.rendered = "1";
      return;
    }
    body.innerHTML = `<p class="muted">Loading…</p>`;
    delete body.dataset.rendered;
    document.getElementById("rp-docx").href = `${base}/report.docx${q()}`;
    try {
      const r = await Agenti.get(`${base}/report${q()}`);
      markdown = r.report_markdown || "";
      body.innerHTML = markdown.trim() ? AgentiMarkdown.render(markdown) : `<p class="report-empty">This report is empty.</p>`;
      raw.textContent = markdown;
      banner.className = "banner";
    } catch (err) {
      body.innerHTML = `<p class="report-empty">${esc(Agenti.errorText(err))}</p>`;
      Agenti.banner(banner, "err", Agenti.errorText(err));
    }
    body.dataset.rendered = "1";
    if (location.hash === "#print") {
      history.replaceState(null, "", location.pathname + location.search);
      setTimeout(() => window.print(), 300);
    }
  }
  await load();

  // "Keep this report": copies it into YOUR permanent Outputs store (§4 item
  // 78). Only for your own run's report, and only when you hold
  // output:promote — never when an admin is viewing someone else's dashboard
  // (the server refuses that too: the route takes no ?user=).
  const keepBtn = document.getElementById("rp-keep");
  if (!team && !viewUser && !noReports && keepBtn) {
    try {
      const perms = (await Agenti.me()).permissions || [];
      keepBtn.hidden = !perms.includes("output:promote");
    } catch (e) { keepBtn.hidden = true; }
    keepBtn.addEventListener("click", async () => {
      keepBtn.disabled = true;
      try {
        const r = await Agenti.post(`${base}/promote-output`, { file, copy: copy || null });
        const warn = (r.warnings || []).map((w) => ` ${w.message}`).join("");
        Agenti.banner(banner, "ok", `Kept as “${r.name}” in your Outputs.${warn}`);
      } catch (err) {
        Agenti.banner(banner, "err", Agenti.errorText(err));
      } finally { keepBtn.disabled = false; }
    });
  }

  // Hand THIS report to another agent (send-output.js): your own run only.
  const sendBtn = document.getElementById("rp-send");
  if (!team && !viewUser && !noReports && sendBtn) {
    try {
      const perms = (await Agenti.me()).permissions || [];
      sendBtn.hidden = !perms.includes("agent:start");
    } catch (e) { sendBtn.hidden = true; }
    sendBtn.dataset.sendAgent = agent;
    sendBtn.dataset.sendCopy = copy || "";
    sendBtn.dataset.sendPre = file ? `report:${file}` : "";
  }

  document.getElementById("rp-print").addEventListener("click", () => window.print());
  document.getElementById("rp-raw").addEventListener("click", () => {
    raw.hidden = !raw.hidden;
    body.hidden = !raw.hidden;
  });
});
