// agent.js — one agent: the console (activity + chat + controls), history,
// report.
//
// This is the page the dashboard cards open. It reads ?agent=, and
// optionally ?copy= (a second concurrent run of the agent), ?run= (a history
// row to show the report for) and ?user= (another user's run, opened from
// their dashboard by an admin — CLAUDE.md §4 item 71; ?embed=1 when inside
// the Settings pop-up).
//
// THE CONSOLE reads the run's ledger (findings.jsonl via GET /agents/{a}/findings
// or, for a live run, the SSE stream at /agents/{a}/stream). Since §4 item 25
// that ledger carries four kinds of row, and they are rendered differently:
//   agent:says / text     what the model wrote between tool calls — prose;
//   <tool> / call         a tool call as it is issued, with its arguments —
//                         the "what is it doing right now" line, marked as
//                         running until its result lands;
//   <tool> / ok | error   the result, summarised — a finding;
//   operator:* / received a note or message the run consumed.
// A message the person sends is shown at once as "queued" and replaced by
// the real operator:message row when the run consumes it at a turn
// boundary — so the delay between typing and delivery is visible rather
// than mysterious.
//
// Which controls are drawn: your own run gets everything your role allows
// (GET /auth/me); someone else's (?user=) gets only what an admin
// may do there — stop, interrupt, mark complete. The routes enforce both;
// this only decides what to draw.

document.addEventListener("DOMContentLoaded", async function () {
  const params = new URLSearchParams(location.search);
  const agent = params.get("agent") || "";
  const wantRun = params.get("run") || "";
  const copy = params.get("copy") || "";
  const viewUser = params.get("user") || "";
  const embed = params.get("embed") === "1";
  if (embed) document.body.classList.add("embedded");
  else renderNav("dashboard");
  const base = `agents/${encodeURIComponent(agent)}`;
  // Per-RUN routes say which run (copy) and whose (user); per-agent-TYPE ones
  // (tools, permissions, engagement) describe the agent, not a run.
  const runQS = [copy && `copy=${encodeURIComponent(copy)}`, viewUser && `user=${encodeURIComponent(viewUser)}`]
    .filter(Boolean).join("&");
  const u = (path) => (runQS ? `${path}${path.includes("?") ? "&" : "?"}${runQS}` : path);
  const viewQS = viewUser ? `&user=${encodeURIComponent(viewUser)}${embed ? "&embed=1" : ""}` : "";
  const dashboardHref = viewUser ? `dashboard.html?${viewQS.slice(1)}` : "dashboard.html";
  const esc = Agenti.esc;
  const R = Agenti.run;

  if (!agent) {
    document.querySelector("main").innerHTML =
      `<div class="empty-state"><p>No agent named in the URL.</p>
       <a class="btn btn-primary" href="${dashboardHref}">Back to the dashboard</a></div>`;
    return;
  }

  // Fetched once, used wherever a recorded name (launched_by, hidden_by,
  // acknowledged_by) is rendered, so a renamed/deleted account still reads
  // sensibly instead of silently going stale — see api.js's own comment on
  // userLabel() for the one known, accepted edge case. Fails silently
  // to [] for a plain viewer (no iam:read), which is fine: every name then
  // simply displays as recorded, exactly as it always has.
  const userHistoryRows = await Agenti.userHistory();
  const plabel = (n) => n ? Agenti.userLabel(n, userHistoryRows) : n;

  const els = {
    avatar: document.getElementById("ag-avatar"),
    title: document.getElementById("ag-title"),
    meta: document.getElementById("ag-meta"),
    badge: document.getElementById("ag-badge"),
    awaiting: document.getElementById("ag-awaiting"),
    needsInput: document.getElementById("ag-needs-input"),
    controls: document.getElementById("ag-controls"),
    consoleStatus: document.getElementById("ag-console-status"),
    feed: document.getElementById("ag-feed"),
    chatForm: document.getElementById("ag-chat-form"),
    chatInput: document.getElementById("ag-chat-input"),
    sendBtn: document.getElementById("ag-send-btn"),
    noteBtn: document.getElementById("ag-note-btn"),
    modelSwitch: document.getElementById("ag-model-switch"),
    modelSelect: document.getElementById("ag-model-select"),
    modelSwitchBtn: document.getElementById("ag-model-switch-btn"),
    reviewPanel: document.getElementById("ag-review-panel"),
    markBtn: document.getElementById("ag-mark-complete"),
    reportKv: document.getElementById("ag-report-kv"),
    reportActions: document.getElementById("ag-report-actions"),
    reportToggle: document.getElementById("ag-report-toggle"),
    reportPage: document.getElementById("ag-report-page"),
    reportPdf: document.getElementById("ag-report-pdf"),
    reportDocx: document.getElementById("ag-report-docx"),
    msg: document.getElementById("ag-msg"),
    report: document.getElementById("ag-report-body"),
    toolsSummary: document.getElementById("ag-tools-summary"),
    toolsBody: document.getElementById("ag-tools-body"),
    engPanel: document.getElementById("ag-engagement-panel"),
    engSummary: document.getElementById("ag-engagement-summary"),
    engBody: document.getElementById("ag-engagement-body"),
  };

  els.avatar.innerHTML = Agenti.avatarInner(agent);
  // A team member's page was reached from its team, so "back" goes there, not
  // to the dashboard.
  if (copy.startsWith("team-")) {
    document.getElementById("ag-back").href = `team.html?team=${encodeURIComponent(copy.slice(5))}${viewQS}`;
    document.getElementById("ag-back-label").textContent = "Team";
  }
  // A team member's run says which team in the title; someone else's run says
  // whose it is. The generated label every start gets (run-1a2b3c4d) is
  // plumbing, not a name an operator should have to read, so it is not shown —
  // the page tells runs apart by target and start time.
  const autoRun = /^run-[0-9a-f]{8}$/.test(copy);
  const copyLabel = copy.startsWith("team-") ? `team ${copy.slice(5)}` : (autoRun ? "" : copy);
  els.title.textContent = (viewUser ? `${viewUser}'s ` : "") + (copyLabel ? `${agent} · ${copyLabel}` : agent);

  // ---------- the run's name ----------
  // Its name is the title; the kind of agent sits under it in italics. A run
  // from before names existed keeps the agent as its title. Only the owner
  // renames (display only: nothing addresses a run by its name).
  const kindEl = document.getElementById("ag-kind");
  const renameBtn = document.getElementById("ag-rename");
  const renameForm = document.getElementById("ag-rename-form");
  const renameInput = document.getElementById("ag-rename-input");
  let runName = "";
  const agentTitleP = Agenti.get("agents")
    .then((c) => ((c.agents || []).find((a) => a.name === agent) || {}).title || agent)
    .catch(() => agent);
  function paintName(name) {
    if (!name || copy.startsWith("team-")) return;
    runName = name;
    els.title.textContent = (viewUser ? `${viewUser}'s ` : "") + name;
    document.title = `${name} — Agenti`;
    agentTitleP.then((t) => { kindEl.textContent = t; kindEl.hidden = false; });
    renameBtn.hidden = !!viewUser;
  }
  renameBtn.addEventListener("click", () => {
    renameInput.value = runName;
    renameForm.hidden = false;
    els.title.parentElement.hidden = true;
    renameInput.focus(); renameInput.select();
  });
  const closeRename = () => { renameForm.hidden = true; els.title.parentElement.hidden = false; };
  document.getElementById("ag-rename-cancel").addEventListener("click", closeRename);
  renameInput.addEventListener("keydown", (e) => { if (e.key === "Escape") closeRename(); });
  renameForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = renameInput.value.trim();
    if (!name || name === runName) { closeRename(); return; }
    try {
      const r = await Agenti.post(u(`${base}/rename`), { name });
      paintName(r.name || name);
      closeRename();
    } catch (err) {
      renameInput.setCustomValidity(Agenti.errorText(err));
      renameInput.reportValidity();
      renameInput.addEventListener("input", () => renameInput.setCustomValidity(""), { once: true });
    }
  });

  // ---------- tools & permissions (§4 item 26) ----------
  // What this agent is actually able to do, from the same declarations that
  // enforce it. Loaded once; reaching this page already required agent:read.
  (async function loadTools() {
    try {
      const t = await Agenti.get(`${base}/tools`);
      const mcp = t.mcp_tools || [];
      const cli = t.command_line_tools || { items: [] };
      const items = cli.items || [];
      els.toolsSummary.textContent =
        `${mcp.length} tool${mcp.length === 1 ? "" : "s"}` +
        (items.length ? `, ${items.length} ${cli.enforced ? "allowed program" : "external tool"}${items.length === 1 ? "" : "s"}` : "") +
        (t.scope_kind ? ` · ${t.scope_kind === "FilesScope" ? "attached files" : t.scope_kind}` : "");
      // Each tool and program is a title (its name) over an italic subtitle
      // (what it does) — the site-wide .ti item, not "name — description".
      const toolList = mcp.map((x) => Agenti.ti(x.name, x.purpose, { icon: "wrench", mono: true })).join("");
      const cliList = items.map((x) => Agenti.ti(x.name, x.purpose, { icon: "terminal", mono: true })).join("");
      const denied = t.denied_patterns || [];
      els.toolsBody.innerHTML = `
        ${t.scope_kind === "FilesScope"
          ? Agenti.ti("Attached files", "Works only on files an operator attached to the run. No network, no target.", { icon: "target", cls: "ti-scope" })
          : t.scope_kind ? Agenti.ti(t.scope_kind, "Scope boundary — a target can only narrow it.", { icon: "target", cls: "ti-scope" }) : ""}
        <h3 class="ih" data-icon="wrench">Tools</h3>
        <div class="ti-grid">${toolList || '<p class="muted">None declared.</p>'}</div>
        ${items.length ? `<h3 class="ih" data-icon="terminal">${cli.enforced ? "Programs it may run" : "External programs"}</h3>
        <div class="ti-grid">${cliList}</div>` : ""}
        ${denied.length ? `<h3 class="ih" data-icon="lock">Always refused</h3>
        <p class="denied-patterns">${denied.map((p) => `<code>${esc(p)}</code>`).join(" ")}</p>` : ""}
        <p class="hint ih" data-icon="shield">No raw shell. Scope is enforced outside the conversation.</p>`;
      if (window.applyIcons) applyIcons(els.toolsBody);
    } catch (err) {
      els.toolsSummary.textContent = "";
      els.toolsBody.innerHTML = `<p class="hint warn">${esc(Agenti.errorText(err))}</p>`;
    }
  })();

  function say(kind, el, text) {
    el.hidden = false;
    el.className = kind === "err" ? "hint warn" : "hint";
    el.textContent = text;
  }

  // ---------- the console ----------
  // What the agent said, what it did (folded into "Ran N steps"), and what you
  // or a teammate said to it — see activity.js. Built here, filled below.
  const feed = new AgentiActivity.Feed(els.feed, { you: viewUser || "You" });
  const latestReportHref = () => `report.html?agent=${encodeURIComponent(agent)}`
    + (copy ? `&copy=${encodeURIComponent(copy)}` : "") + viewQS;

  // ---------- permissions ----------
  let perms = [];
  try {
    const p = await Agenti.me();
    perms = p.permissions || [];
  } catch (err) {
    document.querySelector("main").innerHTML =
      `<div class="empty-state"><p>${esc(Agenti.errorText(err))}</p>
       <a class="btn btn-primary" href="${dashboardHref}">Back to the dashboard</a></div>`;
    return;
  }
  // On someone else's run an admin may only end it or mark it reviewed.
  const ADMIN_VIEW = new Set(["agent:stop", "agent:note:ack"]);
  const may = (p) => perms.includes(p === "agent:note:ack" ? "agent:note" : p)
    && (!viewUser || ADMIN_VIEW.has(p));

  // "Send output to another agent" (send-output.js): your own run only, and only
  // if you may start agents — it ends in an attached file for your next run.
  const sendBtn = document.getElementById("ag-send");
  if (sendBtn) {
    sendBtn.dataset.sendAgent = agent;
    sendBtn.dataset.sendCopy = copy || "";
    sendBtn.hidden = !!viewUser || !perms.includes("agent:start");
  }

  // ---------- exploit approvals: per-action, CLAUDE.md safety invariant 3 ----
  // Unlike the tool-allowlist offers below, approving one of these FIRES a
  // real Metasploit module against a real target immediately — so deciding
  // needs a fresh re-authentication (password+2FA or a passkey), bound to
  // exactly this request, via the same popup admin-sensitive actions use.
  const exploitBox = document.getElementById("ag-exploit-approvals");
  let exploitKey = null;
  async function refreshExploitApprovals(question) {
    // This endpoint only exists for the exploit agent (CLAUDE.md safety
    // invariant 3, carve-out B) — every other agent's page would otherwise
    // poll it on every SSE event and get a 400 back for no reason.
    if (agent !== "exploit") return;
    if (!question) { exploitKey = null; exploitBox.hidden = true; exploitBox.innerHTML = ""; return; }
    if (exploitKey === question) return;
    exploitKey = question;
    let list = [];
    try { list = await Agenti.get(`${base}/action-pending`); } catch (e) { return; }
    exploitBox.hidden = !list.length;
    exploitBox.innerHTML = list.map((r) => {
      const summary = r.plain_summary || ("Run " + r.module + " with options " + JSON.stringify(r.options || {}));
      return `
      <div class="banner warn show" data-id="${esc(r.request_id)}" style="margin:6px 0;">
        <strong>APPROVE THIS?</strong>
        <div style="margin:4px 0;overflow-wrap:anywhere;">${esc(summary)}</div>
        <div class="muted" style="overflow-wrap:anywhere;">Its reason (written by the agent): "${esc(r.reason || "none given")}"</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;">
          <button type="button" class="btn btn-sm btn-primary" data-decide="approve">Approve — fire it now</button>
          <button type="button" class="btn btn-sm" data-decide="reject">Reject</button>
        </div>
        <p class="hint" style="margin:6px 0 0;">This fires immediately on approval. Scope is still enforced; nothing outside the engagement can be targeted.</p>
      </div>`;
    }).join("");
  }
  exploitBox.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-decide]"); if (!b) return;
    const row = b.closest("[data-id]");
    const requestId = row.dataset.id;
    const decision = b.dataset.decide;
    let reason = "";
    if (decision === "reject") {
      reason = (prompt("Why are you rejecting this? The agent will be told.") || "").trim();
      if (!reason) return;
    }
    row.querySelectorAll("button").forEach((x) => (x.disabled = true));
    try {
      const res = await Agenti.requireApproval({
        title: decision === "approve" ? "Approve this exploit action?" : "Reject this exploit action?",
        description: decision === "approve"
          ? "This fires a real Metasploit module against a real target the moment you confirm."
          : "The agent will be told why and asked to wait for guidance.",
        submit: (creds) => Agenti.post(`${base}/action-pending/${encodeURIComponent(requestId)}`,
          { decision, reason: reason || undefined, password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
      if (!res) { row.querySelectorAll("button").forEach((x) => (x.disabled = false)); return; }
      exploitKey = null; await refreshExploitApprovals(`force-${Date.now()}`);
    } catch (err) {
      row.querySelectorAll("button").forEach((x) => (x.disabled = false));
      alert(Agenti.errorText(err));
    }
  });

  // ---------- tool approvals (phase 7) ----------
  const approvalBox = document.getElementById("ag-tool-approvals");
  let approvalKey = null;
  async function refreshToolApprovals(question) {
    if (!question) { approvalKey = null; approvalBox.hidden = true; approvalBox.innerHTML = ""; return; }
    if (approvalKey === question) return;       // already drawn for this state of the run
    approvalKey = question;
    let list = [];
    try { list = (await Agenti.get(`${base}/tool-approvals`)).requests || []; } catch (e) { return; }
    const offered = list.filter((r) => r.offered);
    approvalBox.hidden = !offered.length;
    approvalBox.innerHTML = offered.map((r) => `
      <div class="banner warn show" data-id="${esc(r.id)}" data-slot="${esc(r.slot)}" style="margin:6px 0;">
        <strong>The agent asks to use <code>${esc(r.program)}</code> for this run.</strong>
        <div class="muted">${esc(r.purpose || "")}</div>
        <div style="margin:4px 0;overflow-wrap:anywhere;">Its reason (written by the agent): “${esc(r.reason || "none given")}”</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button type="button" class="btn btn-sm btn-primary" data-decide="approve">Allow for this run</button>
          <button type="button" class="btn btn-sm" data-decide="deny">Decline</button>
        </div>
        <p class="hint" style="margin:6px 0 0;">For this run only. Scope and safety checks still apply.</p>
      </div>`).join("");
  }
  approvalBox.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-decide]"); if (!b) return;
    const row = b.closest("[data-id]");
    b.disabled = true;
    try {
      await Agenti.post(`${base}/tool-approvals/${encodeURIComponent(row.dataset.id)}`,
        { slot: row.dataset.slot, decision: b.dataset.decide });
      approvalKey = null; approvalBox.hidden = true; approvalBox.innerHTML = "";
    } catch (err) { b.disabled = false; alert(Agenti.errorText(err)); }
  });

  // ---------- preferences (memory.md): this user's notes for this agent ----------
  // Yours to edit with just your session; an admin viewing your dashboard
  // gets it read-only. It never widens anything — the server frames it so.
  if (viewUser ? true : perms.includes("agent:start")) {
    const memPanel = document.getElementById("ag-memory-panel");
    memPanel.hidden = false;
    document.getElementById("ag-memory-title").textContent = viewUser ? `${viewUser}'s preferences` : "My preferences";
    document.getElementById("ag-memory-summary").textContent = viewUser
      ? "view only" : "style notes for your runs";
    // Preferences the agent itself SUGGESTED during this user's runs. Nothing
    // is saved until the owner says yes; an admin looking in never sees these.
    const propBox = document.getElementById("ag-memory-proposals");
    async function loadProposals() {
      if (viewUser) return;
      let list = [];
      try { list = (await Agenti.get(`${base}/memory/proposals`)).proposals || []; } catch (e) { return; }
      const sum = document.getElementById("ag-memory-summary");
      sum.textContent = list.length
        ? `${list.length} suggestion${list.length === 1 ? "" : "s"} from the agent waiting for you`
        : "style notes for your runs";
      propBox.innerHTML = list.length ? `
        <div class="banner warn show" style="margin:8px 0;">
          <strong>The agent suggests remembering:</strong>
          <div class="list" style="margin-top:6px;">${list.map((p) => `
            <div class="list-row" data-id="${esc(p.id)}">
              <div style="flex:1;overflow-wrap:anywhere;">${esc(p.text)}</div>
              <button type="button" class="btn btn-sm btn-primary" data-decide="approve">Add to my preferences</button>
              <button type="button" class="btn btn-sm" data-decide="dismiss">Dismiss</button>
            </div>`).join("")}</div>
          <p class="hint" style="margin:6px 0 0;">Written by the agent — nothing is saved unless you add it.</p>
        </div>` : "";
    }
    propBox.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-decide]"); if (!b) return;
      const id = b.closest("[data-id]").dataset.id;
      b.disabled = true;
      try {
        await Agenti.post(`${base}/memory/proposals/${encodeURIComponent(id)}`, { decision: b.dataset.decide });
        await loadProposals();
        if (b.dataset.decide === "approve" && mounted) { mounted = false; memPanel.open = false; memPanel.open = true; }
      } catch (err) { b.disabled = false; alert(Agenti.errorText(err)); }
    });
    loadProposals();
    let mounted = false;
    memPanel.addEventListener("toggle", () => {
      if (!memPanel.open || mounted) return;
      mounted = true;
      AgentiContextEditor.mount(document.getElementById("ag-memory-editor"), {
        url: `${base}/memory${viewUser ? `?user=${encodeURIComponent(viewUser)}` : ""}`,
        postUrl: `${base}/memory`, title: "Preferences", readOnly: !!viewUser,
        blurb: viewUser
          ? "View only — preferences belong to their owner."
          : "Read at the start of each of your runs. Style only — never scope or tools.",
      });
      if (window.applyIcons) applyIcons(document.getElementById("ag-memory-editor"));
    });
  }

  // ---------- engagement (CLAUDE.md "Current plan", phase 1: engagement is
  // the organisation's, shared by every agent — read-only
  // here, always. Authoring and approving it lives in Settings.) Own /tools fetch rather than sharing loadTools()'s (that
  // IIFE isn't awaited, so its result isn't reliably ready by the time
  // perms is) — the descriptor is small and cheap, and this keeps the two
  // independent.
  async function paintEngagement() {
    let data;
    try {
      data = await Agenti.get(`${base}/engagement`);
    } catch (err) {
      els.engBody.innerHTML = `<p class="hint warn">${esc(Agenti.errorText(err))}</p>`;
      return;
    }
    const record = data.record || {};
    // `view` is THIS agent's own scope-kind-filtered slice (a CIDR agent
    // never sees a domain agent's entries, or vice versa) — the same split
    // the tool allow-list/scope boundary itself enforces, not just this
    // page's own choice of what to show.
    const view = data.view || { in_scope: [], out_of_scope: [] };
    const st = data.approval_status || {};
    const lineCount = (view.in_scope || []).length + (view.out_of_scope || []).length;
    if (!data.exists) {
      els.engSummary.textContent = "not set";
      els.engBody.innerHTML = `<p class="hint warn">No engagement yet — an admin must set one before this agent can start.</p>${engagementLink()}`;
      return;
    }
    if (data.invalid) {
      els.engSummary.textContent = "invalid record";
      els.engBody.innerHTML = `<p class="hint warn">${esc(data.invalid)}</p>${engagementLink()}`;
      return;
    }
    els.engSummary.textContent = `${esc(record.engagement_id || "?")} · ${lineCount} scope ${lineCount === 1 ? "entry" : "entries"}`;
    let statusLine;
    const requiresApproval = (data.effective_policy || {}).require_approval !== false;
    if (st.current) statusLine = `<span style="color:var(--ok);">approved by ${esc(st.approved_by || "?")} — current</span>`;
    else if (!requiresApproval) statusLine = `<span style="color:var(--ok);">not required by the organisation's policy</span>`;
    else if (st.approved) statusLine = `<span style="color:var(--warn);">stale — ${esc(st.reason || "edited since approval")}</span>`;
    else statusLine = `<span style="color:var(--warn);">not approved — ${esc(st.reason || "no approval on record")}</span>`;
    const pol = data.effective_policy || {};
    const models = (pol.allowed_models || []).join(", ") || "(none)";
    const policyLine = `caps up to ${esc(String(pol.max_turns_ceiling))} turns / `
      + `$${esc(String(pol.max_budget_usd_ceiling))} / ${esc(String(pol.timeout_s_ceiling))}s &middot; models: ${esc(models)}`;
    els.engBody.innerHTML = `
      <dl class="kv">
        <dt>Engagement</dt><dd>${esc(record.engagement_id || "—")}</dd>
        <dt>Client</dt><dd>${esc(record.client || "—")}</dd>
        <dt>Authorized by</dt><dd>${esc(record.authorizing_party || "—")}${record.authorizing_title ? ` (${esc(record.authorizing_title)})` : ""}</dd>
        <dt>Reference</dt><dd>${esc(record.authorization_ref || "—")}</dd>
        <dt>Valid</dt><dd>${esc(record.valid_from || "?")} to ${esc(record.valid_until || "?")}</dd>
        <dt>This agent's scope (${esc(view.scope_kind || "?")})</dt>
        <dd>${(view.in_scope || []).map((s) => esc(s)).join("<br>") || '<span style="color:var(--warn);">none — this agent cannot start</span>'}</dd>
        <dt>Out of scope</dt><dd>${(view.out_of_scope || []).map((s) => esc(s)).join("<br>") || "(none)"}</dd>
        <dt>Emergency contact</dt><dd>${esc(record.emergency_contact || "—")}</dd>
        <dt>Approval</dt><dd>${statusLine}</dd>
        <dt>Policy</dt><dd>${policyLine}</dd>
      </dl>
      ${(data.history || []).length ? `<p class="hint">last changed by ${esc(data.history[data.history.length - 1].by)}</p>` : ""}
      ${engagementLink()}`;
  }

  function engagementLink() {
    return `<p class="hint">Shared by every agent · <a href="settings.html#engagement">Edit in Settings</a></p>`;
  }

  (async function loadEngagement() {
    // A file-analysis agent runs without an engagement (it touches no network
    // or client asset), so there is nothing to show for it.
    try {
      const t = await Agenti.get(`${base}/tools`);
      if (t.scope_kind === "FilesScope") return;
    } catch (err) { /* fall through: show the panel, which reports its own error */ }
    els.engPanel.hidden = false;
    await paintEngagement();
  })();

  // ---------- status ----------
  let status;
  try {
    status = await Agenti.get(u(`${base}/status`));
  } catch (err) {
    say("err", els.awaiting, Agenti.errorText(err));
    status = { live: {} };
  }
  const isActive = status.state === "active";
  const isFrozen = isActive && status.freezer === "frozen";

  function paintHeader(st) {
    const l = st.live || {};
    if (st.name && st.name !== runName) paintName(st.name);
    const meta = [
      st.target || l.target || "no target",
      l.turn !== undefined ? `turn ${l.turn}` : null,
      l.findings_count !== undefined ? `${l.findings_count} findings` : null,
      st.model || null,
      l.launched_by ? `launched by ${plabel(l.launched_by)}${l.launched_via ? ` (${l.launched_via})` : ""}` : null,
    ].filter(Boolean).join(" · ");
    els.meta.textContent = meta;
    els.meta.title = meta;
    const question = (l.awaiting_operator && l.awaiting_operator.question) || null;
    // An exploit/session-command proposal already gets its own banner with
    // real Approve/Reject buttons (refreshExploitApprovals) — typing a
    // reply in the composer below does NOT approve anything, it is just a
    // steering message the model sees next turn. Saying "answer in the box
    // below" here for this case is actively misleading (the exact
    // confusion that caused "it keeps requesting approval and timing out"
    // in practice), so this case points at that banner instead.
    const isExploitQuestion = /^\[(Exploit|Command) approval pending\]/.test(question || "");
    if (question && st.state === "active") {
      Agenti.banner(els.needsInput, "warn", isExploitQuestion
        ? `Waiting on ${viewUser || "you"} to approve or reject below: ${question}`
        : viewUser ? `Waiting on ${viewUser}: ${question}` : `Waiting on you: ${question} — answer in the box below.`);
    } else if (question) {
      // The run ended (turn cap, stop, timeout) with its question still open.
      Agenti.banner(els.needsInput, "warn", `Before it ended, the agent asked: ${question}${viewUser ? "" : " — resume the run to answer."}`);
    } else {
      els.needsInput.hidden = true;
    }
    // A tool request is a question with buttons: the agent asked to use one
    // program from the admin-reviewed catalog for THIS run. Only the run's
    // owner decides, so an admin looking in sees the question but no buttons.
    // Keyed on the run's state and question, not on the question's wording: an
    // agent may ask something else afterwards, and the request is still waiting.
    refreshExploitApprovals(viewUser ? null : `${l.phase || ""}|${question || ""}`);
    refreshToolApprovals(viewUser ? null : `${l.phase || ""}|${question || ""}`);
    const [cls, label, full] = R.badge(st);
    els.badge.innerHTML = `<span class="badge ${cls}" title="${esc(full)}">${esc(label)}</span>`;
    els.consoleStatus.className = `console-status ${cls}`;
    // "paused" here means a frozen LIVE run; a finished run shows its outcome
    // (its badge class may also be "paused" — the Task History reading of
    // "incomplete" — which is not the same thing as someone pressing Pause).
    els.consoleStatus.textContent = st.state === "active"
      ? (cls === "warn-soft" ? `? waiting on ${viewUser || "you"}`
        : st.freezer === "frozen" ? "❚❚ paused" : `● live — turn ${l.turn ?? 0}`)
      : l.phase === "finished" ? `ended — ${full}` : "no run";
  }
  paintHeader(status);

  if (status.vault === "locked") {
    say("err", els.awaiting, "The vault is LOCKED — nothing can run and reports are unreadable until it is unlocked on the host.");
  }

  // ---------- controls (icon buttons in the composer) ----------
  const controlPerm = { pause: "agent:pause", resume: "agent:resume", stop: "agent:stop", interrupt: "agent:stop" };
  els.controls.querySelectorAll("[data-action]").forEach((btn) => {
    const action = btn.dataset.action;
    const resumable = isFrozen || (!isActive && (status.live || {}).phase === "finished");
    const relevant = action === "resume" ? resumable
      : action === "pause" ? (isActive && !isFrozen) : isActive;
    if (!may(controlPerm[action]) || !relevant) { btn.hidden = true; return; }
    btn.addEventListener("click", async () => {
      if (action === "interrupt" &&
          !confirm("Interrupt this run?\n\nThe step in flight is aborted immediately and the run ends. A partial report is still written. To carry on with the same context afterwards, resume it.")) return;
      if (action === "stop" &&
          !confirm("Stop this run?\n\nIt ends once the step in flight finishes, and a partial report is written. Use Interrupt to abort that step now.")) return;
      btn.disabled = true;
      try {
        const r = await Agenti.post(u(`${base}/${action}`));
        say("ok", els.msg, r.note || { pause: "Paused.", resume: "Resumed.", stop: "Stopped — a partial report was written.",
                                       interrupt: "Interrupt sent — the run is ending." }[action]);
        setTimeout(() => location.reload(), 1200);
      } catch (e) {
        say("err", els.msg, Agenti.errorText(e));
        btn.disabled = false;
      }
    });
  });
  // A single visible control is an unlabelled glyph with no siblings to give
  // it context — a finished run leaves just "▶". One control gets its name;
  // several stay compact, where their grouping and tooltips carry it.
  const shownControls = Array.from(els.controls.querySelectorAll("[data-action]"))
    .filter((b) => !b.hidden);
  if (shownControls.length === 1) shownControls[0].classList.add("with-label");
  if (!shownControls.length) els.controls.hidden = true;

  // ---------- live model switch (CLAUDE.md "Current plan") ----------
  // Active only for a running, non-frozen run, and only for a caller who
  // could already steer it with Send (agent:chat) — changing the model is
  // at least as consequential as a steering message, arguably more so
  // since it changes real spend rate.
  if (isActive && !isFrozen && may("agent:chat")) {
    (async () => {
      try {
        const data = await Agenti.get(`${base}/engagement`);
        const models = ((data.effective_policy || {}).allowed_models || []);
        if (!models.length) return;
        els.modelSelect.innerHTML = models.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
        const current = status.model;
        if (current && models.includes(current)) els.modelSelect.value = current;
        els.modelSwitch.hidden = false;
        els.modelSwitchBtn.addEventListener("click", async () => {
          const target = els.modelSelect.value;
          if (!target) return;
          if (!confirm(`Switch to ${target} at the next turn boundary?\n\nApplied between steps, never mid-tool-call.`)) return;
          els.modelSwitchBtn.disabled = true;
          try {
            await Agenti.post(u(`${base}/set-model`), { model: target });
            say("ok", els.msg, `Requested switch to ${target} — applied at the next turn boundary.`);
          } catch (e) {
            say("err", els.msg, Agenti.errorText(e));
          } finally {
            els.modelSwitchBtn.disabled = false;
          }
        });
      } catch (e) { /* engagement panel below already reports this failure */ }
    })();
  }

  // ---------- composer ----------
  async function send(kind) {
    const text = els.chatInput.value.trim();
    if (!text) return;
    els.sendBtn.disabled = true; els.noteBtn.disabled = true;
    try {
      await Agenti.post(u(`${base}/${kind === "note" ? "note" : "say"}`), { body: text });
      els.chatInput.value = "";
      if (kind === "message") {
        // Visible at once, replaced by the consumed row once the step in flight ends.
        feed.queue(text);
        say("ok", els.msg, "Sent — the agent sees it after the step it is on.");
      } else {
        say("ok", els.msg, "Note recorded. It appears in the report and in the ledger, and never reaches the model.");
      }
    } catch (e) {
      say("err", els.msg, Agenti.errorText(e));
    } finally {
      els.sendBtn.disabled = !isActive || !may("agent:chat");
      els.noteBtn.disabled = !may("agent:note");
      els.chatInput.focus();
    }
  }
  if (viewUser) els.chatForm.hidden = true;   // nobody steers someone else's run
  if (!isActive || !may("agent:chat")) {
    els.sendBtn.disabled = true;
    els.chatInput.disabled = !isActive || !(may("agent:chat") || may("agent:note"));
    if (!isActive) els.chatInput.placeholder = "This run has ended — resume it to keep talking to it.";
    else if (!may("agent:chat")) els.chatInput.placeholder = "You may add notes, but not steer this run.";
  }
  if (!may("agent:note")) els.noteBtn.disabled = true;
  // The whole bar reads as inert when nothing in it can be used, rather than
  // leaving a fully-styled Send button beside a disabled input.
  if (els.sendBtn.disabled && els.noteBtn.disabled) {
    els.chatForm.classList.add("is-disabled");
  }
  els.chatForm.addEventListener("submit", (e) => { e.preventDefault(); send("message"); });
  els.noteBtn.addEventListener("click", () => send("note"));

  // ---------- files ----------
  // What the operator attached to this run, and any waiting for the next.
  // The paperclip adds more: a run going now gets a file at once (and is
  // told), otherwise the next run does. Never on someone else's run.
  const filesPanel = document.getElementById("ag-files-panel");
  async function loadFiles() {
    try {
      const l = await Agenti.get(u(`${base}/files`));
      const n = AgentiFiles.render(document.getElementById("ag-files-body"), l, viewUser ? {} : {
        onRemove: async (name) => {
          try { await Agenti.del(u(`${base}/files/${encodeURIComponent(name)}`)); }
          catch (e) { say("err", els.msg, Agenti.errorText(e)); }
          loadFiles();
        },
      });
      const run = (l.run || []).length, waiting = (l.pending || []).length;
      document.getElementById("ag-files-summary").textContent =
        [run && `${run} on this run`, waiting && `${waiting} waiting for the next`].filter(Boolean).join(" · ");
      filesPanel.hidden = !n;
    } catch (e) { filesPanel.hidden = true; }
  }
  loadFiles();
  const attachBtn = document.getElementById("ag-attach-btn");
  if (viewUser || !may("agent:start")) attachBtn.hidden = true;
  else AgentiFiles.wireAttachButton(attachBtn, {
    path: () => u(`${base}/files`), say: (kind, text) => say(kind, els.msg, text), done: loadFiles,
  });

  // ---------- the console feed ----------
  if (isActive) {
    const liveFeed = Agenti.stream(u(`${base}/stream`), {
      // The server ended the feed for good (access removed, or too many feeds
      // open): stop reconnecting and say why.
      ended: (d) => { liveFeed.close(); say("err", els.msg, d.reason || "This live feed ended — reload the page."); },
      reset: () => { feed.clear(); },
      finding: (f) => feed.add(f, { live: true }),
      status: (s) => {
        paintHeader(s);
        if (s.state !== "active") setTimeout(() => location.reload(), 1500);
      },
      error: () => { /* EventSource reconnects on its own */ },
    });
  } else {
    try {
      const fx = await Agenti.get(u(`${base}/findings?n=500`));
      if (fx && fx.length) {
        feed.clear();
        fx.forEach((f) => feed.add(f));
        feed.finish(latestReportHref());
        els.feed.scrollTop = els.feed.scrollHeight;
      } else {
        feed.empty("No activity recorded for the last run.");
      }
    } catch (e) {
      feed.empty(Agenti.errorText(e));
    }
  }

  // ---------- this run's record + review ----------
  // Every start is its own isolated run, so this page is about ONE run; there
  // is no list of earlier runs here (Task History, on the dashboard, is that
  // list). What this needs from the history record is the finished run's row:
  // its outcome and report link, and whether it still awaits "Mark complete".
  let history = [];
  let reviewTarget = null;
  const reportHref = (r, extra) => `report.html?agent=${encodeURIComponent(agent)}`
    + (copy ? `&copy=${encodeURIComponent(copy)}` : "") + (r && r.report ? `&file=${encodeURIComponent(r.report)}` : "")
    + viewQS + (extra || "");

  async function loadHistory() {
    try {
      history = await Agenti.get(u(`${base}/history?n=50`));
    } catch (e) { history = []; }
    const mine = wantRun ? history.filter((r) => r.run_id === wantRun) : history;
    const unreviewed = mine.filter((r) => !r.acknowledged);
    if (unreviewed.length && may("agent:note:ack")) {
      els.reviewPanel.hidden = false;
      reviewTarget = unreviewed[0];
      els.reviewPanel.querySelector("[data-run]").textContent = reviewTarget.run_id;
    } else {
      els.reviewPanel.hidden = true;
      reviewTarget = null;
    }
  }

  els.markBtn.addEventListener("click", async () => {
    if (!reviewTarget) return;
    els.markBtn.disabled = true;
    try {
      await Agenti.post(u(`${base}/acknowledge`), { run_id: reviewTarget.run_id });
      Agenti.flash(`Marked ${agent} complete — it's now in Task History.`);
      location.href = dashboardHref;
    } catch (e) {
      say("err", els.msg, Agenti.errorText(e));
      els.markBtn.disabled = false;
    }
  });

  await loadHistory();
  const selected = wantRun ? history.find((r) => r.run_id === wantRun) : history[0];

  // ---------- report ----------
  if (selected || status.last_report) {
    els.reportKv.innerHTML = selected ? `
      <dt>Run</dt><dd><code>${esc(selected.run_id || "?")}</code></dd>
      <dt>Outcome</dt><dd>${esc(selected.status)}${selected.reason ? ` (${esc(selected.reason)})` : ""}</dd>
      <dt>Findings</dt><dd>${esc(selected.findings_count || 0)}</dd>
      <dt>Ended</dt><dd>${esc(Agenti.when(selected.ended))}</dd>
      <dt>Reviewed by</dt><dd>${selected.acknowledged ? esc(selected.acknowledged_by) : "—"}</dd>
      <dt>File</dt><dd>${selected.report ? `<code>${esc(selected.report)}</code>` : '<span class="muted">latest (this run predates per-run report tracking)</span>'}</dd>`
      : `<dt>Latest report</dt><dd>${esc(status.last_report)}</dd>`;
    const fileQuery = selected && selected.report ? `?file=${encodeURIComponent(selected.report)}` : "";
    els.reportPage.href = reportHref(selected);
    els.reportPdf.href = reportHref(selected, "#print");
    els.reportDocx.href = u(`${base}/report.docx${fileQuery}`);
    els.reportToggle.addEventListener("click", async () => {
      if (!els.report.hidden) { els.report.hidden = true; els.reportToggle.querySelector("span").textContent = "Show report here"; return; }
      els.report.hidden = false;
      els.reportToggle.querySelector("span").textContent = "Hide report";
      els.report.innerHTML = `<p class="muted">loading…</p>`;
      try {
        const r = await Agenti.get(u(`${base}/report${fileQuery}`));
        els.report.innerHTML = r.report_markdown ? AgentiMarkdown.render(r.report_markdown) : `<p class="muted">(empty report)</p>`;
      } catch (err) {
        els.report.innerHTML = `<p class="hint warn">${esc(Agenti.errorText(err))}</p>`;
      }
    });
  } else {
    els.reportKv.innerHTML = `<dt>Status</dt><dd class="muted">No report yet — one is written when a run finishes, is stopped, or is interrupted.</dd>`;
    els.reportActions.hidden = true;
  }
});
