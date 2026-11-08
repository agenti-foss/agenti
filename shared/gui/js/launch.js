// launch.js — the "Launch an agent" page. A two-mode single/team switch over
// one grid of cards, one per installed agent this caller may launch.
//
// GET /agents supplies each installed agent's title, description and scope
// kind. Every installed agent may be launched by an operator or admin; a
// signed-in account with neither role sees a view-only note instead.
//
// Selecting a card in single mode opens a run panel scoped to that one
// agent; in team mode, cards multi-select and the panel becomes a roster
// (role + target per member). A CIDR/domain agent's run panel shows the
// organization's own engagement ceiling for that scope kind (GET
// /agents/{agent}/engagement) and warns if it's missing or unapproved,
// naming who can fix it; a live, client-side CIDR/domain containment check
// nudges before submit, but SCOPE.narrow() server-side is what actually
// enforces it — this page can only be a convenience, never the boundary.

document.addEventListener("DOMContentLoaded", async function () {
  renderNav("dashboard");
  const esc = Agenti.esc;

  const viewOnly = document.getElementById("launch-view-only");
  const launchMain = document.getElementById("launch-main");
  const grid = document.getElementById("agent-grid");
  const gridHeading = document.getElementById("grid-heading");
  const runPanel = document.getElementById("run-panel");
  const runTitle = document.getElementById("run-title");
  const runVia = document.getElementById("run-via");
  const runForm = document.getElementById("run-form");
  const runBanner = document.getElementById("run-banner");
  // No provider ready at any level: every start would be refused, so say so first.
  Agenti.get("dashboard").then(async (d) => {
    if (!d || d.api_key !== "missing") return;
    const me = await Agenti.me().catch(() => ({}));
    const admin = (me.permissions || []).includes("iam:manage");
    const kb = document.getElementById("key-banner");
    kb.innerHTML = `<strong>No model provider is configured yet.</strong> `
      + (admin ? `Connect one in <a href="settings.html#providers">Settings → AI providers</a>.`
               : `Ask an admin to connect one (Settings → AI providers).`);
    kb.classList.add("show");
    await Agenti.dismissibleBanner(kb, "no-provider");
  }).catch(() => { /* the start itself still says why */ });
  const runBtn = document.getElementById("run-btn");
  const teamRoster = document.getElementById("team-roster");
  const targetField = document.getElementById("target-field");
  const runTargetInput = document.getElementById("run-target");
  const ceilingInfo = document.getElementById("ceiling-info");
  const ceilingBanner = document.getElementById("ceiling-banner");
  const teamNameField = document.getElementById("team-name-field");
  const runNameField = document.getElementById("run-name-field");
  const runNameInput = document.getElementById("run-name");
  const instructionsHint = document.getElementById("run-instructions-hint");
  let runModelSel = null;
  const modelHost = document.getElementById("run-model-picker");
  const memberModels = new Map();
  const runTurnsInput = document.getElementById("run-turns");
  const runBudgetInput = document.getElementById("run-budget");
  const runTimeoutInput = document.getElementById("run-timeout");

  // Every start is its own isolated run, so a launch reserves that run's label
  // up front: files attached before "Run" is pressed wait in THAT run's own
  // slot and go with it. "Send output" hands one over in ?copy= (the files it
  // staged are already waiting there); otherwise a fresh one is made. Kept for
  // the life of the form, so a start that fails can be retried with the same
  // files still attached.
  const LABEL_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
  const newRunLabel = () => "run-" + Array.from(crypto.getRandomValues(new Uint8Array(4)),
    (b) => b.toString(16).padStart(2, "0")).join("");
  const wantedLabel = new URLSearchParams(location.search).get("copy") || "";
  const runLabel = LABEL_RE.test(wantedLabel) ? wantedLabel : newRunLabel();
  const filesWaiting = document.getElementById("run-files-waiting");
  const filesStatus = document.getElementById("run-files-status");
  // Choosing or removing a file clears an earlier "attach a file" message.
  const filePicker = AgentiFiles.picker(document.getElementById("run-files"),
    { onChange: () => { runBanner.className = "banner"; } });
  const showFilesStatus = (t) => { filesStatus.hidden = !t; filesStatus.textContent = t || ""; };

  let me = null;
  let catalog = [];          // every installed agent: {agent, title, description, scope_kind, category, tools}
  let mode = "single";
  let selected = [];        // [{agent, scope_kind, tools}, ...]
  let currentCeiling = null; // {kind, inScope, outScope} for the single-mode selection
  let currentPolicy = null;  // {max_turns_ceiling, max_budget_usd_ceiling, timeout_s_ceiling, allowed_models, model_prices}

  try {
    me = await Agenti.me();
  } catch (err) {
    document.querySelector("main").innerHTML = `<div class="empty-state"><p>${esc(Agenti.errorText(err))}</p></div>`;
    return;
  }

  // Launching needs the operator or admin role.
  if (!Agenti.roleAtLeast(me.role, "operator")) {
    viewOnly.hidden = false;
    viewOnly.querySelector(".empty-icon").innerHTML = Agenti.icon("eye", 22);
    launchMain.hidden = true;
    return;
  }
  const teamTab = document.querySelector('#launch-switch [data-mode="team"]');

  try {
    const r = await Agenti.get("agents");
    catalog = r.agents || [];
  } catch (err) {
    grid.innerHTML = `<p class="hint">${esc(Agenti.errorText(err))}</p>`;
    return;
  }

  function resetSelection() {
    selected = [];
    currentCeiling = null;
    runPanel.hidden = true;
    teamRoster.hidden = true;
    teamRoster.innerHTML = "";
  }

  const ICON_BY_CATEGORY = { cybersecurity: "search", research: "globe", "network-evidence": "activity", "file-analysis": "file" };

  // preserve=true keeps the current `selected` set across a repaint in team
  // mode. A mode change always resets: a single-agent launch only ever tracks
  // one pick.
  function paintGrid(preserve) {
    if (!preserve) resetSelection();
    const agents = catalog;
    gridHeading.textContent = "Which agent would you like to deploy?";
    if (!agents.length) { grid.innerHTML = `<p class="hint">No agents are available to you yet.</p>`; return; }
    const isPicked = (name) => selected.some((a) => a.agent === name);
    grid.innerHTML = agents.map((a) => {
      const sel = mode === "team" && isPicked(a.agent) ? " selected" : "";
      return `<button type="button" class="agent-card category-card${sel}" data-agent="${esc(a.agent)}"
                title="Runs the ${esc(a.agent)} agent">
        <span class="cat-icon">${Agenti.icon(ICON_BY_CATEGORY[a.category] || "bolt", 18)}</span>
        <div class="cat-title">${esc(a.title || a.agent)}</div>
        <div class="cat-desc">${esc(a.description || "")}</div>
      </button>`;
    }).join("");

    grid.querySelectorAll(".category-card").forEach((card) => {
      card.addEventListener("click", () => {
        const info = catalog.find((a) => a.agent === card.dataset.agent);
        if (info) toggleSelect(info, card);
      });
    });
  }

  function toggleSelect(agentInfo, card) {
    if (mode === "single") {
      selected = [agentInfo];
      grid.querySelectorAll(".category-card").forEach((c) => c.classList.remove("selected"));
      card.classList.add("selected");
      openSingleRunPanel(agentInfo);
    } else {
      const i = selected.findIndex((a) => a.agent === agentInfo.agent);
      if (i >= 0) { selected.splice(i, 1); card.classList.remove("selected"); }
      else { selected.push(agentInfo); card.classList.add("selected"); }
      openTeamRunPanel();
    }
  }

  async function openSingleRunPanel(agentInfo) {
    runPanel.hidden = false;
    runBanner.className = "banner";
    teamRoster.hidden = true; teamRoster.innerHTML = "";
    teamNameField.hidden = true;
    runNameField.hidden = false;
    runNameInput.value = "";
    const kind = agentInfo.scope_kind;
    // A file-analysis agent has no network target: the files ARE its input.
    const filesKind = kind === "files";
    document.getElementById("files-label").textContent = filesKind ? "Files to analyze" : "Files for the agent";
    document.getElementById("files-need").textContent = filesKind ? "(at least one)" : "(optional)";
    runBtn.querySelector("span").textContent = "Run";
    runTitle.textContent = `Run ${agentInfo.agent}`;
    runVia.textContent = filesKind
      ? `Analyzes the files you attach, in a sandbox with no network.`
      : `Runs the ${agentInfo.agent} agent, inside its own bounded scope.`;
    instructionsHint.dataset.tip = filesKind ? "Tell it what to look for — it can only analyze the files you attach."
      : "Steers what it tries — never what it may touch.";
    targetField.hidden = filesKind;
    runTargetInput.required = !filesKind;
    runTargetInput.value = "";
    runTargetInput.placeholder = targetPlaceholder(kind);
    ceilingInfo.innerHTML = ""; ceilingBanner.hidden = true;
    currentCeiling = null;
    runTurnsInput.value = ""; runBudgetInput.value = ""; runTimeoutInput.value = "";
    if (kind === "cidr" || kind === "domain") {
      await paintCeiling(agentInfo.agent, kind);
    }
    await paintModelAndCaps(agentInfo.agent, kind);
    paintWaitingFiles();
    runPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // Files attached earlier (an attempt whose start failed) that are still
  // waiting for this agent's next run — shown so nothing goes with a run
  // unseen, and so they can be taken back.
  const filesPath = (agent) => `agents/${encodeURIComponent(agent)}/files?copy=${encodeURIComponent(runLabel)}`;
  let waitingCount = 0;       // files already waiting for this agent's next run
  async function paintWaitingFiles() {
    filesWaiting.hidden = true;
    waitingCount = 0;
    if (mode !== "single" || !selected.length) return;
    const agent = selected[0].agent;
    try {
      const l = await Agenti.get(filesPath(agent));
      waitingCount = (l.pending || []).length;
      if (!waitingCount) return;
      filesWaiting.hidden = false;
      filesWaiting.innerHTML = `<p class="hint">Already waiting for this run:</p><div></div>`;
      AgentiFiles.render(filesWaiting.lastElementChild, { pending: l.pending }, {
        onRemove: async (name) => {
          try {
            await Agenti.del(`agents/${encodeURIComponent(agent)}/files/${encodeURIComponent(name)}?copy=${encodeURIComponent(runLabel)}`);
          } catch (err) { Agenti.banner(runBanner, "err", Agenti.errorText(err)); }
          paintWaitingFiles();
        },
      });
    } catch (err) { /* a bad copy label is reported when the run starts */ }
  }

  const targetPlaceholder = (kind) => kind === "domain" ? "or type one, e.g. example.com" : "or type one, e.g. 192.168.1.50";

  // ---- the target bank ---------------------------------------------------
  // The engagement already IS the definitive list of what an agent
  // may be pointed at, so the form offers those values to click rather than
  // asking for one to be retyped from memory (and typo'd into a refusal).
  //
  // An in_scope entry may carry a human label after the value, e.g.
  // "10.0.0.0/24 (internal server VLAN)". The rule is not invented here:
  // CIDRScope/DomainScope.ceiling_from_engagement() both parse `entry
  // .split()[0]` and leave the rest for people, so a chip's VALUE is that
  // first token and the remainder is shown as a note.
  const scopeValue = (entry) => String(entry).trim().split(/\s+/)[0];
  function scopeNote(entry) {
    const s = String(entry).trim();
    const i = s.search(/\s/);
    return i === -1 ? "" : s.slice(i + 1).trim();
  }
  // Exactly how the server splits a run-target (scope_cidr/scope_domain:
  // re.split(r"[,\s]+", text.strip())), so what a chip shows as selected is
  // what the agent will actually be narrowed to.
  const targetTokens = (text) => String(text || "").split(/[,\s]+/).filter(Boolean);

  // A run-target takes SEVERAL values and narrow() validates each against
  // the ceiling, so the bank is multi-select: picking three hosts runs one
  // agent scoped to those three. The text input stays — a ceiling of
  // 192.168.1.0/24 with one host of interest inside it is a normal thing
  // to want, and only free text can express it — and the two stay in sync
  // both ways.
  function wireTargetBank(bankEl, input, entries) {
    const list = (entries || []).filter((e) => scopeValue(e));
    if (!list.length) {
      bankEl.innerHTML = `<p class="target-bank-empty">Nothing is authorized for this agent's scope yet — an admin sets it in Settings &rarr; Engagement.</p>`;
      return;
    }
    bankEl.innerHTML = list.map((e) => {
      const v = scopeValue(e), note = scopeNote(e);
      return `<button type="button" class="target-chip" aria-pressed="false"
                data-value="${esc(v)}" title="${esc(e)}">
        <span>${esc(v)}</span>${note ? `<span class="tc-note">${esc(note)}</span>` : ""}
      </button>`;
    }).join("");
    const chips = Array.from(bankEl.querySelectorAll(".target-chip"));
    function syncFromInput() {
      const picked = new Set(targetTokens(input.value));
      chips.forEach((c) => c.setAttribute("aria-pressed", picked.has(c.dataset.value) ? "true" : "false"));
    }
    chips.forEach((chip) => chip.addEventListener("click", () => {
      const tokens = targetTokens(input.value);
      const v = chip.dataset.value;
      const i = tokens.indexOf(v);
      if (i >= 0) tokens.splice(i, 1); else tokens.push(v);
      input.value = tokens.join(", ");
      syncFromInput();
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }));
    input.addEventListener("input", syncFromInput);
    syncFromInput();
  }

  // One engagement for the organization, presented per scope kind (CLAUDE.md item 42),
  // so two cidr-scoped members of a team share one answer — fetched once per
  // kind rather than once per member.
  const ceilingCache = new Map();
  function fetchCeiling(agent, kind) {
    if (!ceilingCache.has(kind)) {
      ceilingCache.set(kind, Agenti.get(`agents/${encodeURIComponent(agent)}/engagement`));
    }
    return ceilingCache.get(kind);
  }

  async function paintCeiling(agent, kind) {
    const bank = document.getElementById("target-bank");
    const bankHint = document.getElementById("target-bank-hint");
    bank.innerHTML = "";
    try {
      const data = await fetchCeiling(agent, kind);
      const view = data.view || { in_scope: [], out_of_scope: [] };
      const st = data.approval_status || {};
      if (!data.exists) {
        bankHint.hidden = true;
        Agenti.banner(ceilingBanner, "warn",
          "No engagement yet — an admin must set one first.");
        return;
      }
      if (data.invalid) {
        bankHint.hidden = true;
        Agenti.banner(ceilingBanner, "warn", data.invalid);
        return;
      }
      // The bank IS the authorized list, so it replaces the old prose
      // repetition of the same values underneath the field.
      bankHint.hidden = false;
      wireTargetBank(bank, runTargetInput, view.in_scope || []);
      const outs = (view.out_of_scope || []).map((s) => `<code>${esc(scopeValue(s))}</code>`).join(", ");
      ceilingInfo.innerHTML = outs ? `Excluded from scope: ${outs}` : "";
      if (!st.current) {
        // Dismissible: a run would still be refused, with a clear message.
        Agenti.banner(ceilingBanner, "warn", "");
        ceilingBanner.innerHTML = st.approved
          ? "<strong>The engagement changed since it was approved.</strong> An admin approves it in Settings → Engagement before a run can start."
          : `<strong>The engagement isn't approved yet.</strong> An admin approves it in Settings → Engagement before a run can start.${st.reason ? ` (${esc(st.reason)})` : ""}`;
        await Agenti.dismissibleBanner(ceilingBanner, "engagement-not-approved");
      } else if (data.pending) {
        Agenti.banner(ceilingBanner, "warn",
          `A change to the engagement by ${data.pending.author} is waiting for another admin's approval. Until then a run must fit both versions, so the targets below are only what both allow.`);
      } else {
        ceilingBanner.hidden = true;
      }
      currentCeiling = { kind, inScope: view.in_scope || [], outScope: view.out_of_scope || [] };
    } catch (err) {
      bankHint.hidden = true;
      Agenti.banner(ceilingBanner, "warn", Agenti.errorText(err));
    }
  }

  // Model is mandatory, and caps left blank default to the organization's own
  // ceiling, so this mounts the model picker (models.js) and shows each cap's
  // ceiling as its placeholder ("up to 40"). Reuses fetchCeiling()'s own
  // per-(kind) cache, so calling both for the same kind costs one request.
  const LAST_MODEL_KEY = "agenti-last-model";
  async function paintModelAndCaps(agent, kind) {
    modelHost.hidden = mode !== "single";
    if (mode !== "single") modelHost.querySelectorAll("input,select").forEach((el) => { el.disabled = true; });
    if (mode === "single") {
      let remembered = "";
      try { remembered = localStorage.getItem(LAST_MODEL_KEY) || ""; } catch (e) { /* no persistence */ }
      runModelSel = AgentiModels.mount(modelHost, { agent, remembered });
    }
    try {
      const data = await fetchCeiling(agent, kind);
      const policy = data.effective_policy || {};
      currentPolicy = policy;
      const ceil = (v) => (v === undefined || v === null) ? "" : String(v);
      runTurnsInput.placeholder = `up to ${ceil(policy.max_turns_ceiling)}`;
      runTurnsInput.max = ceil(policy.max_turns_ceiling) || "";
      runBudgetInput.placeholder = `up to $${ceil(policy.max_budget_usd_ceiling)}`;
      runBudgetInput.max = ceil(policy.max_budget_usd_ceiling) || "";
      runTimeoutInput.placeholder = `up to ${ceil(policy.timeout_s_ceiling)} s`;
      runTimeoutInput.max = ceil(policy.timeout_s_ceiling) || "";
    } catch (err) {
      currentPolicy = null;
      Agenti.banner(runBanner, "err", Agenti.errorText(err));
    }
  }

  // ---- a client-side nudge only; SCOPE.narrow() server-side is what
  // actually enforces this, unchanged. ----
  function ipToInt(ip) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  }
  function cidrContains(cidr, target) {
    const [base, bitsStr] = String(cidr).split("/");
    const bits = bitsStr === undefined ? 32 : parseInt(bitsStr, 10);
    const baseInt = ipToInt(base);
    if (baseInt === null || Number.isNaN(bits)) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const [tgt, tbitsStr] = String(target).split("/");
    const targetInt = ipToInt(tgt);
    if (targetInt === null) return false;
    const tbits = tbitsStr === undefined ? 32 : parseInt(tbitsStr, 10);
    if (tbits < bits) return false;
    return (targetInt & mask) === (baseInt & mask);
  }
  function domainContains(suffix, host) {
    suffix = String(suffix).toLowerCase().replace(/^\*\./, "");
    host = String(host).toLowerCase().replace(/^\*\./, "");
    return host === suffix || host.endsWith("." + suffix);
  }
  // One token, against the ceiling. Scope entries are compared by their
  // VALUE (scopeValue) — an entry carrying a human label would otherwise be
  // compared verbatim, which a domain suffix match can never satisfy.
  function tokenLooksInCeiling(token) {
    if (!currentCeiling || !token) return null;
    const { kind, inScope, outScope } = currentCeiling;
    if (!inScope.length) return false;
    const contains = kind === "cidr" ? cidrContains : domainContains;
    if (outScope.some((o) => contains(scopeValue(o), token))) return false;
    return inScope.some((i) => contains(scopeValue(i), token));
  }
  // A run-target may hold several values, so every one of them is checked —
  // checking the whole field as a single target would call a perfectly good
  // multi-target run out of scope.
  function offendingTarget(text) {
    return targetTokens(text).find((t) => tokenLooksInCeiling(t) === false) || null;
  }
  runTargetInput.addEventListener("input", () => {
    const t = runTargetInput.value.trim();
    if (!t || !currentCeiling) { if (runBanner.classList.contains("warn")) runBanner.className = "banner"; return; }
    const bad = offendingTarget(t);
    if (bad) {
      Agenti.banner(runBanner, "warn", `'${bad}' looks like it falls outside the organization's authorized scope — the server will refuse it if so.`);
    } else if (runBanner.classList.contains("warn")) {
      runBanner.className = "banner";
    }
  });

  function openTeamRunPanel() {
    if (!selected.length) { runPanel.hidden = true; return; }
    runPanel.hidden = false;
    runBanner.className = "banner";
    teamNameField.hidden = false;
    runNameField.hidden = true;
    targetField.hidden = true;
    // A named run slot addresses one agent's second concurrent run; a team
    // launch has no way to express that, and submitTeam never reads it.
    filesWaiting.hidden = true;
    document.getElementById("files-label").textContent = "Files for every member";
    document.getElementById("files-need").textContent = "(optional)";
    runBtn.querySelector("span").textContent = "Launch team";
    runTitle.textContent = `Launch team (${selected.length} agent${selected.length === 1 ? "" : "s"})`;
    runVia.textContent = selected.length < 2
      ? "Pick at least one more agent — a team needs more than one member."
      : "Each agent still only runs its own tools inside its own scope; a team changes how they talk to each other, never what any one of them is allowed to do.";
    instructionsHint.dataset.tip = "Posted to the shared channel once the project starts — every member sees it.";
    teamRoster.hidden = false;
    memberModels.clear();
    teamRoster.innerHTML = selected.map((a) => `
      <div class="panel" style="padding:10px 12px; margin:0;" data-member="${esc(a.agent)}">
        <strong>${esc(a.agent)}</strong>
        <div class="team-model-picker"></div>
        <div class="field" style="margin-top:6px;">
          <label>Role for ${esc(a.agent)}</label>
          <input type="text" class="team-role" placeholder="e.g. internal network assessment">
        </div>
        ${(a.scope_kind === "cidr" || a.scope_kind === "domain") ? `
        <div class="field">
          <label>Target for ${esc(a.agent)}</label>
          <p class="hint">Pick from the organization's authorized scope.</p>
          <div class="target-bank" data-bank></div>
          <input type="text" class="team-target" placeholder="${esc(targetPlaceholder(a.scope_kind))}">
        </div>` : ""}
      </div>`).join("");

    // Each member's bank is filled from ITS OWN scope kind's authorized
    // list, after the roster markup exists. Async and per-member, but
    // fetchCeiling caches per (kind), so two cidr members cost one
    // request. A member whose engagement can't be read keeps its text input
    // and says so, rather than the whole roster failing.
    selected.forEach(async (a) => {
      const modelRow = teamRoster.querySelector(`[data-member="${CSS.escape(a.agent)}"]`);
      memberModels.set(a.agent, AgentiModels.mount(modelRow.querySelector(".team-model-picker"), { agent: a.agent, compact: true }));
      if (a.scope_kind !== "cidr" && a.scope_kind !== "domain") return;
      const row = teamRoster.querySelector(`[data-member="${CSS.escape(a.agent)}"]`);
      if (!row) return;
      const bank = row.querySelector("[data-bank]");
      const input = row.querySelector(".team-target");
      if (!bank || !input) return;
      try {
        const data = await fetchCeiling(a.agent, a.scope_kind);
        if (!data.exists || data.invalid) {
          bank.innerHTML = `<p class="target-bank-empty">${esc(data.invalid
            || "No engagement yet — an admin must set one first.")}</p>`;
          return;
        }
        wireTargetBank(bank, input, (data.view || {}).in_scope || []);
      } catch (err) {
        bank.innerHTML = `<p class="target-bank-empty">${esc(Agenti.errorText(err))}</p>`;
      }
    });
    // Model/caps policy is a organization-wide property, not per-agent — the same
    // answer regardless of which member's own engagement route is asked —
    // so one shared model/caps section covers the whole team (one choice,
    // not per member). Fetched via the first selected member; fetchCeiling's own
    // per-(kind) cache means this rides the same request the
    // roster's own target banks just made, when kinds match.
    runTurnsInput.value = ""; runBudgetInput.value = ""; runTimeoutInput.value = "";
    paintModelAndCaps(selected[0].agent, selected[0].scope_kind);
    // No scroll here, unlike a single run: picking a team member keeps you
    // at the agent cards so you can pick the next one (operator note 2026-11-07).
  }

  function setMode(m) {
    mode = m;
    document.querySelectorAll("#launch-switch button").forEach((b) => {
      const on = b.dataset.mode === m;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    paintGrid(false);
  }
  document.getElementById("launch-switch").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-mode]");
    if (!btn || btn.hidden) return;
    location.hash = btn.dataset.mode === "single" ? "" : btn.dataset.mode;
    setMode(btn.dataset.mode);
  });
  function modeFromHash() { return (!teamTab.hidden && location.hash === "#team") ? "team" : "single"; }
  window.addEventListener("hashchange", () => setMode(modeFromHash()));

  setMode(modeFromHash());

  // Arriving from "Send output to another agent" (send-output.js): the agent is
  // chosen and the note is filled in; the files are already waiting for this
  // run, so the "Already waiting" list shows them (and lets them be removed).
  (async function prefillFromSend() {
    const q = new URLSearchParams(location.search);
    const want = q.get("agent");
    if (!want || mode !== "single") return;
    const info = catalog.find((a) => a.agent === want);
    if (!info) return;
    const card = [...grid.querySelectorAll(".category-card")].find((c) => c.dataset.agent === want);
    if (card) card.classList.add("selected");
    selected = [info];
    await openSingleRunPanel(info);
    const note = q.get("note");
    if (note) document.getElementById("run-instructions").value = note;
    // The sending run's own target (send-output.js's "Open Launch" path) —
    // prefilled instead of asking the operator to retype a target the
    // system already has on file. openSingleRunPanel() always clears
    // run-target first, so this must run after it, same as the note above.
    const target = q.get("target");
    if (target && !targetField.hidden) runTargetInput.value = target;
    const from = q.get("from");
    if (from) showFilesStatus(`Output from ${from} is attached to this run — see “Already waiting” above.`);
  })();

  runForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    runBanner.className = "banner";
    if (mode === "single") await submitSingle();
    else await submitTeam();
  });

  async function submitSingle() {
    if (!selected.length) return;
    const agentInfo = selected[0];
    const agent = agentInfo.agent;
    const model = runModelSel.value;
    if (!model) {
      Agenti.banner(runBanner, "err", "Pick a model — required for every launch.");
      runModelSel.reportValidity();
      return;
    }
    const instructions = document.getElementById("run-instructions").value.trim();
    const target = runTargetInput.value.trim();
    if ((agentInfo.scope_kind === "cidr" || agentInfo.scope_kind === "domain") && !target) {
      Agenti.banner(runBanner, "err", "A target is required for this agent.");
      return;
    }
    if (agentInfo.scope_kind === "files" && !filePicker.files().length && !waitingCount) {
      Agenti.banner(runBanner, "err", "Attach at least one file for this agent to analyze.");
      return;
    }
    // This launch's own run (reserved when the form opened). Its label goes
    // with every request so the files, the start and the follow-up message all
    // land in the same fresh, isolated run.
    const copy = runLabel;
    const qCopy = `?copy=${encodeURIComponent(copy)}`;
    runBtn.disabled = true;
    try {
      try { localStorage.setItem(LAST_MODEL_KEY, model); } catch (e) { /* no persistence */ }
      AgentiModels.remember(model);
      const body = { model };
      if (target) body.target = target;
      const runName = runNameInput.value.trim();
      if (runName) body.name = runName;
      if (copy) body.copy = copy;
      if (runTurnsInput.value) body.turns = parseInt(runTurnsInput.value, 10);
      if (runBudgetInput.value) body.budget = parseFloat(runBudgetInput.value);
      if (runTimeoutInput.value) body.timeout = parseInt(runTimeoutInput.value, 10);
      // Files first: a start hands every waiting file to the new run.
      if (filePicker.files().length) {
        await AgentiFiles.uploadAll(filesPath(agent), filePicker.files(), showFilesStatus);
        filePicker.clear(); showFilesStatus("");
      }
      const r = await Agenti.post(`agents/${encodeURIComponent(agent)}/start`, body);
      if (instructions) {
        try {
          await Agenti.post(`agents/${encodeURIComponent(agent)}/say${qCopy}`, { body: instructions });
        } catch (err) {
          // The run itself started fine; a failed steering message is not
          // worth blocking the redirect over.
          console.warn("could not deliver launch instructions:", err);
        }
      }
      Agenti.banner(runBanner, "ok", `Started ${(r && r.name) ? `“${r.name}” (${agent})` : agent}${(r && r.target) || target ? ` against ${(r && r.target) || target}` : ""}. Opening its page…`);
      setTimeout(() => {
        location.href = `agent.html?agent=${encodeURIComponent(agent)}&copy=${encodeURIComponent(copy)}`;
      }, 900);
    } catch (err) {
      showFilesStatus("");
      Agenti.banner(runBanner, "err", Agenti.errorText(err));
      paintWaitingFiles();
    } finally {
      runBtn.disabled = false;
    }
  }

  async function submitTeam() {
    if (selected.length < 2) {
      Agenti.banner(runBanner, "err", "Pick at least two agents — a team needs more than one member.");
      return;
    }
    const models = {};
    for (const a of selected) {
      const picker = memberModels.get(a.agent);
      if (!picker || !picker.value) {
        Agenti.banner(runBanner, "err", `Choose a model for ${a.agent}.`);
        if (picker) picker.reportValidity();
        return;
      }
      models[a.agent] = picker.value;
    }
    const agents = selected.map((a) => a.agent);
    const rolesBody = {}, overrides = {};
    teamRoster.querySelectorAll("[data-member]").forEach((row) => {
      const agent = row.dataset.member;
      const roleInput = row.querySelector(".team-role");
      if (roleInput && roleInput.value.trim()) rolesBody[agent] = roleInput.value.trim();
      const targetInput = row.querySelector(".team-target");
      if (targetInput && targetInput.value.trim()) overrides[agent] = targetInput.value.trim();
    });
    let name = document.getElementById("team-name").value.trim();
    if (!name) name = `project-${Date.now().toString(36)}`;
    const instructions = document.getElementById("run-instructions").value.trim();

    runBtn.disabled = true;
    try {
      try {
        await Agenti.post(`teams`, { name, agents });
      } catch (err) {
        // A team is a persistent, reusable grouping — relaunching one you
        // already created is the normal case, not an error.
        if (!/already exists/i.test(Agenti.errorText(err))) throw err;
      }
      // Every member gets each file (written once, shared on disk).
      if (filePicker.files().length) {
        await AgentiFiles.uploadAll(`teams/${encodeURIComponent(name)}/files`, filePicker.files(), showFilesStatus);
        filePicker.clear(); showFilesStatus("");
      }
      const startBody = { models, roles: rolesBody, overrides };
      if (runTurnsInput.value) startBody.turns = parseInt(runTurnsInput.value, 10);
      if (runBudgetInput.value) startBody.budget = parseFloat(runBudgetInput.value);
      if (runTimeoutInput.value) startBody.timeout = parseInt(runTimeoutInput.value, 10);
      await Agenti.post(`teams/${encodeURIComponent(name)}/start`, startBody);
      AgentiModels.remember(models[agents[0]]);
      if (instructions) {
        try {
          await Agenti.post(`teams/${encodeURIComponent(name)}/say`,
            { body: instructions });
        } catch (err) {
          console.warn("could not deliver team instructions:", err);
        }
      }
      Agenti.banner(runBanner, "ok", `Team '${name}' launched. Opening its page…`);
      setTimeout(() => {
        location.href = `team.html?team=${encodeURIComponent(name)}`;
      }, 900);
    } catch (err) {
      Agenti.banner(runBanner, "err", Agenti.errorText(err));
    } finally {
      runBtn.disabled = false;
    }
  }
});
