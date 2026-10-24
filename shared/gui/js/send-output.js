// send-output.js — "Send output to another agent": ONE component for every page.
//
// Any element carrying data-send-agent (the sending agent; empty = this page's
// ?agent=) opens the same two windows:
//
//   1. WHAT and WHO. The run's report, the files its tools saved and the files
//      it was given, each with a tick box; and the agent that should get them.
//   2. HOW. "Open Launch" stages the files and opens the Launch form with that
//      agent chosen and the default note filled in. "Start now" asks only for
//      a note, a model and limits (defaulting to what the sending run used) and
//      starts the run at once. An agent that takes a target (enum → exploit) gets
//      the SENDING run's own target, shown in the form so it can be narrowed; the
//      two must take the same kind of target (a CIDR run cannot hand a domain
//      agent anything to aim at). The engagement still enforces scope on the start.
//
// What "send" does is small and safe: the chosen items become FILES ATTACHED to
// your next run of the other agent (shared/run_files.py), with who sent them
// and from where on the record. The receiving agent gets no authority from
// them — a file is data. Every other rule (permissions, the model list, the
// limits, the engagement for a network agent) is enforced by the same routes
// as any launch; this file only chooses and asks.
//
// Markup, anywhere:
//   <button type="button" class="link-btn send-link" data-send-agent="enum"
//           data-send-copy="" data-send-pre="report:foo.md,output:bar.txt">…</button>
const AgentiSend = (() => {
  const esc = (s) => Agenti.esc(s);
  const params = new URLSearchParams(location.search);

  const noteFor = (title) => `Complete your task with this output from ${title}.`;

  // Every start is its own isolated run. Sending output reserves the receiving
  // run's label now, so the files wait in THAT run's own slot (no earlier run
  // of the agent, and no other launch, can pick them up) and the start that
  // follows names the same one.
  const newRunLabel = () => "run-" + Array.from(crypto.getRandomValues(new Uint8Array(4)),
    (b) => b.toString(16).padStart(2, "0")).join("");

  function size(n) {
    if (n < 1024) return `${n} B`;
    const u = ["KB", "MB", "GB"]; let v = n, i = -1;
    do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
    return `${v.toFixed(1).replace(/\.0$/, "")} ${u[i]}`;
  }

  // style: "link" (text), "btn" (a small button) or "icon" (icon only, for a table row)
  function link({ agent = "", copy = "", pre = [], label = "Send output to another agent", style = "link" } = {}) {
    const cls = style === "icon" ? "btn btn-sm btn-icon" : style === "btn" ? "btn btn-sm" : "link-btn";
    return `<button type="button" class="${cls} send-link" data-send-agent="${esc(agent)}"
      data-send-copy="${esc(copy)}" data-send-pre="${esc(pre.join(","))}"
      title="${esc(label)} — hand this run's report, saved outputs or files to another agent"
      aria-label="${esc(label)}">${Agenti.icon("send", style === "icon" ? 15 : 14)}${style === "icon" ? "" : `<span>${esc(label)}</span>`}</button>`;
  }

  // ---- window 1: choose items and the receiving agent ----------------------
  let dlg = null;
  function buildDialog() {
    if (dlg) return dlg;
    dlg = document.createElement("dialog");
    dlg.className = "agenti-modal send-modal";
    dlg.innerHTML = `
      <form class="stack" method="dialog" id="send-form">
        <div class="approval-head">${Agenti.icon("send", 22)}<h2 class="approval-title">Send output to another agent</h2></div>
        <p class="hint">What you tick becomes files attached to your next run of the agent you choose.</p>
        <div id="send-items" class="send-items"></div>
        <div class="field">
          <label for="send-to">Send to</label>
          <select id="send-to" required></select>
          <p class="hint" id="send-to-hint"></p>
        </div>
        <div class="banner err" id="send-banner"></div>
        <div class="btn-row send-actions">
          <button type="button" class="btn btn-primary" id="send-launch" data-icon="open"><span>Open Launch</span></button>
          <button type="button" class="btn" id="send-now" data-icon="play"><span>Start now</span></button>
          <button type="button" class="btn btn-ghost" id="send-cancel">Cancel</button>
        </div>
      </form>`;
    document.body.appendChild(dlg);
    dlg.querySelector("#send-cancel").addEventListener("click", () => dlg.close());
    if (typeof applyIcons === "function") applyIcons(dlg);
    return dlg;
  }

  function itemGroup(title, kind, rows, pre) {
    if (!rows.length) return "";
    return `<fieldset class="send-group"><legend>${esc(title)}</legend>${rows.map((r) => {
      const id = `${kind}:${r.name}`;
      return `<label class="send-item"><input type="checkbox" value="${esc(id)}"${pre.has(id) ? " checked" : ""}>
        <span class="send-name">${esc(r.name)}</span><span class="hint">${esc(size(r.bytes))}</span></label>`;
    }).join("")}</fieldset>`;
  }

  async function open(opts) {
    const agent = opts.agent || params.get("agent") || "";
    const copy = opts.copy ?? params.get("copy") ?? "";
    if (!agent) return;
    const d = buildDialog();
    const itemsEl = d.querySelector("#send-items"), toSel = d.querySelector("#send-to");
    const banner = d.querySelector("#send-banner"), toHint = d.querySelector("#send-to-hint");
    const btnLaunch = d.querySelector("#send-launch"), btnNow = d.querySelector("#send-now");
    const runLabel = newRunLabel();
    banner.className = "banner err";
    itemsEl.innerHTML = `<p class="hint">Loading…</p>`;
    toSel.innerHTML = ""; toHint.textContent = "";
    btnLaunch.disabled = btnNow.disabled = true;
    d.showModal();

    let src, catalog;
    try {
      const q = copy ? `?copy=${encodeURIComponent(copy)}` : "";
      [src, catalog] = await Promise.all([
        Agenti.get(`agents/${encodeURIComponent(agent)}/send-list${q}`),
        Agenti.get("agents"),
      ]);
    } catch (err) {
      itemsEl.innerHTML = "";
      Agenti.banner(banner, "err", Agenti.errorText(err));
      return;
    }
    const agents = (catalog.agents || []);
    const me = agents.find((a) => a.agent === agent);
    const srcTitle = (me && me.title) || agent;

    // What is ticked at first: what the link named, else the newest report.
    const named = (opts.pre || []).filter(Boolean);
    const pre = new Set(named.length ? named : (src.reports[0] ? [`report:${src.reports[0].name}`] : []));
    const html = itemGroup("Reports", "report", src.reports, pre)
      + itemGroup("Saved outputs", "output", src.outputs, pre)
      + itemGroup("Files attached to this run", "file", src.files, pre);
    itemsEl.innerHTML = html || `<p class="hint">This run has nothing to send yet — no report, saved output or attached file.</p>`;

    toSel.innerHTML = `<option value="" disabled selected>Choose an agent…</option>`
      + agents.map((a) => `<option value="${esc(a.agent)}">${esc(a.title || a.agent)}</option>`).join("");
    const chosen = () => agents.find((a) => a.agent === toSel.value);
    const ticked = () => [...itemsEl.querySelectorAll('input[type="checkbox"]:checked')].map((c) => c.value);

    // The sending run's own target can start the receiving agent only when both
    // take the same kind of target (cidr→cidr, domain→domain).
    const carriesTarget = (a) => !!a && !!src.target && !!me && a.scope_kind === me.scope_kind
      && (a.scope_kind === "cidr" || a.scope_kind === "domain");
    function refresh() {
      const a = chosen();
      const needsTarget = !!a && (a.scope_kind === "cidr" || a.scope_kind === "domain");
      const canStart = !needsTarget || carriesTarget(a);
      toHint.textContent = !a ? "" : !needsTarget ? (a.description || "")
        : canStart ? `${a.description ? a.description + " " : ""}Start now aims it at ${srcTitle}'s target, ${src.target} — you can narrow it first.`
        : src.target ? `${a.title || a.agent} takes a ${a.scope_kind === "cidr" ? "network address" : "domain"}, which ${srcTitle}'s target (${src.target}) is not — use Open Launch to pick one.`
        : "This agent needs a target, so use Open Launch to pick one.";
      const ready = !!a && ticked().length > 0;
      btnLaunch.disabled = !ready;
      btnNow.disabled = !ready || !canStart;
      btnNow.title = canStart ? "" : "This agent needs a target — use Open Launch";
    }
    toSel.addEventListener("change", refresh);
    itemsEl.addEventListener("change", refresh);
    refresh();

    async function stage() {
      const a = chosen();
      const items = ticked();
      return Agenti.post(`agents/${encodeURIComponent(agent)}/send`,
                         { to: a.agent, items, copy: copy || null, to_copy: runLabel });
    }

    btnLaunch.onclick = async () => {
      banner.className = "banner err";
      btnLaunch.disabled = btnNow.disabled = true;
      try {
        const a = chosen();
        await stage();
        // Carry the SENDING run's own target along (enum's CIDR, research's
        // domain, …) so Launch can prefill it instead of asking the operator
        // to retype a target the system already has on file. Only makes
        // sense when the destination actually takes a target of its own;
        // launch.js ignores an unknown/empty one harmlessly either way.
        const targetQS = src.target && (a.scope_kind === "cidr" || a.scope_kind === "domain")
          ? `&target=${encodeURIComponent(src.target)}` : "";
        location.href = `launch.html?agent=${encodeURIComponent(a.agent)}`
          + `&copy=${encodeURIComponent(runLabel)}`
          + `&note=${encodeURIComponent(noteFor(srcTitle))}&from=${encodeURIComponent(srcTitle)}${targetQS}`;
      } catch (err) {
        Agenti.banner(banner, "err", Agenti.errorText(err));
        refresh();
      }
    };

    btnNow.onclick = async () => {
      const a = chosen();
      const items = ticked();
      d.close();
      await quickStart({ source: agent, sourceTitle: srcTitle, dest: a, items, copy, runLabel, config: src.config || {},
                         target: carriesTarget(a) ? src.target : "" });
    };
  }

  // ---- window 2: start now --------------------------------------------------
  let qdlg = null;
  function buildQuick() {
    if (qdlg) return qdlg;
    qdlg = document.createElement("dialog");
    qdlg.className = "agenti-modal send-modal";
    qdlg.innerHTML = `
      <form class="stack" id="quick-form" method="dialog">
        <div class="approval-head">${Agenti.icon("play", 22)}<h2 class="approval-title" id="quick-title"></h2></div>
        <p class="hint" id="quick-sub"></p>
        <div class="field">
          <label for="quick-note">Note for the agent</label>
          <textarea id="quick-note" rows="3"></textarea>
          <p class="hint">Steers what it tries — never what it may touch.</p>
        </div>
        <div class="field" id="quick-target-field">
          <label for="quick-target">Target</label>
          <input type="text" id="quick-target" autocomplete="off" spellcheck="false">
          <p class="hint" id="quick-target-hint"></p>
        </div>
        <div class="field">
          <label for="quick-model">Model</label>
          <select id="quick-model" required></select>
          <p class="hint" id="quick-model-hint"></p>
        </div>
        <div class="field-row">
          <div class="field"><label for="quick-turns">Max turns</label><input type="number" id="quick-turns" min="1"></div>
          <div class="field"><label for="quick-budget">Max budget (USD)</label><input type="number" id="quick-budget" min="0" step="0.01"></div>
          <div class="field"><label for="quick-timeout">Timeout (s)</label><input type="number" id="quick-timeout" min="1"></div>
        </div>
        <div class="banner err" id="quick-banner"></div>
        <div class="btn-row">
          <button type="submit" class="btn btn-primary" id="quick-go" data-icon="play"><span>Start</span></button>
          <button type="button" class="btn btn-ghost" id="quick-cancel">Cancel</button>
        </div>
      </form>`;
    document.body.appendChild(qdlg);
    qdlg.querySelector("#quick-cancel").addEventListener("click", () => qdlg.close());
    if (typeof applyIcons === "function") applyIcons(qdlg);
    return qdlg;
  }

  let stagedKey = "";   // what was already handed over, so a retry does not send it twice
  async function quickStart({ source, sourceTitle, dest, items, copy, runLabel, config, target = "" }) {
    const d = buildQuick();
    const $ = (id) => d.querySelector("#" + id);
    const banner = $("quick-banner"), go = $("quick-go");
    banner.className = "banner err";
    $("quick-title").textContent = `Start ${dest.title || dest.agent} now`;
    $("quick-sub").textContent = `${items.length} item${items.length === 1 ? "" : "s"} from ${sourceTitle} will be attached to it.`;
    $("quick-note").value = noteFor(sourceTitle);
    // [hidden] loses to any author `display`, so the field is shown/hidden by style.
    $("quick-target-field").style.display = target ? "" : "none";
    $("quick-target").value = target;
    $("quick-target-hint").textContent = target
      ? `The same target ${sourceTitle} had. You may narrow it; the engagement still decides what is in scope.` : "";
    $("quick-model").innerHTML = `<option value="" disabled selected>Loading…</option>`;
    $("quick-model-hint").textContent = "";
    for (const id of ["quick-turns", "quick-budget", "quick-timeout"]) { $(id).value = ""; $(id).placeholder = ""; $(id).removeAttribute("max"); }
    go.disabled = true;
    d.showModal();

    let policy = {};
    try {
      const data = await Agenti.get(`agents/${encodeURIComponent(dest.agent)}/engagement`);
      policy = data.effective_policy || {};
    } catch (err) {
      Agenti.banner(banner, "err", Agenti.errorText(err));
      return;
    }
    const models = policy.allowed_models || [];
    const label = (m) => ({ haiku: "Haiku (fastest, cheapest)", sonnet: "Sonnet (balanced)", opus: "Opus (most capable)" }[m] || m);
    // Default to what the sending run used, if this agent may use it too.
    const want = models.includes(config.model) ? config.model : "";
    $("quick-model").innerHTML = models.length
      ? `<option value="" disabled${want ? "" : " selected"}>Choose a model…</option>`
        + models.map((m) => `<option value="${esc(m)}"${m === want ? " selected" : ""}>${esc(label(m))}</option>`).join("")
      : `<option value="" disabled selected>(none allowed — ask an admin)</option>`;
    $("quick-model-hint").textContent = want ? `The same model ${sourceTitle} used.`
      : models.length ? "From the organisation's allowed list." : "";
    // Limits default to the sending run's, held to this agent's ceilings.
    const cap = (v, ceil) => (v == null ? "" : (ceil != null && v > ceil ? ceil : v));
    const f = [["quick-turns", config.max_turns, policy.max_turns_ceiling],
               ["quick-budget", config.max_budget_usd, policy.max_budget_usd_ceiling],
               ["quick-timeout", config.timeout_s, policy.timeout_s_ceiling]];
    for (const [id, v, ceil] of f) {
      $(id).value = cap(v, ceil);
      if (ceil != null) { $(id).max = ceil; $(id).placeholder = `up to ${ceil}`; }
    }
    go.disabled = !models.length;

    const form = $("quick-form");
    form.onsubmit = async (e) => {
      e.preventDefault();
      banner.className = "banner err";
      const model = $("quick-model").value;
      if (!model) { Agenti.banner(banner, "err", "Pick a model."); return; }
      go.disabled = true;
      let staged = false;
      try {
        const key = `${source}|${copy}|${dest.agent}|${runLabel}`;
        if (stagedKey !== key) {
          await Agenti.post(`agents/${encodeURIComponent(source)}/send`,
                            { to: dest.agent, items, copy: copy || null, to_copy: runLabel });
          stagedKey = key;
        }
        staged = true;
        const body = { model, copy: runLabel };
        const n = (id) => $(id).value;
        if (target) {
          const t = $("quick-target").value.trim();
          if (!t) throw new Error("A target is required for this agent.");
          body.target = t;
        }
        if (n("quick-turns")) body.turns = parseInt(n("quick-turns"), 10);
        if (n("quick-budget")) body.budget = parseFloat(n("quick-budget"));
        if (n("quick-timeout")) body.timeout = parseInt(n("quick-timeout"), 10);
        await Agenti.post(`agents/${encodeURIComponent(dest.agent)}/start`, body);
        const note = $("quick-note").value.trim();
        if (note) {
          try { await Agenti.post(`agents/${encodeURIComponent(dest.agent)}/say?copy=${encodeURIComponent(runLabel)}`, { body: note }); }
          catch (err) { console.warn("could not deliver the note:", err); }
        }
        try { localStorage.setItem("agenti-last-model", model); } catch (e2) { /* no persistence */ }
        location.href = `agent.html?agent=${encodeURIComponent(dest.agent)}&copy=${encodeURIComponent(runLabel)}`;
      } catch (err) {
        let msg = Agenti.errorText(err);
        if (staged) msg += ` The files are attached to this run — press Start again to retry.`;
        Agenti.banner(banner, "err", msg);
        go.disabled = false;
      }
    };
  }

  // One delegated listener serves every link on every page, including ones a
  // page draws later.
  document.addEventListener("click", (e) => {
    const el = e.target.closest("[data-send-agent]");
    if (!el) return;
    e.preventDefault();
    open({ agent: el.dataset.sendAgent, copy: el.dataset.sendCopy,
           pre: (el.dataset.sendPre || "").split(",").filter(Boolean) });
  });

  return { link, open, noteFor };
})();
