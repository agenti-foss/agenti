/* agent-builder.js — Settings → Agents → "Build an agent".
 *
 * A four-step dialog that produces a spec for shared/agent_builder.py:
 *   1 Basics        the kind (network recon / file analysis), display name,
 *                   short name, one-line description
 *   2 Programs      which reviewed programs it may run (the list depends on the kind)
 *   3 Instructions  its system prompt
 *   4 Review        the server validates it, then a global admin
 *                   re-authenticates and it is built and made ready.
 *
 * Nothing here is trusted: the root CLI re-validates every field, and the
 * approval it asks for is bound to the SHA-256 of the exact spec.
 *
 *   AgentiBuilder.open({ onBuilt(result) })
 */
(function () {
  "use strict";
  const A = Agenti;   // api.js's top-level const (not a window property)
  const esc = A.esc;

  const STEPS = [
    { key: "basics", label: "Basics" },
    { key: "programs", label: "Programs" },
    { key: "prompt", label: "Instructions" },
    { key: "review", label: "Review" },
  ];
  const GROUP_LABEL = { network: "Network", web: "Web", tls: "TLS", windows: "Windows & directory",
    unix: "Unix", analysis: "Packet captures", "": "Other" };

  let catalogP = null;          // one fetch per page load
  let dlg = null;
  let state = null;

  function slug(text) {
    let s = (text || "").toLowerCase().replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "-")
      .replace(/^[^a-z]+/, "").replace(/-+$/, "");
    if (s.length > 32) {
      // keep whole words that fit
      const parts = s.split("-"); s = "";
      for (const p of parts) { if ((s ? s.length + 1 : 0) + p.length > 32) break; s = s ? `${s}-${p}` : p; }
      if (!s) s = parts[0].slice(0, 32);
    }
    return s;
  }

  function starterPrompt(st) {
    const head = [`You are ${st.title || "this agent"}. ${st.description || ""}`.trim(), ""];
    if (st.kind === "analysis") {
      return [...head,
        "## What to do",
        "1. List the attached file(s) with list_files, and say what each one is. For a packet capture, use capinfos for its size, time span and packet count, then tshark -z io,phs for the protocols in it.",
        "2. <describe what to look for, step by step>", "",
        "## What to produce",
        "End with a short report: what the file contains, what you found (with frame numbers and the evidence for each point), and what you could not determine.", "",
        "## Rules",
        "- Analyse only: never try to log in to, exploit or contact anything the file mentions.",
        "- Cite exact evidence: frame numbers, addresses, protocols, field values.",
        "- If a credential is what you were asked to find, report where it was and its value; otherwise refer to it by location only.",
        "- If you need a decision, ask the operator with ask_operator."].join("\n") + "\n";
    }
    return [...head,
      "## What to do",
      "1. Look at the authorized target(s) you were given, using only the programs you were given.",
      "2. <describe the job, step by step>", "",
      "## What to produce",
      "End with a short findings summary: what you looked at, what you found, and how sure you are.", "",
      "## Rules",
      "- Reconnaissance only: look, never exploit, brute-force or disrupt anything.",
      "- Stay inside the scope for this run; commands outside it are refused.",
      "- If something looks critical, stop and say so plainly for a human to review.",
      "- If you need a decision, ask the operator with ask_operator."].join("\n") + "\n";
  }

  function build() {
    dlg = document.createElement("dialog");
    dlg.className = "wizard";
    dlg.id = "build-agent-dialog";
    dlg.setAttribute("aria-labelledby", "wiz-title");
    dlg.innerHTML = `
      <form method="dialog" class="wizard-form" novalidate>
        <header class="wizard-head">
          <div class="wizard-title-row">
            <h2 id="wiz-title">Build an agent</h2>
            <button type="button" class="icon-btn" data-wiz-close aria-label="Close">${A.icon("close")}</button>
          </div>
          <ol class="wizard-steps" aria-label="Steps">
            ${STEPS.map((s, i) => `<li data-step-dot="${i}"><span class="wizard-dot">${i + 1}</span><span class="wizard-step-label">${s.label}</span></li>`).join("")}
          </ol>
        </header>
        <div class="wizard-body">
          <section data-step="0">
            <div class="field"><label id="wiz-kind-label">Kind of agent</label>
              <div id="wiz-kinds" role="radiogroup" aria-labelledby="wiz-kind-label"
                   style="display:flex;flex-direction:column;gap:var(--space-2);"></div>
              <p class="hint" id="wiz-kind-note" hidden>The kind is fixed once an agent is built.</p></div>
            <div class="field"><label for="wiz-title-in">Name</label>
              <input type="text" id="wiz-title-in" maxlength="60" autocomplete="off" placeholder="e.g. Web server check">
              <p class="hint">What people see on the Launch page.</p></div>
            <div class="field"><label for="wiz-name">Short name</label>
              <input type="text" id="wiz-name" maxlength="32" autocomplete="off" spellcheck="false" placeholder="web-server-check">
              <p class="hint" id="wiz-name-hint">Lowercase letters, digits and hyphens. Used in commands and links; it can't be changed later.</p></div>
            <div class="field"><label for="wiz-desc">What it does <span class="muted" id="wiz-desc-count"></span></label>
              <input type="text" id="wiz-desc" maxlength="200" autocomplete="off" placeholder="One sentence, e.g. Checks a web server's headers and open ports.">
            </div>
          </section>
          <section data-step="1" hidden>
            <p class="hint" id="wiz-programs-hint" style="margin-top:0;"></p>
            <div class="field"><input type="search" id="wiz-prog-search" placeholder="Search programs…" autocomplete="off" aria-label="Search programs"></div>
            <div id="wiz-programs"></div>
            <p class="hint" id="wiz-programs-count"></p>
          </section>
          <section data-step="2" hidden>
            <div class="field"><label for="wiz-prompt">Instructions <span class="muted" id="wiz-prompt-count"></span></label>
              <textarea id="wiz-prompt" rows="16" spellcheck="true"></textarea>
              <p class="hint">The agent's system prompt: what it is for, the steps, what to produce, and what it must
                not do. Text only — it can never widen the agent's tools or what it can reach. You can edit it later
                in the control centre, and every edit is kept.</p>
              <button type="button" class="btn btn-sm" id="wiz-prompt-reset" data-icon="refresh">Start again from the template</button>
            </div>
          </section>
          <section data-step="3" hidden>
            <dl class="kv wiz-review" id="wiz-review"></dl>
            <div class="wiz-callout" id="wiz-access"></div>
          </section>
          <section data-step="4" hidden>
            <div class="wiz-done">
              <span class="wiz-done-icon">${A.icon("check", 28)}</span>
              <h3 id="wiz-done-title"></h3>
              <p class="hint" id="wiz-done-text"></p>
            </div>
          </section>
          <div class="banner err" id="wiz-banner" role="alert"></div>
        </div>
        <footer class="wizard-foot">
          <button type="button" class="btn" data-wiz-back>Back</button>
          <span class="wizard-spacer"></span>
          <button type="button" class="btn" data-wiz-cancel>Cancel</button>
          <button type="button" class="btn btn-primary" data-wiz-next>Next</button>
        </footer>
      </form>`;
    document.body.appendChild(dlg);

    const titleIn = $("#wiz-title-in"), nameIn = $("#wiz-name"), descIn = $("#wiz-desc"), promptIn = $("#wiz-prompt");

    titleIn.addEventListener("input", () => {
      state.title = titleIn.value;
      if (!state.nameEdited) { state.name = slug(titleIn.value); nameIn.value = state.name; }
      paintNameHint();
    });
    nameIn.addEventListener("input", () => {
      state.nameEdited = nameIn.value.trim() !== "";
      state.name = nameIn.value.trim();
      paintNameHint();
    });
    descIn.addEventListener("input", () => { state.description = descIn.value; paintDescCount(); });
    $("#wiz-kinds").addEventListener("change", (e) => {
      const id = e.target && e.target.dataset && e.target.dataset.kind;
      if (!id || id === state.kind || state.edit) return;
      state.kind = id;
      state.programs = [];                 // the two kinds offer different programs
      if (!state.promptEdited) state.prompt = starterPrompt(state);
      paintPrograms(kindPrograms(state.cat, id)); paintProgramsHint(); paintNameHint();
    });
    promptIn.addEventListener("input", () => { state.prompt = promptIn.value; state.promptEdited = true; paintPromptCount(); });
    $("#wiz-prompt-reset").addEventListener("click", () => {
      if (state.promptEdited && !confirm("Replace your instructions with the template?")) return;
      state.prompt = starterPrompt(state); state.promptEdited = false;
      promptIn.value = state.prompt; paintPromptCount();
    });
    $("#wiz-programs").addEventListener("change", (e) => {
      const t = e.target.dataset.program; if (!t) return;
      state.programs = e.target.checked ? [...new Set([...state.programs, t])] : state.programs.filter((x) => x !== t);
      paintProgramCount();
    });
    $("#wiz-prog-search").addEventListener("input", () => paintPrograms(state.catalog));
    $("[data-wiz-close]").addEventListener("click", close);
    $("[data-wiz-cancel]").addEventListener("click", close);
    $("[data-wiz-back]").addEventListener("click", () => go(state.edit && state.step === 3 ? 1 : state.step - 1));
    $("[data-wiz-next]").addEventListener("click", next);
    dlg.addEventListener("cancel", (e) => { if (state.busy) e.preventDefault(); else if (!confirmDiscard()) e.preventDefault(); });
    // Enter in a one-line field moves on instead of submitting the form.
    dlg.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.tagName === "INPUT" && e.target.type === "text") { e.preventDefault(); next(); }
    });
  }

  function confirmDiscard() {
    if (state.step >= 4 || (!state.title && !state.description && !state.programs.length)) return true;
    return confirm("Discard this agent? Nothing has been built yet.");
  }
  function close() {
    if (state.busy) return;
    if (!confirmDiscard()) return;
    dlg.close();
  }

  const $ = (sel) => dlg.querySelector(sel);
  function err(msg) { A.banner($("#wiz-banner"), "err", msg); }
  function clearErr() { $("#wiz-banner").className = "banner err"; $("#wiz-banner").textContent = ""; }

  function paintNameHint() {
    const h = $("#wiz-name-hint"), n = state.name;
    const ok = /^[a-z][a-z0-9-]{0,31}$/.test(n);
    const taken = !state.edit && state.existing.includes(n);
    h.classList.toggle("warn", !!n && (!ok || taken));
    h.textContent = !n ? "Lowercase letters, digits and hyphens. Used in commands and links; it can't be changed later."
      : taken ? `An agent called “${n}” already exists — pick another.`
      : !ok ? "Use lowercase letters, digits and hyphens, starting with a letter (32 at most)."
      : state.kind === "analysis" ? `Commands will use it like this: agenti ${n} attach <file>`
      : `Commands will use it like this: agenti ${n} start -t <target>`;
  }
  function paintDescCount() { $("#wiz-desc-count").textContent = `${state.description.length}/200`; }
  function paintPromptCount() {
    const b = new TextEncoder().encode(state.prompt).length;
    $("#wiz-prompt-count").textContent = `${b.toLocaleString()} / 20,000 bytes`;
  }
  function paintProgramCount() {
    const n = state.programs.length;
    $("#wiz-programs-count").textContent = n ? `${n} program${n === 1 ? "" : "s"} selected.` : "Pick at least one program.";
    $("#wiz-programs-count").classList.toggle("warn", !n);
  }

  function kindPrograms(cat, kind) {
    const k = ((cat && cat.kinds) || []).find((x) => x.id === kind);
    return k ? k.programs : ((cat && cat.programs) || []);
  }
  function paintProgramsHint() {
    $("#wiz-programs-hint").textContent = state.kind === "analysis"
      ? "Pick the programs it may use on the files you attach. They run in a sandbox with no network, on those files only, and each accepts just the options reviewed for it."
      : "Pick the programs it may run. Only reviewed recon programs are listed; an admin can add more in Settings → Agents → Program catalog. Every command is still checked against the engagement's scope.";
  }
  function paintKinds() {
    const kinds = (state.cat && state.cat.kinds) || [];
    $("#wiz-kinds").innerHTML = kinds.map((k) => `
      <label class="wiz-kit${state.edit && k.id !== state.kind ? " disabled" : ""}">
        <input type="radio" name="wiz-kind" data-kind="${esc(k.id)}" ${k.id === state.kind ? "checked" : ""} ${state.edit ? "disabled" : ""}>
        <span class="wiz-kit-body"><span class="wiz-kit-name">${esc(k.title)}</span>
          <span class="wiz-kit-desc">${esc(k.blurb)}</span></span></label>`).join("");
    $("#wiz-kind-note").hidden = !state.edit;
  }

  function paintPrograms(programs) {
    state.catalog = programs;
    const q = ($("#wiz-prog-search").value || "").trim().toLowerCase();
    const shown = programs.filter((p) => !q || p.name.toLowerCase().includes(q)
      || p.purpose.toLowerCase().includes(q) || (p.group || "").toLowerCase().includes(q));
    const groups = {};
    for (const p of shown) (groups[p.group || ""] = groups[p.group || ""] || []).push(p);
    $("#wiz-programs").innerHTML = Object.entries(groups).map(([g, list]) => `
      <fieldset class="wiz-tool-group"><legend>${esc(GROUP_LABEL[g] || g)}</legend>
        ${list.map((p) => {
          const off = !p.installed;
          const src = p.source === "admin" ? `<span class="wiz-tag" title="Added by an admin to the program catalog">Added by an admin</span>` : "";
          return `<label class="wiz-tool${off ? " disabled" : ""}">
            <input type="checkbox" data-program="${esc(p.name)}" ${state.programs.includes(p.name) ? "checked" : ""} ${off ? "disabled" : ""}>
            <span class="wiz-tool-body">
              <span class="wiz-tool-name"><code>${esc(p.name)}</code>${src}</span>
              <span class="wiz-tool-desc">${off ? `Not installed on this server — <code>sudo apt install ${esc(p.package || p.name)}</code>` : esc(p.purpose)}</span>
            </span></label>`;
        }).join("")}
      </fieldset>`).join("") || `<p class="hint">No programs match.</p>`;
    paintProgramCount();
  }

  function specFromState() {
    const base = { kind: state.kind, name: state.name, title: state.title.trim(), description: state.description.trim(),
      programs: state.programs };
    return state.edit ? base : { ...base, system_prompt: state.prompt };
  }

  function paintReview(checked) {
    const s = checked ? checked.spec : specFromState();
    const firstLine = (s.system_prompt || "").split("\n").find((l) => l.trim()) || "";
    const kindTitle = (((state.cat && state.cat.kinds) || []).find((k) => k.id === (s.kind || state.kind)) || {}).title || s.kind;
    $("#wiz-review").innerHTML = `
      <dt>Kind</dt><dd>${esc(kindTitle)}</dd>
      <dt>Name</dt><dd>${esc(s.title)} <span class="muted">(${esc(s.name)})</span></dd>
      <dt>What it does</dt><dd>${esc(s.description)}</dd>
      <dt>Programs</dt><dd>${s.programs.map((t) => `<span class="chip">${esc(t)}</span>`).join(" ")}</dd>
      ${state.edit ? "" : `<dt>Instructions</dt><dd>${esc(firstLine.slice(0, 140))}${(s.system_prompt || "").length > firstLine.length ? " …" : ""}
        <span class="muted">(${new TextEncoder().encode(s.system_prompt || "").length.toLocaleString()} bytes)</span></dd>`}`;
    $("#wiz-access").innerHTML = state.edit ? `${A.icon("info")}<div>
      <strong>Applies from the next run.</strong> Runs already going keep what they started with.</div>` : `${A.icon("info")}<div>
      <strong>Ready for everyone.</strong> ${state.kind === "analysis"
        ? "Any operator can launch it with files attached. It can only run the programs above, in a sandbox, and needs no target or engagement."
        : "Any operator can launch it, against targets inside the engagement's scope. It can only run the programs above."}</div>`;
  }

  function validateStep(i) {
    if (i === 0) {
      if (!state.title.trim()) return ["Give the agent a name.", "#wiz-title-in"];
      if (!/^[a-z][a-z0-9-]{0,31}$/.test(state.name)) return ["The short name must be lowercase letters, digits and hyphens, starting with a letter.", "#wiz-name"];
      if (!state.edit && state.existing.includes(state.name)) return [`An agent called “${state.name}” already exists.`, "#wiz-name"];
      if (!state.description.trim()) return ["Say in one sentence what it does.", "#wiz-desc"];
    }
    if (i === 1 && !state.programs.length) return ["Pick at least one program.", "#wiz-programs input:not(:disabled)"];
    if (i === 2 && !state.edit) {
      if (state.prompt.trim().length < 20) return ["Write the instructions: what it is for, what to produce, what it must not do.", "#wiz-prompt"];
      if (/<describe [^>]*>/.test(state.prompt)) return ["Replace the “<describe …>” line with the actual steps.", "#wiz-prompt"];
      if (new TextEncoder().encode(state.prompt).length > 20000) return ["The instructions are over 20,000 bytes.", "#wiz-prompt"];
    }
    return null;
  }

  function go(i) {
    i = Math.max(0, Math.min(4, i));
    state.step = i;
    clearErr();
    dlg.querySelectorAll("[data-step]").forEach((s) => { s.hidden = Number(s.dataset.step) !== i; });
    dlg.querySelectorAll("[data-step-dot]").forEach((d) => {
      const n = Number(d.dataset.stepDot);
      d.classList.toggle("done", n < i); d.classList.toggle("current", n === i);
      if (n === i) d.setAttribute("aria-current", "step"); else d.removeAttribute("aria-current");
    });
    const back = $("[data-wiz-back]"), nextB = $("[data-wiz-next]"), cancel = $("[data-wiz-cancel]");
    back.hidden = i === 0 || i === 4;
    cancel.hidden = i === 4;
    nextB.innerHTML = i === 3 ? (state.edit ? `${A.icon("check")}<span>Save changes</span>` : `${A.icon("rocket")}<span>Build agent</span>`)
      : i === 4 ? "<span>Done</span>" : "<span>Next</span>";
    dlg.querySelector('[data-step-dot="2"]').hidden = !!state.edit;
    $("#wiz-title").textContent = state.edit ? `Edit ${state.title || state.name}` : "Build an agent";
    dlg.querySelector(".wizard-steps").hidden = i === 4;
    if (i === 2 && !state.promptEdited) {
      state.prompt = starterPrompt(state); $("#wiz-prompt").value = state.prompt;
    }
    if (i === 2) paintPromptCount();
    if (i === 3) paintReview(null);
    const first = { 0: "#wiz-title-in", 1: "#wiz-prog-search", 2: "#wiz-prompt" }[i];
    if (first && dlg.querySelector(first)) dlg.querySelector(first).focus();
    dlg.querySelector(".wizard-body").scrollTop = 0;
  }

  async function next() {
    if (state.busy) return;
    if (state.step === 4) { dlg.close(); return; }
    const bad = validateStep(state.step);
    if (bad) { err(bad[0]); const el = dlg.querySelector(bad[1]); if (el) el.focus(); return; }
    if (state.step < 3) { go(state.edit && state.step === 1 ? 3 : state.step + 1); return; }
    await buildIt();
  }

  // Which step a server-side error belongs to, so the person lands on the field.
  function stepForError(msg) {
    if (/program/i.test(msg)) return 1;
    if (/instructions|system prompt/i.test(msg)) return 2;
    return 0;
  }

  async function buildIt() {
    const nextB = $("[data-wiz-next]");
    state.busy = true; nextB.disabled = true;
    try {
      const spec = specFromState();
      let checked;
      try {
        checked = await A.post(state.edit ? "admin/agent-builder/check-update" : "admin/agent-builder/check", spec);
      } catch (e) {
        const msg = A.errorText(e); go(stepForError(msg)); err(msg); return;
      }
      paintReview(checked);
      const result = await A.requireApproval({
        title: state.edit ? "Save these changes?" : "Build this agent?",
        description: state.edit ? `Changes “${checked.spec.title}”.`
          : `Builds “${checked.spec.title}” and makes it ready.`,
        submit: (creds) => A.post(state.edit ? "admin/agent-builder/update" : "admin/agent-builder/create",
          { spec, password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
      if (!result) return;   // cancelled — stay on Review
      $("#wiz-done-title").textContent = state.edit ? `${checked.spec.title} was updated` : `${checked.spec.title} is ready`;
      if (state.edit) {
        $("#wiz-done-text").textContent = "The changes apply from the next run.";
      } else if (result.ready === false) {
        $("#wiz-done-text").innerHTML = `It was built, but could not be prepared yet — <span class="warn">it will be prepared the first time someone launches it.</span>`;
      } else {
        $("#wiz-done-text").textContent = state.kind === "analysis"
          ? "Operators can launch it from the Launch page and attach the files to analyse there."
          : "Operators can launch it from the Launch page.";
      }
      go(4);
      if (state.onBuilt) state.onBuilt(result);
    } catch (e) {
      err(A.errorText(e));
    } finally {
      state.busy = false; nextB.disabled = false;
    }
  }

  async function open(opts) {
    if (!dlg) build();
    state = { step: 0, kind: "recon", cat: null, title: "", name: "", nameEdited: false, description: "", programs: [], catalog: [],
      prompt: "", promptEdited: false, busy: false, existing: (opts && opts.existing) || [],
      onBuilt: opts && opts.onBuilt, edit: !!(opts && opts.edit) };
    $("#wiz-name").readOnly = state.edit;
    ["#wiz-title-in", "#wiz-name", "#wiz-desc"].forEach((s) => { $(s).value = ""; });
    $("#wiz-prompt").value = "";
    paintNameHint(); paintDescCount();
    dlg.showModal();
    go(0);
    $("#wiz-prog-search").value = "";
    $("#wiz-programs").innerHTML = `<p class="hint">Loading…</p>`;
    try {
      catalogP = catalogP || A.get("admin/agent-builder/catalog");
      const cat = await catalogP;
      state.cat = cat;
      if (state.edit) {
        const cur = await A.get(`admin/agent-builder/${encodeURIComponent(opts.edit)}/remove-preview`);
        Object.assign(state, { name: cur.name, title: cur.title, description: cur.description || "",
          kind: cur.kind || "recon", programs: cur.programs || [], nameEdited: true });
        $("#wiz-title-in").value = state.title; $("#wiz-name").value = state.name; $("#wiz-desc").value = state.description;
        paintNameHint(); paintDescCount();
        $("#wiz-name-hint").textContent = "The short name can't be changed.";
        $("#wiz-title").textContent = `Edit ${state.title}`;
      }
      paintKinds(); paintProgramsHint();
      paintPrograms(kindPrograms(cat, state.kind));
    } catch (e) {
      catalogP = null;
      err(A.errorText(e));
    }
  }

  window.AgentiBuilder = { open };
})();
