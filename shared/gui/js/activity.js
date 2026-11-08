// activity.js — how a run's ledger is shown to a person.
//
// The ledger (findings.jsonl) is a complete record: every thing the model said,
// every tool call and every result. Shown row by row that is a wall of text
// nobody reads. This turns it into a conversation:
//
//   what the agent SAID          a short bubble, Markdown rendered; a long one
//                                is clamped with "Show more"; the closing
//                                message of a finished run is the "Summary"
//   what it DID in between       ONE collapsed line — "Ran 6 steps" (or
//                                "Working · fetch page …" while live) — that
//                                opens to the individual steps, each of which
//                                opens to its result. Failures are called out.
//   what you / a teammate SAID   right-aligned for you, left for a teammate
//
// Used by the agent console (agent.js) and by the team chat (team.js), so a
// run reads the same in both places.
//
// SESSION mode ({session: true}, the agent console): the way a Claude Code or
// Codex session reads. Every step is its own line, in order: what it ran,
// a live marker while it runs, and a one-line result that opens to the whole
// recorded result. What the agent said sits between them as plain text, what
// you said as a prompt line. Nothing is folded away, so the run can be
// followed step by step; the team chat keeps the folded form.
//
// Everything is built from escaped text (AgentiMarkdown escapes its input).
const AgentiActivity = (() => {
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const baseTool = (t) => String(t || "?").replace(/^mcp__[a-z0-9_]+__/, "");
  const nice = (t) => baseTool(t).replace(/_/g, " ");
  // "run_scan" -> "Run scan": a step's name as a sentence starts.
  const stepName = (t) => { const n = nice(t); return n.charAt(0).toUpperCase() + n.slice(1); };
  // "2 refused · 1 failed": refusals are named apart from errors.
  const stepsMeta = (failed, refused) => [refused ? `${refused} refused` : "",
                                          failed ? `${failed} failed` : ""].filter(Boolean).join(" · ");

  // Rows recorded before the ledger kept line breaks are one flattened line
  // ("## Findings - **Host** ... | a | b |"). Rendering that as Markdown shows
  // stray # and ** everywhere, so strip the markup instead of pretending.
  function looksFlattened(text) {
    return !/\n/.test(text) && text.length > 160 && /(#{2,4}\s|\*\*|\|\s*-{3,}\s*\|)/.test(text);
  }
  function plainify(text) {
    return String(text).replace(/\|[\s:|-]{3,}\|/g, " ").replace(/\s*\|\s*/g, " · ")
      .replace(/#{1,6}\s+/g, "").replace(/\*\*/g, "").replace(/`/g, "").replace(/\s+/g, " ").trim();
  }
  function bodyHtml(text) {
    const t = String(text || "").trim();
    if (looksFlattened(t)) return `<p>${esc(plainify(t))}</p>`;
    // `const AgentiMarkdown` is a global binding, not a window property, so it
    // is tested with typeof — window.AgentiMarkdown would always be undefined.
    return typeof AgentiMarkdown !== "undefined" ? AgentiMarkdown.render(t) : `<p>${esc(t)}</p>`;
  }

  // "[agent:research via tool] text" — how a delivered message is recorded.
  function parseReceived(summary) {
    const m = /^\[([^\]]+?) via ([^\]]+)\]\s*([\s\S]*)$/.exec(String(summary || ""));
    return m ? { author: m[1], via: m[2], body: m[3] } : { author: "", via: "", body: String(summary || "") };
  }
  const isAgent = (a) => String(a).startsWith("agent:");
  const agentName = (a) => String(a).replace(/^agent:/, "");

  // team_message / ask_operator calls arrive as "body=…, to=…" or a bare value.
  function parseArgs(summary) {
    const s = String(summary || "");
    const m = /^body=([\s\S]*?)(?:, to=([a-z0-9-]+))?$/.exec(s);
    return m ? { body: m[1], to: m[2] || "" } : { body: s, to: "" };
  }

  function clampify(el) {
    // Called after the node is in the page, when its height can be measured.
    const body = el.querySelector(".say-body");
    const more = el.querySelector(".say-more");
    if (!body || !more) return;
    if (body.scrollHeight > body.clientHeight + 6) {
      more.hidden = false;
    } else {
      body.classList.remove("clamped");
    }
  }

  class Feed {
    // opts: {onFirst, reportHref, you: "name to show for the operator's own rows"}
    constructor(el, opts = {}) {
      this.el = el;
      this.opts = opts;
      this.group = null;        // the open "steps" group, if any
      this.pending = [];        // steps still waiting for a result
      this.lastSay = null;
      if (opts.session) el.classList.add("session");
      el.addEventListener("click", (e) => {
        const b = e.target.closest(".say-more");
        if (!b) return;
        const body = b.parentElement.querySelector(".say-body");
        const open = body.classList.toggle("clamped") === false;
        b.textContent = open ? "Show less" : "Show more";
      });
    }

    clear() {
      const working = this.workingEl;
      this.el.innerHTML = ""; this.group = null; this.pending = []; this.lastSay = null;
      if (working) this.el.appendChild(working);
    }
    empty(msg) { this.el.innerHTML = `<div class="act-empty">${esc(msg)}</div>`; }

    _atBottom() { return this.el.scrollHeight - this.el.scrollTop - this.el.clientHeight < 80; }
    _append(node) {
      const stick = this._atBottom();
      const empty = this.el.querySelector(".act-empty");
      if (empty) empty.remove();
      if (this.workingEl) { this.el.insertBefore(node, this.workingEl); this.since = Date.now(); this._paintWorking(); }
      else this.el.appendChild(node);
      if (stick) this.el.scrollTop = this.el.scrollHeight;
      return node;
    }
    _html(html) { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; }

    add(f, { live } = {}) {
      const tool = baseTool(f.tool);
      if (tool === "agent:says") return this._say(f);
      if (tool.startsWith("operator:")) return this._received(f, tool.slice(9));
      if (tool === "team_message") return f.verdict === "call" ? this._teamPost(f) : undefined;
      if (tool === "propose_complete") return f.verdict === "call" ? this._vote(f) : undefined;
      if (tool === "ask_operator") return f.verdict === "call" ? this._ask(f) : undefined;
      if (tool === "model_switch") return this._modelSwitch(f);
      if (this.opts.session) {
        // The Claude Agent SDK loading its own tool definitions: not a step
        // the run took, so one quiet line, and its (empty) result is dropped.
        if (tool === "ToolSearch") return f.verdict === "call" ? this._muted("Loaded its tools") : undefined;
        return f.verdict === "call" ? this._line(f, tool, live) : this._lineResult(f, tool);
      }
      if (f.verdict === "call") return this._step(f, tool, live);
      return this._result(f, tool);
    }

    // ---- a model switch, as the run applied (or refused) it ------------------
    _modelSwitch(f) {
      this.el.querySelectorAll(".act-note.switch-pending").forEach((n) => n.remove());
      const v = f.verdict || "";
      if (this.opts.onModel && v === "applied") this.opts.onModel(f.summary || "");
      const text = v === "applied" ? `Switched to ${f.summary || "the new model"}`
        : v === "refused" ? `Model not switched: ${String(f.summary || "").replace(/^model switch to /, "")}`
        : `Model switch ${v}: ${f.summary || ""}`;
      const node = this._muted(text);
      node.classList.add("switch", v === "applied" ? "ok" : "bad");
      return node;
    }
    // Shown at once when /model is sent; replaced by the run's own row.
    switchPending(model) {
      const node = this._muted(`Switching to ${model} after the step it is on…`);
      node.classList.add("switch", "switch-pending");
      return node;
    }

    // ---- SESSION mode: one line per step --------------------------------------
    _line(f, tool, live) {
      this._closeGroup();
      const node = this._html(`<details class="sess-step${live ? " run" : " done"}" data-tool="${esc(tool)}">
        <summary>
          <span class="sess-head"><span class="mark" aria-hidden="true"></span><span class="sess-name">${esc(stepName(tool))}</span><code class="sess-arg">${esc(f.summary || "")}</code></span>
          <span class="sess-peek">${live ? "Running…" : ""}</span>
        </summary>
        <pre class="sess-out"></pre></details>`);
      this.pending.push({ node, tool });
      this.lastSay = null;
      return this._append(node);
    }
    _lineResult(f, tool) {
      let i = this.pending.findIndex((p) => p.tool === tool);
      if (i < 0) i = this.pending.length ? 0 : -1;
      const node = i >= 0 ? this.pending.splice(i, 1)[0].node : this._line({ summary: "" }, tool, false);
      if (i < 0) this.pending.pop();
      const bad = f.verdict === "error", refused = f.verdict === "denied";
      node.classList.remove("run");
      node.classList.add("done");
      node.classList.toggle("bad", bad);
      node.classList.toggle("refused", refused);
      const out = String(f.summary || "").trim();
      const peek = refused ? `Refused: ${out.replace(/^DENIED:\s*/, "")}`
        : out || (bad ? "Failed" : "Done, no output");
      node.querySelector(".sess-peek").textContent = peek;
      node.querySelector(".sess-out").textContent = out || peek;
      // Nothing more to see than the line already shows: not openable.
      if (!out || out.length < 90) node.classList.add("short");
      const stick = this._atBottom();
      if (stick) this.el.scrollTop = this.el.scrollHeight;
      return node;
    }

    // While the run is live and not waiting on anyone: one line at the very
    // bottom saying it is working, and for how long since its last step.
    working(on) {
      if (!on) { if (this.workingEl) { this.workingEl.remove(); this.workingEl = null; clearInterval(this.workingTimer); } return; }
      if (!this.workingEl) {
        this.workingEl = this._html(`<div class="sess-working" aria-hidden="true"><span class="spark"></span><span class="sess-working-text">Working…</span></div>`);
        this.el.appendChild(this.workingEl);
        this.workingTimer = setInterval(() => this._paintWorking(), 1000);
      }
      this.since = this.since || Date.now();
      this._paintWorking();
    }
    _paintWorking() {
      if (!this.workingEl) return;
      const s = Math.max(0, Math.round((Date.now() - (this.since || Date.now())) / 1000));
      this.workingEl.querySelector(".sess-working-text").textContent =
        `Working… ${s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`}`;
    }

    // ---- what it said --------------------------------------------------------
    _say(f) {
      this._closeGroup();
      const node = this._html(`<div class="say">
        <div class="say-body md clamped">${bodyHtml(f.summary)}</div>
        <button type="button" class="say-more" hidden>Show more</button></div>`);
      this._append(node);
      this.lastSay = node;
      requestAnimationFrame(() => clampify(node));
      return node;
    }

    // The closing message of a finished run is its summary: say so, once.
    markFinal(reportHref) {
      if (!this.lastSay || this.lastSay.classList.contains("final")) return;
      this.lastSay.classList.add("final");
      const head = document.createElement("div");
      head.className = "say-head";
      head.innerHTML = `<span>Summary</span>${reportHref ? `<a href="${esc(reportHref)}">Open the full report →</a>` : ""}`;
      this.lastSay.prepend(head);
    }

    // ---- what it did ---------------------------------------------------------
    _openGroup() {
      if (this.group) return this.group;
      const node = this._html(`<details class="steps">
        <summary><span class="steps-title"></span><span class="steps-meta"></span></summary>
        <div class="steps-body"></div></details>`);
      this._append(node);
      this.group = { el: node, n: 0, failed: 0, refused: 0, last: "" };
      return this.group;
    }
    _closeGroup() {
      if (!this.group) return;
      this._paintGroup();
      this.group = null;
    }
    _paintGroup() {
      const g = this.group;
      if (!g) return;
      const running = g.el.querySelector(".step.run");
      const title = g.el.querySelector(".steps-title");
      const meta = g.el.querySelector(".steps-meta");
      g.el.classList.toggle("working", !!running);
      title.textContent = running ? `Working · ${g.last}` : `Ran ${g.n} step${g.n === 1 ? "" : "s"}`;
      meta.textContent = stepsMeta(g.failed, g.refused);
      meta.classList.toggle("bad", g.failed > 0);
    }
    _step(f, tool, live) {
      const g = this._openGroup();
      const node = this._html(`<details class="step${live ? " run" : ""}" data-tool="${esc(tool)}">
        <summary><span class="mark"></span><span class="name">${esc(nice(tool))}</span><span class="arg">${esc(f.summary || "")}</span></summary>
        <pre class="step-out"></pre></details>`);
      g.el.querySelector(".steps-body").appendChild(node);
      g.n += 1;
      g.last = `${nice(tool)} ${String(f.summary || "").slice(0, 60)}`.trim();
      // Historical rows have no live marker: a call whose result never came
      // simply shows no mark.
      this.pending.push({ node, tool });
      if (!live) node.classList.add("done");
      this._paintGroup();
      if (this._atBottom()) this.el.scrollTop = this.el.scrollHeight;
      return node;
    }
    _result(f, tool) {
      let i = this.pending.findIndex((p) => p.tool === tool);
      if (i < 0) i = this.pending.length ? 0 : -1;
      let step;
      if (i >= 0) { step = this.pending.splice(i, 1)[0].node; }
      else {
        this._step({ summary: "" }, tool, false);
        step = this.pending.pop().node;
      }
      step.classList.remove("run");
      step.classList.add("done");
      // "denied" is the scope or allow-list refusing a step: the boundary
      // holding, counted apart from a step that went wrong.
      const bad = f.verdict === "error";
      const refused = f.verdict === "denied";
      step.classList.toggle("bad", bad);
      step.classList.toggle("refused", refused);
      step.querySelector(".step-out").textContent = f.summary || "";
      if (bad && this.group) this.group.failed += 1;
      if (refused && this.group) this.group.refused += 1;
      // A result can land on a group that has since been closed by narration.
      const grp = step.closest(".steps");
      if (grp && (!this.group || grp !== this.group.el)) this._repaintClosed(grp);
      else this._paintGroup();
    }
    _repaintClosed(grp) {
      const steps = grp.querySelectorAll(".step");
      const failed = grp.querySelectorAll(".step.bad").length;
      const refused = grp.querySelectorAll(".step.refused").length;
      grp.classList.toggle("working", !!grp.querySelector(".step.run"));
      grp.querySelector(".steps-title").textContent = grp.querySelector(".step.run")
        ? "Working…" : `Ran ${steps.length} step${steps.length === 1 ? "" : "s"}`;
      const meta = grp.querySelector(".steps-meta");
      meta.textContent = stepsMeta(failed, refused);
      meta.classList.toggle("bad", failed > 0);
    }

    // The run is over: nothing is still working.
    finish(reportHref) {
      this.working(false);
      this.pending.forEach((p) => {
        p.node.classList.remove("run");
        const peek = p.node.querySelector(".sess-peek");
        if (peek && peek.textContent === "Running…") { peek.textContent = "No result recorded"; p.node.classList.add("short"); }
      });
      this.pending = [];
      this._closeGroup();
      this.el.querySelectorAll(".steps.working").forEach((g) => this._repaintClosed(g));
      this.markFinal(reportHref);
    }

    // ---- the agent talking to its team / asking you ---------------------------
    _teamPost(f) {
      this._closeGroup();
      const a = parseArgs(f.summary);
      return this._append(this._html(`<div class="say post"><div class="say-meta">${a.to ? `to ${esc(a.to)}` : "to the team"}</div>
        <div class="say-body md">${bodyHtml(a.body)}</div></div>`));
    }
    _vote(f) {
      this._closeGroup();
      return this._append(this._html(`<div class="say post vote"><div class="say-meta">says the project is complete</div>
        <div class="say-body md">${bodyHtml(parseArgs(f.summary).body)}</div></div>`));
    }
    _ask(f) {
      this._closeGroup();
      return this._append(this._html(`<div class="say ask"><div class="say-meta">Asks you — paused until you reply</div>
        <div class="say-body md">${bodyHtml(f.summary)}</div></div>`));
    }
    _muted(text) {
      this._closeGroup();
      return this._append(this._html(`<div class="act-note">${esc(text)}</div>`));
    }

    // ---- what you or a teammate said to it ------------------------------------
    _received(f, kind) {
      this._closeGroup();
      const r = parseReceived(f.summary);
      if (kind === "message") {
        this.el.querySelectorAll(".say.queued").forEach((q) => {
          if (q.dataset.body && r.body.endsWith(q.dataset.body)) q.remove();
        });
        if (isAgent(r.author)) {
          return this._append(this._html(`<div class="say mate"><div class="say-meta">${esc(agentName(r.author))} says</div>
            <div class="say-body md">${bodyHtml(r.body)}</div></div>`));
        }
        return this._append(this._html(`<div class="say you"><div class="say-meta">${esc(this.opts.you || "You")}</div>
          <div class="say-body md">${bodyHtml(r.body)}</div></div>`));
      }
      if (kind === "vote_complete") {
        return this._append(this._html(`<div class="say mate vote"><div class="say-meta">${esc(agentName(r.author))} says the project is complete</div>
          <div class="say-body md">${bodyHtml(r.body)}</div></div>`));
      }
      if (kind === "member_ended") {
        const m = /^(\S+) has ended \(status: ([^,)]+)/.exec(r.body);
        return this._muted(m ? `${m[1]} finished (${m[2]}).` : r.body);
      }
      if (kind === "note") return this._muted(`Note: ${r.body}`);
      if (kind === "kickoff") return null;
      // The request itself; the run's own model_switch row says what came of it.
      if (kind === "set_model") return null;
      return this._muted(`${kind}: ${r.body}`);
    }

    // Shown at once when you send a message, replaced by the real row when
    // the run takes it in at its next break.
    queue(text) {
      this._closeGroup();
      const node = this._html(`<div class="say you queued"><div class="say-meta">${esc(this.opts.you || "You")} · queued</div>
        <div class="say-body md"><p>${esc(text)}</p></div></div>`);
      node.dataset.body = text;
      return this._append(node);
    }
  }

  // One hue per team member, in roster order. None sits near the accent blue,
  // the operator's own color. Shared by the team page and the dashboard card.
  const MEMBER_HUES = [168, 280, 28, 330, 120, 48, 200, 0];

  return { Feed, bodyHtml, plainify, parseReceived, MEMBER_HUES };
})();
