// team.js — one team's project console: roster + roles, consensus, the
// shared channel, and fan-out controls.
//
//   team.html?team=[&user=<owner>][&embed=1]
//
// A team belongs to whoever started it (CLAUDE.md §4 item 71); its members
// run in that user's "team-<team>" copies. ?user= is another user's team,
// opened from their dashboard by an admin, who may stop it or mark it
// complete but not message it.
//
// Data:
//   GET  /teams/{team}                  -> {name, created_by, fixed, members:[{agent, scope_mode}]}
//   GET  /teams/{team}/status            -> per-member fan-out of the SAME
//                                              shape the dashboard/agent pages
//                                              already render (ok[], results[], failed[])
//   GET  /teams/{team}/consensus         -> {complete, members:{agent:{voted,stale,vote_id}}}
//   GET  /teams/{team}/inbox?n=          -> the full channel transcript, in
//                                              order — the latest kind="kickoff"
//                                              entry's own `roster` field is
//                                              read here for each member's role,
//                                              rather than a separate endpoint
//   GET  /agents/{agent}/findings?n=           -> each member's own ledger (what it
//                                              said to itself, called, got back),
//                                              merged by time into the chat
//   POST /teams/{team}/say|note|stop|pause|resume
//
// Live updates come from GET /teams/{team}/stream (server-sent events): the
// server pushes a fresh snapshot only when something changed. If that stream
// is not open (dropped, or the browser is reconnecting) this page falls back
// to a slow poll so it never goes stale.
const TEAM_FALLBACK_POLL_MS = 15000;

document.addEventListener("DOMContentLoaded", async function () {
  const esc = Agenti.esc;
  const enc = encodeURIComponent;
  const params = new URLSearchParams(location.search);
  const team = params.get("team") || "";
  const viewUser = params.get("user") || "";
  const embed = params.get("embed") === "1";
  if (embed) document.body.classList.add("embedded");
  else renderNav("dashboard");
  const base = `teams/${enc(team)}`;
  const userQ = (path) => (viewUser ? `${path}${path.includes("?") ? "&" : "?"}user=${enc(viewUser)}` : path);
  const viewQS = viewUser ? `&user=${enc(viewUser)}${embed ? "&embed=1" : ""}` : "";
  const dashboardHref = viewUser ? `dashboard.html?${viewQS.slice(1)}` : "dashboard.html";
  const R = Agenti.run;

  if (!team) {
    document.querySelector("main").innerHTML =
      `<div class="empty-state"><p>No team named in the URL.</p>
       <a class="btn btn-primary" href="${dashboardHref}">Back to the dashboard</a></div>`;
    return;
  }

  const els = {
    avatar: document.getElementById("tm-avatar"),
    title: document.getElementById("tm-title"),
    meta: document.getElementById("tm-meta"),
    badge: document.getElementById("tm-badge"),
    banner: document.getElementById("tm-banner"),
    roster: document.getElementById("tm-roster"),
    consensus: document.getElementById("tm-consensus"),
    docLink: document.getElementById("tm-document-link"),
    openDoc: document.getElementById("tm-open-document"),
    controls: document.getElementById("tm-controls"),
    consoleStatus: document.getElementById("tm-console-status"),
    feed: document.getElementById("tm-feed"),
    chatForm: document.getElementById("tm-chat-form"),
    chatInput: document.getElementById("tm-chat-input"),
    sendBtn: document.getElementById("tm-send-btn"),
    noteBtn: document.getElementById("tm-note-btn"),
    msg: document.getElementById("tm-msg"),
  };

  els.avatar.innerHTML = Agenti.avatarInner(`team:${team}`, { initials: "TM" });
  els.title.textContent = viewUser ? `${viewUser}'s ${team}` : team;

  function say(kind, el, text) {
    el.hidden = false;
    el.className = kind === "err" ? "banner err show" : "banner ok show";
    el.textContent = text;
  }

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
  // On someone else's team an admin may only stop it or mark it complete.
  const may = (p) => perms.includes(p) && (!viewUser || p === "agent:stop");

  // ---------- controls (fan-out — every member, not just one) ----------
  els.controls.querySelectorAll("[data-action]").forEach((btn) => {
    const action = btn.dataset.action;
    const perm = { pause: "agent:pause", resume: "agent:resume", stop: "agent:stop",
                   acknowledge: "agent:stop" }[action];
    if (!may(perm)) { btn.hidden = true; return; }
    btn.addEventListener("click", async () => {
      if (action === "stop" &&
          !confirm(`Stop every member of '${team}'?\n\nEach one ends its current run and writes its own partial report.`)) return;
      if (action === "acknowledge" &&
          !confirm(`Mark '${team}' complete?\n\nAny member still running is stopped first (its own partial report is written), then the project is recorded as reviewed/done. This cannot be undone from here.`)) return;
      btn.disabled = true;
      try {
        if (action === "acknowledge") {
          const r = await Agenti.post(userQ(`${base}/acknowledge`));
          const stopped = r.stopped || [];
          say("ok", els.msg, `Marked complete by ${r.acknowledged_by}${stopped.length ? ` — stopped first: ${stopped.join(", ")}` : ""}.`);
          setTimeout(refresh, 1200);
          return;
        }
        const r = await Agenti.post(action === "stop" ? userQ(`${base}/stop`) : `${base}/${action}`);
        const n = (r.ok || []).length, f = (r.failed || []).length;
        const done = { stop: "stopped", pause: "paused", resume: "resumed" }[action];
        say(f ? "err" : "ok", els.msg, `${n} member${n === 1 ? "" : "s"} ${done}${f ? `, ${f} could not be` : ""}.`);
        setTimeout(refresh, 1200);
      } catch (e) {
        say("err", els.msg, Agenti.errorText(e));
      } finally {
        btn.disabled = false;
      }
    });
  });
  const shownControls = Array.from(els.controls.querySelectorAll("[data-action]")).filter((b) => !b.hidden);
  if (!shownControls.length) els.controls.hidden = true;

  // ---------- composer ----------
  async function send(kind) {
    const text = els.chatInput.value.trim();
    if (!text) return;
    els.sendBtn.disabled = true; els.noteBtn.disabled = true;
    try {
      await Agenti.post(`${base}/${kind === "note" ? "note" : "say"}`, { body: text });
      els.chatInput.value = "";
      say("ok", els.msg, kind === "note"
        ? "Note saved. The agents never see notes."
        : "Sent — every agent sees it after its next step.");
      setTimeout(refresh, 1500);
    } catch (e) {
      say("err", els.msg, Agenti.errorText(e));
    } finally {
      els.sendBtn.disabled = !may("agent:chat");
      els.noteBtn.disabled = !may("agent:note");
      els.chatInput.focus();
    }
  }
  if (viewUser) els.chatForm.hidden = true;   // nobody messages someone else's team
  if (!may("agent:chat")) { els.sendBtn.disabled = true; }
  if (!may("agent:note")) { els.noteBtn.disabled = true; }
  if (els.sendBtn.disabled && els.noteBtn.disabled) {
    els.chatForm.classList.add("is-disabled");
    els.chatInput.disabled = true;
    els.chatInput.placeholder = "You do not have permission to message this team.";
  }
  els.chatForm.addEventListener("submit", (e) => { e.preventDefault(); send("message"); });
  els.noteBtn.addEventListener("click", () => send("note"));

  // ---------- files ----------
  // A team's file goes to every member (stored once); members running now
  // get it at once and the team is told, the others when they next start.
  const filesPanel = document.getElementById("tm-files-panel");
  async function loadFiles() {
    try {
      const l = AgentiFiles.merge(await Agenti.get(userQ(`${base}/files`)));
      const n = AgentiFiles.render(document.getElementById("tm-files-body"), l, viewUser ? {} : {
        onRemove: async (name) => {
          try { await Agenti.del(`${base}/files/${encodeURIComponent(name)}`); }
          catch (e) { say("err", els.msg, Agenti.errorText(e)); }
          loadFiles();
        },
      });
      const run = (l.run || []).length, waiting = (l.pending || []).length;
      document.getElementById("tm-files-summary").textContent =
        [run && `${run} shared with the team`, waiting && `${waiting} waiting for the next start`].filter(Boolean).join(" · ");
      filesPanel.hidden = !n;
    } catch (e) { filesPanel.hidden = true; }
  }
  loadFiles();
  const attachBtn = document.getElementById("tm-attach-btn");
  if (viewUser || !may("agent:start")) attachBtn.hidden = true;
  else AgentiFiles.wireAttachButton(attachBtn, {
    path: () => `${base}/files`, say: (kind, text) => say(kind, els.msg, text),
    done: () => { loadFiles(); setTimeout(refresh, 1500); },
  });

  // ---------- colours, names, time ----------
  // One hue per member, in roster order. None of these sits near the accent
  // blue, which is the operator's own colour — "you" and "a member" must
  // never read alike. Eight is plenty; a ninth member wraps.
  const MEMBER_HUES = AgentiActivity.MEMBER_HUES;
  let hueOf = {};
  const hue = (agent) => (hueOf[agent] !== undefined ? hueOf[agent] : 215);
  const me = await Agenti.me().catch(() => ({}));
  // A channel author is "agent:<name>" for a member, a user name otherwise.
  function who(author) {
    const a = String(author || "?");
    return a.startsWith("agent:") ? { kind: "agent", name: a.slice(6) } : { kind: "operator", name: a };
  }
  // An operator's name in the channel can outlive the account (renamed or
  // deleted since) — an agent's own name is never a user, so this only
  // ever applies on the "operator" side of who().
  const userHistoryRows = await Agenti.userHistory();
  const wlabel = (w) => w.kind === "operator" ? Agenti.userLabel(w.name, userHistoryRows) : w.name;
  const clock = (ts) => {
    const d = new Date(Number(ts) * 1000);
    return isNaN(d) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  // "Show each agent's work": a per-viewer preference, so localStorage, same as
  // the theme. OFF by default — the chat is about what the team SAID to each
  // other; the work in between is one click away for whoever wants it.
  const THINK_KEY = "agenti-team-thinking";
  const thinkToggle = document.getElementById("tm-show-thinking");
  try { thinkToggle.checked = localStorage.getItem(THINK_KEY) === "on"; } catch (e) { /* default off */ }
  thinkToggle.addEventListener("change", () => {
    try { localStorage.setItem(THINK_KEY, thinkToggle.checked ? "on" : "off"); } catch (e) { /* no persistence */ }
    paint();
  });

  // ---------- roster + status + consensus ----------
  const memberBadge = (st) => (st ? R.badge(st) : ["incomplete", "Not started"]);

  // `pushed` is a snapshot the stream just delivered; without one (first
  // load, the fallback poll, the thinking toggle) the page reads it itself.
  async function paint(pushed) {
    let show, statusFan, consensus, inbox;
    if (pushed && pushed.show) {
      ({ show, status: statusFan, consensus, inbox } = pushed);
    } else {
      try {
        [show, statusFan, consensus, inbox] = await Promise.all([
          Agenti.get(userQ(base)),
          Agenti.get(userQ(`${base}/status`)),
          Agenti.get(userQ(`${base}/consensus`)),
          Agenti.get(userQ(`${base}/inbox?n=200`)),
        ]);
      } catch (err) {
        Agenti.banner(els.banner, "err", Agenti.errorText(err));
        return;
      }
    }

    // The roster: each member's task comes from the LATEST kickoff entry's own
    // structured fields, not a separate endpoint — every member's instructions
    // are built from this same entry.
    const kickoffs = (inbox || []).filter((e) => e.kind === "kickoff");
    const lastKickoff = kickoffs.length ? kickoffs[kickoffs.length - 1] : null;
    const roster = lastKickoff && lastKickoff.roster ? lastKickoff.roster : {};
    const details = lastKickoff && lastKickoff.details ? lastKickoff.details : {};

    const members = (show.members || []).map((m) => m.agent);
    hueOf = {};
    members.forEach((a, i) => { hueOf[a] = MEMBER_HUES[i % MEMBER_HUES.length]; });

    // shared/agenti's cmd_team_fanout pairs ok[i] with results[i] — only
    // members it actually reached appear in either array at all.
    const statusByAgent = {};
    const okList = statusFan.ok || [];
    (statusFan.results || []).forEach((r, i) => {
      if (okList[i]) statusByAgent[okList[i]] = r;
    });

    // Each member's own ledger, for the chat's "thinking" rows — only rows
    // since THIS project's kickoff, so an earlier solo run's narration never
    // reads as part of the team's work. A member the caller cannot read
    // simply contributes no thoughts; the channel still shows what it said.
    const sinceTs = lastKickoff ? Number(lastKickoff.ts || 0) - 1 : Infinity;
    const ledgers = {};
    if (thinkToggle.checked && isFinite(sinceTs)) {
      await Promise.all(members.map(async (a) => {
        try {
          ledgers[a] = await Agenti.get(userQ(`agents/${enc(a)}/findings?n=300&copy=team-${enc(team)}`));
        } catch (e) { ledgers[a] = []; }
      }));
    }

    // ---------- header badge: the WORST member state, roughly ----------
    const anyActive = members.some((a) => statusByAgent[a] && statusByAgent[a].state === "active");
    const anyNeedsInput = members.some((a) => {
      const l = (statusByAgent[a] || {}).live || {};
      return l.awaiting_operator && l.awaiting_operator.question;
    });
    let headCls, headLabel;
    if (show.acknowledged) { headCls = "completed"; headLabel = "Complete"; }
    else if (anyNeedsInput) { headCls = "warn-soft"; headLabel = "Needs input"; }
    else if (consensus.complete) { headCls = "completed"; headLabel = "Complete"; }
    else if (anyActive) { headCls = "running"; headLabel = "Running"; }
    else { headCls = "incomplete"; headLabel = "Idle"; }
    els.badge.innerHTML = `<span class="badge ${headCls}">${esc(headLabel)}</span>`;
    els.meta.textContent = `${members.length} member${members.length === 1 ? "" : "s"}` +
      (show.created_by ? ` · started by ${Agenti.userLabel(show.created_by, userHistoryRows)}` : "") +
      (show.fixed ? " · fixed membership" : "") +
      (show.acknowledged ? ` · marked complete by ${Agenti.userLabel(show.acknowledged_by, userHistoryRows)}` : "");

    // Once marked complete there is nothing left to control — only ADD to
    // hidden here, never remove: a button already hidden for lacking the
    // permission must stay hidden regardless of ack state.
    if (show.acknowledged) {
      els.controls.querySelectorAll("[data-action]").forEach((b) => { b.hidden = true; });
    }

    // ---------- roster panel (avatars in each member's chat colour) ----------
    els.roster.innerHTML = members.map((agent) => {
      const st = statusByAgent[agent];
      const [cls, label] = memberBadge(st);
      const d = details[agent] || {};
      const job = [d.title, d.target].filter(Boolean).join(" · ") || "No task recorded";
      const focus = d.role || roster[agent] || "";
      const href = `agent.html?agent=${enc(agent)}&copy=team-${enc(team)}${viewQS}`;
      const vote = (consensus.members || {})[agent];
      const voteNote = !vote ? "" : vote.voted && !vote.stale ? "Says the project is done"
        : vote.stale ? "Vote is out of date — something new came up" : "";
      return `<a class="member-row" href="${href}">
        <div class="chat-avatar" style="--hue:${hue(agent)};">${Agenti.avatarInner(agent, { hue: hue(agent) })}</div>
        <div class="member-main">
          <div class="member-name">${esc(agent)}</div>
          <div class="member-job">${esc(job)}</div>
          ${focus ? `<div class="member-focus">Focus: ${esc(focus)}</div>` : ""}
          ${voteNote ? `<div class="member-vote">${esc(voteNote)}</div>` : ""}
        </div>
        <span class="badge ${cls}">${esc(label)}</span>
      </a>`;
    }).join("") || `<p class="muted">No members.</p>`;

    // ---------- consensus panel ----------
    const votedCount = Object.values(consensus.members || {}).filter((m) => m.voted && !m.stale).length;
    const total = members.length;
    if (consensus.complete) {
      els.consensus.innerHTML = `<p class="hint" style="color:var(--ok);">
        <strong>Every member has agreed the project is complete.</strong>
        The team document is ready below.</p>`;
      els.docLink.hidden = false;
      els.openDoc.href = `report.html?team=${enc(team)}${viewQS}`;
    } else {
      els.consensus.innerHTML = `<p class="hint">${esc(votedCount)} of ${esc(total)} member(s) currently agree the project is complete.
        ${total && votedCount ? "The rest are still working, or something new has come up since a vote." : ""}</p>`;
      els.docLink.hidden = true;
    }

    // ---------- the group chat ----------
    renderChat(inbox || [], ledgers, sinceTs);
    els.consoleStatus.textContent = anyActive ? "● live" : consensus.complete ? "project complete" : "idle";
    els.consoleStatus.className = `console-status ${anyActive ? "running" : consensus.complete ? "completed" : ""}`;
  }

  // ---------- rendering the chat ----------
  // What the team SAID, in order: the kickoff as an opening card, messages as
  // bubbles (you on the right, each agent in its own colour, "→ name" when
  // addressed to someone), a "says the project is done" card for a vote, and a
  // quiet line when someone finishes. With "Show each agent's work" on, each
  // member's own narration and a one-line count of the steps it took are
  // interleaved by time. Never shown here, because the channel already holds
  // their canonical copy: a member's own team_message / propose_complete call,
  // and every operator:* row (a channel message being DELIVERED to a member).
  const AX = AgentiActivity;
  function renderChat(inbox, ledgers, sinceTs) {
    const atBottom = els.feed.scrollHeight - els.feed.scrollTop - els.feed.clientHeight < 80;
    const items = [];
    inbox.forEach((e) => items.push({ ts: Number(e.ts) || 0, seq: Number(e.id) || 0, channel: e }));
    Object.entries(ledgers).forEach(([agent, rows]) => (rows || []).forEach((r, i) => {
      const ts = Number(r.ts) || 0;
      if (ts < sinceTs) return;
      const tool = String(r.tool || "").replace(/^mcp__[a-z0-9_]+__/, "");
      if (tool.startsWith("operator:") || tool === "team_message" || tool === "propose_complete") return;
      if (tool === "ask_operator" && r.verdict !== "call") return;   // the question is the call; its result is plumbing
      items.push({ ts, seq: 1e9 + i, agent, tool, row: r });
    }));
    items.sort((a, b) => a.ts - b.ts || a.seq - b.seq);

    // An agent re-confirms its vote each time a teammate posts something new;
    // only its LATEST vote is worth a card — the earlier ones are the same
    // statement said again.
    const lastVote = {};
    inbox.forEach((e) => { if (e.kind === "vote_complete") lastVote[e.author] = Number(e.id); });
    let prev = null;      // consecutive messages by one author drop their header
    let steps = null;     // a run of tool rows by one member, folded into one line
    const out = [];
    const flushSteps = () => {
      if (!steps) return;
      const bad = steps.failed ? ` · ${steps.failed} failed` : "";
      out.push(`<div class="chat-steps${steps.failed ? " bad" : ""}" style="--hue:${hue(steps.agent)}"><span class="dot"></span>${esc(steps.agent)} ran ${steps.n} step${steps.n === 1 ? "" : "s"}${bad}</div>`);
      steps = null;
    };
    items.forEach((it) => {
      if (it.channel) {
        flushSteps();
        const e = it.channel;
        const w = who(e.author);
        if (e.kind === "kickoff") { prev = null; out.push(kickoffCard(e)); return; }
        if (e.kind === "vote_complete") {
          if (Number(e.id) === lastVote[e.author]) { prev = null; out.push(voteCard(w, e)); }
          return;
        }
        if (e.kind === "member_ended") {
          prev = null;
          const m = /\(status: ([^,)]+)/.exec(e.body || "");
          out.push(`<div class="chat-event">${esc(w.name)} finished${m ? ` (${esc(m[1])})` : ""}</div>`);
          return;
        }
        const side = w.kind === "agent" ? "agent" : "you";
        const note = e.kind === "note";
        const key = `${side}:${w.name}:${e.to || ""}`;
        const cont = !note && key === prev;
        prev = note ? null : key;
        out.push(bubble({
          side, h: side === "agent" ? hue(w.name) : null,
          name: side === "you" && w.name === me.user ? "you" : wlabel(w),
          initials: w.name, ts: e.ts, body: e.body, note, cont, to: e.to,
        }));
        return;
      }
      const r = it.row;
      if (it.tool === "agent:says") {
        flushSteps(); prev = null;
        out.push(bubble({ side: "agent", h: hue(it.agent), name: it.agent, initials: it.agent, ts: r.ts, body: r.summary, thought: true }));
        return;
      }
      if (it.tool === "ask_operator") {
        flushSteps(); prev = null;
        out.push(bubble({ side: "agent", h: hue(it.agent), name: it.agent, initials: it.agent, ts: r.ts, body: r.summary, ask: true }));
        return;
      }
      if (!steps || steps.agent !== it.agent) { flushSteps(); steps = { agent: it.agent, n: 0, failed: 0 }; }
      if (r.verdict === "call") steps.n += 1;
      else if (r.verdict === "error" || r.verdict === "denied") steps.failed += 1;
    });
    flushSteps();
    els.feed.innerHTML = out.join("") || `<p class="muted" style="margin:auto;">Nothing posted yet.</p>`;
    if (atBottom) els.feed.scrollTop = els.feed.scrollHeight;
  }

  function bubble(o) {
    const cls = ["chat-msg", o.side, o.cont ? "cont" : ""].filter(Boolean).join(" ");
    const bub = ["chat-bubble", "md", o.note ? "note" : "", o.thought ? "thought" : "", o.ask ? "ask" : ""].filter(Boolean).join(" ");
    const tag = o.note ? `<span class="chat-tag">note · the agents never see it</span>`
              : o.ask ? `<span class="chat-tag">asks you — paused until you reply</span>` : "";
    const to = o.to ? `<span class="chat-to">→ ${esc(o.to)}</span>` : "";
    const style = o.h !== null && o.h !== undefined ? ` style="--hue:${o.h}"` : "";
    return `<div class="${cls}"${style}>
      <div class="chat-avatar">${Agenti.avatarInner(String(o.initials || "?"), { hue: o.h })}</div>
      <div class="chat-body">
        <div class="chat-meta"><span class="chat-name">${esc(o.name)}</span>${to}<span class="chat-time">${esc(clock(o.ts))}</span>${tag}</div>
        <div class="${bub}">${AX.bodyHtml(o.body || "")}</div>
      </div></div>`;
  }

  // The project's opening card: who is on it and what each one is doing.
  function kickoffCard(e) {
    const d = e.details || {};
    const names = Object.keys(d).length ? Object.keys(d) : Object.keys(e.roster || {});
    const rows = names.map((a) => {
      const x = d[a] || {};
      const job = [x.title, x.target].filter(Boolean).join(" · ");
      return `<div class="kick-row" style="--hue:${hue(a)}"><span class="dot"></span><strong>${esc(a)}</strong>${job ? `<span>${esc(job)}</span>` : ""}</div>`;
    }).join("");
    return `<div class="chat-card kickoff"><div class="chat-card-title">Project started</div>${rows}</div>`;
  }
  function voteCard(w, e) {
    return `<div class="chat-card vote" style="--hue:${hue(w.name)}">
      <div class="chat-card-title">${esc(wlabel(w))} says the project is complete</div>
      <div class="md">${AX.bodyHtml(e.body || "")}</div></div>`;
  }

  async function refresh() { await paint(); }

  await paint();
  let painting = false;
  const live = Agenti.stream(`${base}/stream${viewUser ? `?user=${enc(viewUser)}` : ""}`, {
    team: async (snap) => {
      if (painting) return;   // a slow paint (it fetches ledgers) must not stack up
      painting = true;
      try { await paint(snap); } finally { painting = false; }
    },
    ended: (d) => { live.close(); liveEnded = true; Agenti.banner(els.banner, "err", d.reason || "This live feed ended — reload the page."); },
    error: () => { /* EventSource reconnects on its own */ },
  });
  let liveEnded = false;
  setInterval(() => { if (live.readyState !== 1 && !liveEnded) refresh(); }, TEAM_FALLBACK_POLL_MS);
});
