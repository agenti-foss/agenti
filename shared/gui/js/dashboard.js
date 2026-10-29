// dashboard.js — one user's dashboard: Active Agents, Task History, Outputs.
//
// Runs are private to the user who launched them (CLAUDE.md §4 item 71), so
// this page only ever shows ONE user's runs: your own, or — opened with
// ?user=<name>, normally inside the "<name>'s dashboard" pop-up in Settings →
// Users (?embed=1) — the user an admin is allowed to look at. Everything comes
// from one call, GET /dashboard[?user=], which also lists what this view may
// do (`actions`): your own dashboard can do everything; an admin's view of
// someone else's can stop a run and mark it complete, never launch or message.
//
//   Active Agents — a run slot that is running or paused, or whose latest run
//                   has finished and is not reviewed yet (it needs a decision).
//   Task History  — finished runs, and completed team projects.
//
// Live activity streams over SSE for up to MAX_LIVE_STREAMS running slots (a
// browser allows ~6 connections per origin, and this page shares them with the
// API it reads). The dashboard is re-read every SLOW_REFRESH_MS and redrawn
// when any slot's state changes.
const MAX_LIVE_STREAMS = 4;
const SLOW_REFRESH_MS = 8000;

document.addEventListener("DOMContentLoaded", async function () {
  const params = new URLSearchParams(location.search);
  const viewUser = params.get("user") || "";
  const embed = params.get("embed") === "1";
  if (embed) document.body.classList.add("embedded");
  else renderNav("dashboard");

  const esc = Agenti.esc;
  const enc = encodeURIComponent;
  const R = Agenti.run;
  const activeGrid = document.getElementById("active-agents-grid");
  const activeEmpty = document.getElementById("active-empty");
  const historyBody = document.getElementById("history-tbody");
  const historyEmpty = document.getElementById("history-empty");
  const historyFilter = document.getElementById("history-filter");
  const pageBanner = document.getElementById("page-banner");
  Agenti.showFlash(pageBanner);   // e.g. "Marked enum complete" from the agent page

  // Outputs may be opened (#outputs) before /dashboard answers; it waits on
  // this for whose files to show and whether they may be deleted here.
  let outputsReady;
  window.AgentiOutputs.configure(new Promise((r) => { outputsReady = r; }));

  // ---------- view switch (URL fragment: "" | #history | #outputs) ----------
  const viewActive = document.getElementById("view-active");
  const viewHistory = document.getElementById("view-history");
  const subHistory = document.getElementById("sub-history");
  const subOutputs = document.getElementById("sub-outputs");
  const historyFilterField = document.getElementById("history-filter-field");
  let lastSub = "history";   // the outer Task History tab returns to this
  function setActive(switchSel, attr, value) {
    document.querySelectorAll(`${switchSel} button`).forEach((b) => {
      const on = b.dataset[attr] === value;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
  }
  function showView(view) {
    const inHistory = view === "history" || view === "outputs";
    setActive("#view-switch", "view", inHistory ? "history" : "active");
    viewActive.hidden = inHistory;
    viewHistory.hidden = !inHistory;
    if (!inHistory) return;
    lastSub = view;
    setActive("#history-switch", "sub", view);
    subHistory.hidden = view !== "history";
    historyFilterField.hidden = view !== "history";
    subOutputs.hidden = view !== "outputs";
    if (view === "outputs") window.AgentiOutputs.open();
  }
  const viewFromHash = () =>
    location.hash === "#outputs" ? "outputs" : location.hash === "#history" ? "history" : "active";
  function go(view) {
    history.replaceState(null, "", view === "active" ? location.pathname + location.search : `#${view}`);
    showView(view);
  }
  document.getElementById("view-switch").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-view]");
    if (btn) go(btn.dataset.view === "history" ? lastSub : "active");
  });
  document.getElementById("history-switch").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-sub]");
    if (btn) go(btn.dataset.sub);
  });
  window.addEventListener("hashchange", () => showView(viewFromHash()));
  showView(viewFromHash());

  // ---------- load ----------
  const dashPath = viewUser ? `dashboard?user=${enc(viewUser)}` : "dashboard";
  let dash;
  try {
    dash = await Agenti.get(dashPath);
  } catch (err) {
    Agenti.banner(pageBanner, "err", Agenti.errorText(err));
    activeEmpty.hidden = true;
    outputsReady(null);
    return;
  }
  const can = (a) => (dash.actions || []).includes(a);
  outputsReady({ owner: dash.owner, user: viewUser, canDelete: can("outputs_delete") });
  // Every link from this view carries the view along, so an admin who opens
  // a run from someone's dashboard keeps looking at THEIR run, in the pop-up.
  const viewQS = viewUser ? `&user=${enc(viewUser)}${embed ? "&embed=1" : ""}` : "";
  function slotQuery(sl, extra) {
    const p = new URLSearchParams(extra || {});
    if (sl.copy) p.set("copy", sl.copy);
    if (viewUser) p.set("user", viewUser);
    const s = p.toString();
    return s ? `?${s}` : "";
  }
  const slotBase = (sl) => `agents/${enc(sl.agent)}`;
  const agentHref = (sl, runId) => `agent.html?agent=${enc(sl.agent)}`
    + (sl.copy ? `&copy=${enc(sl.copy)}` : "") + (runId ? `&run=${enc(runId)}` : "") + viewQS;
  const teamHref = (name) => `team.html?team=${enc(name)}` + viewQS;
  const userQ = viewUser ? `?user=${enc(viewUser)}` : "";

  // No Anthropic API key at any level: say so until one is saved. Closing it
  // hides it for this sign-in only (sessionStorage), so it comes back.
  const keyBanner = document.getElementById("key-banner");
  let keyHidden = false;
  try { keyHidden = sessionStorage.getItem("agenti-key-banner") === "closed"; } catch (e) { /* no storage */ }
  if (dash.api_key === "missing" && !viewUser && !keyHidden) {
    const me = await Agenti.me().catch(() => ({}));
    const admin = (me.permissions || []).includes("iam:manage");
    keyBanner.innerHTML = `<strong>No Anthropic API key yet: agents can't start.</strong> `
      + (admin ? `Add one in <a href="settings.html#platform">Settings → Platform</a>.`
               : `Ask an admin to add one (Settings → Platform).`)
      + `<button type="button" class="banner-close" aria-label="Dismiss">${Agenti.icon("close", 14) || "×"}</button>`;
    keyBanner.classList.add("show");
    keyBanner.querySelector(".banner-close").addEventListener("click", () => {
      keyBanner.classList.remove("show");
      try { sessionStorage.setItem("agenti-key-banner", "closed"); } catch (e) { /* still closes */ }
    });
  }

  if (dash.vault === "locked") {
    Agenti.banner(pageBanner, "err",
      "The vault is locked — no agent can run, and reports can't be read, until someone unlocks it on the host: sudo agenti vault unlock");
  } else if (dash.storage && dash.storage.encrypted === false) {
    // Decision 5 (audit run 1): runs work on an unencrypted disk, and every
    // dashboard says so, with the way to fix it.
    const me = await Agenti.me().catch(() => ({}));
    const admin = (me.permissions || []).includes("iam:manage");
    pageBanner.hidden = false;
    pageBanner.className = "banner warn show";
    pageBanner.innerHTML = `<strong>Data from agents is currently not encrypted.</strong> Reports, scans, attached files and the API key are stored as plain files on this server's disk. `
      + (admin ? `<a href="settings.html#platform">Turn on the vault</a> in Settings → Platform.`
               : `Ask an admin to turn on the vault (Settings → Platform).`);
  }

  // The agent catalogue: who may launch, and each agent's title — a card's
  // italic subtitle ("Hash cracker" under "amber-falcon").
  const cat = await Agenti.get("agents").catch(() => null);
  const agentTitles = Object.fromEntries(((cat && cat.agents) || []).map((a) => [a.name, a.title || a.name]));
  const agentTitle = (a) => agentTitles[a] || a;
  // Launch: only on your own dashboard, and only if an agent is installed.
  const canLaunch = can("launch") && !!(cat && (cat.agents || []).length);
  document.getElementById("launch-btn").hidden = !canLaunch;
  document.getElementById("launch-btn-empty").hidden = !canLaunch;
  const viewOnly = document.getElementById("view-only-note");
  viewOnly.hidden = !(can("launch") && !canLaunch);
  if (!viewOnly.hidden) {
    viewOnly.innerHTML = dash.note ? esc(dash.note)
      : `${Agenti.icon("eye")} <span>You don't have any agents you can launch yet — ask an admin for access.</span>`;
  }

  // ---------- small pieces ----------
  // A card's activity reads like the tail of the agent page's console
  // (activity.js): the agent's last message, with what it ran folded into
  // "Ran N steps". The server sends just that window (state.read_recent_activity).
  function newFeed(el) { return new AgentiActivity.Feed(el, { you: "You" }); }
  function fillFeed(feed, rows, empty, opts = {}) {
    feed.clear();
    (rows || []).forEach((f) => feed.add(f));
    if (!(rows || []).length) { feed.empty(empty); return; }
    if (opts.finished) feed.finish(opts.reportHref);
    feed.el.scrollTop = feed.el.scrollHeight;
  }
  // A question only the operator can answer outranks the last message: it sits
  // above the console, so it cannot be scrolled past.
  function paintAsk(box, live) {
    const q = live && live.awaiting_operator && live.awaiting_operator.question;
    box.hidden = !q;
    box.innerHTML = q
      ? `<div class="say ask"><div class="say-meta">Waiting on you — paused until you reply</div>
         <div class="say-body md">${AgentiActivity.bodyHtml(q)}</div></div>`
      : "";
  }
  function setBadge(el, [cls, word, full]) {
    el.className = `badge ${cls}`;
    el.textContent = word;
    el.title = full || word;
  }
  // Every start gets a generated label (run-1a2b3c4d): plumbing, not a name to
  // read. Two cards of one agent are told apart by their target and times; only
  // a label somebody chose themselves (a script's --copy) is shown.
  const isAutoCopy = (c) => /^run-[0-9a-f]{8}$/.test(c || "");
  const slotLabel = (sl) => sl.name ? sl.name
    : sl.copy && !sl.copy.startsWith("team-") && !isAutoCopy(sl.copy) ? `${sl.agent} · ${sl.copy}` : agentTitle(sl.agent);
  // The run's name, then what kind of agent it is, in italics. A run from
  // before names existed is called by its agent, with no subtitle to repeat it.
  const nameHtml = (sl) => `<div class="name">${esc(slotLabel(sl))}</div>`
    + (sl.name ? `<div class="run-kind">${esc(agentTitle(sl.agent))}</div>` : "");
  function slotMeta(sl, run) {
    const live = run || sl.live || {};
    return [
      R.target(sl.target || live.target) || "no target",
      live.turn !== undefined && !run ? `turn ${live.turn}` : null,
      live.findings_count !== undefined ? `${live.findings_count} findings` : null,
      run ? `ended ${Agenti.ago(run.ended)}` : sl.model || null,
    ].filter(Boolean).join(" · ");
  }
  function msgInto(el, cls, text) { el.hidden = false; el.className = `hint${cls ? " " + cls : ""}`; el.textContent = text; }

  // ---------- cards ----------
  const streams = [];
  window.addEventListener("beforeunload", () => streams.forEach((s) => s.close()));

  function cardHead(sl, badge, href, metaText, metaTitle, run) {
    // The tooltip carries the exact date behind a relative "ended 2 h ago".
    if (run && run.ended) metaTitle = `${metaTitle || metaText} · ended ${Agenti.when(run.ended)}`;
    return `<a class="open-link" href="${href}">
        <div class="agent-card-head">
          <div class="avatar">${Agenti.avatarInner(sl.agent)}</div>
          <div class="agent-card-title">
            ${nameHtml(sl)}
            <div class="meta" title="${esc(metaTitle || metaText)}">${esc(metaText)}</div>
          </div>
          <span class="badge ${badge[0]}" title="${esc(badge[2] || badge[1])}">${esc(badge[1])}</span>
        </div>
      </a>`;
  }

  function activeCard(sl, live) {
    const card = document.createElement("div");
    card.className = "agent-card" + (R.badge(sl)[0] === "running" ? " is-running" : "");
    const own = can("chat");
    // Your own run: message, note, interrupt. An admin's view of someone
    // else's: Stop only — they may end a run, never steer it.
    const controls = own ? `
      <form class="chatbox" data-chat>
        <input type="text" placeholder="Message or note…" aria-label="Message the agent">
        <div class="chat-actions">
          <button type="submit" class="btn btn-sm btn-primary compact" title="Send to the agent">${Agenti.icon("send", 14)}<span class="btn-label">Send</span></button>
          <button type="button" data-kind="note" class="btn btn-sm compact" title="Note — recorded, never reaches the model">${Agenti.icon("note", 14)}<span class="btn-label">Note</span></button>
          <button type="button" data-kind="interrupt" class="btn btn-sm btn-danger compact push-right" title="Interrupt — abort the step in flight and end the run (a partial report is still written)">${Agenti.icon("bolt", 14)}<span class="btn-label">Interrupt</span></button>
        </div>
      </form>`
      : can("stop") ? `<div class="chat-actions"><button type="button" class="btn btn-sm btn-danger" data-stop>${Agenti.icon("stop", 14)}<span>Stop this run</span></button></div>` : "";
    card.innerHTML = cardHead(sl, R.badge(sl), agentHref(sl), slotMeta(sl), sl.target) + `
      <div data-ask hidden></div>
      <div><p class="card-caption">Latest from the agent</p><div class="console activity card-console" data-feed></div></div>
      ${controls}
      <p class="hint" data-msg hidden></p>`;
    const feed = newFeed(card.querySelector("[data-feed]"));
    const askBox = card.querySelector("[data-ask]");
    const msg = card.querySelector("[data-msg]");
    fillFeed(feed, sl.recent, "No activity recorded yet.");
    paintAsk(askBox, sl.live);

    const post = (path, body, ok) => {
      msgInto(msg, "", "…");
      return Agenti.post(`${slotBase(sl)}/${path}${slotQuery(sl)}`, body)
        .then((r) => msgInto(msg, "", ok(r)))
        .catch((e) => msgInto(msg, "warn", Agenti.errorText(e)));
    };
    const form = card.querySelector("[data-chat]");
    if (form) {
      const input = form.querySelector("input");
      const send = (kind) => {
        const text = input.value.trim();
        if (!text) return;
        post(kind, { body: text }, () => {
          input.value = "";
          return kind === "note" ? "Note recorded — it never reaches the model."
            : "Sent — the agent sees it after the step it is on.";
        });
      };
      form.addEventListener("submit", (e) => { e.preventDefault(); send("say"); });
      form.querySelector('[data-kind="note"]').addEventListener("click", () => send("note"));
      form.querySelector('[data-kind="interrupt"]').addEventListener("click", () => {
        if (!confirm(`Interrupt ${slotLabel(sl)}?\n\nThe step in flight is aborted and the run ends. A partial report is still written, and you can resume it afterwards.`)) return;
        post("interrupt", {}, (r) => r.interrupted ? "Interrupt sent — the run is ending." : (r.note || "Nothing to interrupt."));
      });
    }
    const stopBtn = card.querySelector("[data-stop]");
    if (stopBtn) stopBtn.addEventListener("click", () => {
      if (!confirm(`Stop ${dash.owner}'s ${slotLabel(sl)} run?\n\nIt ends now and writes a partial report. ${dash.owner} sees it as stopped in their task history.`)) return;
      stopBtn.disabled = true;
      post("stop", {}, (r) => r.stopped ? "Stopped — a partial report was written." : (r.note || "It had already ended."))
        .finally(() => { stopBtn.disabled = false; });
    });

    if (live) {
      // Keep the card to the last message: when a new one arrives, repaint with
      // the steps that came since the previous message, then the message.
      let sinceSay = [];
      streams.push(Agenti.stream(`${slotBase(sl)}/stream${slotQuery(sl)}`, {
        reset: () => { feed.clear(); sinceSay = []; },
        finding: (f) => {
          if (String(f.tool) === "agent:says") {
            feed.clear();
            sinceSay.forEach((x) => feed.add(x));
            sinceSay = [];
            feed.add(f);
          } else {
            if (!String(f.tool).startsWith("operator:")) sinceSay.push(f);
            feed.add(f, { live: true });
          }
        },
        status: (s) => {
          setBadge(card.querySelector(".badge"), R.badge(s));
          card.classList.toggle("is-running", R.badge(s)[0] === "running");
          paintAsk(askBox, s);
          if (s.state !== "active") setTimeout(refresh, 1200);
        },
      }));
    }
    return card;
  }

  function reviewCard(sl, row, isLatest) {
    const card = document.createElement("div");
    card.className = "agent-card";
    const badge = [R.outcomeOf(row), R.statusWord(row.status, row.reason), R.statusFull(row.status, row.reason)];
    const mine = can("chat");
    card.innerHTML = cardHead(sl, badge, agentHref(sl, row.run_id), slotMeta(sl, row), row.target, row) + `
      <p class="hint">Finished — ${mine ? "waiting on your review." : `waiting on ${esc(dash.owner)}'s review.`}</p>
      <div><p class="card-caption">Latest from the agent</p><div class="console activity card-console" data-feed></div></div>
      <div class="chat-actions">
        <a class="btn btn-sm" href="${agentHref(sl, row.run_id)}">${Agenti.icon("open", 14)}<span>Open</span></a>
        ${mine && !viewUser ? AgentiSend.link({ agent: sl.agent, copy: sl.copy || "", style: "btn", label: "Send output", pre: row.report ? [`report:${row.report}`] : [] }) : ""}
        ${can("acknowledge") ? `<button type="button" class="btn btn-sm btn-primary" data-ack>${Agenti.icon("check", 14)}<span>Mark complete</span></button>` : ""}
      </div>
      <p class="hint" data-msg hidden></p>`;
    // sl.recent is the slot's CURRENT state.json feed — only means anything
    // for the latest run. An older unreviewed run (found live 2026-10-08: a
    // second run started in the same slot before the first was reviewed,
    // and the first's review prompt silently vanished from the dashboard —
    // only sl.history[0] was ever checked) has no live feed of its own here;
    // point at its report instead of showing the wrong run's activity.
    const rfeed = newFeed(card.querySelector("[data-feed]"));
    if (isLatest) {
      const rep = `report.html?agent=${enc(sl.agent)}` + (sl.copy ? `&copy=${enc(sl.copy)}` : "")
        + (row.report ? `&file=${enc(row.report)}` : "") + viewQS;
      fillFeed(rfeed, sl.recent, "No activity recorded.", { finished: true, reportHref: rep });
    } else {
      fillFeed(rfeed, [], "Open this run to see its findings.");
    }
    const btn = card.querySelector("[data-ack]");
    if (btn) btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await Agenti.post(`${slotBase(sl)}/acknowledge${slotQuery(sl)}`, { run_id: row.run_id });
        await refresh();
        Agenti.banner(pageBanner, "ok", `Marked ${slotLabel(sl)} complete — it's now in Task History.`);
        setTimeout(() => { if (pageBanner.classList.contains("ok")) pageBanner.className = "banner"; }, 6000);
      } catch (e) {
        msgInto(card.querySelector("[data-msg]"), "warn", Agenti.errorText(e));
        btn.disabled = false;
      }
    });
    return card;
  }

  // A team project: one card, members folded in. No SSE for a team — it is
  // repainted on the slow refresh. team.html is the real console.
  function teamCard(t, members) {
    const card = document.createElement("div");
    card.className = "agent-card team-card";
    card.innerHTML = `
      <a class="open-link" href="${teamHref(t.name)}">
        <div class="agent-card-head">
          <div class="avatar">${Agenti.avatarInner(`team:${t.name}`, { initials: "TM" })}</div>
          <div class="agent-card-title">
            <div class="name">${esc(t.name)}</div>
            <div class="meta" data-meta>team · loading…</div>
          </div>
          <span class="badge incomplete" data-badge>…</span>
        </div>
      </a>
      <div><p class="card-caption">Members</p><div class="team-members" data-members></div></div>
      <div><p class="card-caption">Latest in the chat</p><div class="console activity card-console" data-feed></div></div>`;
    const base = `teams/${enc(t.name)}`;
    Promise.all([Agenti.get(`${base}/consensus${userQ}`),
                 Agenti.get(`${base}/inbox${viewUser ? `?user=${enc(viewUser)}&` : "?"}n=12`).catch(() => [])])
      .then(([consensus, inbox]) => {
        const votes = consensus.members || {};
        const names = Object.keys(votes).length ? Object.keys(votes) : (t.members || []).map((m) => m.agent);
        const bySlot = Object.fromEntries(members.map((m) => [m.agent, m]));
        const anyNeeds = members.some((m) => R.badge(m)[1] === "Needs input");
        const anyActive = members.some((m) => m.state === "active");
        const voted = Object.values(votes).filter((v) => v.voted && !v.stale).length;
        setBadge(card.querySelector("[data-badge]"),
          anyNeeds ? ["warn-soft", "Needs input"] : consensus.complete ? ["completed", "Complete"]
          : anyActive ? ["running", "Running"] : ["incomplete", "Idle"]);
        card.querySelector("[data-meta]").textContent = `team of ${names.length} · ${voted}/${names.length} voted complete`;
        card.querySelector("[data-members]").innerHTML = names.map((a) => {
          const sl = bySlot[a];
          const [c, l, full] = sl ? R.badge(sl) : ["incomplete", "Not started", "not started"];
          const v = votes[a] || {};
          const note = v.ended ? "finished" : v.voted && !v.stale ? "voted complete" : v.stale ? "vote is stale" : "";
          const href = sl ? agentHref(sl) : teamHref(t.name);
          return `<a class="team-member" href="${href}" title="${esc(full || l)}">
            <span class="avatar avatar-sm">${Agenti.avatarInner(a)}</span>
            <span class="team-member-name">${esc(a)}${note ? `<small>${esc(note)}</small>` : ""}</span>
            <span class="badge ${c}">${esc(l)}</span></a>`;
        }).join("") || `<p class="muted" style="margin:0;">No members.</p>`;
        const feed = card.querySelector("[data-feed]");
        // Only the last thing said, in its speaker's own colour (the same hue
        // the team page gives them). No ids, no bookkeeping entries, and no
        // Markdown symbols are lost: the message renders as on the team page.
        const roster = (t.members || []).map((m) => m.agent);
        const hueOf = (a) => AgentiActivity.MEMBER_HUES[Math.max(0, roster.indexOf(a)) % AgentiActivity.MEMBER_HUES.length];
        const last = (inbox || []).filter((e) => e.kind === "message" || e.kind === "vote_complete").slice(-1)[0];
        if (!last) {
          feed.innerHTML = `<div class="act-empty">Nothing said yet.</div>`;
        } else {
          const who = String(last.author || "?").replace(/^agent:/, "");
          const isAgentMsg = String(last.author || "").startsWith("agent:");
          const meta = last.kind === "vote_complete" ? `${who} says the project is complete`
            : `${who}${last.to ? ` → ${last.to}` : ""}`;
          feed.innerHTML = `<div class="say team-last${last.kind === "vote_complete" ? " vote" : ""}" style="--hue:${isAgentMsg ? hueOf(who) : 215}">
            <div class="say-meta">${esc(meta)}</div>
            <div class="say-body md clamped">${AgentiActivity.bodyHtml(last.body)}</div></div>`;
        }
      })
      .catch((e) => { card.querySelector("[data-meta]").textContent = Agenti.errorText(e); });
    return card;
  }

  // ---------- render ----------
  let historyRows = [];
  let signature = "";
  const sig = (d) => JSON.stringify([
    // Every unacknowledged run_id, not just history[0] — otherwise marking
    // an OLDER run complete (its review card is still on this page) never
    // changes history[0]'s own id/ack state, so a poll tick would see no
    // difference and leave the just-acknowledged card on screen.
    d.slots.map((s) => [s.slot, s.state, s.freezer,
                        s.history.filter((r) => !r.acknowledged).map((r) => r.run_id).join(","),
                        !!(s.live.awaiting_operator && s.live.awaiting_operator.question)]),
    d.teams.map((t) => [t.name, !!t.acknowledged]),
  ]);

  // ---------- Active Agents order ----------
  // Newest launch first unless the viewer picks otherwise; the choice is a
  // per-browser convenience, so it lives in localStorage (and a browser that
  // refuses storage just gets the default).
  const sortSel = document.getElementById("active-sort");
  const SORTS = {
    newest: (a, b) => b.started - a.started,
    oldest: (a, b) => a.started - b.started,
    attention: (a, b) => a.rank - b.rank || b.started - a.started,
    agent: (a, b) => a.kind.localeCompare(b.kind) || b.started - a.started,
    name: (a, b) => a.name.localeCompare(b.name) || b.started - a.started,
  };
  try { const v = localStorage.getItem("agenti.activeSort"); if (v && SORTS[v]) sortSel.value = v; } catch (e) { /* default */ }
  sortSel.addEventListener("change", () => {
    try { localStorage.setItem("agenti.activeSort", sortSel.value); } catch (e) { /* not kept */ }
    orderCards();
  });
  // What a card is sorted by, stamped on it when it is built.
  //   rank: needs you (a question, or a finished run to review) before running, before paused.
  function stamp(card, { started, kind, name, rank }) {
    Object.assign(card.dataset, { started: started || 0, kind: kind || "", name: name || "", rank });
    return card;
  }
  function orderCards() {
    const cards = Array.from(activeGrid.children).filter((c) => c.dataset.rank !== undefined);
    const key = (c) => ({ started: +c.dataset.started, kind: c.dataset.kind, name: c.dataset.name, rank: +c.dataset.rank });
    cards.sort((x, y) => (SORTS[sortSel.value] || SORTS.newest)(key(x), key(y)));
    cards.forEach((c) => activeGrid.appendChild(c));
    document.getElementById("active-toolbar").hidden = cards.length < 2;
  }
  const rankOf = (sl) => {
    const [cls] = R.badge(sl);
    return cls === "warn-soft" ? 0 : cls === "running" ? 2 : 3;
  };

  function render() {
    streams.splice(0).forEach((s) => s.close());
    activeGrid.innerHTML = "";
    historyRows = [];
    signature = sig(dash);
    const openTeams = dash.teams.filter((t) => !t.acknowledged);
    const membersOf = {};
    dash.teams.filter((t) => t.acknowledged).forEach((t) => historyRows.push({
      team: t.name, label: `team · ${t.name}`, target: "", status: "completed", reason: null,
      findings_count: null, ended: t.acknowledged_at || t.created_at || 0,
      acknowledged: true, acknowledged_by: t.acknowledged_by || "?",
    }));
    let liveCount = 0;
    dash.slots.forEach((sl) => {
      const active = sl.state === "active";
      if (sl.team && openTeams.some((t) => t.name === sl.team)) {
        (membersOf[sl.team] = membersOf[sl.team] || []).push(sl);
      } else if (active) {
        activeGrid.appendChild(stamp(activeCard(sl, liveCount++ < MAX_LIVE_STREAMS),
          { started: (sl.live || {}).started, kind: agentTitle(sl.agent), name: slotLabel(sl), rank: rankOf(sl) }));
      }
      // EVERY unacknowledged finished run asks for review. A start now gets
      // its own slot, so a slot normally holds one run; an older slot (made
      // before that) may hold several, and none of them may silently drop off
      // the operator's radar before being marked complete (found live
      // 2026-10-08: "it replaced the run in the dashboard without me marking
      // it complete").
      const latest = sl.history[0];
      const unreviewed = active || sl.team ? [] : sl.history.filter((r) => !r.acknowledged);
      unreviewed.forEach((row) => activeGrid.appendChild(stamp(reviewCard(sl, row, row === latest),
        { started: row.started, kind: agentTitle(sl.agent), name: slotLabel(sl), rank: 1 })));
      sl.history.forEach((row) => {
        if (unreviewed.includes(row)) return;
        historyRows.push({ ...row, slot: sl,
          label: sl.team ? `${agentTitle(sl.agent)} · team ${sl.team}` : slotLabel(sl),
          kind: sl.name && !sl.team ? agentTitle(sl.agent) : "" });
      });
    });
    openTeams.forEach((t) => activeGrid.appendChild(stamp(teamCard(t, membersOf[t.name] || []),
      { started: t.created_at, kind: "team", name: t.name,
        rank: (membersOf[t.name] || []).some((m) => m.state === "active") ? 2 : 3 })));
    orderCards();
    activeEmpty.hidden = activeGrid.children.length > 0;
    if (!activeEmpty.hidden && !can("chat")) {
      activeEmpty.querySelector("h3").textContent = `Nothing running for ${dash.owner}`;
      activeEmpty.querySelector("p").textContent = "Their runs appear here while they're working, and stay until they've been reviewed.";
    }
    renderHistory();
  }

  async function refresh() {
    try {
      const next = await Agenti.get(dashPath);
      const changed = sig(next) !== signature;
      dash = next;
      if (changed) render();
    } catch (e) { /* keep showing what we have; the next tick retries */ }
  }

  // ---------- Task History ----------
  let sortKey = "ended", sortDir = -1;
  function renderHistory() {
    const filterVal = historyFilter.value;
    let rows = historyRows.slice();
    if (filterVal) rows = rows.filter((r) => R.outcomeOf(r) === filterVal);
    rows.sort((a, b) => {
      const av = sortKey === "agent" ? a.label : a[sortKey];
      const bv = sortKey === "agent" ? b.label : b[sortKey];
      return av === bv ? 0 : (av < bv ? -1 : 1) * sortDir;
    });
    historyEmpty.hidden = rows.length > 0;
    historyBody.innerHTML = rows.map((r) => {
      const href = r.team ? teamHref(r.team) : agentHref(r.slot, r.run_id);
      const openLabel = r.team ? "Open this project" : "Open this run";
      const who = r.acknowledged_by === dash.viewer && dash.viewer !== dash.owner ? "you" : r.acknowledged_by;
      return `<tr>
        <td>${esc(r.label)}${r.kind ? `<div class="run-kind">${esc(r.kind)}</div>` : ""}</td>
        <td title="${esc(r.target || "")}">${esc(R.target(r.target) || "—")}</td>
        <td><span class="badge ${R.outcomeOf(r)}" title="${esc(R.statusFull(r.status, r.reason))}">${esc(R.statusWord(r.status, r.reason))}</span></td>
        <td>${r.findings_count === null || r.findings_count === undefined ? "—" : esc(r.findings_count)}</td>
        <td>${esc(Agenti.when(r.ended))}</td>
        <td class="actions">${r.acknowledged ? `<span class="muted">reviewed by ${esc(who || "?")}</span> ` : `<span class="muted">not reviewed</span> `}${r.slot && !viewUser && can("chat") ? AgentiSend.link({ agent: r.slot.agent, copy: r.slot.copy || "", style: "icon",
          pre: r.report ? [`report:${r.report}`] : [] }) + " " : ""}<a class="btn btn-sm btn-icon" href="${href}" title="${esc(openLabel)}" aria-label="${esc(openLabel)}">${Agenti.icon("open", 15)}</a></td>
      </tr>`;
    }).join("");
  }
  document.getElementById("history-table").querySelectorAll("button.sort").forEach((b) => {
    b.addEventListener("click", () => {
      sortDir = sortKey === b.dataset.key ? -sortDir : -1;
      sortKey = b.dataset.key;
      renderHistory();
    });
  });
  historyFilter.addEventListener("change", renderHistory);

  render();
  setInterval(refresh, SLOW_REFRESH_MS);
});
