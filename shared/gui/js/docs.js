// docs.js — the Docs page: every help page listed as on agenti-foss.org/docs,
// one page at a time, and a search across all of them as you type.
//
// GET /docs, /docs/{page} and /docs/search all shell to `agenti docs`, so the
// list, the page and the ranking are exactly what the host's CLI prints.
// URL: ?page=<slug> opens a page, &hl=<words> highlights them, #<anchor> is a
// section, ?search=<words> restores the search box (kept current while
// typing, so Back from a result returns to the results).
document.addEventListener("DOMContentLoaded", () => {
  const esc = Agenti.esc;
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const slug = params.get("page") || "";
  const input = $("docs-q");
  const list = $("docs-list");
  const results = $("docs-results");
  const status = $("docs-status");
  const view = $("docs-view");
  const article = $("docs-article");
  const banner = $("docs-banner");
  const hlBar = $("docs-hl");
  const MIN_CHARS = 2;

  // The back link must exist before renderNav, which mirrors it into the bar.
  if (slug) {
    $("docs-head").hidden = true;
    list.hidden = true;
    document.querySelector("main").insertAdjacentHTML("afterbegin",
      `<a class="back-link" href="docs.html"><svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 3 5 8l5 5"/></svg>All docs</a>`);
  }
  renderNav("docs");

  const icon = (name, size) => Agenti.icon(name, size) || Agenti.icon("book", size);
  const pageHref = (page, terms, anchor) =>
    `docs.html?page=${encodeURIComponent(page)}${terms ? `&hl=${encodeURIComponent(terms)}` : ""}${anchor ? `#${encodeURIComponent(anchor)}` : ""}`;
  const showError = (e) => Agenti.banner(banner, "err", Agenti.errorText(e));
  const clearError = () => { banner.hidden = true; banner.className = "banner err"; };

  // ---- highlighting: text nodes only, so nothing typed becomes markup ----
  const escRx = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  function termsOf(text) {
    const out = [];
    for (const w of String(text || "").toLowerCase().split(/\s+/)) {
      const t = w.replace(/^[.,;:!?"'()[\]{}<>]+|[.,;:!?"'()[\]{}<>]+$/g, "");
      if (t && !out.includes(t)) out.push(t);
    }
    return out.slice(0, 8).sort((a, b) => b.length - a.length);
  }
  function markTerms(root, terms) {
    if (!terms.length) return 0;
    const rx = new RegExp(terms.map(escRx).join("|"), "gi");
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    let count = 0;
    for (const node of nodes) {
      const s = node.nodeValue;
      rx.lastIndex = 0;
      if (!rx.test(s)) continue;
      rx.lastIndex = 0;
      const frag = document.createDocumentFragment();
      let pos = 0; let m;
      while ((m = rx.exec(s)) !== null) {
        if (m.index > pos) frag.append(s.slice(pos, m.index));
        const mark = document.createElement("mark");
        mark.className = "docs-mark";
        mark.textContent = m[0];
        frag.append(mark);
        count++;
        pos = m.index + m[0].length;
      }
      if (pos < s.length) frag.append(s.slice(pos));
      node.replaceWith(frag);
    }
    return count;
  }
  function unmark(root) {
    root.querySelectorAll("mark.docs-mark").forEach((m) => m.replaceWith(m.textContent));
    root.normalize();
  }

  // ---- the list -----------------------------------------------------------
  async function loadList() {
    try {
      const d = await Agenti.get("docs");
      list.innerHTML = d.pages.length ? d.pages.map((p) => `
        <a class="list-row docs-row" href="${pageHref(p.page)}">
          <span class="list-icon">${icon(p.icon, 16)}</span>
          <div class="list-main">
            <div class="list-title">${esc(p.title)}</div>
            ${p.summary ? `<div class="list-sub">${esc(p.summary)}</div>` : ""}
          </div>
          <span class="docs-chev">${Agenti.icon("chevron-right", 14)}</span>
        </a>`).join("") : `<p class="list-empty">No help pages are installed. On the host: sudo apt install --reinstall agenti</p>`;
    } catch (e) {
      list.innerHTML = "";
      showError(e);
    }
  }

  // ---- one page -------------------------------------------------------------
  async function loadPage(name) {
    try {
      const d = await Agenti.get(`docs/${encodeURIComponent(name)}`);
      document.title = `${d.title} — Agenti`;
      // Anchors come from the CLI (one slug rule, shared with search results),
      // matched to the rendered headings by their text, in order.
      const queue = (d.headings || []).slice();
      const headingId = (text) => {
        const i = queue.findIndex((h) => h.text === text);
        return i < 0 ? "" : (queue.splice(i, 1)[0].anchor || "");
      };
      const docLink = (href) => {
        const m = /^([a-z0-9][a-z0-9-]{0,63})\.md(#[a-z0-9-]+)?$/.exec(href);
        return m ? `docs.html?page=${m[1]}${m[2] || ""}` : "";
      };
      article.innerHTML = AgentiMarkdown.render(d.markdown, { docLink, headingId });
      view.hidden = !results.hidden;
      highlight(termsOf(params.get("hl")));
      scrollToTarget();
    } catch (e) {
      showError(e);
    }
  }

  function highlight(terms) {
    const n = markTerms(article, terms);
    if (!n) { hlBar.hidden = true; return; }
    $("docs-hl-text").innerHTML = `Highlighting <strong>${esc(terms.join(" "))}</strong> · ${n} ${n === 1 ? "match" : "matches"}`;
    hlBar.hidden = false;
  }
  $("docs-hl-clear").addEventListener("click", () => {
    unmark(article);
    hlBar.hidden = true;
    const u = new URL(location.href);
    u.searchParams.delete("hl");
    history.replaceState(null, "", u.pathname + u.search + u.hash);
  });

  function scrollToTarget() {
    const id = decodeURIComponent(location.hash.slice(1));
    const target = id ? document.getElementById(id) : null;
    const el = target || article.querySelector("mark.docs-mark");
    if (!el) return;
    requestAnimationFrame(() => {
      el.scrollIntoView({ block: target ? "start" : "center" });
      if (target) {
        target.classList.add("docs-target");
        setTimeout(() => target.classList.remove("docs-target"), 1800);
      }
    });
  }

  // ---- search ---------------------------------------------------------------
  let seq = 0;
  let timer = 0;
  let pending = null;

  function setSearching(on) {
    results.hidden = !on;
    if (slug) view.hidden = on || !article.innerHTML;
    else list.hidden = on;
    if (!on) { status.textContent = ""; status.classList.remove("sr-only"); results.innerHTML = ""; }
  }

  function syncUrl(q) {
    const u = new URL(location.href);
    if (q.length >= MIN_CHARS) u.searchParams.set("search", q); else u.searchParams.delete("search");
    history.replaceState(null, "", u.pathname + u.search + u.hash);
  }

  function runSearch(q) {
    const my = ++seq;
    const slow = setTimeout(() => { if (my === seq) status.textContent = "Searching…"; }, 300);
    pending = Agenti.get(`docs/search?q=${encodeURIComponent(q)}`).then((d) => {
      if (my === seq) showResults(d);
    }).catch((e) => {
      if (my !== seq) return;
      setSearching(true);
      status.textContent = "";
      showError(e);
    }).finally(() => { clearTimeout(slow); if (my === seq) pending = null; });
    return pending;
  }

  function showResults(d) {
    clearError();
    setSearching(true);
    const quoted = `“${d.query}”`;
    if (!d.results.length) {
      status.textContent = `No matches for ${quoted}`;
      status.classList.add("sr-only");
      results.className = "docs-results";
      results.innerHTML = `<div class="empty-state docs-empty">
          <div class="empty-icon">${Agenti.icon("search", 20)}</div>
          <h3>No matches for ${esc(quoted)}</h3>
          <p>A section has to contain every word you typed. Try fewer or different words.</p>
        </div>`;
      return;
    }
    status.classList.remove("sr-only");
    status.textContent = `${d.count} ${d.count === 1 ? "result" : "results"} for ${quoted}`;
    const terms = d.terms.join(" ");
    results.className = "list docs-results";
    results.innerHTML = d.results.map((r) => `
      <a class="list-row docs-hit" href="${pageHref(r.page, terms, r.anchor)}">
        <span class="list-icon">${icon(r.icon, 16)}</span>
        <div class="list-main">
          <div class="list-title">${esc(r.title)}${r.heading ? `<span class="docs-crumb">${Agenti.icon("chevron-right", 12)}${esc(r.heading)}</span>` : ""}</div>
          <div class="list-sub docs-snippet"></div>
        </div>
      </a>`).join("");
    const hl = termsOf(terms);
    results.querySelectorAll(".docs-snippet").forEach((el, i) => {
      el.textContent = d.results[i].snippet;
      markTerms(el, hl);
    });
  }

  const clearBtn = $("docs-clear");
  clearBtn.addEventListener("click", () => {
    input.value = "";
    input.dispatchEvent(new Event("input"));
    input.focus();
  });

  input.addEventListener("input", () => {
    clearTimeout(timer);
    clearBtn.hidden = !input.value;
    const q = input.value.trim();
    syncUrl(q);
    if (q.length < MIN_CHARS) { seq++; pending = null; clearError(); setSearching(false); return; }
    timer = setTimeout(() => runSearch(q), 160);
  });

  $("docs-search").addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (q.length < MIN_CHARS) return;
    if (timer) { clearTimeout(timer); timer = 0; await runSearch(q); }
    else if (pending) await pending;
    const first = results.querySelector("a.docs-hit");
    if (first && !results.hidden) location.href = first.href;
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (input.value) {
        e.preventDefault();
        input.value = "";
        input.dispatchEvent(new Event("input"));
      } else input.blur();
    } else if (e.key === "ArrowDown") {
      const first = results.hidden ? null : results.querySelector("a.docs-hit");
      if (first) { e.preventDefault(); first.focus(); }
    }
  });

  results.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const hits = [...results.querySelectorAll("a.docs-hit")];
    const i = hits.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    if (e.key === "ArrowDown") (hits[i + 1] || hits[i]).focus();
    else (i === 0 ? input : hits[i - 1]).focus();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.closest && e.target.closest("input, textarea, select, [contenteditable]")) return;
    e.preventDefault();
    input.focus();
    input.select();
  });

  // ---- start ----------------------------------------------------------------
  if (slug) loadPage(slug); else loadList();
  const initial = (params.get("search") || "").trim();
  if (initial.length >= MIN_CHARS) {
    input.value = initial;
    clearBtn.hidden = false;
    runSearch(initial);
  }
});
