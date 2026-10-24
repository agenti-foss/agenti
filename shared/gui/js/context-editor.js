/* context-editor.js — one editor for the instruction files an agent reads
 * (system prompt, skills, organisation policy, a user's preferences).
 *
 *   AgentiContextEditor.mount(el, {
 *     url:        "admin/context/system-prompt?agent=enum"   // GET: current + history
 *     postUrl:    "admin/context/system-prompt",             // POST: save/reset/revert
 *     postExtra:  { agent: "enum" },                         // merged into every POST body
 *     title:      "System prompt",
 *     blurb:      "…one line on what this file does…",
 *     reauth:     true,        // admin files: every change needs the approval popup
 *     readOnly:   false,       // view only (an admin looking at a user's preferences)
 *     required:   false,       // the system prompt may not be emptied
 *   })
 *
 * The server decides everything that matters (who may edit, the size limit,
 * the re-authentication); this only draws the file, its history, and the three
 * actions, and says plainly what each one does.
 */
(function () {
  const A = Agenti;   // a top-level const in api.js, so not reachable as window.Agenti
  const esc = A.esc;
  const MAX = 20000;

  function when(ts) {
    if (!ts) return "";
    return new Date(ts * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }
  function byteLen(s) { return new TextEncoder().encode(s).length; }

  async function mount(el, opts) {
    el.innerHTML = `
      <div class="ctx-editor">
        <p class="hint ctx-blurb"></p>
        <div class="banner ctx-banner"></div>
        <div class="ctx-source muted"></div>
        <textarea class="ctx-text" rows="12" spellcheck="false" aria-label="${esc(opts.title)}"></textarea>
        <div class="ctx-meta"><span class="ctx-count muted"></span></div>
        <div class="ctx-actions" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
          <button type="button" class="btn btn-primary ctx-save" data-icon="check">Save</button>
          <button type="button" class="btn ctx-reset" data-icon="refresh" hidden></button>
        </div>
        <details class="disclosure ctx-history" style="margin-top:10px;">
          <summary><strong class="ih" data-icon="history" style="display:inline-flex;">History</strong> <span class="muted ctx-hist-count"></span></summary>
          <div class="list ctx-hist-list" style="margin-top:6px;"></div>
        </details>
        <details class="disclosure ctx-view" hidden style="margin-top:6px;" open>
          <summary><strong class="ctx-view-title"></strong></summary>
          <pre class="ctx-view-text" style="white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0;"></pre>
          <button type="button" class="btn btn-sm ctx-revert" data-icon="check">Make this the current version</button>
        </details>
      </div>`;
    const q = (c) => el.querySelector(c);
    const banner = q(".ctx-banner"), text = q(".ctx-text"), count = q(".ctx-count");
    const saveBtn = q(".ctx-save"), resetBtn = q(".ctx-reset");
    q(".ctx-blurb").textContent = opts.blurb || "";
    q(".ctx-blurb").hidden = !opts.blurb;
    let state = null, viewing = null;

    function describe() {
      return `${opts.title}${opts.where ? " — " + opts.where : ""}`;
    }

    async function change(body, what) {
      banner.className = "banner";
      const run = async (creds) => A.post(opts.postUrl, { ...(opts.postExtra || {}), ...body, ...(creds || {}) });
      try {
        if (opts.reauth) {
          const r = await A.requireApproval({
            title: "Approve this change",
            description: `${what} — ${describe()}.`,
            submit: (creds) => run({ password: creds.password || undefined, totp: creds.totp || undefined, reauth: creds.reauth }),
          });
          if (!r) return;      // cancelled
        } else {
          await run();
        }
        await load();
        A.banner(banner, "ok", "Saved.");
      } catch (err) {
        A.banner(banner, "err", A.errorText(err));
      }
    }

    function paint() {
      const d = state;
      text.value = d.text || "";
      text.readOnly = !!opts.readOnly;
      const src = { edited: "Edited copy", default: "Shipped default", none: "Not set" }[d.source] || d.source;
      q(".ctx-source").textContent = d.source === "none"
        ? (opts.required ? "Not set — required." : "Not set (optional).")
        : `${src}${d.sha256 ? " · version " + d.sha256.slice(0, 8) : ""}`;
      updateCount();
      saveBtn.hidden = !!opts.readOnly;
      resetBtn.hidden = !!opts.readOnly || d.source !== "edited";
      resetBtn.lastChild && resetBtn.lastChild.nodeType === 3 ? (resetBtn.lastChild.textContent = d.has_default ? "Restore default" : "Clear")
        : resetBtn.append(d.has_default ? "Restore default" : "Clear");
      const h = d.history || [];
      q(".ctx-hist-count").textContent = h.length ? `(${h.length})` : "(no edits yet)";
      q(".ctx-hist-list").innerHTML = h.length ? h.map((r) => `
        <div class="list-row">
          <div class="list-main"><div class="list-title">${esc(r.action[0].toUpperCase() + r.action.slice(1))} by ${esc(r.by)}</div>
            <div class="list-sub">${esc(when(r.ts))}${r.via === "api" ? " · web" : ""}${r.note ? " · " + esc(r.note) : ""}</div></div>
          ${r.replaced ? `<button type="button" class="btn btn-sm btn-icon" data-view="${esc(r.replaced)}" data-icon="eye" title="View what it replaced" aria-label="View what it replaced"></button>` : ""}
        </div>`).join("") : `<p class="hint">Every save keeps the previous version here.</p>`;
      q(".ctx-view").hidden = true; viewing = null;
      if (window.applyIcons) applyIcons(el);
    }
    function updateCount() {
      const n = byteLen(text.value);
      count.textContent = `${n.toLocaleString()} of ${MAX.toLocaleString()} bytes`;
      count.style.color = n > MAX ? "var(--danger, #c0392b)" : "";
      saveBtn.disabled = n > MAX;
    }

    async function load() {
      try {
        state = await A.get(opts.url);
        paint();
      } catch (err) {
        A.banner(banner, "err", A.errorText(err));
      }
    }

    {   // innerHTML was just replaced, so these are fresh elements: wire them every mount
      text.addEventListener("input", updateCount);
      saveBtn.addEventListener("click", () => {
        if (opts.required && !text.value.trim()) { A.banner(banner, "err", "The system prompt is required and cannot be empty."); return; }
        change({ change: "set", text: text.value }, "Save new text");
      });
      resetBtn.addEventListener("click", () => {
        const msg = state.has_default
          ? "Go back to the shipped default? Your edited copy is kept in the history."
          : "Clear this file? The current text is kept in the history.";
        if (confirm(msg)) change({ change: "reset", reset: true }, state.has_default ? "Go back to the shipped default" : "Clear this file");
      });
      q(".ctx-hist-list").addEventListener("click", async (e) => {
        const v = e.target.closest("[data-view]"); if (!v) return;
        try {
          const r = await A.get(`${opts.url}${opts.url.includes("?") ? "&" : "?"}version=${encodeURIComponent(v.dataset.view)}`);
          viewing = v.dataset.view;
          q(".ctx-view-title").textContent = "An earlier version";
          q(".ctx-view-text").textContent = r.version_text || "";
          q(".ctx-revert").hidden = !!opts.readOnly;
          q(".ctx-view").hidden = false; q(".ctx-view").open = true;
        } catch (err) { A.banner(banner, "err", A.errorText(err)); }
      });
      q(".ctx-revert").addEventListener("click", () => {
        if (viewing && confirm("Make this earlier version the current one? The current text is kept in the history."))
          change({ change: "revert", version: viewing }, "Restore an earlier version");
      });
    }
    await load();
  }
  window.AgentiContextEditor = { mount };
})();
