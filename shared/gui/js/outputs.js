// outputs.js — the Outputs sub-view of the dashboard's Task History tab: the
// files one user has kept (decision 8's permanent store) and the two-level
// quota. Kept files are private like runs (CLAUDE.md §4 item 71): this shows
// the dashboard's own user — you, or the user an admin is looking at.
//
//   GET    /outputs[?user=]                    list + quota
//   GET    /outputs/{owner}/{name}             download (<a download>;
//                                                       the cookie rides along)
//   DELETE /outputs/{owner}/{name}             delete one
//   POST   /outputs/{owner}/delete {names}     delete several
//
// dashboard.js calls configure() with a promise of {owner, user,
// canDelete} once /dashboard answers, and open() each time the sub-view is
// shown. Nothing is fetched until the sub-view is first opened.

window.AgentiOutputs = (function () {
  let config = Promise.resolve(null);
  let ready = null;
  let load = async () => {};
  return {
    configure(p) { config = p; },
    open() {
      if (!ready) ready = setup();
      return ready.then(() => load());
    },
  };

  async function setup() {
    const esc = Agenti.esc;
    const enc = encodeURIComponent;
    const banner = document.getElementById("outputs-banner");
    const usageKv = document.getElementById("usage-kv");
    const tbody = document.getElementById("outputs-tbody");
    const tableWrap = document.getElementById("outputs-table-wrap");
    const empty = document.getElementById("outputs-empty");
    const selectAll = document.getElementById("outputs-select-all");
    const bulkbar = document.getElementById("outputs-bulkbar");
    const selectedCount = document.getElementById("outputs-selected-count");
    const deleteSelectedBtn = document.getElementById("outputs-delete-selected");
    let selected = new Set();   // file names; cleared on every reload

    const cfg = await config;
    if (!cfg) {
      Agenti.banner(banner, "err", "Your dashboard could not be loaded, so kept files can't be shown either.");
      return;
    }
    const base = `outputs/${enc(cfg.owner)}`;
    const mine = !cfg.user;
    const whose = mine ? "your" : `${cfg.owner}'s`;

    function humanBytes(n) {
      n = Number(n) || 0;
      const units = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
      return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
    }
    // A bar, not a sentence: a filled track answers "how full" at a glance.
    function quotaMeter(label, used, limit, note) {
      const pct = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
      const state = !limit ? "" : used >= limit ? "over" : used >= limit * 0.9 ? "warn" : "";
      const chip = state === "over" ? ' <span class="badge failed">full</span>'
                 : state === "warn" ? ' <span class="badge warn-soft">nearing limit</span>' : "";
      return `<div class="meter-row">
        <div class="meter-label">
          <span class="meter-name">${esc(label)}${chip}</span>
          <span class="meter-value">${humanBytes(used)} of ${humanBytes(limit)} &middot; ${pct}%</span>
        </div>
        <div class="meter ${state}"><span style="width:${pct}%"></span></div>
        ${note ? `<p class="hint" style="margin:0;">${esc(note)}</p>` : ""}
      </div>`;
    }

    load = async function () {
      banner.className = "banner";
      let r;
      try {
        r = await Agenti.get(`outputs${cfg.user ? `?user=${enc(cfg.user)}` : ""}`);
      } catch (err) {
        Agenti.banner(banner, "err", Agenti.errorText(err));
        usageKv.innerHTML = ""; tbody.innerHTML = ""; empty.hidden = true; tableWrap.hidden = true;
        return;
      }
      usageKv.innerHTML =
        quotaMeter("Organisation total", r.total_used, r.total_limit,
                   "Everything everyone in the organisation has kept.") +
        quotaMeter(mine ? "Your own share" : `${cfg.owner}'s share`, r.operator_used, r.operator_limit,
                   `What ${mine ? "you have" : `${cfg.owner} has`} kept. A new run is refused when either bar is full.`);
      const rows = r.outputs || [];
      empty.hidden = rows.length !== 0;
      tableWrap.hidden = rows.length === 0;
      selected = new Set();
      tbody.innerHTML = rows.map((o) => `<tr>
          <td>${cfg.canDelete ? `<input type="checkbox" class="row-select" data-name="${esc(o.name)}" style="width:auto;" aria-label="Select ${esc(o.name)}">` : ""}</td>
          <td>${esc(o.name)}</td>
          <td>${esc(humanBytes(o.bytes))}</td>
          <td>${esc(Agenti.when(o.promoted_at))}</td>
          <td class="actions">
            <a class="btn btn-sm btn-icon" href="${base}/${enc(o.name)}" download="${esc(o.name)}" title="Download ${esc(o.name)}" aria-label="Download ${esc(o.name)}">${Agenti.icon("download", 15)}</a>
            ${cfg.canDelete ? `<button type="button" class="btn btn-sm btn-icon btn-danger" data-delete="${esc(o.name)}" title="Delete ${esc(o.name)}" aria-label="Delete ${esc(o.name)}">${Agenti.icon("trash", 15)}</button>` : ""}
          </td>
        </tr>`).join("");
      selectAll.checked = false;
      selectAll.hidden = !cfg.canDelete || rows.length === 0;
      syncBulkbar();
    };

    function syncBulkbar() {
      bulkbar.hidden = selected.size === 0;
      selectedCount.textContent = selected.size === 1 ? "1 file selected" : `${selected.size} files selected`;
    }
    tbody.addEventListener("change", (e) => {
      const box = e.target.closest("input.row-select");
      if (!box) return;
      if (box.checked) selected.add(box.dataset.name); else selected.delete(box.dataset.name);
      selectAll.checked = selected.size > 0 && selected.size === tbody.querySelectorAll("input.row-select").length;
      syncBulkbar();
    });
    selectAll.addEventListener("change", () => {
      selected = new Set();
      tbody.querySelectorAll("input.row-select").forEach((box) => {
        box.checked = selectAll.checked;
        if (selectAll.checked) selected.add(box.dataset.name);
      });
      syncBulkbar();
    });

    deleteSelectedBtn.addEventListener("click", async () => {
      const names = [...selected];
      if (!names.length) return;
      if (!confirm(`Delete ${names.length} of ${whose} kept file${names.length === 1 ? "" : "s"}? This cannot be undone.`)) return;
      deleteSelectedBtn.disabled = true;
      try {
        const r = await Agenti.post(`${base}/delete`, { names });
        const failed = (r.results || []).filter((row) => !row.deleted);
        if (failed.length) {
          Agenti.banner(banner, "err", `Some files could not be deleted: ${failed.map((f) => `${f.name}: ${f.error || "unknown error"}`).join("; ")}`);
        } else {
          Agenti.banner(banner, "ok", `Deleted ${names.length} file${names.length === 1 ? "" : "s"}.`);
        }
      } catch (err) {
        Agenti.banner(banner, "err", Agenti.errorText(err));
      }
      deleteSelectedBtn.disabled = false;
      await load();
    });

    tbody.addEventListener("click", async (e) => {
      const btn = e.target.closest("button[data-delete]");
      if (!btn) return;
      const name = btn.dataset.delete;
      if (!confirm(`Delete '${name}'? This cannot be undone.`)) return;
      btn.disabled = true;
      try {
        await Agenti.del(`${base}/${enc(name)}`);
        await load();
        Agenti.banner(banner, "ok", `Deleted '${name}'.`);
      } catch (err) {
        Agenti.banner(banner, "err", Agenti.errorText(err));
        btn.disabled = false;
      }
    });
  }
})();
