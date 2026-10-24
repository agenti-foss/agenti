/* catalog-editor.js — add, edit and remove a command-line program in the
 * catalog an admin picks from (Settings -> Agents -> Controls -> tool
 * allow-list). Global admins only; the server re-checks everything.
 *
 *   AgentiCatalog.open({ entry, groups, onSaved })   entry = null to add
 *   AgentiCatalog.remove(name, onRemoved)
 *
 * The form shows, as you type the name, whether the program is installed and
 * allowed (POST admin/catalog/check changes nothing). Adding offers a program;
 * it does not turn it on for any agent.
 */
(function () {
  "use strict";
  const A = Agenti;
  const esc = A.esc;
  let dlg = null, state = null, timer = null;

  function build() {
    dlg = document.createElement("dialog");
    dlg.className = "wizard catalog-dialog";
    dlg.id = "catalog-dialog";
    dlg.innerHTML = `
      <form method="dialog" class="wizard-form" novalidate>
        <header class="wizard-head">
          <div class="wizard-title-row">
            <h2 id="cat-title">Add a program</h2>
            <button type="button" class="icon-btn" data-cat-close aria-label="Close">${A.icon("close")}</button>
          </div>
        </header>
        <div class="wizard-body">
          <p class="hint" style="margin-top:0;">Must be <strong>installed</strong> on this server. You still switch it on per agent.</p>
          <div class="field"><label for="cat-name">Program</label>
            <input type="text" id="cat-name" maxlength="64" autocomplete="off" spellcheck="false" placeholder="e.g. whois">
            <p class="hint cat-status" id="cat-status" aria-live="polite"></p></div>
          <div class="field"><label for="cat-purpose">What it's for <span class="muted" id="cat-purpose-count"></span></label>
            <input type="text" id="cat-purpose" maxlength="200" autocomplete="off" placeholder="One line, e.g. look up who owns a domain">
            <p class="hint">Shown to admins and to the agent.</p></div>
          <div class="field"><label for="cat-group">Group</label>
            <input type="text" id="cat-group" maxlength="24" list="cat-groups" autocomplete="off" placeholder="e.g. network">
            <datalist id="cat-groups"></datalist></div>
          <div class="field"><label for="cat-denied">Blocked arguments <span class="muted">(optional, one pattern per line)</span></label>
            <textarea id="cat-denied" rows="4" spellcheck="false" class="mono"
              placeholder="A command that matches any line is refused, e.g.  (^|\\s)(-o|--output)(\\s|=|$)"></textarea>
            <p class="hint">Regular expressions checked against the whole command. Use them to block options that
              write files, send data or run other programs.</p></div>
          <div class="banner err" id="cat-banner" role="alert"></div>
        </div>
        <footer class="wizard-foot">
          <span class="wizard-spacer"></span>
          <button type="button" class="btn" data-cat-cancel>Cancel</button>
          <button type="button" class="btn btn-primary" data-cat-save>Save</button>
        </footer>
      </form>`;
    document.body.appendChild(dlg);
    const $ = (s) => dlg.querySelector(s);
    $("[data-cat-close]").addEventListener("click", () => dlg.close());
    $("[data-cat-cancel]").addEventListener("click", () => dlg.close());
    $("#cat-name").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(check, 350); });
    $("#cat-purpose").addEventListener("input", () => {
      $("#cat-purpose-count").textContent = `${$("#cat-purpose").value.length}/200`;
    });
    $("[data-cat-save]").addEventListener("click", save);
    dlg.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.tagName === "INPUT") { e.preventDefault(); save(); }
    });
  }

  const $ = (s) => dlg.querySelector(s);
  const err = (m) => A.banner($("#cat-banner"), "err", m);

  function entryFromForm() {
    return {
      name: $("#cat-name").value.trim(),
      group: $("#cat-group").value.trim() || "other",
      purpose: $("#cat-purpose").value.trim(),
      extra_denied: $("#cat-denied").value.split("\n").map((l) => l.trim()).filter(Boolean),
    };
  }

  // Live "installed? allowed?" line under the name field.
  async function check() {
    const st = $("#cat-status"), e = entryFromForm();
    if (!e.name) { st.className = "hint cat-status"; st.textContent = ""; return null; }
    const seq = ++state.seq;
    try {
      const r = await A.post(state.editing ? "admin/catalog/check-update" : "admin/catalog/check",
        { ...e, purpose: e.purpose || "-" });
      if (seq !== state.seq) return null;
      st.className = "hint cat-status ok";
      st.innerHTML = `${A.icon("check", 14)} Installed at <code>${esc(r.path || "")}</code>`;
      return r;
    } catch (ex) {
      if (seq !== state.seq) return null;
      const msg = A.errorText(ex);
      st.className = "hint cat-status warn";
      st.innerHTML = `${A.icon("warning", 14)} ${esc(msg)}`;
      return null;
    }
  }

  async function save() {
    if (state.busy) return;
    $("#cat-banner").className = "banner err";
    const e = entryFromForm();
    if (!e.name) { err("Enter the program's name."); $("#cat-name").focus(); return; }
    if (!e.purpose) { err("Say what it's for, in one line."); $("#cat-purpose").focus(); return; }
    state.busy = true;
    try {
      const r = await check();
      if (!r) { err($("#cat-status").textContent.trim() || "That program can't be added."); return; }
      const res = await A.requireApproval({
        title: state.editing ? `Change ${e.name}?` : `Offer ${e.name} to agents?`,
        description: state.editing
          ? `Changes how ${e.name} is described and which arguments are blocked.`
          : `Adds ${e.name} to the program catalog. No agent gets it until you switch it on for that agent.`,
        submit: (creds) => A.post(state.editing ? "admin/catalog/update" : "admin/catalog/add",
          { entry: e, password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
      if (!res) return;
      dlg.close();
      if (state.onSaved) state.onSaved(e.name, state.editing);
    } catch (ex) {
      err(A.errorText(ex));
    } finally { state.busy = false; }
  }

  function open({ entry, groups, onSaved }) {
    if (!dlg) build();
    state = { editing: !!entry, onSaved, seq: 0, busy: false };
    $("#cat-title").textContent = entry ? `Edit ${entry.name}` : "Add a program";
    $("#cat-name").value = entry ? entry.name : ""; $("#cat-name").readOnly = !!entry;
    $("#cat-purpose").value = entry ? (entry.purpose || "") : "";
    $("#cat-group").value = entry ? (entry.group || "") : "";
    $("#cat-denied").value = entry ? (entry.extra_denied || []).join("\n") : "";
    $("#cat-groups").innerHTML = (groups || []).map((g) => `<option value="${esc(g)}">`).join("");
    $("#cat-purpose-count").textContent = "";
    $("#cat-status").className = "hint cat-status"; $("#cat-status").textContent = "";
    $("#cat-banner").className = "banner err";
    dlg.showModal();
    (entry ? $("#cat-purpose") : $("#cat-name")).focus();
    if (entry) check();
  }

  async function remove(name, onRemoved) {
    const res = await A.requireApproval({
      title: `Remove ${name} from the catalog?`,
      description: `${name} stops being offered. This is refused while any agent still has it switched on.`,
      submit: (creds) => A.post(`admin/catalog/${encodeURIComponent(name)}/remove`,
        { password: creds.password, totp: creds.totp, reauth: creds.reauth }),
    });
    if (res && onRemoved) onRemoved(name);
    return res;
  }

  window.AgentiCatalog = { open, remove };
})();
