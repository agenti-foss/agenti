// settings.js — the Settings page: Account, Security (password, 2FA,
// passkeys), Appearance (theme + mode), and — for an admin — Agents,
// Engagement, Users and Platform (policies, the passkey domain wizard,
// tool requests).
//
// Self-service: POST /auth/password, POST /auth/mfa/enrol/start,
// POST /auth/mfa/enrol/confirm, the /auth/webauthn/* routes.
//
// Admin routes: GET/POST /admin/users…, GET /admin/bindings,
// GET /admin/policy, GET/POST /engagement (+ /approve), GET/POST
// /context/org, the /admin/agent-* control-centre routes and the
// /admin/agent-builder/* ones. One organisation, one list of users, two
// roles (operator, admin).
//
// Granting a role, renaming, deleting or re-enabling a user all go through
// the SAME re-authenticated, single-use action grant (Agenti.requireApproval
// — password and a 2FA code, or a passkey), never a bare permission check.
// Granting admin only succeeds when the approver already holds it.
//
// THE DASHBOARD COLUMN (CLAUDE.md §4 item 71). Runs are private to the user
// who launched them; an admin's only way to see someone else's is their
// "Dashboard" button here, which opens an exact copy of their landing page
// (dashboard.html?user=…&embed=1) in a pop-up. Who may open whose is the
// server's ladder (iam.dashboard_access): an admin -> any non-admin;
// everyone -> themselves.
//
// SECTIONS AND WHO SEES THEM. One list of sections shown as tabs (phone) or
// a sidebar (desktop). A tab is shown only when the caller holds what the
// routes behind it require, so an operator gets Account / Security /
// Appearance and nothing that would only 403. The active section lives in
// the URL fragment (#security …); ?mfa=required lands on Security.

document.addEventListener("DOMContentLoaded", async function () {
  renderNav("settings");
  const esc = Agenti.esc;

  // ---------- icons on the labelled buttons ----------
  // Markup carries the words (so a failed fetch never leaves a blank
  // button); the glyph is added here from the shared set.
  applyIcons(document);

  // ---------- a fixed-window pager over an already-fetched array ----------
  // Client-side only: the backend routes this page calls (list-users) return their full result set every time, unfiltered by page —
  // this caps how much of that gets painted into the DOM at once, which is
  // what actually costs time for an organisation with hundreds of accounts.
  function makePager(containerEl, { onChange }) {
    let page = 1;
    let size = 25;
    let total = 0;
    function pageCount() { return size === Infinity ? 1 : Math.max(1, Math.ceil(total / size)); }
    function clamp() { const p = pageCount(); if (page > p) page = p; if (page < 1) page = 1; }
    return {
      setTotal(t) { total = t; clamp(); },
      reset() { page = 1; },
      slice(items) { clamp(); return size === Infinity ? items : items.slice((page - 1) * size, page * size); },
      render() {
        clamp();
        const pages = pageCount();
        const start = total === 0 ? 0 : (size === Infinity ? 1 : (page - 1) * size + 1);
        const end = size === Infinity ? total : Math.min(total, page * size);
        containerEl.innerHTML = total === 0 ? "" : `
          <div class="pager-size">
            <label>Show
              <select class="pager-size-select">
                ${[25, 50, 100].map((n) => `<option value="${n}"${n === size ? " selected" : ""}>${n}</option>`).join("")}
                <option value="all"${size === Infinity ? " selected" : ""}>All</option>
              </select>
            </label>
          </div>
          <div class="pager-info">${start}–${end} of ${total}</div>
          <div class="pager-nav">
            <button type="button" class="btn btn-sm pager-prev"${page <= 1 ? " disabled" : ""}>Prev</button>
            <span class="pager-page">Page ${page} of ${pages}</span>
            <button type="button" class="btn btn-sm pager-next"${page >= pages ? " disabled" : ""}>Next</button>
          </div>`;
        if (total === 0) return;
        containerEl.querySelector(".pager-size-select").addEventListener("change", (e) => {
          size = e.target.value === "all" ? Infinity : parseInt(e.target.value, 10);
          page = 1;
          onChange();
        });
        containerEl.querySelector(".pager-prev").addEventListener("click", () => { page -= 1; onChange(); });
        containerEl.querySelector(".pager-next").addEventListener("click", () => { page += 1; onChange(); });
      },
    };
  }

  // ---------- sections ----------
  const TABS = [
    { id: "account", label: "Account", icon: "user" },
    { id: "security", label: "Security", icon: "shield" },
    { id: "appearance", label: "Appearance", icon: "palette" },
    { id: "agents", label: "Agents", icon: "tools", note: "admin" },
    { id: "engagement", label: "Engagement", icon: "shield", note: "admin" },
    { id: "users", label: "Users", icon: "users", note: "admin" },
    { id: "platform", label: "Platform", icon: "sliders", note: "admin" },
  ];
  const tabs = document.getElementById("settings-tabs");
  TABS.forEach((t) => {
    const b = tabs.querySelector(`[data-pane="${t.id}"]`);
    if (!b) return;
    b.innerHTML = `${Agenti.icon(t.icon)}<span>${esc(t.label)}</span>${t.note ? `<span class="tab-note">${esc(t.note)}</span>` : ""}`;
    b.id = `tab-${t.id}`;
    b.setAttribute("aria-controls", `pane-${t.id}`);
  });
  const paneOf = (id) => document.getElementById(`pane-${id}`);
  function visibleTab(id) {
    const b = tabs.querySelector(`[data-pane="${id}"]`);
    return b && !b.hidden;
  }
  function showPane(id, { push } = {}) {
    if (!visibleTab(id)) id = "account";
    TABS.forEach((t) => {
      const b = tabs.querySelector(`[data-pane="${t.id}"]`);
      const on = t.id === id;
      if (b) { b.classList.toggle("active", on); b.setAttribute("aria-selected", on ? "true" : "false"); }
      const p = paneOf(t.id);
      if (p) p.hidden = !on;
    });
    if (push !== false) {
      const want = id === "account" ? "" : `#${id}`;
      if (location.hash !== want && !(want === "" && location.hash === "")) {
        history.replaceState(null, "", location.pathname + location.search + want);
      }
    }
    const b = tabs.querySelector(`[data-pane="${id}"]`);
    if (b && b.scrollIntoView) b.scrollIntoView({ block: "nearest", inline: "nearest" });
  }
  function paneFromHash() {
    const h = location.hash.replace(/^#/, "");
    return TABS.some((t) => t.id === h) ? h : "account";
  }
  tabs.addEventListener("click", (e) => {
    const b = e.target.closest("[data-pane]");
    if (b) showPane(b.dataset.pane);
  });
  window.addEventListener("hashchange", () => showPane(paneFromHash(), { push: false }));
  // Arrow keys move between tabs, the way a native tab strip does.
  tabs.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const visible = TABS.filter((t) => visibleTab(t.id)).map((t) => t.id);
    const cur = visible.indexOf(paneFromHash());
    const next = visible[(cur + (e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : visible.length - 1)) % visible.length];
    showPane(next);
    tabs.querySelector(`[data-pane="${next}"]`).focus();
    e.preventDefault();
  });

  const mfaParam = new URLSearchParams(location.search).get("mfa") === "required";
  showPane(mfaParam && !location.hash ? "security" : paneFromHash(), { push: false });

  // ---------- Appearance ----------
  // Theme cards from theme.js's catalogue, each painting both modes from
  // its swatch in its own heading face, and a System / Light / Dark switch.
  // Applied instantly (the whole page re-skins in place) and remembered per
  // browser; every other wired control (the nav toggle) follows via
  // AgentiTheme.onChange.
  const T = window.AgentiTheme;
  const cards = document.getElementById("theme-cards");
  const modeSeg = document.getElementById("mode-seg");
  const modeHint = document.getElementById("mode-hint");
  const MODE_LABEL = { system: ["monitor", "System"], light: ["sun", "Light"], dark: ["moon", "Dark"] };
  function preview(sw, font, pixel) {
    return `<div class="theme-preview${pixel ? " pixel" : ""}" style="--p-bg:${sw.bg};--p-panel:${sw.panel};--p-text:${sw.text};--p-dim:${sw.dim};--p-accent:${sw.accent};--p-border:${sw.border};--p-font:${font}">
      <div class="p-bar"><i></i><b></b></div>
      <div class="p-card"><div class="p-title">Agenti</div><div class="p-line"></div><div class="p-line short"></div><div class="p-btn">Run</div></div>
    </div>`;
  }
  function paintThemes() {
    if (!T) { cards.innerHTML = `<p class="hint">Theme switching is unavailable (theme.js did not load).</p>`; return; }
    const current = T.skin();
    cards.innerHTML = Object.entries(T.SKINS).map(([id, s]) => `
      <button type="button" class="theme-card${id === current ? " active" : ""}" role="radio" aria-checked="${id === current}" data-skin="${esc(id)}">
        <div class="theme-previews">${preview(s.swatch.light, s.display, id !== "original")}${preview(s.swatch.dark, s.display, id !== "original")}</div>
        <div class="theme-card-body">
          <span class="check">${Agenti.icon("check", 13)}</span>
          <span><span class="theme-name">${esc(s.label)}</span><div class="theme-blurb">${esc(s.blurb)}</div></span>
        </div>
      </button>`).join("");
    modeSeg.querySelectorAll("[data-mode]").forEach((b) => {
      const [ic, label] = MODE_LABEL[b.dataset.mode];
      b.innerHTML = `${Agenti.icon(ic)}<span>${label}</span>`;
      const on = T.mode() === b.dataset.mode;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    modeHint.textContent = T.mode() === "system"
      ? `Following your system, which is ${T.resolvedMode()} right now.`
      : `Always ${T.mode()}, whatever your system is set to.`;
  }
  cards.addEventListener("click", (e) => {
    const b = e.target.closest("[data-skin]");
    if (b && T) T.setSkin(b.dataset.skin);
  });
  modeSeg.addEventListener("click", (e) => {
    const b = e.target.closest("[data-mode]");
    if (b && T) T.setMode(b.dataset.mode);
  });
  if (T) T.onChange(paintThemes);
  paintThemes();

  // ---------- who am I ----------
  const kv = document.getElementById("account-kv");
  let me;
  try {
    me = await Agenti.me();
  } catch (err) {
    kv.innerHTML = `<dt>Error</dt><dd>${esc(Agenti.errorText(err))}</dd>`;
    return;
  }
  // Read for gating the admin sections below; not shown as a list. What a
  // person sees here is their ROLE — the one word the permission list was
  // standing in for.
  const perms = me.permissions || [];
  kv.innerHTML = `
    <dt>User</dt><dd>${esc(me.user)}</dd>
    <dt>Role</dt><dd>${me.role ? esc(Agenti.roleLabel(me.role)) : '<span class="muted">none — ask an admin for access</span>'}</dd>`;

  // ---------- which sections this caller gets ----------
  const canManage = perms.includes("iam:manage");
  const canReadIam = perms.includes("iam:read") || canManage;
  const canEditEngagement = perms.includes("engagement:manage");
  const canApproveEngagement = perms.includes("engagement:approve");
  const showEngagementBtn = canEditEngagement || canApproveEngagement;
  const showUsers = canReadIam;
  const showPlatform = canManage || canReadIam;
  // Agents: admins (and readers, view only). The agent catalogue, the control
  // centre, building and removing agents.
  const showAgents = canManage || canReadIam;
  tabs.querySelector('[data-pane="agents"]').hidden = !showAgents;
  tabs.querySelector('[data-pane="engagement"]').hidden = !showEngagementBtn;
  tabs.querySelector('[data-pane="users"]').hidden = !showUsers;
  tabs.querySelector('[data-pane="platform"]').hidden = !showPlatform;
  // A fragment naming a section this caller cannot see falls back to Account.
  showPane(paneFromHash(), { push: false });

  // The require-2fa policy (rbac.MFA_SETUP_ALLOWED_PATHS): this session may
  // only enrol until it has. Every other panel on this page would 403, so
  // say why once, at the top, and put the person in front of the form.
  const mfaRequired = !!me.mfa_setup_required || mfaParam;
  if (mfaRequired) {
    Agenti.banner(document.getElementById("mfa-required-banner"), "err",
      "Two-factor authentication is required for your account and is not set up yet. " +
      "Until it is, this account can do nothing else — set it up under Security with your password and an authenticator app.");
    showPane("security");
  }

  // ---------- password change ----------
  // The current password (+ 2FA code, if enrolled) is collected by the ONE
  // universal admin-authentication popup (Agenti.requireApproval — api.js),
  // not fields embedded in this form. requireCode reflects what we already
  // know about this account (me.totp_enrolled) rather than reactively
  // revealing a field after a first attempt is refused for missing one.
  const pwForm = document.getElementById("password-form");
  const pwBanner = document.getElementById("pw-banner");
  pwForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    pwBanner.className = "banner";
    const newPassword = document.getElementById("pw-new").value;
    if (newPassword.length < 8) { Agenti.banner(pwBanner, "err", "Use at least 8 characters."); return; }
    const btn = pwForm.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      const r = await Agenti.requireApproval({
        title: "Change password",
        description: "Confirm it's you to set your new password.",
        submit: (creds) => Agenti.post("auth/password",
          { current: creds.password || undefined, new: newPassword, totp: creds.totp || undefined, reauth: creds.reauth }),
      });
      if (!r) return; // cancelled — nothing changed
      Agenti.banner(pwBanner, "ok", "Password changed. Signing you out — log back in with the new one.");
      setTimeout(() => { Agenti.clearAuth(); location.href = "login.html"; }, 1600);
    } finally {
      btn.disabled = false;
    }
  });

  // ---------- 2FA enrol/re-enrol ----------
  // Re-authentication (current password + a current code from the OLD
  // factor, if any) happens ONCE, in the universal popup, at "start" — it
  // mints a single-use grant server-side (iam.mint_action_grant) that
  // "confirm" consumes instead of asking again. That's not just tidier: a
  // SECOND reauthenticate_self call with the SAME old code would fail its
  // own replay check (the code is already spent), which is exactly the
  // class of bug already found and fixed once for WebAuthn registration.
  const mfaBanner = document.getElementById("mfa-banner");
  const mfaStatus = document.getElementById("mfa-status");
  const mfaStartPanel = document.getElementById("mfa-start-panel");
  const mfaOldCodeHint = document.getElementById("mfa-old-code-hint");
  const mfaConfirmPanel = document.getElementById("mfa-confirm-panel");
  const mfaRecoveryPanel = document.getElementById("mfa-recovery-panel");
  mfaStatus.textContent = me.totp_enrolled
    ? "Enabled."
    : "Not set up yet — you need an authenticator app.";
  mfaOldCodeHint.hidden = !me.totp_enrolled;
  if (mfaRequired) {
    document.getElementById("mfa-start-btn").focus();
    mfaStartPanel.scrollIntoView({ block: "center" });
  }

  document.getElementById("mfa-start-btn").addEventListener("click", async () => {
    mfaBanner.className = "banner";
    const r = await Agenti.requireApproval({
      title: me.totp_enrolled ? "Replace two-factor authentication" : "Set up two-factor authentication",
      description: me.totp_enrolled
        ? "Confirm your password and a current code from the device you're replacing."
        : "Confirm your password to generate a new 2FA secret.",
      submit: (creds) => Agenti.post("auth/mfa/enrol/start",
        { current: creds.password || undefined, totp: creds.totp || undefined, reauth: creds.reauth }),
    });
    if (!r) return; // cancelled
    const secretEl = document.getElementById("mfa-secret");
    secretEl.textContent = r.secret;
    secretEl.parentElement.querySelectorAll("button.copy-btn").forEach((b) => b.remove());
    secretEl.parentElement.appendChild(Agenti.copyButton(r.secret, "Copy secret"));
    const qrHost = document.getElementById("mfa-qr");
    qrHost.innerHTML = "";
    const img = Agenti.qrImage(r.qr_svg, "QR code for your authenticator app");
    if (img) qrHost.appendChild(img);
    document.getElementById("mfa-otpauth-link").href = r.otpauth_uri;
    mfaConfirmPanel.dataset.secret = r.secret;
    mfaConfirmPanel.dataset.grant = r.grant;
    mfaStartPanel.hidden = true;
    mfaConfirmPanel.hidden = false;
    mfaRecoveryPanel.hidden = true;
  });

  document.getElementById("mfa-cancel-btn").addEventListener("click", () => {
    mfaConfirmPanel.hidden = true;
    mfaStartPanel.hidden = false;
    document.getElementById("mfa-code").value = "";
  });

  document.getElementById("mfa-confirm-btn").addEventListener("click", async () => {
    mfaBanner.className = "banner";
    const body = {
      grant: mfaConfirmPanel.dataset.grant,
      secret: mfaConfirmPanel.dataset.secret,
      code: document.getElementById("mfa-code").value.trim(),
    };
    try {
      const r = await Agenti.post("auth/mfa/enrol/confirm", body);
      mfaConfirmPanel.hidden = true;
      mfaRecoveryPanel.hidden = false;
      const codes = (r.recovery_codes || []).join("\n");
      const pre = document.getElementById("mfa-recovery-codes");
      pre.textContent = codes;
      pre.parentElement.querySelectorAll("button.copy-btn").forEach((b) => b.remove());
      pre.parentElement.appendChild(Agenti.copyButton(codes, "Copy recovery codes"));
      mfaStatus.textContent = "Enabled. You've been signed out everywhere — sign in again with your new code.";
      // Enrolling lifts the require-2fa confinement on the next request; the
      // rest of the page can be used again, so tell them so.
      const req = document.getElementById("mfa-required-banner");
      if (req.classList.contains("show")) {
        Agenti.banner(req, "ok", "Two-factor authentication is set up. Save the recovery codes below, then sign in again — enrolling a new factor signs out every session, this one included.");
      }
    } catch (err) {
      // Most likely cause of a failure here: the grant from "start" expired
      // (2 minutes) before this was submitted — the message says so and
      // names the fix (start over), rather than reading as a mystery.
      Agenti.banner(mfaBanner, "err", Agenti.errorText(err));
    }
  });

  // ---------- passkeys ----------
  // Registration is a real WebAuthn ceremony (Agenti.webauthnCreate — see
  // api.js), gated by the SAME current-password(+2FA)-first discipline as
  // password change / TOTP enrolment above — collected by the universal
  // popup, not fields on this page: reauthenticate_self runs inside
  // agenti-authd's op_webauthn_register_begin, so a hijacked session cookie
  // cannot silently add a persistent login method. Removal opens the same
  // popup fresh per row, rather than reusing one set of embedded fields.
  const passkeyBanner = document.getElementById("passkey-banner");
  const passkeyList = document.getElementById("passkey-list");
  const passkeyEmpty = document.getElementById("passkey-empty");
  const passkeyName = document.getElementById("passkey-name");

  if (!window.PublicKeyCredential) {
    document.getElementById("passkey-unsupported").hidden = false;
    document.getElementById("passkey-add-panel").hidden = true;
  }

  // Same origin/rp-id check login.html does (see webauthnOriginHint in
  // api.js) — this is where the actual "OriginMissingDomain" failure
  // surfaces if it's missed, since adding a passkey happens here. Checked
  // once, up front: a banner + a disabled button beat a native error after
  // the OS picker has already been shown.
  let passkeyOriginHint = null;
  try {
    const wcfg = await Agenti.get("auth/webauthn/config");
    if (wcfg && wcfg.enabled) passkeyOriginHint = Agenti.webauthnOriginHint(wcfg.rpId, wcfg.origin);
  } catch { /* best-effort — a failed check just means no proactive warning */ }
  if (passkeyOriginHint) {
    Agenti.banner(passkeyBanner, "err", passkeyOriginHint);
    const addBtn = document.getElementById("passkey-add-btn");
    if (addBtn) addBtn.disabled = true;
  }

  function passkeyRowHtml(p) {
    const when = p.last_used_at ? `last used ${Agenti.when(p.last_used_at)}` : "never used yet";
    return `<div class="list-row field-row" style="margin-bottom:0;">
      <span class="list-icon">${Agenti.icon("fingerprint")}</span>
      <div class="list-main">
        <div class="list-title">${esc(p.name || "(unnamed device)")}</div>
        <div class="list-sub">added ${Agenti.when(p.created_at)} · ${esc(when)}</div>
      </div>
      <div class="list-actions">
        <button type="button" class="btn btn-sm btn-ghost" data-remove-passkey="${esc(p.credential_id)}" title="Remove this passkey">${Agenti.icon("trash", 14)}<span class="btn-label">Remove</span></button>
      </div>
    </div>`;
  }

  async function loadPasskeys() {
    try {
      const rows = await Agenti.get("auth/webauthn/passkeys");
      passkeyList.innerHTML = rows.map(passkeyRowHtml).join("");
      passkeyList.hidden = rows.length === 0;
      passkeyEmpty.hidden = rows.length > 0;
      passkeyList.querySelectorAll("[data-remove-passkey]").forEach((b) => {
        b.addEventListener("click", () => removePasskey(b.dataset.removePasskey));
      });
    } catch (err) {
      Agenti.banner(passkeyBanner, "err", Agenti.errorText(err));
    }
  }
  const passkeysLoading = loadPasskeys();   // nothing below needs it; awaited at the end

  async function removePasskey(credentialId) {
    passkeyBanner.className = "banner";
    const r = await Agenti.requireApproval({
      title: "Remove passkey",
      description: "Confirm it's you to remove this passkey.",
      submit: (creds) => Agenti.post(`auth/webauthn/passkeys/${encodeURIComponent(credentialId)}/remove`,
        { current: creds.password || undefined, totp: creds.totp || undefined, reauth: creds.reauth }),
    });
    if (!r) return; // cancelled
    // Removing a passkey signs the account out everywhere (a session opened
    // with a lost passkey must not outlive it), this one included.
    Agenti.banner(passkeyBanner, "ok", "Passkey removed. Signing you out everywhere — sign in again.");
    setTimeout(() => { Agenti.clearAuth(); location.href = "login.html"; }, 1600);
  }

  const passkeyAddBtn = document.getElementById("passkey-add-btn");
  if (passkeyAddBtn) {
    passkeyAddBtn.addEventListener("click", async () => {
      passkeyBanner.className = "banner";
      if (passkeyOriginHint) {
        Agenti.banner(passkeyBanner, "err", passkeyOriginHint);
        return;
      }
      const name = passkeyName.value.trim();
      passkeyAddBtn.disabled = true;
      try {
        const r = await Agenti.requireApproval({
          title: "Add a passkey",
          description: "Confirm it's you to start adding a new passkey.",
          submit: async (creds) => {
            const options = await Agenti.post("auth/webauthn/register/start",
              { password: creds.password, totp: creds.totp || undefined, reauth: creds.reauth });
            let credential;
            try {
              credential = await Agenti.webauthnCreate(options);
            } catch (ceremonyErr) {
              const ceremonyName = ceremonyErr && ceremonyErr.name;
              const msg = (ceremonyName === "NotAllowedError" || ceremonyName === "AbortError")
                ? "Passkey setup was cancelled."
                : Agenti.errorText(ceremonyErr);
              throw new Error(msg);
            }
            // finish deliberately does NOT re-send password/totp — the
            // server no longer asks for them here (see authd.py's
            // op_webauthn_register_finish docstring): sending the same
            // code twice used to trip its own replay defense on the
            // second use, meaning any account with 2FA enrolled could
            // never finish adding a passkey at all.
            return Agenti.post("auth/webauthn/register/finish", { name, credential });
          },
        });
        if (!r) return; // cancelled
        Agenti.banner(passkeyBanner, "ok", "Passkey added.");
        passkeyName.value = "";
        await loadPasskeys();
      } finally {
        passkeyAddBtn.disabled = false;
      }
    });
  }

  // Every section below loads independently; each is started here and awaited
  // together at the end, so the slowest one (the control centre) no longer
  // holds up the Users list or the Platform cards.
  const tasks = [];

  // ---------- Agents: the agent types on this server, and building one ----------
  // Hand-built agents arrive with a deploy; built agents (manifest "built")
  // were made with the wizard (agent-builder.js) and can be removed here.
  const SCOPE_WORD = { cidr: "Network (IP ranges)", domain: "Web (domains)", files: "Attached files" };
  let agentCatalog = [];   // the latest GET /agents rows, refreshed after a build or removal
  async function paintDeployedAgents() {
    const panel = document.getElementById("deployed-agents-panel");
    panel.hidden = false;
    const banner = document.getElementById("deployed-agents-banner");
    const list = document.getElementById("deployed-agents-list");
    banner.className = "banner";
    if (!list.children.length) list.innerHTML = `<p class="hint">Loading…</p>`;
    document.getElementById("build-agent-btn").hidden = !canManage;
    try {
      const r = await Agenti.get("agents");
      const rows = r.agents || [];
      agentCatalog = rows;
      list.innerHTML = rows.length ? rows.map((a) => {
        const built = a.built && a.built.by;
        const when = built && a.built.at ? new Date(a.built.at).toLocaleDateString() : "";
        return `<article class="agent-type" data-agent="${esc(a.agent)}">
          <div class="agent-type-main">
            <div class="agent-type-title"><strong>${esc(a.title || a.agent)}</strong>
              ${a.title && a.title !== a.agent ? `<span class="muted mono">${esc(a.agent)}</span>` : ""}</div>
            ${a.description ? `<p class="agent-type-desc">${esc(a.description)}</p>` : ""}
            <div class="agent-type-meta">
              <span class="chip">${esc(SCOPE_WORD[a.scope_kind] || a.scope_kind || "?")}</span>
              <span class="chip">${(a.programs || a.tools || []).length} ${(a.programs || []).length ? "program" : "tool"}${(a.programs || a.tools || []).length === 1 ? "" : "s"}</span>
              <span class="muted">${built ? `Built by ${esc(a.built.by)}${when ? ` · ${esc(when)}` : ""}` : "Hand-built"}</span>
            </div>
          </div>
          <div class="agent-type-actions">
            ${canManage && built ? `<button type="button" class="btn btn-sm" data-edit-agent="${esc(a.agent)}" data-icon="edit">Edit</button>` : ""}
            ${canManage ? `<button type="button" class="btn btn-sm" data-open-controls="${esc(a.agent)}" data-icon="sliders">Controls</button>` : ""}
            ${canManage && built ? `<button type="button" class="btn btn-sm btn-danger compact" data-remove-agent="${esc(a.agent)}" data-icon="trash" title="Remove ${esc(a.agent)}" aria-label="Remove ${esc(a.agent)}"><span>Remove</span></button>` : ""}
          </div>
        </article>`;
      }).join("") : `<p class="hint">No agent types are installed yet.${canManage ? " Build one, or deploy a hand-built one from a terminal." : ""}</p>`;
      if (window.applyIcons) applyIcons(list);
      return rows;
    } catch (err) {
      Agenti.banner(banner, "err", Agenti.errorText(err));
      return [];
    }
  }

  // ---------- Agents: control centre + per-agent scope (admin) ----------
  async function paintAgentScope(deployedAgents) {
    const panel = document.getElementById("agent-scope-panel");
    if (!canManage) { panel.hidden = true; return; }
    if (!deployedAgents.length) { panel.hidden = true; return; }
    panel.hidden = false;
    const aSel = document.getElementById("agent-scope-agent");
    const editor = document.getElementById("agent-scope-editor");
    const banner = document.getElementById("agent-scope-banner");
    const drift = document.getElementById("agent-drift");
    const controls = document.getElementById("agent-controls");
    if (!aSel.options.length) {
      aSel.innerHTML = deployedAgents.map((a) => `<option value="${esc(a.agent)}">${esc(a.agent)}</option>`).join("");
    }
    const lines = (id) => document.getElementById(id).value.split("\n").map((x) => x.trim()).filter(Boolean);
    const path = (kind) => `admin/${kind}/${encodeURIComponent(aSel.value)}`;
    const isScoped = () => {
      const a = agentCatalog.find((x) => x.agent === aSel.value);
      return !!a && /cidr|domain/i.test(a.scope_kind || "");
    };

    function paintControls(c) {
      const d = c.drift || {};
      const failing = (d.checks || []).filter((x) => x.status === "fail");
      drift.className = "banner show " + (failing.length ? "err" : (d.loaded ? "ok" : "warn"));
      drift.innerHTML = `<strong>Drift check:</strong> ${esc(d.summary || "")}` + (failing.length
        ? `<ul style="margin:6px 0 0 18px;">${failing.map((x) =>
            `<li>${esc(x.name)}: deployed <code>${esc(x.declared || "—")}</code>, running <code>${esc(x.live || "—")}</code></li>`).join("")}</ul>` : "");
      // Each section: an icon, its title, and a small badge saying whether
      // it can be changed here (where, on hover). Each row is a title over
      // an italic subtitle; a row with no value (a guard, a refused pattern)
      // is one line.
      const SECTION_ICON = { identity: "info", scope: "target", instructions: "file", limits: "sliders",
        tools: "wrench", programs: "terminal", denied: "lock", privileges: "shield", isolation: "eye", guards: "check" };
      controls.innerHTML = (c.sections || []).map((s) => `
        <details class="disclosure cc-section" ${s.id === "scope" || s.id === "limits" ? "open" : ""}>
          <summary><span class="ih">${Agenti.icon(SECTION_ICON[s.id] || "info")}<strong>${esc(s.title)}</strong></span>
            <span class="chip cc-badge${s.editable ? " cc-edit" : ""}" title="${esc(s.edit_where || "")}">${s.editable ? "editable" : "view only"}</span></summary>
          <div class="list" style="margin-top:6px;">${(s.rows || []).map(([k, v]) => v
            ? `<div class="list-row"><div class="list-main"><div class="list-title">${esc(k)}</div><div class="list-sub">${esc(v)}</div></div></div>`
            : s.id === "denied"
              ? `<div class="list-row"><code>${esc(k)}</code></div>`
              : `<div class="list-row cc-plain">${Agenti.icon("check", 14)}<span>${esc(k)}</span></div>`).join("")}</div>
        </details>`).join("");
    }

    const ctxKind = document.getElementById("agent-context-kind");
    function mountContext() {
      const kind = ctxKind.value, agent = aSel.value;
      const perAgent = kind !== "platform-skills";
      const q = perAgent ? `?agent=${encodeURIComponent(agent)}` : "";
      const blurbs = {
        "system-prompt": "What this agent is for and how it works. Required: a run is refused without one.",
        "skills": "Techniques this agent may try, using only the tools it already has.",
        "platform-skills": "Techniques every agent may try, using only the tools each already has.",
      };
      AgentiContextEditor.mount(document.getElementById("agent-context-editor"), {
        url: `admin/context/${kind}${q}`, postUrl: `admin/context/${kind}`,
        postExtra: perAgent ? { agent } : {},
        title: { "system-prompt": "System prompt", "skills": "Skills", "platform-skills": "Skills for every agent" }[kind],
        where: perAgent ? agent : "all agents", blurb: blurbs[kind], reauth: true, required: kind === "system-prompt",
      });
      if (window.applyIcons) applyIcons(document.getElementById("agent-context-editor"));
    }

    async function load() {
      mountContext();
      banner.className = "banner";
      controls.innerHTML = `<p class="hint">Loading…</p>`;
      try {
        paintControls(await Agenti.get(path("agent-controls")));
      } catch (err) {
        controls.innerHTML = ""; drift.className = "banner";
        Agenti.banner(banner, "err", Agenti.errorText(err));
      }
      // The scope editor and the tool-allowlist editor are two independent
      // panels on this same agent — one's early return (no scope
      // kind, or no engagement yet) must never skip loading the other.
      editor.hidden = true;
      if (isScoped()) {
        try {
          const r = await Agenti.get(path("agent-scope"));
          if (!(r.org_in_scope || []).length) {
            Agenti.banner(banner, "warn", "No engagement scope here yet — set it under Engagement.");
          } else {
            document.getElementById("agent-scope-org-in").textContent = (r.org_in_scope || []).join(", ");
            document.getElementById("agent-scope-in").value = (r.agent_in_scope || []).join("\n");
            document.getElementById("agent-scope-out").value = (r.agent_out_of_scope || []).join("\n");
            document.getElementById("agent-scope-effective").textContent = (r.effective_in_scope || []).join(", ") || "NOTHING — runs are refused";
            if (r.effective_error) Agenti.banner(banner, "err", r.effective_error);
            editor.hidden = false;
          }
        } catch (err) {
          Agenti.banner(banner, "err", Agenti.errorText(err));
        }
      }
      await loadToolSettings();
    }

    // ---------- the tool allow-list override (CLAUDE.md "Current plan" phase 6) ----------
    const toolsEditor = document.getElementById("agent-tools-editor");
    const toolsBanner = document.getElementById("agent-tools-banner");
    let toolsCatalog = [];
    let toolsEnabled = new Set(), toolsApprovable = new Set();
    // The reviewed + admin-added programs, searchable, each marked installed
    // or not. Rows are hidden (never removed) by the search so Save still
    // sees every row's checkboxes.
    function currentPicks() {
      const rows = [...document.querySelectorAll("#agent-tools-catalog [data-cat]")];
      if (!rows.length) return { enable: toolsEnabled, approvable: toolsApprovable };
      const pick = (mode) => new Set(rows.filter((r) => r.querySelector(`input[data-mode="${mode}"]`).checked).map((r) => r.dataset.cat));
      return { enable: pick("enable"), approvable: pick("approvable") };
    }
    function paintCatalog() {
      const { enable: enabled, approvable } = currentPicks();
      const q = (document.getElementById("agent-tools-search") || {}).value || "";
      const groups = {};
      for (const p of toolsCatalog) (groups[p.group || "other"] = groups[p.group || "other"] || []).push(p);
      const row = (p) => {
        const off = p.installed === false;
        const on = enabled.has(p.name), appr = approvable.has(p.name);
        const admin = p.source === "admin";
        return `
        <div class="list-row prog-row" data-cat="${esc(p.name)}" data-text="${esc((p.name + " " + (p.purpose || "") + " " + (p.group || "")).toLowerCase())}" style="flex-wrap:wrap;">
          <div class="list-main" style="min-width:12rem;"><div class="list-title">${esc(p.name)}
            ${off ? `<span class="wiz-tag prog-missing" title="Not installed on this server">Not installed</span>` : ""}
            ${admin ? `<span class="wiz-tag" title="Added by ${esc(p.added_by || "an admin")}">Added by admin</span>` : ""}</div>
            <div class="list-sub">${esc(p.purpose || "")}</div>
            ${off ? `<br><span class="hint warn">Install it first: <code>${esc(p.install_hint || "sudo apt install " + p.name)}</code>
              ${Agenti.copyButtonHtml(p.install_hint || "sudo apt install " + p.name, "Copy the install command")}</span>` : ""}
          </div>
          <label style="display:flex;gap:6px;align-items:center;cursor:pointer;">
            <input type="checkbox" data-mode="enable" ${on ? "checked" : ""} ${off && !on ? "disabled" : ""}> Always allow</label>
          <label style="display:flex;gap:6px;align-items:center;cursor:pointer;">
            <input type="checkbox" data-mode="approvable" ${appr ? "checked" : ""} ${off && !appr ? "disabled" : ""}> Operators may approve</label>
          ${admin ? `<span class="list-actions">
            <button type="button" class="btn btn-sm btn-ghost" data-cat-edit="${esc(p.name)}" title="Edit ${esc(p.name)}" aria-label="Edit ${esc(p.name)}">${Agenti.icon("edit", 14)}</button>
            <button type="button" class="btn btn-sm btn-ghost" data-cat-remove="${esc(p.name)}" title="Remove ${esc(p.name)} from the catalog" aria-label="Remove ${esc(p.name)} from the catalog">${Agenti.icon("trash", 14)}</button></span>` : ""}
        </div>`;
      };
      document.getElementById("agent-tools-catalog").innerHTML = `
        <div class="panel-head" style="margin-bottom:6px;">
          <div class="ti" style="flex:1;min-width:14rem;"><span class="ti-icon">${Agenti.icon("terminal")}</span><div class="ti-body">
            <div class="ti-title">Program catalog</div>
            <div class="ti-sub">Reviewed recon tools. "Operators may approve" lets the operator allow it for one run.</div></div></div>
          <button type="button" class="btn btn-sm btn-primary" id="catalog-add-btn" data-icon="plus">Add a program</button>
        </div>
        <div class="field" style="margin-bottom:6px;"><input type="search" id="agent-tools-search" placeholder="Search programs…" aria-label="Search programs" value="${esc(q)}" autocomplete="off"></div>
        <p class="hint" id="agent-tools-none" hidden>No program matches.</p>
        ${Object.keys(groups).sort().map((g) => `
          <div class="prog-group" data-group="${esc(g)}">
            <p class="muted prog-group-label">${esc(g)}</p>
            <div class="list">${groups[g].map(row).join("")}</div></div>`).join("")}`;
      if (window.applyIcons) applyIcons(document.getElementById("agent-tools-catalog"));
      if (Agenti.wireCopyButtons) Agenti.wireCopyButtons(document.getElementById("agent-tools-catalog"));
      filterCatalog();
    }
    function filterCatalog() {
      const q = ((document.getElementById("agent-tools-search") || {}).value || "").trim().toLowerCase();
      let shown = 0;
      document.querySelectorAll("#agent-tools-catalog .prog-row").forEach((r) => {
        const hit = !q || r.dataset.text.includes(q); r.hidden = !hit; if (hit) shown++;
      });
      document.querySelectorAll("#agent-tools-catalog .prog-group").forEach((g) => {
        g.hidden = !g.querySelector(".prog-row:not([hidden])");
      });
      const none = document.getElementById("agent-tools-none"); if (none) none.hidden = shown > 0;
    }
    async function loadToolSettings() {
      toolsEditor.hidden = true;
      let r;
      try {
        r = await Agenti.get(path("tool-settings"));
      } catch (err) {
        // An agent with no shell allow-list at all (research, trafficmon) answers a plain, expected refusal here — hide the
        // section rather than show it as an error. Anything else (a real
        // failure) still shows, same as every other panel on this page.
        if (!/no enforced shell allow-list/i.test(Agenti.errorText(err))) {
          toolsBanner.className = "banner show err";
          toolsBanner.textContent = Agenti.errorText(err);
        }
        return;
      }
      toolsEditor.hidden = false;
      toolsBanner.className = "banner";
      toolsCatalog = r.catalog || [];
      const disabled = new Set(r.settings.disable || []);
      const enabled = new Set(r.settings.enable || []);
      document.getElementById("agent-tools-baseline").innerHTML = `
        <div class="ti" style="margin:4px 0 8px;"><span class="ti-icon">${Agenti.icon("check")}</span><div class="ti-body">
          <div class="ti-title">This agent's own programs</div><div class="ti-sub">Uncheck to remove one.</div></div></div>
        <div class="list">${(r.baseline || []).map((n) => `
          <div class="list-row" data-base="${esc(n)}">
            <label style="display:flex;gap:8px;align-items:flex-start;flex:1;cursor:pointer;">
              <input type="checkbox" ${disabled.has(n) ? "" : "checked"} style="margin-top:3px;">
              <span class="list-main"><span class="list-title" style="display:block;">${esc(n)}</span><span class="list-sub" style="display:block;">${esc((r.purposes || {})[n] || "")}</span></span>
            </label>
          </div>`).join("")}</div>`;
      const approvable = new Set(r.settings.approvable || []);
      toolsApprovable = approvable; toolsEnabled = enabled;
      document.getElementById("agent-tools-catalog").innerHTML = "";   // rows from another agent must not leak in
      paintCatalog();
      const hist = r.history || [];
      document.getElementById("agent-tools-hist-count").textContent = hist.length ? `(${hist.length})` : "(no changes yet)";
      document.getElementById("agent-tools-hist-list").innerHTML = hist.map((row) => `
        <div class="list-row"><div class="list-main"><div class="list-title">Changed by ${esc(row.by)}</div><div class="list-sub">${esc(Agenti.when(row.ts))}</div>
          ${(row.enable || []).length ? `<br>added: ${esc(row.enable.join(", "))}` : ""}
          ${(row.approvable || []).length ? `<br>operators may approve: ${esc(row.approvable.join(", "))}` : ""}
          ${(row.disable || []).length ? `<br>removed: ${esc(row.disable.join(", "))}` : ""}</div></div>`).join("");
    }
    if (!toolsEditor.dataset.wired) {
      toolsEditor.dataset.wired = "1";
      // "Always allow" and "operators may approve" exclude each other: always
      // already means allowed, so there is nothing left to approve.
      document.getElementById("agent-tools-catalog").addEventListener("input", (e) => {
        if (e.target.id === "agent-tools-search") filterCatalog();
      });
      const refreshCatalog = async (msg) => {
        await loadToolSettings();
        if (msg) Agenti.banner(toolsBanner, "ok", msg);
      };
      document.getElementById("agent-tools-catalog").addEventListener("click", (e) => {
        const groups = [...new Set(toolsCatalog.map((p) => p.group || "other"))].sort();
        if (e.target.closest("#catalog-add-btn")) {
          AgentiCatalog.open({ entry: null, groups, onSaved: (n) => refreshCatalog(`Added ${n} to the catalog. Switch it on below to give this agent the program.`) });
          return;
        }
        const ed = e.target.closest("[data-cat-edit]");
        if (ed) {
          const entry = toolsCatalog.find((p) => p.name === ed.dataset.catEdit);
          AgentiCatalog.open({ entry, groups, onSaved: (n) => refreshCatalog(`Updated ${n}.`) });
          return;
        }
        const rm = e.target.closest("[data-cat-remove]");
        if (rm) {
          AgentiCatalog.remove(rm.dataset.catRemove, (n) => refreshCatalog(`Removed ${n} from the catalog.`))
            .catch((err) => Agenti.banner(toolsBanner, "err", Agenti.errorText(err)));
        }
      });
      document.getElementById("agent-tools-catalog").addEventListener("change", (e) => {
        const box = e.target.closest('input[data-mode]'); if (!box || !box.checked) return;
        const other = box.closest("[data-cat]").querySelector(`input[data-mode="${box.dataset.mode === "enable" ? "approvable" : "enable"}"]`);
        if (other) other.checked = false;
      });
      document.getElementById("agent-tools-save").addEventListener("click", async (e) => {
        e.target.disabled = true; toolsBanner.className = "banner";
        const disable = [...document.querySelectorAll('#agent-tools-baseline [data-base]')]
          .filter((row) => !row.querySelector("input").checked).map((row) => row.dataset.base);
        const picked = (mode) => [...document.querySelectorAll('#agent-tools-catalog [data-cat]')]
          .filter((row) => row.querySelector(`input[data-mode="${mode}"]`).checked).map((row) => row.dataset.cat);
        const enable = picked("enable"), approvable = picked("approvable");
        try {
          const r = await Agenti.post(path("tool-settings"), { enable, disable, approvable });
          await loadToolSettings();
          Agenti.banner(toolsBanner, "ok", r.unchanged ? "No change." : "Saved.");
        } catch (err) {
          Agenti.banner(toolsBanner, "err", Agenti.errorText(err));
        } finally { e.target.disabled = false; }
      });
    }
    if (!panel.dataset.wired) {
      panel.dataset.wired = "1";
      aSel.addEventListener("change", load);
      ctxKind.addEventListener("change", mountContext);
      document.getElementById("agent-scope-save").addEventListener("click", async (e) => {
        e.target.disabled = true; banner.className = "banner";
        try {
          const r = await Agenti.post(path("agent-scope"),
            { in_scope: lines("agent-scope-in"), out_of_scope: lines("agent-scope-out") });
          await load();
          Agenti.banner(banner, "ok", (r.unchanged ? "No change." : "Saved.") + stoppedNote(r));
        } catch (err) {
          Agenti.banner(banner, "err", Agenti.errorText(err));
        } finally { e.target.disabled = false; }
      });
    }
    await load();
  }

  // Runs the change took out of scope are stopped by the server (audit run 1,
  // F04); say which, so the admin is never surprised by a run that ended.
  function stoppedNote(r) {
    const s = (r && r.runs_stopped) || [];
    if (!s.length) return "";
    return ` Stopped ${s.length} run${s.length === 1 ? "" : "s"} it no longer covers (each wrote a partial report): `
      + s.map((x) => `${x.agent} ${x.slot} — ${x.reason}`).join("; ") + ".";
  }

  // ---------- Agents: build, open controls, remove ----------
  async function refreshAgents(selectAgent) {
    const deployed = await paintDeployedAgents();
    const aSel = document.getElementById("agent-scope-agent");
    const keep = selectAgent || aSel.value;
    aSel.innerHTML = deployed.map((a) => `<option value="${esc(a.agent)}">${esc(a.agent)}</option>`).join("");
    if (deployed.some((a) => a.agent === keep)) aSel.value = keep;
    await paintAgentScope(deployed);
    if (aSel.options.length) aSel.dispatchEvent(new Event("change"));
    return deployed;
  }

  function openControls(agent) {
    const aSel = document.getElementById("agent-scope-agent");
    const panel = document.getElementById("agent-scope-panel");
    if (panel.hidden || ![...aSel.options].some((o) => o.value === agent)) return;
    aSel.value = agent;
    aSel.dispatchEvent(new Event("change"));
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function removeBuiltAgent(name) {
    const banner = document.getElementById("deployed-agents-banner");
    banner.className = "banner";
    let pv;
    try {
      pv = await Agenti.get(`admin/agent-builder/${encodeURIComponent(name)}/remove-preview`);
    } catch (err) { Agenti.banner(banner, "err", Agenti.errorText(err)); return; }
    if (pv.blocked) {
      Agenti.banner(banner, "warn", `“${pv.title}” can't be removed yet: ${pv.blocked}.`);
      return;
    }
    const dataLine = (pv.slots || pv.reports)
      ? ` This also permanently deletes its ${pv.slots} run slot${pv.slots === 1 ? "" : "s"} and ${pv.reports} report${pv.reports === 1 ? "" : "s"}.`
      : " It has no runs or reports yet.";
    const r = await Agenti.requireApproval({
      title: `Remove ${pv.title}?`,
      description: `Removes “${pv.title}” from everyone's Launch page.${dataLine}`
        + ` Kept outputs are not touched. This cannot be undone.`,
      confirmText: "DELETE",
      submit: (creds) => Agenti.post(`admin/agent-builder/${encodeURIComponent(name)}/remove`,
        { password: creds.password, totp: creds.totp, reauth: creds.reauth }),
    });
    if (!r) return;
    await refreshAgents();
    Agenti.banner(banner, "ok", `Removed “${pv.title}”.`);
  }

  let deployed = [];   // the latest catalogue; read at click time by the Build button below
  if (showAgents) {
    const list = document.getElementById("deployed-agents-list");
    list.addEventListener("click", (e) => {
      const ctl = e.target.closest("[data-open-controls]");
      const rm = e.target.closest("[data-remove-agent]");
      const ed = e.target.closest("[data-edit-agent]");
      if (ed) {
        window.AgentiBuilder.open({ edit: ed.dataset.editAgent, existing: agentCatalog.map((a) => a.agent),
          onBuilt: async () => { await refreshAgents(ed.dataset.editAgent);
            Agenti.banner(document.getElementById("deployed-agents-banner"), "ok", "Saved. The changes apply from the next run."); } });
      }
      if (ctl) openControls(ctl.dataset.openControls);
      if (rm) removeBuiltAgent(rm.dataset.removeAgent);
    });
    document.getElementById("build-agent-btn").addEventListener("click", () => {
      window.AgentiBuilder.open({
        existing: deployed.map((a) => a.agent),
        onBuilt: async (result) => {
          deployed = await refreshAgents(result.name);
          const banner = document.getElementById("deployed-agents-banner");
          Agenti.banner(banner, "ok", `Built “${result.title}”. Its controls are below.`);
        },
      });
    });
    tasks.push((async () => {
      deployed = await paintDeployedAgents();
      await paintAgentScope(deployed);
    })());
  }
  // ---------- Engagement (admin) ----------
  // The organisation's ONE engagement record: client, authorization, the
  // scope every agent is narrowed from, the validity window and the
  // operational policy (caps, models, approval). A panel summarises it; the
  // dialog edits and approves it. The Edit button is offered to anyone who
  // could do anything with it (author it, or approve it as it stands) — the
  // dialog then narrows what is editable vs read-only, the same "gate the
  // button, then gate the form" pattern the grant dialog uses.
  if (showEngagementBtn) {
    const engDlg = document.getElementById("engagement-dialog");
    const engForm = document.getElementById("engagement-form");
    const engBanner = document.getElementById("engagement-banner");
    const engStatus = document.getElementById("engagement-status");
    const engApproveBtn = document.getElementById("engagement-approve");
    const engSaveBtn = document.getElementById("engagement-save");
    const engLinesOf = (id) => document.getElementById(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
    // Which ceilings the admin asked to revert to the platform default this
    // dialog session (Reset button) — reset on every open, consumed on
    // submit. "Blank" already means "leave it alone" (a --clear-* flag is the
    // only way to say "no, really, remove the override").
    let clearCeilings = new Set();
    engForm.querySelectorAll("[data-clear-ceiling]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = btn.dataset.clearCeiling;
        clearCeilings.add(key);
        const input = document.getElementById(`eng2-${key}-ceiling`);
        input.value = "";
        input.disabled = true;
        btn.hidden = true;
      });
    });

    function approvalLine(data) {
      const st = data.approval_status || {};
      const requiresApproval = (data.effective_policy || {}).require_approval !== false;
      if (st.current) return ["ok", `Approved by ${st.approved_by || "?"} — current.`];
      if (!requiresApproval) return ["ok", "The organisation's policy does not require approval, so a run can start regardless."];
      if (st.approved) return ["warn", `Stale — ${st.reason || "edited since approval"}. A run cannot start until this is approved again.`];
      return ["warn", `Not approved — ${st.reason || "no approval on record"}. A run cannot start against this engagement until it is.`];
    }
    function paintApprovalStatus(data) {
      const [cls, text] = approvalLine(data);
      engStatus.className = `banner ${cls} show`;
      engStatus.textContent = text;
    }

    // The summary panel on the Engagement tab.
    const engSummary = document.getElementById("eng-summary");
    async function paintEngagementSummary() {
      try {
        const data = await Agenti.get("engagement");
        const rec = data.record || {};
        const scope = rec.scope || {};
        const count = (k) => ((scope[k] || {}).in_scope || []).length;
        if (!data.exists) {
          engSummary.innerHTML = `<p class="hint">No engagement yet — nothing can be scanned until one is set.</p>`;
          return;
        }
        const [cls, text] = approvalLine(data);
        engSummary.innerHTML = `<dl class="kv">
          <dt>Engagement</dt><dd>${esc(rec.engagement_id || "—")}</dd>
          <dt>Client</dt><dd>${esc(rec.client || "—")}</dd>
          <dt>Valid</dt><dd>${esc(rec.valid_from || "?")} to ${esc(rec.valid_until || "?")}</dd>
          <dt>In scope</dt><dd>${count("cidr")} network range${count("cidr") === 1 ? "" : "s"}, ${count("domain")} domain${count("domain") === 1 ? "" : "s"}</dd>
          <dt>Approval</dt><dd><span style="color:var(--${cls === "ok" ? "ok" : "warn"});">${esc(text)}</span></dd>
        </dl>`;
      } catch (err) {
        engSummary.innerHTML = `<p class="hint warn">${esc(Agenti.errorText(err))}</p>`;
      }
    }
    tasks.push(paintEngagementSummary());

    async function openEngagement() {
      engBanner.className = "banner";
      engStatus.className = "banner";
      engStatus.textContent = "";
      engForm.querySelectorAll("input, textarea").forEach((el) => { el.disabled = !canEditEngagement; });
      engSaveBtn.hidden = !canEditEngagement;
      engApproveBtn.hidden = !canApproveEngagement;
      clearCeilings = new Set();
      engForm.querySelectorAll("[data-clear-ceiling]").forEach((btn) => { btn.hidden = !canEditEngagement; });
      engDlg.showModal();
      try {
        const data = await Agenti.get("engagement");
        const record = data.record || {};
        const scope = record.scope || {};
        document.getElementById("eng2-id").value = record.engagement_id || "";
        document.getElementById("eng2-client").value = record.client || "";
        document.getElementById("eng2-party").value = record.authorizing_party || "";
        document.getElementById("eng2-title").value = record.authorizing_title || "";
        document.getElementById("eng2-ref").value = record.authorization_ref || "";
        document.getElementById("eng2-from").value = record.valid_from || "";
        document.getElementById("eng2-until").value = record.valid_until || "";
        document.getElementById("eng2-cidr-in").value = ((scope.cidr || {}).in_scope || []).join("\n");
        document.getElementById("eng2-cidr-out").value = ((scope.cidr || {}).out_of_scope || []).join("\n");
        document.getElementById("eng2-domain-in").value = ((scope.domain || {}).in_scope || []).join("\n");
        document.getElementById("eng2-domain-out").value = ((scope.domain || {}).out_of_scope || []).join("\n");
        document.getElementById("eng2-contact").value = record.emergency_contact || "";
        document.getElementById("eng2-notes").value = record.notes || "";
        document.getElementById("eng2-capture").checked = !!record.capture_payloads;
        document.getElementById("eng2-exploitation-enabled").checked =
            !!(record.exploitation_enabled ||
               (record.enabled_capabilities || []).includes("exploit"));
        document.getElementById("eng2-retention").value = record.retention_days || 0;
        document.getElementById("eng2-redact").value = (record.redact || []).join("\n");
        // Policy: the CHECKBOX/VALUE state reflects what the record itself
        // has set (record.policy, blank/unchecked = "not set here" — saving
        // leaves it alone, same as the CLI's own per-field merge); the
        // ceiling placeholders show what would actually apply right now
        // (effective_policy — an override or the platform default), so
        // leaving a field blank is never a guess at what happens.
        const pol = record.policy || {};
        const eff = data.effective_policy || {};
        const reqApproval = document.getElementById("eng2-require-approval");
        reqApproval.checked = pol.require_approval !== false;
        // Turning approval OFF lets runs start without anyone approving the
        // scope, so from the web it can only be turned on (audit run 1, F10).
        reqApproval.disabled = reqApproval.checked;
        reqApproval.title = reqApproval.checked
          ? "Turning approval off is a console-only decision: sudo agenti engagement set --no-require-approval"
          : "";
        shownDigest = data.digest || "";
        const turnsEl = document.getElementById("eng2-turns-ceiling");
        turnsEl.value = pol.max_turns_ceiling != null ? pol.max_turns_ceiling : "";
        turnsEl.placeholder = `platform default: ${eff.max_turns_ceiling}`;
        const budgetEl = document.getElementById("eng2-budget-ceiling");
        budgetEl.value = pol.max_budget_usd_ceiling != null ? pol.max_budget_usd_ceiling : "";
        budgetEl.placeholder = `platform default: $${eff.max_budget_usd_ceiling}`;
        const timeoutEl = document.getElementById("eng2-timeout-ceiling");
        timeoutEl.value = pol.timeout_s_ceiling != null ? pol.timeout_s_ceiling : "";
        timeoutEl.placeholder = `platform default: ${eff.timeout_s_ceiling}s`;
        const allowed = new Set(pol.allowed_models || []);
        engForm.querySelectorAll(".eng2-model").forEach((cb) => { cb.checked = allowed.has(cb.value); });
        paintApprovalStatus(data);
      } catch (err) {
        // GET answers 200 with exists:false before the first engagement is
        // written (the fields just come back empty, ready to fill in) —
        // reaching this catch means a REAL failure: no permission, a
        // network error, or similar.
        Agenti.banner(engBanner, "err", Agenti.errorText(err));
      }
    }
    // Exposed on window so gui_check.py (and a future deep link) can open the
    // dialog without synthesising a click.
    window.__agentiOpenEngagement = openEngagement;
    let shownDigest = "";   // the version on screen: an approval signs exactly this one
    document.getElementById("eng-edit-btn").addEventListener("click", openEngagement);
    document.getElementById("engagement-cancel").addEventListener("click", () => {
      engDlg.close();
      paintEngagementSummary();
    });

    engForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!canEditEngagement) return;
      engBanner.className = "banner";
      const body = {
        engagement_id: document.getElementById("eng2-id").value.trim(),
        client: document.getElementById("eng2-client").value.trim(),
        authorizing_party: document.getElementById("eng2-party").value.trim(),
        authorizing_title: document.getElementById("eng2-title").value.trim(),
        authorization_ref: document.getElementById("eng2-ref").value.trim(),
        valid_from: document.getElementById("eng2-from").value,
        valid_until: document.getElementById("eng2-until").value,
        cidr_in: engLinesOf("eng2-cidr-in"),
        cidr_out: engLinesOf("eng2-cidr-out"),
        domain_in: engLinesOf("eng2-domain-in"),
        domain_out: engLinesOf("eng2-domain-out"),
        emergency_contact: document.getElementById("eng2-contact").value.trim(),
        notes: document.getElementById("eng2-notes").value.trim(),
        capture_payloads: document.getElementById("eng2-capture").checked,
        enabled_capabilities: document.getElementById("eng2-exploitation-enabled").checked ? ["exploit"] : [],
        exploitation_enabled: false,
        retention_days: parseInt(document.getElementById("eng2-retention").value, 10) || 0,
        redact: engLinesOf("eng2-redact"),
        require_approval: document.getElementById("eng2-require-approval").checked,
        allowed_models: Array.from(engForm.querySelectorAll(".eng2-model:checked")).map((cb) => cb.value),
      };
      if (clearCeilings.has("turns")) body.clear_max_turns_ceiling = true;
      else { const v = document.getElementById("eng2-turns-ceiling").value; if (v) body.max_turns_ceiling = parseInt(v, 10); }
      if (clearCeilings.has("budget")) body.clear_max_budget_ceiling = true;
      else { const v = document.getElementById("eng2-budget-ceiling").value; if (v) body.max_budget_ceiling = parseFloat(v); }
      if (clearCeilings.has("timeout")) body.clear_timeout_ceiling = true;
      else { const v = document.getElementById("eng2-timeout-ceiling").value; if (v) body.timeout_ceiling = parseInt(v, 10); }
      engSaveBtn.disabled = true;
      try {
        // The engagement is the legal boundary: saving it is confirmed like
        // any other admin action (audit run 1, F13).
        const r = await Agenti.requireApproval({
          title: "Save the engagement",
          description: "Confirm it's you to save these engagement details. A run needs an approval of this exact version before it can start.",
          submit: (creds) => Agenti.post("engagement", { ...body,
            password: creds.password, totp: creds.totp, reauth: creds.reauth }),
        });
        if (!r) return;
        Agenti.banner(engBanner, "ok", "Saved. Approve it below before a run can start against it." + stoppedNote(r));
        await openEngagement();
      } catch (err) {
        Agenti.banner(engBanner, "err", Agenti.errorText(err));
      } finally {
        engSaveBtn.disabled = false;
      }
    });

    engApproveBtn.addEventListener("click", async () => {
      const id = document.getElementById("eng2-id").value.trim();
      engApproveBtn.disabled = true;
      try {
        // Approve exactly the version on screen: if anyone edited it since
        // it was opened, the server refuses and asks for a fresh review (F25).
        const r = await Agenti.requireApproval({
          title: "Approve the engagement",
          description: "Confirm it's you to approve the engagement exactly as shown. Runs may then start against its scope until it is edited again.",
          submit: (creds) => Agenti.post("engagement/approve", {
            ...(id ? { engagement_id: id } : {}), digest: shownDigest,
            password: creds.password, totp: creds.totp, reauth: creds.reauth }),
        });
        if (!r) return;
        Agenti.banner(engBanner, "ok", "Approved.");
        await openEngagement();
      } catch (err) {
        Agenti.banner(engBanner, "err", Agenti.errorText(err));
      } finally {
        engApproveBtn.disabled = false;
      }
    });

    // The organisation's own instructions (org.md): rules every agent reads,
    // e.g. report style or contacts. Guides behaviour only.
    if (canReadIam) {
      AgentiContextEditor.mount(document.getElementById("org-policy-editor"), {
        url: "context/org", postUrl: "context/org",
        title: "Organisation instructions", where: "everyone", reauth: true, blurb: "",
      });
      if (window.applyIcons) applyIcons(document.getElementById("org-policy-editor"));
    }
  }

  // ---------- Domain setup wizard for passkeys (admin) ----------
  // The one step this page deliberately does NOT turn into a button:
  // switching the deployment's own domain/certificate is a privileged,
  // root-level action (sudo agenti gui configure --hostname), the same as every
  // other deploy step in this project — an admin session being able to
  // trigger that from a web form would be a real, novel privilege surface
  // this platform's whole architecture has deliberately kept out of the
  // web tier's reach. What THIS wizard does: explain the exact DNS record,
  // build the exact command to copy, and — since turning the FEATURE on
  // once the domain exists is a narrow, already-safe API call
  // (admin/webauthn, see its own comment) — offer a real working button for
  // that one step, with a live status check driving which step to show.
  if (canManage) {
    document.getElementById("domain-setup-panel").hidden = false;
    document.getElementById("ds-current-host").textContent = location.hostname;

    const dsBanner = document.getElementById("ds-banner");
    const dsInput = document.getElementById("ds-domain-input");
    const dsCommand1 = document.getElementById("ds-command-1");
    const dsCommand2 = document.getElementById("ds-command-2");
    const dsEnableBtn = document.getElementById("ds-enable-btn");

    function dsRenderCommands() {
      const domain = dsInput.value.trim();
      const host = location.hostname;
      dsCommand1.textContent =
        "sudo rm -f /var/lib/agenti/tls/api.crt /var/lib/agenti/tls/api.key";
      dsCommand2.textContent = domain
        ? `sudo agenti gui configure --bind ${host} --tls --hostname ${domain}`
        : "enter a domain above to see the exact command";
    }
    dsInput.addEventListener("input", dsRenderCommands);
    dsRenderCommands();
    // Two independent copy buttons, each reading its OWN command's CURRENT
    // text — the function form of Agenti.copyButton exists for exactly
    // this, since the second command changes as the domain field is typed.
    dsCommand1.parentElement.appendChild(Agenti.copyButton(() => dsCommand1.textContent, "Copy command"));
    dsCommand2.parentElement.appendChild(Agenti.copyButton(() => dsCommand2.textContent, "Copy command"));

    async function dsCheckStatus() {
      dsBanner.className = "banner";
      try {
        const cfg = await Agenti.get("auth/webauthn/config");
        if (!cfg.configured) {
          Agenti.banner(dsBanner, "err",
            "No domain configured yet — complete steps 1 and 2 below.");
          dsEnableBtn.disabled = true;
          dsEnableBtn.textContent = "Turn on WebAuthn / passkeys";
        } else if (!cfg.enabled) {
          Agenti.banner(dsBanner, "ok",
            `Domain configured (${cfg.rpId}). WebAuthn is still OFF — turn it on below.`);
          dsEnableBtn.disabled = false;
          dsEnableBtn.textContent = "Turn on WebAuthn / passkeys";
        } else {
          Agenti.banner(dsBanner, "ok",
            `All set — ${cfg.rpId}, WebAuthn is ON. Register a passkey under Security and test it.`);
          dsEnableBtn.disabled = true;
          dsEnableBtn.textContent = "Already on";
        }
      } catch (err) {
        Agenti.banner(dsBanner, "err", Agenti.errorText(err));
      }
    }
    tasks.push(dsCheckStatus());
    document.getElementById("ds-recheck-btn").addEventListener("click", dsCheckStatus);
    dsEnableBtn.addEventListener("click", async () => {
      dsEnableBtn.disabled = true;
      try {
        await Agenti.post("admin/webauthn", { enabled: true });
        await dsCheckStatus();
      } catch (err) {
        Agenti.banner(dsBanner, "err", Agenti.errorText(err));
        dsEnableBtn.disabled = false;
      }
    });
  }
  // ---------- Policies (admin, read-only: each shows the command that changes it) ----------
  if (canManage) {
    const panel = document.getElementById("limits-panel");
    panel.hidden = false;
    const policyList = document.getElementById("policy-list");

    // One policy as a list row: icon, the policy as the title with its
    // on/off badge, and the command that changes it as the subtitle.
    function polRow(ic, title, on, subHtml) {
      return `<div class="list-row"><span class="list-icon">${Agenti.icon(ic)}</span>
        <div class="list-main"><div class="list-title">${title}
          <span class="badge ${on ? "completed" : "incomplete"}" style="margin-left:6px;">${on ? "on" : "off"}</span></div>
          <div class="list-sub">${subHtml}</div></div></div>`;
    }
    async function paintPolicies() {
      if (!policyList.children.length) policyList.innerHTML = `<p class="hint">Loading…</p>`;
      try {
        const pol = await Agenti.get("admin/policy");
        const rows = [];
        const rsa = pol["require-separate-approver"] === "on";
        rows.push(polRow("users", "Separate approver for run approvals", rsa,
            `Whoever approves an engagement can't also start a run against it. Turn it on once two people share the work: <code>sudo agenti admin set-policy require-separate-approver ${rsa ? "off" : "on"}</code>`));
        // require-2fa: platform default (ON unless set off) and per-account
        // exemptions — every row a set-policy command, since
        // weakening authentication is refused to the web tier by design.
        const tfa = pol["require-2fa"] !== "off";
        const exempt = Object.keys(pol).filter((k) => /^require-2fa:/.test(k)).map((k) =>
          `<div class="hint" style="margin:2px 0 0;">${esc(k.slice("require-2fa:".length))}: <span class="badge ${pol[k] === "off" ? "incomplete" : "completed"}">${esc(pol[k])}</span>
             <code>sudo agenti admin set-policy ${esc(k)} ${pol[k] === "off" ? "on" : "off"}</code></div>`).join("");
        rows.push(polRow("shield", "Two-factor authentication required", tfa,
            `<code>sudo agenti admin set-policy require-2fa ${tfa ? "off" : "on"}</code>
            <details class="disclosure" style="margin-top:4px;"><summary>Per account</summary>
              <div class="hint" style="margin:6px 0 0;">${exempt || '<span class="muted">No per-account settings.</span>'}</div>
              <div class="hint" style="margin:2px 0 0;">Exempt one account: <code>sudo agenti admin set-policy require-2fa:&lt;name&gt; off</code></div>
            </details>`));
        // WebAuthn/passkeys: status only here (read-only, like every other
        // row on this card) — the actual walkthrough, including the one
        // real working toggle button, lives in the dedicated "Set up your
        // own domain for passkeys" panel below, so there is exactly one
        // place to turn it on rather than two controls that could drift.
        const ucOn = pol["update-check"] === "on";
        rows.push(polRow("download", "Update checking (asks GitHub when you click)", ucOn,
            `Off by default. <code>sudo agenti admin set-policy update-check ${ucOn ? "off" : "on"}</code>`));
        const webauthnOn = pol["webauthn-enabled"] === "on";
        rows.push(polRow("fingerprint", "Passkey sign-in", webauthnOn, "Turned on from the domain panel below."));

        policyList.className = "list";
        policyList.innerHTML = rows.join("");
        // A copy button after every command shown on these cards.
        policyList.querySelectorAll("code").forEach((c) => {
          if (/^sudo /.test(c.textContent)) c.insertAdjacentHTML("afterend", Agenti.copyButtonHtml(c.textContent, "Copy command"));
        });
        Agenti.wireCopyButtons(policyList);
      } catch (err) {
        policyList.innerHTML = `<p class="hint warn">${esc(Agenti.errorText(err))}</p>`;
      }
    }
    tasks.push(paintPolicies());

    // Vault (decisions 5 and 6, audit run 1): what protects the data now, and
    // the one vault action the web may take — turning it on, behind a fresh
    // admin re-authentication. The passphrase goes to the server in the request
    // body and reaches root on stdin; nothing stores it.
    const vPanel = document.getElementById("vault-panel");
    vPanel.hidden = false;
    const vState = document.getElementById("vault-state");
    const vBanner = document.getElementById("vault-banner");
    const vBtn = document.getElementById("vault-on-btn");
    const vDlg = document.getElementById("vault-dialog");
    const vForm = document.getElementById("vault-form");
    const vFormBanner = document.getElementById("vault-form-banner");
    async function paintVault() {
      try {
        const d = await Agenti.get("dashboard");
        const st = d.storage || {};
        document.getElementById("vault-on-row").hidden = d.vault !== "off";
        if (d.vault === "unlocked") {
          vState.innerHTML = `<p><strong>The vault is on and unlocked.</strong> Locking, unlocking, changing the passphrase and turning it off are done at the server's terminal (<code>sudo agenti vault --help</code>).</p>`;
        } else if (d.vault === "locked") {
          vState.innerHTML = `<p><strong>The vault is locked.</strong> Unlock it at the server: <code>sudo agenti vault unlock</code></p>`;
        } else if (st.encrypted) {
          vState.innerHTML = `<p>The vault is off, but this server's disk is encrypted (full-disk encryption), so the data is encrypted at rest. You can still add the vault.</p>`;
        } else {
          vState.innerHTML = "";
          Agenti.banner(vBanner, "warn", "Data from agents is currently not encrypted: reports, scans, attached files and the API key are plain files on this server's disk.");
        }
      } catch (err) {
        Agenti.banner(vBanner, "err", Agenti.errorText(err));
      }
    }
    tasks.push(paintVault());
    vBtn.addEventListener("click", () => {
      vForm.reset(); vFormBanner.className = "banner err";
      vDlg.showModal();
    });
    document.getElementById("vault-cancel").addEventListener("click", () => vDlg.close());
    vForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const pass = document.getElementById("vault-pass").value;
      const pass2 = document.getElementById("vault-pass2").value;
      const size = document.getElementById("vault-size").value;
      if (pass.length < 12) { Agenti.banner(vFormBanner, "err", "The passphrase must be at least 12 characters."); return; }
      if (pass !== pass2) { Agenti.banner(vFormBanner, "err", "The two passphrases are not the same."); return; }
      if (!document.getElementById("vault-ack").checked) { Agenti.banner(vFormBanner, "err", "Tick the box to confirm you have stored the passphrase."); return; }
      vDlg.close();
      vBtn.disabled = true;
      Agenti.banner(vBanner, "ok", "Turning the vault on — this takes a few minutes. Keep this page open.");
      try {
        const r = await Agenti.requireApproval({
          title: "Turn on the vault",
          description: `Confirm it's you to create a ${size.replace("G", " GB")} encrypted vault and move the data into it.`,
          submit: (creds) => Agenti.post("admin/vault/enable", { size, passphrase: pass,
            password: creds.password, totp: creds.totp, reauth: creds.reauth }),
        });
        if (!r) { Agenti.banner(vBanner, "warn", "Cancelled — nothing was changed."); return; }
        Agenti.banner(vBanner, "ok", "The vault is on. After every restart of the server, someone must unlock it at its terminal: sudo agenti vault unlock");
        await paintVault();
      } catch (err) {
        Agenti.banner(vBanner, "err", Agenti.errorText(err));
      } finally {
        vBtn.disabled = false;
        vForm.reset();
      }
    });

    // Updates: report-only. The button calls GET admin/update-check, which asks GitHub
    // only if root switched the policy on; otherwise it answers with the command to enable it.
    const upPanel = document.getElementById("updates-panel");
    upPanel.hidden = false;
    const upBtn = document.getElementById("updates-check-btn");
    const upOut = document.getElementById("updates-result");
    const upBanner = document.getElementById("updates-banner");
    const cmdLine = (cmd) => `<div class="copyable"><code class="cmd-block">${esc(cmd)}</code>${Agenti.copyButtonHtml(cmd, "Copy command")}</div>`;
    upBtn.addEventListener("click", async () => {
      upBtn.disabled = true;
      upBanner.innerHTML = "";
      upOut.innerHTML = `<p class="hint">Checking…</p>`;
      try {
        const r = await Agenti.get("admin/update-check");
        const inst = esc(r.installed || "unknown");
        if (!r.enabled) {
          upOut.innerHTML = `<p>Update checking is off, so no request was made. Installed version: <strong>${inst}</strong>.</p>
            <p class="hint">To allow it, run on the host:</p>${cmdLine(r.enable_command)}`;
        } else if (!r.checked) {
          upOut.innerHTML = "";
          Agenti.banner(upBanner, "warn", `Could not check for updates: ${r.error || "unknown problem"}.`);
        } else if (r.update_available) {
          upOut.innerHTML = `<p>Installed <strong>${inst}</strong>. A newer version, <strong>${esc(r.latest)}</strong>, is available.</p>
            <p class="hint">Nothing has been installed. To update, run on the host:</p>${cmdLine(r.install_command)}
            ${r.release_url ? `<p class="hint"><a href="${esc(r.release_url)}" target="_blank" rel="noopener noreferrer">Release notes</a></p>` : ""}`;
        } else {
          upOut.innerHTML = `<p>Installed <strong>${inst}</strong>. You are up to date (latest release: ${esc(r.latest)}).</p>`;
        }
        if (Agenti.wireCopyButtons) Agenti.wireCopyButtons(upOut);
      } catch (err) {
        upOut.innerHTML = "";
        Agenti.banner(upBanner, "err", Agenti.errorText(err));
      } finally {
        upBtn.disabled = false;
      }
    });
  }
  // ---------- Tool requests (admin, read-only — phase 7 of the
  // generic-launcher arc, decision 4) ----------
  if (canReadIam) {
    const panel = document.getElementById("tool-requests-panel");
    panel.hidden = false;
    const list = document.getElementById("tool-requests-list");
    const banner = document.getElementById("tool-requests-banner");
    list.innerHTML = `<p class="list-empty">Loading…</p>`;
    tasks.push((async () => { try {
      const rows = await Agenti.get("admin/tool-requests");
      // A "program" request: show the install command to run at a terminal
      // (the website never installs software), only for a plain program name.
      const installCmd = (r) => {
        if (r.category !== "install-program") return "";
        const prog = String(r.text || "").split(":")[0].trim();
        return /^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/.test(prog) ? `sudo apt install ${prog}` : "";
      };
      list.innerHTML = rows.length
        ? rows.map((r) => {
          const cmd = installCmd(r);
          return `
          <div class="list-row">
            <span class="list-icon">${Agenti.icon(r.category === "install-program" ? "download" : "wrench")}</span>
            <div class="list-main">
              <div class="list-title">${r.category === "install-program" ? `<span class="wiz-tag">Install a program</span> ` : ""}${esc(r.text)}</div>
              <div class="list-sub">${esc(r.by)}${r.category && r.category !== "install-program" ? ` · ${esc(r.category)}` : ""} · ${esc(Agenti.when(r.created_at))}</div>
              ${cmd ? `<div class="list-sub">Run on the server: <code>${esc(cmd)}</code> ${Agenti.copyButtonHtml(cmd, "Copy the install command")}
                — then add it under Agents → Controls → Program catalog.</div>` : ""}
            </div>
          </div>`; }).join("")
        : `<p class="list-empty">Nothing filed yet.</p>`;
      if (Agenti.wireCopyButtons) Agenti.wireCopyButtons(list);
    } catch (err) {
      Agenti.banner(banner, "err", Agenti.errorText(err));
    } })());
  }
  // ---------- Users (admin) ----------
  if (showUsers) {
    const panel = document.getElementById("users-panel");
    panel.hidden = false;
    const tbody = document.getElementById("users-tbody");
    const usersBanner = document.getElementById("users-banner");
    const WEB_ROLES = ["operator", "admin"];
    const roleLabel = Agenti.roleLabel;
    const userUrl = (name, action) => `admin/users/${encodeURIComponent(name)}/${action}`;
    const describeAccess = (role) => `${roleLabel(role)} access for the whole organisation`;

    // The table's Role cell is read-only plain text: just the role word(s).
    // Removing access only happens from inside the Grant dialog.
    function roleText(name, bindings) {
      const mine = bindings.filter((b) => b.subject_kind === "user" && b.subject === name
        && WEB_ROLES.includes(b.role));
      if (!mine.length) return `<span class="muted">none</span>`;
      return esc(mine.map((b) => `${b.effect === "deny" ? "DENY " : ""}${roleLabel(b.role)}`).join(", "));
    }

    const usersPager = makePager(document.getElementById("users-pager"), { onChange: renderUsersRows });
    let usersCache = [];
    let bindingsCache = [];
    // Status is a plain dot, the word rides the title tooltip along with the
    // password/2FA set-up state.
    function statusTitle(r) {
      if (!r.active) return "Disabled";
      if (r.kind === "service") return "Active (service account)";
      if (!r.has_password) return "Active — no password set yet (one-time link pending)";
      if (r.totp_required && !r.has_totp) return "Active — 2FA required by policy, not yet set up";
      return "Active";
    }
    // The Dashboard button, drawn only where the server's ladder
    // (iam.dashboard_access) would let this caller open it: an admin opens
    // anyone's but another admin's, never their own (that's the landing
    // page). The server checks again regardless.
    const roleOf = (name, role) => bindingsCache.some((b) => b.subject_kind === "user"
      && b.subject === name && b.effect === "allow" && b.role === role);
    function canOpenDashboard(r) {
      return canManage && r.name !== me.user && !roleOf(r.name, "admin");
    }
    function renderUsersRows() {
      const rows = usersPager.slice(usersCache);
      tbody.innerHTML = rows.map((r) => `
          <tr>
            <td>${esc(r.name)}</td>
            <td>${esc(r.kind)}</td>
            <td class="status-cell"><span class="status-dot ${r.active ? "ok" : "err"}" title="${esc(statusTitle(r))}"><span class="sr-only">${esc(statusTitle(r))}</span></span></td>
            <td class="access-cell">${roleText(r.name, bindingsCache)}</td>
            <td class="dashboard-cell">${canOpenDashboard(r) ? `<button type="button" class="btn btn-sm" data-dashboard="${esc(r.name)}" title="Open ${esc(r.name)}'s dashboard" aria-label="Open ${esc(r.name)}'s dashboard">${Agenti.icon("dashboard", 14)}<span class="lbl-full">View dashboard</span></button>` : ""}</td>
            <td class="actions">${canManage && r.active ? `
              <button type="button" class="btn btn-sm btn-icon btn-primary" data-grant="${esc(r.name)}" title="Security settings for ${esc(r.name)}…" aria-label="Security settings for ${esc(r.name)}">${Agenti.icon("key", 15)}</button>
              ${!r.has_password ? `<button type="button" class="btn btn-sm btn-icon" data-relink="${esc(r.name)}" title="New set-up link for ${esc(r.name)}" aria-label="New set-up link for ${esc(r.name)}">${Agenti.icon("link", 15)}</button>` : ""}
            ` : ""}${canManage && r.name !== me.user ? `
              <button type="button" class="btn btn-sm btn-icon" data-rename="${esc(r.name)}" title="Rename ${esc(r.name)}…" aria-label="Rename ${esc(r.name)}">${Agenti.icon("edit", 15)}</button>
              <span class="actions-gap" aria-hidden="true"></span>
              ${r.active ? `<button type="button" class="btn btn-sm btn-icon btn-danger" data-disable="${esc(r.name)}" title="Disable ${esc(r.name)}" aria-label="Disable ${esc(r.name)}">${Agenti.icon("lock", 15)}</button>`
                         : `<button type="button" class="btn btn-sm btn-icon" data-enable="${esc(r.name)}" title="Re-enable ${esc(r.name)}…" aria-label="Re-enable ${esc(r.name)}">${Agenti.icon("check", 15)}</button>`}
              <button type="button" class="btn btn-sm btn-icon btn-danger" data-delete="${esc(r.name)}" title="Permanently delete ${esc(r.name)}…" aria-label="Permanently delete ${esc(r.name)}">${Agenti.icon("trash", 15)}</button>
            ` : ""}</td>
          </tr>`).join("") || `<tr><td colspan="6" class="muted">No users.</td></tr>`;
      usersPager.render();
    }

    async function paintUsers() {
      if (!tbody.querySelector("tr")) tbody.innerHTML = `<tr><td colspan="6" class="muted">Loading…</td></tr>`;
      try {
        const [rows, bindings] = await Promise.all([Agenti.get("admin/users"), Agenti.get("admin/bindings")]);
        bindingsCache = bindings || [];
        usersCache = (rows || []).slice().sort((a, b) => a.name.localeCompare(b.name));
        usersPager.setTotal(usersCache.length);
        renderUsersRows();
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6"><p class="hint warn">${esc(Agenti.errorText(err))}</p></td></tr>`;
        document.getElementById("users-pager").innerHTML = "";
      }
    }
    tasks.push(paintUsers());

    // ----- "<name>'s dashboard" pop-up -----
    // An exact copy of that user's landing page: dashboard.html itself, in
    // embed mode, scoped to them (?user=). Every page reached from it keeps
    // ?user=&embed=1, so the admin stays inside the pop-up and inside what
    // the server lets them do there.
    const udDialog = document.getElementById("user-dashboard-dialog");
    const udFrame = document.getElementById("ud-frame");
    tbody.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-dashboard]");
      if (!btn) return;
      const name = btn.dataset.dashboard;
      document.getElementById("ud-title").textContent = `${name}'s dashboard`;
      udFrame.title = `${name}'s dashboard`;
      udFrame.src = `dashboard.html?user=${encodeURIComponent(name)}&embed=1`;
      udDialog.showModal();
    });
    document.getElementById("ud-close").addEventListener("click", () => udDialog.close());
    // Closing unloads the page, which ends its live streams.
    udDialog.addEventListener("close", () => { udFrame.src = "about:blank"; });

    // ----- the grant dialog -----
    const dlg = document.getElementById("grant-dialog");
    const grantForm = document.getElementById("grant-form");
    const grantBanner = document.getElementById("grant-banner");
    const grantWho = document.getElementById("grant-who");
    const grantCurrentField = document.getElementById("grant-current-field");
    const grantCurrentList = document.getElementById("grant-current-list");
    // The shared role picker — ONE template (settings.html's
    // #access-section-template), cloned into the Grant dialog and the New
    // User dialog, so the two pickers are structurally identical markup, not
    // two hand-copied lookalikes.
    function mountAccessSection(mountEl) {
      const tpl = document.getElementById("access-section-template");
      mountEl.innerHTML = "";
      mountEl.appendChild(tpl.content.cloneNode(true));
      const root = mountEl;
      return {
        root,
        getRole: () => root.querySelector('input[name="role"]:checked').value,
        setRole: (role) => {
          const r = root.querySelector(`input[name="role"][value="${role}"]`)
            || root.querySelector('input[name="role"][value="operator"]');
          r.checked = true;
        },
      };
    }
    const grantEls = mountAccessSection(document.querySelector("#grant-form [data-access-mount]"));

    // The ONLY place access can be removed from: an immediate web_unbind call
    // with no re-authentication, since taking authority away is always the
    // safe direction.
    function renderGrantCurrent(name) {
      const mine = bindingsCache.filter((b) => b.subject_kind === "user" && b.subject === name
        && WEB_ROLES.includes(b.role));
      grantCurrentField.hidden = !mine.length;
      grantCurrentList.innerHTML = mine.map((b) => {
        // Your own admin binding is the one thing this dialog must not let you
        // take away: there would be nobody left signed in to give it back
        // from here (the server refuses it too).
        const own = name === me.user && b.role === "admin";
        const removable = b.effect === "allow" && !own;
        return `<div class="field-row" style="align-items:center; gap:8px; margin:0;">
          <span class="chip chip-locked" style="flex:1 1 auto; margin:0;">${esc(`${b.effect === "deny" ? "DENY " : ""}${roleLabel(b.role)}`)}</span>
          ${removable ? `<button type="button" class="btn btn-sm btn-danger" data-remove-current='${esc(JSON.stringify({ name, role: b.role }))}'>Remove</button>`
            : own ? `<span class="hint" style="margin:0;">your own access — another admin can change it</span>` : ""}
        </div>`;
      }).join("");
    }
    grantCurrentList.addEventListener("click", async (e) => {
      const target = e.target.closest("[data-remove-current]");
      if (!target) return;
      const b = JSON.parse(target.dataset.removeCurrent);
      grantBanner.className = "banner";
      if (!confirm(`Remove ${roleLabel(b.role)} from '${b.name}'? They lose that access on their next request.`)) return;
      target.disabled = true;
      try {
        await Agenti.post(userUrl(b.name, "access/remove"), { role: b.role });
        await paintUsers();
        renderGrantCurrent(b.name);
      } catch (err) {
        Agenti.banner(grantBanner, "err", Agenti.errorText(err));
      } finally {
        target.disabled = false;
      }
    });
    // Password/MFA reset for a DIFFERENT user — admin only, through
    // /admin/users/... Two independent actions, per their own explicit ask
    // ("I want the resetting password job and resetting MFA job to be
    // separate tasks") — resetting one never touches the other, and each
    // mints its own approval grant.
    const resetPasswordField = document.getElementById("reset-password-field");
    const resetMfaField = document.getElementById("reset-mfa-field");
    const resetBanner = document.getElementById("reset-banner");
    const resetPasswordDirectBtn = document.getElementById("reset-password-direct-btn");
    const resetPasswordLinkBtn = document.getElementById("reset-password-link-btn");
    const resetPasswordDirectForm = document.getElementById("reset-password-direct-form");
    const resetPasswordValue = document.getElementById("reset-password-value");
    const resetPasswordDirectConfirm = document.getElementById("reset-password-direct-confirm");
    const resetPasswordDirectCancel = document.getElementById("reset-password-direct-cancel");
    const resetPasswordLinkResult = document.getElementById("reset-password-link-result");
    const resetPasswordLinkValue = document.getElementById("reset-password-link-value");
    const resetMfaBtn = document.getElementById("reset-mfa-btn");

    function resetPasswordWithApproval(name, mode, newPassword) {
      return Agenti.requireApproval({
        title: mode === "link" ? "Send password reset link" : "Reset password",
        description: mode === "link"
          ? `Generate a one-time password reset link for '${name}', valid 24h. `
            + `You never see the password they choose.`
          : `Set a new password for '${name}' directly. They are signed out `
            + `everywhere immediately.`,
        submit: (creds) => Agenti.post(`admin/users/${encodeURIComponent(name)}/reset-password`,
          { mode, new_password: mode === "direct" ? newPassword : undefined,
            password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
    }

    function resetMfaWithApproval(name) {
      return Agenti.requireApproval({
        title: "Reset two-factor authentication",
        description: `Clear every authenticator app and passkey for '${name}'. They'll be `
          + `prompted to set up 2FA again at their next sign-in, if it's required for `
          + `their account.`,
        submit: (creds) => Agenti.post(`admin/users/${encodeURIComponent(name)}/reset-mfa`,
          { password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
    }

    resetPasswordDirectBtn.addEventListener("click", () => {
      resetBanner.className = "banner";
      resetPasswordLinkResult.hidden = true;
      resetPasswordValue.value = "";
      resetPasswordDirectForm.hidden = false;
      resetPasswordValue.focus();
    });
    resetPasswordDirectCancel.addEventListener("click", () => {
      resetPasswordDirectForm.hidden = true;
      resetPasswordValue.value = "";
    });
    resetPasswordDirectConfirm.addEventListener("click", async () => {
      const name = grantForm.dataset.name;
      const value = resetPasswordValue.value;
      resetBanner.className = "banner";
      if (!value) {
        Agenti.banner(resetBanner, "err", "Enter a new password first.");
        return;
      }
      resetPasswordDirectConfirm.disabled = true;
      try {
        const r = await resetPasswordWithApproval(name, "direct", value);
        if (!r) return; // cancelled
        resetPasswordDirectForm.hidden = true;
        resetPasswordValue.value = "";
        Agenti.banner(resetBanner, "ok", `Password reset for '${r.user}' (approved by `
          + `${r.approved_by}); ${r.sessions_revoked} session(s) revoked.`);
      } finally {
        resetPasswordDirectConfirm.disabled = false;
      }
    });
    resetPasswordLinkBtn.addEventListener("click", async () => {
      const name = grantForm.dataset.name;
      resetBanner.className = "banner";
      resetPasswordDirectForm.hidden = true;
      resetPasswordLinkBtn.disabled = true;
      try {
        const r = await resetPasswordWithApproval(name, "link");
        if (!r) return; // cancelled
        const url = `${location.origin}/reset-password.html?token=${encodeURIComponent(r.reset_token)}`;
        resetPasswordLinkValue.textContent = url;
        resetPasswordLinkValue.parentElement.querySelectorAll("button.copy-btn").forEach((b) => b.remove());
        resetPasswordLinkValue.parentElement.appendChild(Agenti.copyButton(url, "Copy link"));
        resetPasswordLinkResult.hidden = false;
      } finally {
        resetPasswordLinkBtn.disabled = false;
      }
    });
    resetMfaBtn.addEventListener("click", async () => {
      const name = grantForm.dataset.name;
      if (!confirm(`Reset MFA for '${name}'? Every authenticator app and passkey on the `
        + `account stops working immediately.`)) return;
      resetBanner.className = "banner";
      resetMfaBtn.disabled = true;
      try {
        const r = await resetMfaWithApproval(name);
        if (!r) return; // cancelled
        Agenti.banner(resetBanner, "ok", `2FA reset for '${r.user}' (approved by `
          + `${r.approved_by}); ${r.passkeys_removed} passkey(s) removed.`);
      } finally {
        resetMfaBtn.disabled = false;
      }
    });

    // Pre-selects the target's current BEST role — highest authority first.
    const ROLE_PRIORITY = ["admin", "operator"];
    async function openGrant(name, presetRole) {
      grantWho.textContent = name;
      grantForm.dataset.name = name;
      grantBanner.className = "banner";
      resetBanner.className = "banner";
      resetPasswordDirectForm.hidden = true;
      resetPasswordLinkResult.hidden = true;
      resetPasswordValue.value = "";
      resetPasswordField.hidden = !canManage;
      resetMfaField.hidden = !canManage;
      const resetSection = document.getElementById("reset-section");
      resetSection.hidden = !canManage;
      resetSection.open = false;
      renderGrantCurrent(name);
      const currentRoles = bindingsCache.filter((b) => b.subject_kind === "user"
        && b.subject === name && b.effect === "allow" && WEB_ROLES.includes(b.role));
      grantEls.setRole(ROLE_PRIORITY.find((r) => currentRoles.some((b) => b.role === r)) || presetRole || "operator");
      dlg.showModal();
    }
    document.getElementById("grant-cancel").addEventListener("click", () => dlg.close());
    // Runs the actual re-authenticated grant through the ONE universal
    // approval popup (api.js requireApproval). Returns the API response on
    // success, or null if the admin cancelled the popup.
    async function grantWithApproval(name, role) {
      return Agenti.requireApproval({
        title: "Grant access",
        description: `Grant ${describeAccess(role)} to '${name}'.`,
        submit: (creds) => Agenti.post(userUrl(name, "access"),
          { role, password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
    }

    // Rename/delete both re-point or destroy an identity every audit/run-
    // history record refers to, so authd always requires the password too.
    async function renameWithApproval(oldName, newName) {
      return Agenti.requireApproval({
        title: "Rename user",
        description: `Rename '${oldName}' to '${newName}' — every permission, API key `
          + `and passkey moves with it. Their session ends; they'll need to sign in `
          + `again as '${newName}'.`,
        submit: (creds) => Agenti.post(userUrl(oldName, "rename"),
          { new_name: newName, password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
    }

    async function deleteWithApproval(name) {
      return Agenti.requireApproval({
        title: "Delete user",
        description: `Permanently delete '${name}'. This cannot be undone — every `
          + `credential, permission and API key is destroyed. Their name stays on `
          + `past reports, run history and audit logs, marked (deleted).`,
        confirmText: "DELETE",
        submit: (creds) => Agenti.post(userUrl(name, "delete"),
          { password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
    }

    async function enableWithApproval(name) {
      return Agenti.requireApproval({
        title: "Re-enable user",
        description: `Re-enable '${name}'. They can sign in again and get back whatever `
          + `access the account kept, so this needs your password and a 2FA code (or a passkey).`,
        submit: (creds) => Agenti.post(userUrl(name, "enable"),
          { password: creds.password, totp: creds.totp, reauth: creds.reauth }),
      });
    }

    // "Save access": grants the chosen role. Granting is a real,
    // re-authenticated action (the one approval popup, every time); a role
    // already held is simply left alone.
    grantForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      grantBanner.className = "banner";
      const name = grantForm.dataset.name;
      const role = grantEls.getRole();
      const already = bindingsCache.some((b) => b.subject_kind === "user" && b.subject === name
        && b.effect === "allow" && b.role === role);
      if (already) {
        Agenti.banner(grantBanner, "ok", `${name} already has ${roleLabel(role)} access.`);
        return;
      }
      const btn = document.getElementById("grant-submit");
      btn.disabled = true;
      try {
        const r = await grantWithApproval(name, role);
        if (!r) { Agenti.banner(grantBanner, "err", "Cancelled — nothing was saved."); return; }
        dlg.close();
        Agenti.banner(usersBanner, "ok", `${name} now has ${describeAccess(role)}.`);
        await paintUsers();
      } catch (err) {
        Agenti.banner(grantBanner, "err", Agenti.errorText(err));
      } finally {
        btn.disabled = false;
      }
    });

    tbody.addEventListener("click", async (e) => {
      const target = e.target.closest("button");
      if (!target) return;
      const disableName = target.dataset.disable;
      const relinkName = target.dataset.relink;
      const grantName = target.dataset.grant;
      const renameName = target.dataset.rename;
      const deleteName = target.dataset.delete;
      const enableName = target.dataset.enable;
      usersBanner.className = "banner";
      if (enableName) {
        const r = await enableWithApproval(enableName);
        if (!r) return; // cancelled
        Agenti.banner(usersBanner, "ok", `'${r.user}' can sign in again (approved by ${r.approved_by}).`);
        await paintUsers();
      } else if (grantName) {
        openGrant(grantName);
      } else if (renameName) {
        openRenameUser(renameName);
      } else if (deleteName) {
        const r = await deleteWithApproval(deleteName);
        if (!r) return; // cancelled
        Agenti.banner(usersBanner, "ok", `'${r.name}' was permanently deleted (approved by ${r.approved_by}).`);
        await paintUsers();
      } else if (disableName) {
        if (!confirm(`Disable '${disableName}'? They will be signed out immediately and cannot log in until an admin re-enables the account (the check-mark button on their row).`)) return;
        try {
          await Agenti.post(userUrl(disableName, "disable"));
          await paintUsers();
        } catch (err) { Agenti.banner(usersBanner, "err", Agenti.errorText(err)); }
      } else if (relinkName) {
        try {
          const r = await Agenti.post(userUrl(relinkName, "enrolment-link"));
          showEnrolmentLink(relinkName, r.enrolment_token,
            `New one-time set-up link for '${relinkName}'. Send it to them — it lets them set their own password (and 2FA) and expires in 48h:`);
        } catch (err) { Agenti.banner(usersBanner, "err", Agenti.errorText(err)); }
      }
    });

    // ----- the Rename user dialog -----
    const renameUserDlg = document.getElementById("user-rename-dialog");
    const renameUserForm = document.getElementById("user-rename-form");
    const renameUserInput = document.getElementById("user-rename-name");
    const renameUserBanner = document.getElementById("user-rename-banner");
    let renameUserTarget = null;
    function openRenameUser(name) {
      renameUserTarget = name;
      renameUserBanner.className = "banner";
      document.getElementById("user-rename-who").textContent = name;
      renameUserInput.value = name;
      renameUserDlg.showModal();
      renameUserInput.select();
    }
    document.getElementById("user-rename-cancel").addEventListener("click", () => renameUserDlg.close());
    renameUserForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const oldName = renameUserTarget;
      const newName = renameUserInput.value.trim().toLowerCase();
      if (!newName || newName === oldName) { renameUserDlg.close(); return; }
      if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(newName)) {
        Agenti.banner(renameUserBanner, "err", "Names are lowercase letters, digits, '-' or '_', starting with a letter or digit, max 64 characters.");
        return;
      }
      renameUserDlg.close();
      const r = await renameWithApproval(oldName, newName);
      if (!r) return; // cancelled
      Agenti.banner(usersBanner, "ok", `'${r.old}' is now '${r.new}' (approved by ${r.approved_by}).`);
      await paintUsers();
    });

    const linkPanel = document.getElementById("new-user-link-panel");
    const linkCode = document.getElementById("new-user-link");
    function showEnrolmentLink(name, token, lead) {
      const url = `${location.origin}/enrol.html?token=${encodeURIComponent(token)}`;
      document.getElementById("new-user-link-lead").textContent = lead;
      linkCode.textContent = url;
      linkCode.parentElement.querySelectorAll("button.copy-btn").forEach((b) => b.remove());
      linkCode.parentElement.appendChild(Agenti.copyButton(url, "Copy link"));
      linkPanel.hidden = false;
      linkPanel.scrollIntoView({ block: "nearest" });
    }

    // ----- the New user dialog -----
    const newUserOpenBtn = document.getElementById("new-user-open-btn");
    if (canManage) {
      const newUserDlg = document.getElementById("new-user-dialog");
      const newUserForm = document.getElementById("add-user-form");
      const newUserBanner = document.getElementById("new-user-banner");
      const newUserName = document.getElementById("new-user-name");
      const newUserKind = document.getElementById("new-user-kind");
      const newUserEls = mountAccessSection(document.querySelector("#add-user-form [data-access-mount]"));

      newUserOpenBtn.addEventListener("click", () => {
        newUserBanner.className = "banner";
        newUserForm.reset();
        newUserEls.setRole("operator");
        newUserDlg.showModal();
        newUserName.focus();
      });
      document.getElementById("new-user-cancel").addEventListener("click", () => newUserDlg.close());

      newUserForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        newUserBanner.className = "banner";
        linkPanel.hidden = true;
        const name = newUserName.value.trim();
        const kind = newUserKind.value;
        const role = newUserEls.getRole();
        const btn = document.getElementById("new-user-submit");
        btn.disabled = true;
        try {
          // Creating an account is an admin action like any other: the wizard
          // ends with the re-authentication popup, every time, and one
          // approval covers the account AND its role. Nothing
          // is created until it passes (operator decision 2026-10-22).
          const r = await Agenti.requireApproval({
            title: "Create user",
            description: `Create ${kind === "service" ? "the service account" : "the account"} `
              + `'${name}' with ${describeAccess(role)}. Confirm it's you to finish.`,
            submit: (creds) => Agenti.post("admin/users", {
              name, kind, role, no_link: kind === "service",
              password: creds.password, totp: creds.totp, reauth: creds.reauth }),
          });
          if (!r) return;     // cancelled: nothing was created; the wizard stays open
          newUserDlg.close();
          await paintUsers();
          if (r.enrolment_token) {
            showEnrolmentLink(name, r.enrolment_token,
              `Account created with ${describeAccess(role)}. Send this ONE-TIME link to them — it lets them set their own password and 2FA, and expires in 48h:`);
          } else {
            Agenti.banner(usersBanner, "ok", `Service account '${name}' created with ${describeAccess(role)}. Issue it an API key on the host: sudo agenti admin issue-key --user ${name}`);
          }
        } catch (err) {
          Agenti.banner(newUserBanner, "err", Agenti.errorText(err));
        } finally {
          btn.disabled = false;
        }
      });
    } else if (newUserOpenBtn) {
      newUserOpenBtn.hidden = true;
    }
  }

  await Promise.allSettled([...tasks, passkeysLoading]);
});
