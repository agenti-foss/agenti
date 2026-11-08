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
    { id: "providers", label: "AI providers", icon: "cpu", note: "admin" },
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

  // ---------- Hidden messages ("Don't show again", api.js) ----------
  (async () => {
    const panel = document.getElementById("hidden-messages-panel");
    const n = await Agenti.hiddenBannerCount();
    if (!n) return;
    panel.hidden = false;
    document.getElementById("hidden-messages-count").textContent =
      `${n} message${n === 1 ? "" : "s"} hidden with “Don't show again”.`;
    document.getElementById("hidden-messages-btn").addEventListener("click", async () => {
      await Agenti.showHiddenBanners();
      document.getElementById("hidden-messages-count").textContent =
        "They'll show again where they apply.";
      document.getElementById("hidden-messages-btn").hidden = true;
    });
  })();

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
  tabs.querySelector('[data-pane="providers"]').hidden = !canManage;
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
  // Like 2FA set-up (operator note 2026-11-08): only a "Change password"
  // button until you've confirmed it's you in the ONE popup
  // (Agenti.requireApproval). That re-authentication mints a single-use,
  // two-minute grant server-side (`self password-start`); then the box
  // appears, filled with a generated password (password-gen.js), and saving
  // spends the grant. A too-short or unchanged password is refused without
  // spending it, so it can be fixed in place.
  const pwForm = document.getElementById("password-form");
  const pwBanner = document.getElementById("pw-banner");
  const pwStartPanel = document.getElementById("pw-start-panel");
  const pwStartBtn = document.getElementById("pw-start-btn");
  document.getElementById("pw-username").value = me.user || "";
  const pwGen = AgentiPassword.attach(document.getElementById("pw-new"));
  let pwGrant = null, pwTimer = null;
  function closePasswordForm() {
    clearTimeout(pwTimer);
    pwGrant = null;
    pwGen.hide();
    pwForm.hidden = true;
    pwStartPanel.hidden = false;
  }
  pwStartBtn.addEventListener("click", async () => {
    pwBanner.className = "banner";
    const r = await Agenti.requireApproval({
      title: "Change password",
      description: "Confirm it's you, then choose your new password.",
      submit: (creds) => Agenti.post("auth/password/start",
        { current: creds.password || undefined, totp: creds.totp || undefined, reauth: creds.reauth }),
    });
    if (!r) return; // cancelled — nothing changed
    pwGrant = r.grant;
    pwGen.regenerate();
    pwStartPanel.hidden = true;
    pwForm.hidden = false;
    pwForm.querySelector("button[type=submit]").focus();
    clearTimeout(pwTimer);
    pwTimer = setTimeout(() => {
      closePasswordForm();
      Agenti.banner(pwBanner, "warn", "For your security, that closed after 2 minutes. Press Change password to start again.");
    }, Math.max(10, (r.expires_in || 120) - 2) * 1000);
  });
  document.getElementById("pw-cancel-btn").addEventListener("click", () => {
    pwBanner.className = "banner";
    closePasswordForm();
    pwStartBtn.focus();
  });
  pwForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    pwBanner.className = "banner";
    const problem = pwGen.check();
    if (problem) { Agenti.banner(pwBanner, "err", problem); return; }
    if (!pwGrant) { closePasswordForm(); return; }
    const btn = pwForm.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      await Agenti.post("auth/password", { new: pwGen.value, grant: pwGrant });
      clearTimeout(pwTimer);
      await pwGen.saved(me.user);
      Agenti.banner(pwBanner, "ok", "Password changed. Signing you out — log back in with the new one.");
      setTimeout(() => { Agenti.clearAuth(); location.href = "login.html"; }, 1600);
    } catch (err) {
      const msg = String((err && err.message) || err);
      // A spent or expired grant can't be retried: back to the button.
      if (/approval grant/i.test(msg)) {
        closePasswordForm();
        Agenti.banner(pwBanner, "err", "That confirmation has expired. Press Change password to confirm it's you again.");
      } else {
        Agenti.banner(pwBanner, "err", msg);
      }
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
    const qr = Agenti.qrCode(r.qr_modules, "QR code for your authenticator app");
    if (qr) qrHost.appendChild(qr);
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

  // The whole section exists only where passkeys can work: turned on, a
  // domain set, and this tab open at that domain (operator note 2026-11-06 —
  // opened by IP, it used to show a red warning and a greyed button).
  const passkeysHere = await Agenti.passkeysUsable();
  document.getElementById("passkeys-panel").hidden = !passkeysHere;

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
  const passkeysLoading = passkeysHere ? loadPasskeys() : Promise.resolve();   // awaited at the end

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
  // operational policy (caps, models). A card summarises it; the dialog
  // edits it. Operator decision 2026-11-06:
  //   * the second-approver policy OFF (default): one "Save and close", one
  //     confirmation — the save also records you as its approver;
  //   * ON: a save becomes a pending change that ANOTHER admin approves or
  //     rejects (its author may withdraw it). The card gets an amber outline
  //     and says so; the dialog shows Current | Pending. Until it is decided,
  //     runs must fit both versions. Caps, models and prices apply at once.
  // Nothing is ever lost by pressing the wrong button: Approve and Reject
  // are offered only while the form shows the change exactly as submitted.
  if (showEngagementBtn) {
    const engDlg = document.getElementById("engagement-dialog");
    const engForm = document.getElementById("engagement-form");
    const engBanner = document.getElementById("engagement-banner");
    const engStatus = document.getElementById("engagement-status");
    const engSaveBtn = document.getElementById("engagement-save");
    const engApproveBtn = document.getElementById("engagement-approve");
    const engApprovePendingBtn = document.getElementById("engagement-approve-pending");
    const engRejectBtn = document.getElementById("engagement-reject-pending");
    const engWithdrawBtn = document.getElementById("engagement-withdraw-pending");
    const engToggle = document.getElementById("eng-view-toggle");
    const rejectField = document.getElementById("eng-reject-field");
    const $id = (id) => document.getElementById(id);
    const engLinesOf = (id) => $id(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
    const when = (ts) => { const a = ts ? Agenti.ago(ts) : ""; return /ago|now/.test(a) ? a : a ? `on ${a}` : ""; };
    let data = null;            // GET /engagement, as opened
    let view = "current";       // which version the form shows
    let snapshot = "";          // the form as filled, to know if it was edited
    let clearCeilings = new Set();
    // Which ceilings the admin asked to revert to the platform default this
    // dialog session (Reset button) — "blank" already means "leave it alone".
    engForm.querySelectorAll("[data-clear-ceiling]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = btn.dataset.clearCeiling;
        clearCeilings.add(key);
        const input = $id(`eng2-${key}-ceiling`);
        input.value = "";
        input.disabled = true;
        btn.hidden = true;
        refreshButtons();
      });
    });

    // ---- the record <-> the form ----
    const FIELD_IDS = { engagement_id: "eng2-id", client: "eng2-client", authorizing_party: "eng2-party",
      authorizing_title: "eng2-title", valid_from: "eng2-from",
      valid_until: "eng2-until", emergency_contact: "eng2-contact", notes: "eng2-notes" };
    const LIST_IDS = { "scope.cidr.in_scope": "eng2-cidr-in", "scope.cidr.out_of_scope": "eng2-cidr-out",
      "scope.domain.in_scope": "eng2-domain-in", "scope.domain.out_of_scope": "eng2-domain-out",
      redact: "eng2-redact" };
    const pick = (rec, path) => path.split(".").reduce((o, k) => (o || {})[k], rec);
    function fillAuth(rec) {
      rec = rec || {};
      for (const [k, id] of Object.entries(FIELD_IDS)) $id(id).value = rec[k] || "";
      for (const [k, id] of Object.entries(LIST_IDS)) $id(id).value = (pick(rec, k) || []).join("\n");
      $id("eng2-capture").checked = !!rec.capture_payloads;
      $id("eng2-exploitation-enabled").checked = !!(rec.exploitation_enabled || (rec.enabled_capabilities || []).includes("exploit"));
      $id("eng2-retention").value = rec.retention_days || 0;
      // Exceptions fold away unless there are some: then they are shown.
      $id("eng-exceptions").open = !!($id("eng2-cidr-out").value || $id("eng2-domain-out").value);
    }
    function fillPolicy(rec) {
      // Values: what the record itself sets (blank = the platform default);
      // placeholders: the platform default a Reset goes back to.
      const pol = (rec || {}).policy || {};
      const def = data.platform_default_policy || {};
      const set = (id, v, ph) => { const el = $id(id); el.value = v != null ? v : ""; el.placeholder = ph; el.disabled = false; };
      set("eng2-turns-ceiling", pol.max_turns_ceiling, `default ${def.max_turns_ceiling ?? 40}`);
      set("eng2-budget-ceiling", pol.max_budget_usd_ceiling, `default $${def.max_budget_usd_ceiling ?? 10}`);
      set("eng2-timeout-ceiling", pol.timeout_s_ceiling, `default ${def.timeout_s_ceiling ?? 3600}`);
      $id("eng2-models").value = (pol.allowed_models || []).join("\n");
      $id("eng2-model-prices").value = Object.entries(pol.model_prices || {}).map(([n, p]) => `${n}=${p.join(",")}`).join("\n");
    }
    const formState = () => JSON.stringify([...engForm.querySelectorAll("input, textarea")]
      .filter((el) => el.id && !el.closest("#eng-reject-field"))
      .map((el) => (el.type === "checkbox" ? el.checked : el.value)).concat([...clearCeilings]));
    const edited = () => formState() !== snapshot;

    // Pending view: each field the change touches says so, with what is in
    // force now under it.
    function markChanges() {
      engForm.querySelectorAll(".field.changed, .check-row.changed").forEach((el) => el.classList.remove("changed"));
      engForm.querySelectorAll(".was").forEach((el) => el.remove());
      if (view !== "pending" || !data.pending || !data.record) return;
      const live = data.record, prop = data.pending.record;
      const show = (path, was) => {
        const host = engForm.querySelector(`[data-eng="${path}"]`);
        if (!host) return;
        host.classList.add("changed");
        const note = document.createElement("p");
        note.className = "was";
        note.textContent = `In force now: ${was === "" || was == null ? "(empty)" : was}`;
        host.appendChild(note);
      };
      for (const k of Object.keys(FIELD_IDS)) if ((live[k] || "") !== (prop[k] || "")) show(k, live[k] || "");
      for (const k of Object.keys(LIST_IDS)) {
        const a = pick(live, k) || [], b = pick(prop, k) || [];
        if (a.join("\n") !== b.join("\n")) show(k, a.join(", "));
      }
      if (!!live.capture_payloads !== !!prop.capture_payloads) show("capture_payloads", live.capture_payloads ? "on" : "off");
      const ex = (r) => (r.enabled_capabilities || []).includes("exploit");
      if (ex(live) !== ex(prop)) show("enabled_capabilities", ex(live) ? "allowed" : "not allowed");
      if ((live.retention_days || 0) !== (prop.retention_days || 0)) show("retention_days", String(live.retention_days || 0));
      for (const fold of ["eng-data-handling", "eng-exceptions"]) {
        if (engForm.querySelector(`#${fold} .changed`)) $id(fold).open = true;
      }
    }

    // ---- what the dialog says and offers ----
    const policyOn = () => data && data.second_approver === "on";
    const isAuthor = () => !!(data && data.pending && data.pending.author === me.user);
    function status(kind, text, extraHtml) {
      engStatus.className = `banner ${kind} show`;
      engStatus.textContent = text;
      if (extraHtml) { engStatus.insertAdjacentHTML("beforeend", extraHtml); Agenti.wireCopyButtons(engStatus); }
    }
    function paintStatus() {
      const st = data.approval_status || {}, p = data.pending;
      if (data.pending_invalid) {
        return status("err", `A waiting change can't be read, so runs are refused until it is replaced or rejected: ${data.pending_invalid}`);
      }
      if (!data.exists && !p) return status("warn", "No engagement yet: nothing can be scanned until one is saved.");
      if (p && view === "pending") {
        if (p.stale) return status("err", `${isAuthor() ? "Your" : `${p.author}'s`} change was made against an older version. Save it again, or reject it.`);
        if (isAuthor() && !policyOn()) return status("warn", "The second-approver policy is off now, so you may approve your own change.");
        if (isAuthor()) {
          if (p.approvers_available === false) {
            const cmd = "sudo agenti admin set-policy engagement-second-approver off";
            return status("warn", "Your change is waiting, but no other admin can approve it. Add an admin in Settings → Users, withdraw the change, or turn the policy off on the host and approve it yourself: ",
              `<span class="cmd-inline"><code>${esc(cmd)}</code>${Agenti.copyButtonHtml(cmd, "Copy command")}</span>`);
          }
          return status("warn", `Your change, saved ${when(p.authored_at)}, is waiting for another admin to approve it. Until then, runs must fit both versions.`);
        }
        return status("warn", `${p.author} submitted this change ${when(p.authored_at)}. Review it, then approve or reject it. Until then, runs must fit both versions.`);
      }
      if (p && view === "current") return status("ok", "The version in force. Switch to Pending to see the change waiting for approval.");
      if (data.exists && !st.current) {
        return status("warn", policyOn()
          ? "Not approved yet. Another admin approves it here before a run can start."
          : "Not approved yet. Save and close approves it as shown.");
      }
      if (policyOn()) {
        const lone = data.approvers_count != null && data.approvers_count < 2;
        return status(lone ? "warn" : "ok", lone
          ? "A save waits for another admin's approval, and no other admin can approve yet. Add one in Settings → Users first, or turn the second-approver policy off on the host."
          : "A save waits for another admin's approval. Until then, runs must fit both versions.");
      }
      engStatus.className = "banner";      // in force, approved, one-step saves: nothing to say
    }
    function refreshButtons() {
      const p = data && data.pending;
      const viewingPending = !!p && view === "pending";
      const untouched = !edited();
      const editable = canEditEngagement && (!p || viewingPending);
      engForm.querySelectorAll("input, textarea").forEach((el) => {
        if (el.closest("#eng-reject-field")) return;
        if (el.closest("[data-clear-ceiling]")) return;
        el.disabled = !editable || (el.id.endsWith("-ceiling") && clearCeilings.has(el.id.split("-")[1]));
      });
      engForm.querySelectorAll("[data-clear-ceiling]").forEach((b) => { b.hidden = !editable || clearCeilings.has(b.dataset.clearCeiling); });
      // One main action at a time: on a waiting change shown as submitted,
      // the choices are Approve / Reject (or Withdraw); editing it offers Save.
      engSaveBtn.hidden = !editable || (viewingPending && untouched);
      engSaveBtn.lastChild.textContent = p && !isAuthor() && viewingPending && !untouched ? "Save my version" : "Save and close";
      engApprovePendingBtn.hidden = !(viewingPending && canApproveEngagement && (!policyOn() || !isAuthor()) && !p.stale && untouched);
      engRejectBtn.hidden = !(viewingPending && canApproveEngagement && !isAuthor() && untouched);
      rejectField.hidden = engRejectBtn.hidden;
      engWithdrawBtn.hidden = !(viewingPending && isAuthor() && canEditEngagement && untouched);
      const st = (data && data.approval_status) || {};
      engApproveBtn.hidden = !(data && data.exists && !p && !st.current && policyOn() && canApproveEngagement
                               && (data.record || {}).updated_by !== me.user && untouched);
      if (data && data.pending_invalid && canApproveEngagement) { engRejectBtn.hidden = false; engRejectBtn.lastChild.textContent = "Discard it"; }
      else engRejectBtn.lastChild.textContent = "Reject";
    }
    function setView(v) {
      view = v;
      engToggle.querySelectorAll("[data-view]").forEach((b) => {
        const on = b.dataset.view === v;
        b.classList.toggle("active", on);
        b.setAttribute("aria-selected", String(on));
      });
      fillAuth(v === "pending" && data.pending ? data.pending.record : data.record);
      fillPolicy(data.record || (data.pending || {}).record);
      clearCeilings = new Set();
      snapshot = formState();
      markChanges();
      paintStatus();
      refreshButtons();
    }
    engToggle.querySelectorAll("[data-view]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
    engForm.addEventListener("input", refreshButtons);

    // ---- the card on the Engagement tab ----
    const engCard = $id("eng-card");
    const engSummary = $id("eng-summary");
    const engNote = $id("eng-edit-note");
    async function paintEngagementSummary(message) {
      const msg = $id("eng-card-msg");
      if (message) Agenti.banner(msg, "ok", message); else msg.className = "banner ok";
      try {
        const d = await Agenti.get("engagement");
        const rec = d.record || {};
        const p = d.pending;
        engCard.classList.toggle("attention", !!(p || d.pending_invalid));
        $id("eng-card-title").querySelector(".eng-card-icon").innerHTML = Agenti.icon(p ? "warning" : "shield", 18);
        if (p) {
          engNote.hidden = false;
          engNote.textContent = p.author === me.user
            ? "Engagement change submitted, pending approval of another admin"
            : canApproveEngagement ? `${p.author} submitted a change: it's waiting for your approval`
              : `${p.author} submitted a change, pending approval of another admin`;
        } else {
          engNote.hidden = true;
        }
        if (!d.exists && !p) {
          engSummary.innerHTML = `<p class="hint">No engagement yet. Nothing can be scanned until one is saved.</p>`;
          return;
        }
        const scope = (d.exists ? rec : p.record).scope || {};
        const count = (k) => ((scope[k] || {}).in_scope || []).length;
        const st = d.approval_status || {};
        const approval = st.current
          ? `<span class="ok-text">Approved by ${esc(st.approved_by || "?")}</span>`
          : `<span class="warn-text">${d.exists ? "Not approved" : "Waiting for its first approval"}</span>`;
        const r = d.exists ? rec : p.record;
        engSummary.innerHTML = `<dl class="kv">
          <dt>Engagement</dt><dd>${esc(r.engagement_id || "—")}</dd>
          <dt>Client</dt><dd>${esc(r.client || "—")}</dd>
          <dt>Valid</dt><dd>${esc(r.valid_from || "?")} to ${esc(r.valid_until || "?")}</dd>
          <dt>In scope</dt><dd>${count("cidr")} network range${count("cidr") === 1 ? "" : "s"}, ${count("domain")} domain${count("domain") === 1 ? "" : "s"}</dd>
          <dt>Approval</dt><dd>${approval}</dd>
          ${p ? `<dt>Pending</dt><dd>Change by ${esc(p.author === me.user ? "you" : p.author)}: until it's approved, runs must fit both versions.</dd>` : ""}
        </dl>`;
      } catch (err) {
        engSummary.innerHTML = `<p class="hint warn">${esc(Agenti.errorText(err))}</p>`;
      }
    }
    tasks.push(paintEngagementSummary());

    async function openEngagement() {
      engBanner.className = "banner";
      engStatus.className = "banner";
      $id("eng-reject-reason").value = "";
      engDlg.showModal();
      try {
        data = await Agenti.get("engagement");
      } catch (err) {
        // GET answers 200 with exists:false before the first engagement is
        // written; reaching this catch means a real failure.
        Agenti.banner(engBanner, "err", Agenti.errorText(err));
        return;
      }
      engToggle.hidden = !(data.pending && data.exists);
      setView(data.pending ? "pending" : "current");
    }
    // Exposed on window so gui_check.py (and a future deep link) can open the
    // dialog without synthesising a click.
    window.__agentiOpenEngagement = openEngagement;
    $id("eng-edit-btn").addEventListener("click", openEngagement);
    $id("engagement-cancel").addEventListener("click", () => engDlg.close());
    // Closed any way (Close, ✕, Esc): the card shows what is true now.
    engDlg.addEventListener("close", () => { if (!engDlg.dataset.keepMsg) paintEngagementSummary(); delete engDlg.dataset.keepMsg; });
    function done(message) {
      engDlg.dataset.keepMsg = "1";
      engDlg.close();
      paintEngagementSummary(message);
    }

    function formBody() {
      const body = {
        engagement_id: $id("eng2-id").value.trim(),
        client: $id("eng2-client").value.trim(),
        authorizing_party: $id("eng2-party").value.trim(),
        authorizing_title: $id("eng2-title").value.trim(),
        valid_from: $id("eng2-from").value,
        valid_until: $id("eng2-until").value,
        cidr_in: engLinesOf("eng2-cidr-in"),
        cidr_out: engLinesOf("eng2-cidr-out"),
        domain_in: engLinesOf("eng2-domain-in"),
        domain_out: engLinesOf("eng2-domain-out"),
        emergency_contact: $id("eng2-contact").value.trim(),
        notes: $id("eng2-notes").value.trim(),
        capture_payloads: $id("eng2-capture").checked,
        enabled_capabilities: $id("eng2-exploitation-enabled").checked ? ["exploit"] : [],
        exploitation_enabled: false,
        retention_days: parseInt($id("eng2-retention").value, 10) || 0,
        redact: engLinesOf("eng2-redact"),
        allowed_models: engLinesOf("eng2-models"),
        model_prices: {},
      };
      for (const line of engLinesOf("eng2-model-prices")) {
        const [name, pair, extra] = line.split("=");
        const parts = (pair || "").split(",");
        const values = parts.map(Number);
        if (!name || extra !== undefined || parts.some((v) => !v.trim()) || values.length !== 2 || values.some((v) => !Number.isFinite(v) || v < 0)) {
          throw new Error("Write each price as provider:model=input,output, two prices in USD per million tokens.");
        }
        body.model_prices[name] = values;
      }
      if (clearCeilings.has("turns")) body.clear_max_turns_ceiling = true;
      else { const v = $id("eng2-turns-ceiling").value; if (v) body.max_turns_ceiling = parseInt(v, 10); }
      if (clearCeilings.has("budget")) body.clear_max_budget_ceiling = true;
      else { const v = $id("eng2-budget-ceiling").value; if (v) body.max_budget_ceiling = parseFloat(v); }
      if (clearCeilings.has("timeout")) body.clear_timeout_ceiling = true;
      else { const v = $id("eng2-timeout-ceiling").value; if (v) body.timeout_ceiling = parseInt(v, 10); }
      // What was being edited, and under which policy: a save is refused if
      // either moved on meanwhile (nobody's change is silently overwritten).
      body.base_digest = data.pending ? data.pending.digest : (data.digest || "none");
      if (data.second_approver) body.expect_second_approver = data.second_approver;
      return body;
    }

    engForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (engSaveBtn.hidden) return;
      engBanner.className = "banner";
      // Nothing changed and nothing to approve: just close (no 2FA code spent).
      const st = data.approval_status || {};
      if (!edited() && data.exists && (st.current || policyOn())) { engDlg.close(); return; }
      let body;
      try { body = formBody(); } catch (err) { Agenti.banner(engBanner, "err", err.message); return; }
      engSaveBtn.disabled = true;
      try {
        // The engagement is the legal boundary: saving it is confirmed like
        // any other admin action (audit run 1, F13).
        const r = await Agenti.requireApproval({
          title: policyOn() ? "Submit the engagement change" : "Save the engagement",
          description: policyOn()
            ? "Confirm it's you. Another admin approves it before it takes effect; until then, runs must fit both versions."
            : "Confirm it's you. It takes effect at once, approved by you.",
          submit: (creds) => Agenti.post("engagement", { ...body,
            password: creds.password, totp: creds.totp, reauth: creds.reauth }),
        });
        if (!r) return;
        done((r.pending ? "Change submitted: another admin approves it before it takes effect."
          : r.cleared ? "Saved back to the version in force: nothing is waiting any more."
          : r.unchanged ? "Nothing changed."
          : "Saved and approved by you: it is in force now.") + stoppedNote(r));
      } catch (err) {
        Agenti.banner(engBanner, "err", Agenti.errorText(err));
      } finally {
        engSaveBtn.disabled = false;
      }
    });

    async function decide(btn, { title, description, path, body, message }) {
      engBanner.className = "banner";
      btn.disabled = true;
      try {
        const r = await Agenti.requireApproval({
          title, description,
          submit: (creds) => Agenti.post(path, { ...body,
            password: creds.password, totp: creds.totp, reauth: creds.reauth }),
        });
        if (!r) return;
        done(message + stoppedNote(r));
      } catch (err) {
        Agenti.banner(engBanner, "err", Agenti.errorText(err));
      } finally {
        btn.disabled = false;
      }
    }
    engApprovePendingBtn.addEventListener("click", () => {
      const p = data.pending;
      decide(engApprovePendingBtn, {
        title: `Approve ${p.author === me.user ? "your" : `${p.author}'s`} change`,
        description: "Confirm it's you. The change takes effect at once, exactly as shown.",
        path: "engagement/pending/approve",
        body: { digest: p.digest, engagement_id: p.record.engagement_id },
        message: `Approved: ${p.author === me.user ? "your" : `${p.author}'s`} change is in force now.`,
      });
    });
    engRejectBtn.addEventListener("click", () => {
      const p = data.pending;
      const reason = $id("eng-reject-reason").value.trim();
      if (!p && data.pending_invalid) {
        // An unreadable change has no digest to name: the CLI discards it.
        Agenti.banner(engBanner, "err", "Discard it at the server: sudo agenti engagement reject-pending");
        return;
      }
      decide(engRejectBtn, {
        title: `Reject ${p.author}'s change`,
        description: "Confirm it's you. The change is discarded; the version in force stays.",
        path: "engagement/pending/reject",
        body: { digest: p.digest, ...(reason ? { reason } : {}) },
        message: "Rejected: the version in force stays.",
      });
    });
    engWithdrawBtn.addEventListener("click", () => {
      const p = data.pending;
      decide(engWithdrawBtn, {
        title: "Withdraw your change",
        description: "Confirm it's you. The change is discarded; the version in force stays.",
        path: "engagement/pending/withdraw",
        body: { digest: p.digest },
        message: "Withdrawn: the version in force stays.",
      });
    });
    engApproveBtn.addEventListener("click", () => {
      // An older record nobody approved (the policy on): another admin
      // approves exactly the version shown (F25).
      decide(engApproveBtn, {
        title: "Approve the engagement",
        description: "Confirm it's you to approve the engagement exactly as shown.",
        path: "engagement/approve",
        body: { digest: data.digest, engagement_id: (data.record || {}).engagement_id },
        message: "Approved: runs may start against it now.",
      });
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
        // Two different separations of duty, named so they can't be confused.
        const sa = pol["engagement-second-approver"] === "on";
        rows.push(polRow("users", "Second approver for engagement changes", sa,
            `A saved change waits until a different admin approves it; until then, runs must fit both versions. Needs two admins: <code>sudo agenti admin set-policy engagement-second-approver ${sa ? "off" : "on"}</code>`));
        const rsa = pol["require-separate-approver"] === "on";
        rows.push(polRow("users", "Approver can't start runs", rsa,
            `Whoever approved the engagement can't also start a run against it: <code>sudo agenti admin set-policy require-separate-approver ${rsa ? "off" : "on"}</code>`));
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
          Agenti.banner(vBanner, "warn", "");
          vBanner.innerHTML = "<strong>Data from agents is currently not encrypted.</strong> Reports, scans, attached files and the API key are plain files on this server's disk.";
          await Agenti.dismissibleBanner(vBanner, "vault-unencrypted");
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

    // Settings → AI providers: one card per provider (models.js holds the
    // list). Saving goes behind a fresh re-authentication bound to the
    // provider, address and key (model_registry.secret_digest); the key goes to
    // the server in the request body and reaches root on stdin. Nothing here
    // ever receives a key back: readiness is a yes/no from GET models?status.
    const pList = document.getElementById("providers-list");
    const relayCmd = (address) => {
      try {
        const u = new URL(address);
        if (!/^https?:$/.test(u.protocol) || !u.hostname) return "";
        return `sudo agenti admin relay allow ${u.hostname}:${u.port || (u.protocol === "https:" ? 443 : 80)}`;
      } catch (e) { return ""; }
    };
    pList.innerHTML = AgentiModels.PROVIDERS.map((p) => {
      const local = p.id === "local";
      return `
      <div class="panel provider-card" data-provider="${p.id}">
        <div class="provider-card-head">
          <span class="cat-icon" aria-hidden="true">${Agenti.icon(p.icon, 18)}</span>
          <div><h2>${esc(p.name)}</h2><p class="hint">${esc(p.by)}</p></div>
          <span class="badge incomplete" data-badge>Checking…</span>
        </div>
        <p class="hint" style="margin-top:var(--space-3);">${esc(p.blurb)}</p>
        <form class="provider-form" autocomplete="off">
          ${local ? `
          <div class="field wide">
            <label for="pv-${p.id}-address">Server address</label>
            <input id="pv-${p.id}-address" type="url" required spellcheck="false" placeholder="http://model.example.com:11434/v1">
          </div>` : ""}
          <div class="field">
            <label for="pv-${p.id}-key">API key${local ? ' <span class="hint">(optional)</span>' : ""}</label>
            <input id="pv-${p.id}-key" type="password" ${local ? "" : "required"} spellcheck="false" autocomplete="off" placeholder="${esc(p.keyHint)}">
          </div>
          <button type="submit" class="btn btn-primary" data-save data-icon="key">Save</button>
        </form>
        ${local ? `
        <div class="field" data-relay hidden style="margin-top:var(--space-3);">
          <p class="hint">Agents reach a model server only through Agenti's relay. Allow this one once, on the server:</p>
          <div data-relay-cmd></div>
        </div>` : ""}
        <div class="banner" data-banner></div>
        <div class="provider-foot">
          <button type="button" class="btn btn-sm" data-check data-icon="refresh">Check connection</button>
          <span class="check-result" data-result aria-live="polite"></span>
          ${p.keyUrl ? `<a href="${esc(p.keyUrl)}" target="_blank" rel="noopener noreferrer">Get a ${esc(p.name)} API key ${Agenti.icon("open", 12)}</a>` : ""}
        </div>
      </div>`;
    }).join("");
    if (typeof applyIcons === "function") applyIcons(pList);

    async function paintProviders() {
      const providers = await AgentiModels.status({ fresh: true });
      for (const p of AgentiModels.PROVIDERS) {
        const card = pList.querySelector(`[data-provider="${p.id}"]`);
        const badge = card.querySelector("[data-badge]");
        const info = providers && providers[p.id];
        const save = card.querySelector("[data-save]");
        if (!info) { badge.className = "badge incomplete"; badge.textContent = "Unknown"; continue; }
        badge.className = "badge " + (info.ready ? "completed" : "incomplete");
        badge.textContent = info.ready ? (p.id === "local" ? "Address saved" : "Key saved") : "Not set up";
        save.lastChild.textContent = info.ready ? (p.id === "local" ? "Replace" : "Replace key") : (p.id === "local" ? "Save" : "Save key");
        card.querySelector("[data-check]").disabled = !info.ready;
      }
    }
    tasks.push(paintProviders());

    for (const p of AgentiModels.PROVIDERS) {
      const card = pList.querySelector(`[data-provider="${p.id}"]`);
      const form = card.querySelector("form");
      const keyEl = card.querySelector(`#pv-${p.id}-key`);
      const addrEl = card.querySelector(`#pv-${p.id}-address`);
      const banner = card.querySelector("[data-banner]");
      const result = card.querySelector("[data-result]");
      const save = card.querySelector("[data-save]");
      if (addrEl) {
        const relay = card.querySelector("[data-relay]"), relayHost = card.querySelector("[data-relay-cmd]");
        addrEl.addEventListener("input", () => {
          const cmd = relayCmd(addrEl.value.trim());
          relay.hidden = !cmd;
          if (cmd) relayHost.innerHTML = `<div class="copyable"><code class="cmd-block">${esc(cmd)}</code>${Agenti.copyButtonHtml(cmd, "Copy command")}</div>`;
        });
      }
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const key = keyEl.value.trim();
        const base_url = addrEl ? addrEl.value.trim() : "";
        if (/\s/.test(key)) { Agenti.banner(banner, "err", "An API key has no spaces. Paste it again without them."); return; }
        if (p.id !== "local" && !key) { Agenti.banner(banner, "err", `Paste the ${p.name} API key first.`); keyEl.focus(); return; }
        if (addrEl && !relayCmd(base_url)) { Agenti.banner(banner, "err", "Enter the server's full address, starting with http:// or https://, e.g. http://model.example.com:11434/v1"); addrEl.focus(); return; }
        save.disabled = true;
        try {
          const r = await Agenti.requireApproval({
            title: `Save the ${p.name} settings`,
            description: `Confirm it's you to save the organisation's ${p.name} ${p.id === "local" ? "server" : "key"}. Runs started from now on use it.`,
            submit: (creds) => Agenti.post("admin/api-key", { key, provider: p.id, base_url,
              password: creds.password, totp: creds.totp, reauth: creds.reauth }),
          });
          if (!r) { Agenti.banner(banner, "warn", "Cancelled — nothing was changed."); return; }
          form.reset();
          if (addrEl) addrEl.dispatchEvent(new Event("input"));
          Agenti.banner(banner, "ok", `Saved. Runs started from now on use this ${p.id === "local" ? "server" : "key"}. Use Check connection to confirm it works.`);
          result.textContent = ""; result.className = "check-result";
          await paintProviders();
        } catch (err) {
          Agenti.banner(banner, "err", Agenti.errorText(err));
        } finally { save.disabled = false; }
      });
      card.querySelector("[data-check]").addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        btn.disabled = true; result.className = "check-result"; result.textContent = "Asking the provider…";
        try {
          const d = await Agenti.get("models?" + new URLSearchParams({ provider: p.id }));
          const n = (d.models || []).length;
          result.className = "check-result ok";
          result.textContent = n ? `Working: ${n} model${n === 1 ? "" : "s"} on the allowed list.`
            : "Working, but none of its models is on the allowed list (Settings → Engagement).";
        } catch (err) {
          result.className = "check-result err"; result.textContent = Agenti.errorText(err);
        } finally { btn.disabled = false; }
      });
    }

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
      // Slim rows (operator note 2026-11-08): rename is a faint pencil by the
      // name, disable/re-enable a faint glyph by the status dot, and only
      // access and delete stay on the right. No boxes round the icons.
      const glyph = (data, name, title, icon, extra = "") =>
        `<button type="button" class="row-glyph${extra}" data-${data}="${esc(name)}" title="${esc(title)}" aria-label="${esc(title)}">${Agenti.icon(icon, 15)}</button>`;
      tbody.innerHTML = rows.map((r) => {
        const others = canManage && r.name !== me.user;
        return `
          <tr>
            <td class="name-cell"><span class="u-name">${esc(r.name)}</span>${others ? glyph("rename", r.name, `Rename ${r.name}…`, "edit", " soft") : ""}</td>
            <td>${esc(r.kind)}</td>
            <td class="status-cell"><span class="status-dot ${r.active ? "ok" : "err"}" title="${esc(statusTitle(r))}"><span class="sr-only">${esc(statusTitle(r))}</span></span>${others
              ? (r.active ? glyph("disable", r.name, `Disable ${r.name}…`, "lock", " soft")
                          : glyph("enable", r.name, `Re-enable ${r.name}…`, "check", " soft")) : ""}</td>
            <td class="access-cell">${roleText(r.name, bindingsCache)}</td>
            <td class="dashboard-cell">${canOpenDashboard(r) ? `<button type="button" class="row-glyph dash" data-dashboard="${esc(r.name)}" title="Open ${esc(r.name)}'s dashboard" aria-label="Open ${esc(r.name)}'s dashboard">${Agenti.icon("dashboard", 15)}<span class="lbl-full">View dashboard</span></button>` : ""}</td>
            <td class="actions"><div class="actions-wrap">${canManage && r.active ? `${glyph("grant", r.name, `Access and security for ${r.name}…`, "key", " accent")}${!r.has_password ? glyph("relink", r.name, `New set-up link for ${r.name}`, "link") : ""}` : ""}${others ? glyph("delete", r.name, `Permanently delete ${r.name}…`, "trash", " danger") : ""}</div></td>
          </tr>`;
      }).join("") || `<tr><td colspan="6" class="muted">No users.</td></tr>`;
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

    // A generated password, ready to copy and hand over (password-gen.js).
    // Not offered to the admin's own password manager: it isn't theirs.
    const resetPwGen = AgentiPassword.attach(resetPasswordValue);
    resetPasswordDirectBtn.addEventListener("click", () => {
      resetBanner.className = "banner";
      resetPasswordLinkResult.hidden = true;
      resetPwGen.regenerate();
      resetPasswordDirectForm.hidden = false;
    });
    resetPasswordDirectCancel.addEventListener("click", () => {
      resetPasswordDirectForm.hidden = true;
    });
    resetPasswordDirectConfirm.addEventListener("click", async () => {
      const name = grantForm.dataset.name;
      const value = resetPwGen.value;
      resetBanner.className = "banner";
      const problem = resetPwGen.check();
      if (problem) {
        Agenti.banner(resetBanner, "err", problem);
        return;
      }
      resetPasswordDirectConfirm.disabled = true;
      try {
        const r = await resetPasswordWithApproval(name, "direct", value);
        if (!r) return; // cancelled
        resetPasswordDirectForm.hidden = true;
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
        const r = await Agenti.requireApproval({
          title: "Disable user",
          description: `Disable '${disableName}'. They are signed out at once and cannot sign in `
            + `until an admin re-enables the account (the check mark by their status dot).`,
          submit: (creds) => Agenti.post(userUrl(disableName, "disable"),
            { password: creds.password, totp: creds.totp, reauth: creds.reauth }),
        });
        if (!r) return; // cancelled
        Agenti.banner(usersBanner, "ok", `'${disableName}' is disabled (approved by ${r.approved_by}).`);
        await paintUsers();
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
