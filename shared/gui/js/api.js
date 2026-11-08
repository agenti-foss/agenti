// api.js — the ONE fetch wrapper every page uses.
//
// Contract with the API (shared/api/sessions.py, rbac.py, main.py):
//   - auth is the HttpOnly session cookie, sent by the browser on its own.
//     That only works because the API serves these pages itself (main.py
//     mounts shared/gui/ last, same origin): SameSite=Strict + a separate
//     GUI port would be a different site and the cookie would never go;
//   - every cookie-authenticated non-GET must echo the CSRF value that
//     /auth/login (or /auth/totp) returned in its BODY, as the X-Agenti-CSRF
//     header. It is deliberately not a cookie — a value the browser replays
//     automatically would defeat the point — so the page keeps it in
//     localStorage. On its own it grants nothing (no cookie, no session);
//   - a 401 anywhere means "not logged in": go to login.html, carrying the
//     page we were on so login can bring us back;
//   - errors arrive as {"detail": ...} (FastAPI/route) or {"error": ...}
//     (a CLI --json failure forwarded verbatim); both become one Error with
//     .status and a readable message, so pages show the CLI's own words.
const Agenti = (() => {
  const CSRF_KEY = "agenti-csrf";

  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  function csrf() {
    try { return localStorage.getItem(CSRF_KEY) || ""; } catch (e) { return ""; }
  }
  function setCsrf(v) {
    try { v ? localStorage.setItem(CSRF_KEY, v) : localStorage.removeItem(CSRF_KEY); } catch (e) { /* no persistence */ }
  }
  function clearAuth() { setCsrf(""); }

  function toLogin() {
    const next = location.pathname.split("/").pop() + location.search;
    location.href = "login.html?next=" + encodeURIComponent(next);
  }

  function messageOf(data, fallback) {
    if (data == null) return fallback;
    if (typeof data === "string") return data;
    const d = data.detail !== undefined ? data.detail : data.error;
    if (d === undefined) return fallback;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {           // FastAPI 422 validation errors
      return d.map((x) => (x.loc ? x.loc.slice(-1)[0] + ": " : "") + (x.msg || JSON.stringify(x))).join("; ");
    }
    return JSON.stringify(d);
  }

  async function call(method, path, body, opts = {}) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET" && method !== "HEAD") headers["X-Agenti-CSRF"] = csrf();
    let res;
    try {
      res = await fetch(path, {
        method, headers, credentials: "same-origin",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (e) {
      throw new ApiError(0, "could not reach the API — is agenti-api.service running?");
    }
    if (res.status === 401 && !opts.noRedirect) {
      clearAuth();
      toLogin();
      throw new ApiError(401, "not logged in");
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    // The require-2fa policy (rbac.py): a valid session that has not enrolled
    // its second factor yet is refused everything but the enrollment routes,
    // with a structured code rather than prose. Route the person to Settings
    // once, instead of letting every page show the same 403 in its own way.
    if (res.status === 403 && data && data.detail && data.detail.code === "mfa_setup_required" && !opts.noRedirect) {
      if (!location.pathname.endsWith("settings.html")) {
        location.href = "settings.html?mfa=required";
      }
      throw new ApiError(403, data.detail.message || "two-factor authentication must be set up first");
    }
    if (!res.ok) throw new ApiError(res.status, messageOf(data, res.statusText || `HTTP ${res.status}`));
    return data;
  }

  // Server-sent events (GET /agents/{agent}/stream). EventSource sends the
  // session cookie itself on a same-origin URL; no CSRF (it is a GET).
  // `handlers` maps event name -> fn(parsedData). Returns the EventSource so
  // the page can close() it when it navigates away.
  function stream(path, handlers) {
    const es = new EventSource(path);
    for (const [event, fn] of Object.entries(handlers)) {
      if (event === "open" || event === "error") es.addEventListener(event, fn);
      else es.addEventListener(event, (e) => { try { fn(JSON.parse(e.data)); } catch (err) { console.warn("bad SSE payload", err); } });
    }
    return es;
  }

  // Tiny helpers the pages share.
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function when(ts) {
    if (!ts) return "—";
    const d = new Date(Number(ts) * 1000);
    return isNaN(d) ? "—" : d.toLocaleString();
  }
  function banner(el, kind, text) {
    if (!el) return;
    el.hidden = false;   // a banner given text is meant to be seen, whatever the markup started as
    el.className = `banner ${kind} show`;
    el.textContent = text;
  }
  // Relative time for a card ("2 h ago"); the full date stays on a tooltip.
  function ago(ts) {
    if (!ts) return "—";
    const s = Math.max(0, Math.round(Date.now() / 1000 - Number(ts)));
    if (isNaN(s)) return "—";
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    if (s < 7 * 86400) return `${Math.round(s / 86400)} d ago`;
    return new Date(Number(ts) * 1000).toLocaleDateString();
  }
  // A one-shot message for the NEXT page (after "Mark complete" sends you back
  // to the dashboard): stored for one navigation, shown once, then forgotten.
  function flash(text) { try { sessionStorage.setItem("agenti-flash", text); } catch (e) { /* no persistence */ } }
  function showFlash(el) {
    let text = "";
    try { text = sessionStorage.getItem("agenti-flash") || ""; sessionStorage.removeItem("agenti-flash"); } catch (e) { return; }
    if (!text || !el) return;
    banner(el, "ok", text);
    setTimeout(() => { if (el.textContent === text) el.className = "banner"; }, 6000);
  }
  function errorText(e) { return e && e.message ? e.message : String(e); }

  // ---- copy to clipboard ------------------------------------------------
  // One icon button, used wherever a value is meant to be carried somewhere
  // else: an enrollment link, a 2FA secret, recovery codes, a command to run
  // on the host. `text` may be a string or a function returning the current
  // string (for values that change after the button is built).
  const COPY_ICON = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/><path d="M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2"/></svg>';
  const TICK_ICON = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5l3 3 7-7"/></svg>';

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* fall through to the selection path */ }
    // Plain HTTP on the LAN is not a secure context, so the async clipboard
    // API is unavailable there; the selection-based copy still works.
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed"; ta.style.top = "-1000px";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch (e) { return false; }
  }

  function _copyFeedback(b, ok, what) {
    b.innerHTML = ok ? TICK_ICON : COPY_ICON;
    b.classList.toggle("copied", ok);
    b.title = ok ? "Copied" : "Could not copy — select it and copy by hand";
    setTimeout(() => { b.innerHTML = COPY_ICON; b.classList.remove("copied"); b.title = what; }, 1600);
  }

  function copyButton(text, label) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "copy-btn";
    const what = label || "Copy";
    b.title = what; b.setAttribute("aria-label", what);
    b.innerHTML = COPY_ICON;
    b.addEventListener("click", async () => {
      const value = typeof text === "function" ? text() : text;
      _copyFeedback(b, await copyText(String(value ?? "")), what);
    });
    return b;
  }

  // Markup for a copy button, for pages that build rows with innerHTML; the
  // value to copy travels in data-copy. Wire them afterwards with
  // wireCopyButtons(container) — idempotent, so it can run after every repaint.
  function copyButtonHtml(text, label) {
    const what = label || "Copy";
    return `<button type="button" class="copy-btn" data-copy="${esc(text)}" title="${esc(what)}" aria-label="${esc(what)}">${COPY_ICON}</button>`;
  }
  function wireCopyButtons(root) {
    (root || document).querySelectorAll("button.copy-btn[data-copy]:not([data-wired])").forEach((b) => {
      b.dataset.wired = "1";
      const what = b.title || "Copy";
      b.addEventListener("click", async () => _copyFeedback(b, await copyText(b.dataset.copy || ""), what));
    });
  }

  // ---- the universal authentication popup ---------------------------------
  // ONE dialog, injected once and reused, wherever this site asks someone to
  // prove it's really them before a sensitive action (granting access,
  // renaming or deleting, resets, instruction edits, building agents, and
  // their own password, 2FA and passkeys). It always has the same shape:
  //   * the account (read-only) — so password-manager extensions recognize a
  //     login form and offer this site's saved password;
  //   * password (autocomplete="current-password");
  //   * 2FA code (autocomplete="one-time-code") — hidden only for an account
  //     that has no 2FA yet, since it cannot produce a code;
  //   * "Use a passkey" — offered whenever passkeys work from this address
  //     (passkeysUsable). A passkey proves both at once: agenti-authd
  //     verifies it and returns a single-use token the action presents
  //     instead of a password and code.
  // Pages never build their own copy: they call
  // Agenti.requireApproval({ title, description, confirmText, submit }).
  let _approvalDlg = null;
  function _ensureApprovalDialog() {
    if (_approvalDlg) return _approvalDlg;
    const dlg = document.createElement("dialog");
    dlg.id = "agenti-approval-dialog";
    dlg.className = "agenti-modal";
    dlg.innerHTML = `
      <form class="stack approval-form" method="post" action="#" autocomplete="on">
        <div class="approval-head">
          ${icon("shield", 22)}
          <h2 class="approval-title">Confirm it's you</h2>
        </div>
        <p class="approval-desc muted"></p>
        <div class="banner approval-banner" role="alert"></div>
        <div class="field approval-user-field">
          <label for="approval-username">Account</label>
          <input type="text" id="approval-username" name="username" autocomplete="username"
                 readonly tabindex="-1" class="approval-username">
        </div>
        <div class="field">
          <label for="approval-password">Password</label>
          <input type="password" id="approval-password" name="password" autocomplete="current-password" required>
        </div>
        <div class="field approval-code-field">
          <label for="approval-code">2FA code</label>
          <input type="text" id="approval-code" name="one-time-code" inputmode="numeric"
                 pattern="[0-9]{6}|[0-9a-fA-F]{5}-?[0-9a-fA-F]{5}" maxlength="11"
                 autocomplete="one-time-code" class="approval-code-input" spellcheck="false">
          <button type="button" class="link-btn approval-recovery">Lost your device? Use a recovery code</button>
        </div>
        <div class="btn-row">
          <button type="submit" class="btn btn-primary approval-confirm">Confirm</button>
          <button type="button" class="btn btn-ghost approval-cancel">Cancel</button>
        </div>
        <div class="divider approval-passkey-divider">or</div>
        <button type="button" class="btn approval-passkey-btn">${icon("fingerprint", 16)} Use a passkey</button>
      </form>`;
    document.body.appendChild(dlg);
    _approvalDlg = dlg;
    return dlg;
  }

  // A separate warning window for an irreversible action: the person types
  // `word` (e.g. DELETE) before the authentication popup even appears.
  // Resolves true to continue, false if they backed out. A mis-click guard,
  // not authentication — that is still the popup that follows.
  let _dangerDlg = null;
  function confirmDanger({ title, description, word }) {
    word = word || "DELETE";
    if (!_dangerDlg) {
      _dangerDlg = document.createElement("dialog");
      _dangerDlg.id = "agenti-danger-dialog";
      _dangerDlg.className = "agenti-modal danger-modal";
      _dangerDlg.innerHTML = `
        <form class="stack" method="dialog">
          <div class="approval-head danger-head">${icon("warning", 22)}<h2 class="approval-title"></h2></div>
          <p class="approval-desc"></p>
          <div class="field">
            <label for="danger-word"></label>
            <input type="text" id="danger-word" autocomplete="off" spellcheck="false" autocapitalize="characters"
                   class="approval-confirm-input">
          </div>
          <div class="btn-row">
            <button type="submit" class="btn btn-danger danger-go" disabled>Continue</button>
            <button type="button" class="btn btn-ghost danger-cancel">Cancel</button>
          </div>
        </form>`;
      document.body.appendChild(_dangerDlg);
    }
    const dlg = _dangerDlg;
    return new Promise((resolve) => {
      const input = dlg.querySelector("#danger-word");
      const go = dlg.querySelector(".danger-go");
      dlg.querySelector(".approval-title").textContent = title || "Are you sure?";
      dlg.querySelector(".approval-desc").textContent = description || "";
      dlg.querySelector('label[for="danger-word"]').textContent = `Type ${word} to continue`;
      input.value = ""; go.disabled = true;
      let ok = false;
      const onInput = () => { go.disabled = input.value.trim() !== word; };
      const onSubmit = (e) => { e.preventDefault(); if (input.value.trim() !== word) return; ok = true; dlg.close(); };
      const onCancel = () => dlg.close();
      const onClose = () => {
        input.removeEventListener("input", onInput);
        dlg.querySelector("form").removeEventListener("submit", onSubmit);
        dlg.querySelector(".danger-cancel").removeEventListener("click", onCancel);
        dlg.removeEventListener("close", onClose);
        resolve(ok);
      };
      input.addEventListener("input", onInput);
      dlg.querySelector("form").addEventListener("submit", onSubmit);
      dlg.querySelector(".danger-cancel").addEventListener("click", onCancel);
      dlg.addEventListener("close", onClose);
      dlg.showModal();
      input.focus();
    });
  }

  // `submit(creds)` performs the real action. creds is
  //   { password, totp }  from the form, or
  //   { reauth }          after a passkey,
  // It resolves (the popup closes; its value,
  // or true, is this promise's result) or throws (the error shows in the
  // popup, which stays open for another try). Resolves null if dismissed.
  //
  // `confirmText` (e.g. "DELETE") first opens the separate warning window
  // above; backing out there resolves null without asking for anything.
  //
  // Every call asks: there is no grace window (operator decision
  // 2026-10-23); the server checks the credential on every action.
  async function requireApproval({ title, description, confirmText, submit }) {
    if (confirmText) {
      const go = await confirmDanger({ title, description, word: confirmText });
      if (!go) return null;
    }
    let me = null;
    try { me = await memoGet("auth/me"); } catch (err) { /* fields still work */ }
    const passkeyOk = await passkeysUsable();
    return new Promise((resolve) => {
      const dlg = _ensureApprovalDialog();
      if (dlg.open) dlg.close();
      const $ = (sel) => dlg.querySelector(sel);
      const form = $("form"), banner = $(".approval-banner");
      const userInput = $("#approval-username"), pwInput = $("#approval-password");
      const codeField = $(".approval-code-field"), codeInput = $("#approval-code");
      const confirmBtn = $(".approval-confirm"), cancelBtn = $(".approval-cancel"), passkeyBtn = $(".approval-passkey-btn");
      const recoveryBtn = $(".approval-recovery");
      // A recovery code ("xxxxx-xxxxx") has letters, which a numeric keypad
      // cannot type: this swaps the field to a text keyboard and says so.
      let recoveryMode = false;
      function setRecoveryMode(on) {
        recoveryMode = on;
        codeInput.inputMode = on ? "text" : "numeric";
        codeInput.placeholder = on ? "xxxxx-xxxxx" : "";
        $('label[for="approval-code"]').textContent = on ? "Recovery code" : "2FA code";
        recoveryBtn.textContent = on ? "Use the authenticator app instead" : "Lost your device? Use a recovery code";
        codeInput.value = "";
        if (on) codeInput.focus();
      }

      $(".approval-title").textContent = title || "Confirm it's you";
      $(".approval-desc").textContent = description || "";
      userInput.value = (me && me.user) || "";
      $(".approval-user-field").hidden = !userInput.value;
      pwInput.value = ""; codeInput.value = "";
      setRecoveryMode(false);
      // An account with no 2FA can't produce a code (first-time set-up).
      const hasCode = !me || me.totp_enrolled !== false;
      codeField.hidden = !hasCode;
      codeInput.required = hasCode;
      passkeyBtn.hidden = !passkeyOk;
      $(".approval-passkey-divider").hidden = !passkeyOk;
      banner.className = "banner approval-banner";

      const showErr = (err) => {
        banner.className = "banner err approval-banner show";
        banner.textContent = typeof err === "string" ? err : errorText(err);
      };
      let settled = false;
      // A 2FA code works once (replay protection, kept on purpose): two
      // confirmations inside one 30-second step need two codes. When the
      // server says the code was just used, say when the next one comes,
      // keep the password, and confirm by itself as soon as the new code is
      // typed (operator note 2026-11-06).
      let waitTimer = null, autoSubmit = false;
      function stopWait() { clearInterval(waitTimer); waitTimer = null; autoSubmit = false; }
      function waitForNextCode() {
        stopWait();
        autoSubmit = true;
        // Short on screen; the why is behind the (i) (operator note 2026-11-07).
        banner.className = "banner warn approval-banner show";
        banner.innerHTML = codeWaitHtml("this confirms by itself");
        const count = banner.querySelector(".code-wait-count");
        const paint = () => { count.textContent = codeWaitCount(); };
        paint();
        waitTimer = setInterval(paint, 1000);
      }
      function finish(result) { settled = true; stopWait(); dlg.close(); resolve(result === undefined ? true : result); }
      async function run(creds, btn) {
        btn.disabled = true;
        try { finish(await submit(creds)); }
        catch (err) {
          codeInput.value = "";
          if (hasCode && !recoveryMode && creds.totp && /already been used/i.test(errorText(err))) {
            waitForNextCode();
            codeInput.focus();
          } else {
            stopWait();
            showErr(err);
            (hasCode ? codeInput : pwInput).focus();
          }
        }
        finally { btn.disabled = false; }
      }
      function onCodeInput() {
        if (autoSubmit && pwInput.value && /^[0-9]{6}$/.test(codeInput.value.trim())) {
          stopWait();
          banner.className = "banner approval-banner";
          run({ password: pwInput.value, totp: codeInput.value.trim() }, confirmBtn);
        }
      }
      function onSubmit(e) {
        e.preventDefault();
        stopWait();
        banner.className = "banner approval-banner";
        if (!pwInput.value) { showErr("Enter your password."); pwInput.focus(); return; }
        const code = normaliseSecondFactor(codeInput.value);
        if (hasCode && !code) { showErr(recoveryMode ? "Enter one of your recovery codes (xxxxx-xxxxx)." : "Enter the 6-digit code from your authenticator app, or a recovery code."); codeInput.focus(); return; }
        run({ password: pwInput.value, totp: hasCode ? code : "" }, confirmBtn);
      }
      async function onPasskey() {
        banner.className = "banner approval-banner";
        passkeyBtn.disabled = true;
        try {
          const options = await call("POST", "auth/reauth/webauthn/begin", {});
          const hint = webauthnOriginHint(options.rpId, options.origin);
          if (hint) { showErr(hint); return; }
          const credential = await webauthnGet(options);
          const r = await call("POST", "auth/reauth/webauthn/finish", { credential });
          passkeyBtn.disabled = false;
          await run({ reauth: r.reauth }, passkeyBtn);
        } catch (err) {
          const name = err && err.name;
          showErr(name === "NotAllowedError" || name === "AbortError"
            ? "The passkey prompt was canceled. Try again, or use your password and code."
            : err);
        } finally { passkeyBtn.disabled = false; }
      }
      function onCancel() { dlg.close(); }
      function onRecovery() { stopWait(); setRecoveryMode(!recoveryMode); }
      function onClose() {
        stopWait();
        form.removeEventListener("submit", onSubmit);
        codeInput.removeEventListener("input", onCodeInput);
        cancelBtn.removeEventListener("click", onCancel);
        passkeyBtn.removeEventListener("click", onPasskey);
        recoveryBtn.removeEventListener("click", onRecovery);
        dlg.removeEventListener("close", onClose);
        if (!settled) resolve(null);
      }
      form.addEventListener("submit", onSubmit);
      codeInput.addEventListener("input", onCodeInput);
      cancelBtn.addEventListener("click", onCancel);
      passkeyBtn.addEventListener("click", onPasskey);
      recoveryBtn.addEventListener("click", onRecovery);
      dlg.addEventListener("close", onClose);
      dlg.showModal();
      pwInput.focus();
    });
  }

  // A second factor as typed: a 6-digit code, or a recovery code
  // ("xxxxx-xxxxx", accepted with or without the dash, any case). Returns the
  // server's own spelling, or "" if it is neither.
  function normaliseSecondFactor(raw) {
    const s = String(raw || "").trim().toLowerCase().replace(/\s+/g, "");
    if (/^[0-9]{6}$/.test(s)) return s;
    const m = /^([0-9a-f]{5})-?([0-9a-f]{5})$/.exec(s);
    return m ? `${m[1]}-${m[2]}` : "";
  }

  // ---- WebAuthn / passkeys ------------------------------------------------
  // The server always speaks base64url TEXT (webauthn_lite.b64url_encode/
  // decode) — every field in a request/response JSON body. The browser's
  // navigator.credentials API speaks ArrayBuffers. These two conversions,
  // and the two ceremony wrappers below, are the ONE place that boundary is
  // crossed, shared by login.html and settings.js the same way qrImage() is.
  function _b64urlToBuf(s) {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const base64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf.buffer;
  }
  function _bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // `options` is exactly what POST /auth/webauthn/register/start returns —
  // spec-shaped JSON (rp/user/pubKeyCredParams/authenticatorSelection/...)
  // with `challenge` and `user.id` as base64url text needing conversion to
  // ArrayBuffers before the browser will accept them. Returns the shape
  // POST /auth/webauthn/register/finish's `credential` field expects.
  async function webauthnCreate(options) {
    if (!window.PublicKeyCredential) {
      throw new ApiError(0, "this browser does not support passkeys");
    }
    const publicKey = Object.assign({}, options, {
      challenge: _b64urlToBuf(options.challenge),
      user: Object.assign({}, options.user, { id: _b64urlToBuf(options.user.id) }),
    });
    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new ApiError(0, "passkey creation was canceled");
    return {
      id: cred.id,   // already base64url per the WebAuthn spec — no conversion
      response: {
        clientDataJSON: _bufToB64url(cred.response.clientDataJSON),
        attestationObject: _bufToB64url(cred.response.attestationObject),
      },
    };
  }

  // Same shape for the login/assertion ceremony. `options` is what POST
  // /auth/webauthn/login/start returns.
  async function webauthnGet(options) {
    if (!window.PublicKeyCredential) {
      throw new ApiError(0, "this browser does not support passkeys");
    }
    const publicKey = Object.assign({}, options, {
      challenge: _b64urlToBuf(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) =>
        Object.assign({}, c, { id: _b64urlToBuf(c.id) })),
    });
    const cred = await navigator.credentials.get({ publicKey });
    if (!cred) throw new ApiError(0, "passkey sign-in was canceled");
    return {
      id: cred.id,
      response: {
        clientDataJSON: _bufToB64url(cred.response.clientDataJSON),
        authenticatorData: _bufToB64url(cred.response.authenticatorData),
        signature: _bufToB64url(cred.response.signature),
      },
    };
  }

  // WebAuthn's relying-party id must equal (or be a registrable-domain
  // suffix of) the PAGE'S OWN origin — there is no way around that, it is
  // the entire point of an RP id. If this tab is open on the server's bare
  // IP, an old bookmark, or any host other than the configured domain, the
  // browser/OS will refuse the ceremony with an opaque native error before
  // our own code ever runs — Safari's AuthenticationServices layer (which
  // a third-party passkey manager like Proton Pass or 1Password is
  // registered into) reports this specific case as "OriginMissingDomain":
  // an IP-address origin has no domain component at all to check the rp id
  // against. Checked here, once, against the config both pages already
  // fetch, so that native error never has to be the first thing anyone
  // sees — returns a plain-language explanation + the right address to
  // visit, or null if this tab is already on the right host.
  function webauthnOriginHint(rpId, origin) {
    if (!rpId || location.hostname === rpId) return null;
    // The server knows the public address (scheme + host + port as a browser
    // shows it); building it here from this tab's own port was wrong behind a
    // proxy or tunnel, where the two differ (§4 item 78).
    const target = `${origin || `${location.protocol}//${rpId}${location.port ? ":" + location.port : ""}`}${location.pathname}`;
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(location.hostname)
      || location.hostname.includes(":") || location.hostname === "localhost";
    return isIp
      ? `Passkeys need the real domain, not this server's IP address or hostname. Open ${target} instead, then try again.`
      : `Passkeys are set up for ${rpId}, but this page is open at ${location.hostname}. Open ${target} instead, then try again.`;
  }

  // ---- identity ---------------------------------------------------------
  // /auth/me is what the header needs on EVERY page, and what most pages also
  // fetch for themselves. Memoized per page load, so the nav's fetch and the
  // page's fetch are one request, not two.
  const _memo = {};
  function memoGet(path) {
    if (!_memo[path]) {
      _memo[path] = call("GET", path).catch((e) => { delete _memo[path]; throw e; });
    }
    return _memo[path];
  }

  // ---- the (deleted)/(now <new>) annotation ------------------------------
  // A name recorded on a past run, output, report or team message can
  // outlive the account it named — that account might since have been
  // renamed or permanently deleted (Settings > Users). Rather
  // than let a historical record go silently stale or misleading, every
  // page that renders a recorded name runs it through userLabel()
  // first, fed by one (memoized, per-page) fetch of the tombstone/rename
  // log every rename/delete writes to (iam.py's principal-history.jsonl).
  //
  // The fetch is allowed to FAIL SILENTLY: an operator does not hold iam:read,
  // and a page that shows run history to an operator must not break just
  // because it also tried to annotate a name. A failed/absent fetch means
  // every name displays exactly as recorded, which is always correct, just
  // not enriched.
  async function userHistory() {
    try {
      const me = await memoGet("auth/me");
      if (!(me.permissions || []).includes("iam:read")) return [];
      return await memoGet("admin/user-history");
    } catch (e) {
      return [];
    }
  }
  // `rows`: whatever userHistory() resolved to (an array, possibly
  // empty). Known, accepted limitation: if a renamed-away name is later
  // reused for a DIFFERENT, unrelated account (renaming does not tombstone
  // the old name the way a hard delete does — see iam.py's _is_tombstoned
  // docstring), this picks the MOST RECENT matching event by timestamp,
  // which is usually right but could mislabel that reused name with a
  // stale "(now ...)" — a display nicety's cosmetic edge case, not a
  // security or data concern (the underlying record is never altered).
  function userLabel(name, rows) {
    if (!name || !rows || !rows.length) return name;
    const sorted = rows.slice().sort((a, b) => b.ts - a.ts);
    let cur = name;
    const seen = new Set();
    while (!seen.has(cur)) {
      seen.add(cur);
      const hit = sorted.find((r) => r.name === cur);
      if (!hit) break;
      if (hit.event === "deleted") return `${name} (deleted)`;
      if (hit.event === "renamed" && hit.new_name) { cur = hit.new_name; continue; }
      break;
    }
    return cur !== name ? `${name} (now ${cur})` : name;
  }

  // The 2FA QR code, styled: round dots, rounded corner "eyes" in the accent
  // color, on a soft card. Built with DOM calls from the server's module
  // rows ("0101…", shared/qr.py, error correction Q so the dots scan
  // easily), never from markup — nothing here can run script. Colors are
  // CSS variables (--qr-card/--qr-ink/--qr-eye in theme.css), so one code
  // follows light, dark and Arcade live; dark mode keeps dark ink on a light
  // card, which every authenticator app reads (an inverted code is not).
  const SVG_NS = "http://www.w3.org/2000/svg";
  function qrCode(rows, label) {
    if (!Array.isArray(rows) || !rows.length) return null;
    const n = rows.length, quiet = 4, size = n + 2 * quiet;
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label || "QR code");
    const add = (tag, attrs, parent) => {
      const el = document.createElementNS(SVG_NS, tag);
      for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
      (parent || svg).appendChild(el);
      return el;
    };
    add("rect", { x: 0, y: 0, width: size, height: size, rx: 2.4, class: "qr-bg" });
    const inEye = (r, c) => (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7);
    // Agenti's mark sits in a clear square at the center, about a fifth of
    // the width; the server encodes at error correction H, which recovers
    // far more than the few modules it covers.
    let hole = Math.round(n * 0.22); if (hole % 2 !== n % 2) hole += 1;
    const h0 = (n - hole) / 2, inHole = (r, c) => r >= h0 && r < h0 + hole && c >= h0 && c < h0 + hole;
    const dots = add("g", { class: "qr-ink" });
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (rows[r][c] !== "1" || inEye(r, c) || inHole(r, c)) continue;
        add("rect", { x: quiet + c + 0.08, y: quiet + r + 0.08, width: 0.84, height: 0.84, rx: 0.42 }, dots);
      }
    }
    const eyes = add("g", { class: "qr-eye" });
    for (const [r, c] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
      const x = quiet + c, y = quiet + r;
      // the 7×7 ring (one module wide) and the 3×3 center, both rounded
      add("path", { "fill-rule": "evenodd", d:
        `M${x + 2},${y}h3a2,2 0 0 1 2,2v3a2,2 0 0 1-2,2h-3a2,2 0 0 1-2-2v-3a2,2 0 0 1 2-2z` +
        `M${x + 2},${y + 1}a1,1 0 0 0-1,1v3a1,1 0 0 0 1,1h3a1,1 0 0 0 1-1v-3a1,1 0 0 0-1-1z` }, eyes);
      add("rect", { x: x + 2, y: y + 2, width: 3, height: 3, rx: 0.9 }, eyes);
    }
    // The mark: the page's own favicon file, exactly as it is (operator
    // decision 2026-11-08), so a new logo shows up here by itself.
    const fav = document.querySelector('link[rel~="icon"]');
    add("image", { href: (fav && fav.getAttribute("href")) || "favicon.svg", class: "qr-mark",
                   x: quiet + h0 + 0.6, y: quiet + h0 + 0.6, width: hole - 1.2, height: hole - 1.2 });
    const card = document.createElement("div");
    card.className = "qr-card";
    card.appendChild(svg);
    return card;
  }

  // ---- passkeys: usable from this address? -------------------------------
  // Off, no domain configured, or this tab open at another host (the bare IP,
  // an old name): then no passkey button or section is offered at all
  // (operator note 2026-11-06) — a control that can only fail is clutter.
  let _webauthnCfg = null;
  function webauthnConfig() {
    _webauthnCfg = _webauthnCfg || call("GET", "auth/webauthn/config").catch(() => null);
    return _webauthnCfg;
  }
  async function passkeysUsable() {
    const cfg = await webauthnConfig();
    return !!(cfg && cfg.enabled && window.PublicKeyCredential && !webauthnOriginHint(cfg.rpId, cfg.origin));
  }

  // ---- "Don't show again" ------------------------------------------------
  // A standing advisory banner (data not encrypted, no AI provider, …) is
  // laid out as a small card: an icon, its bold first line as the title, the
  // rest as the body, a faint ✕ in the corner and "Don't show again" under it
  // (operator note 2026-11-07).
  //  * ✕ closes it until the next sign-in (login.html clears the list).
  //  * "Don't show again" hides it for good — per account, in this browser.
  //    Settings → Appearance lists how many are hidden and brings them back.
  // Call it AFTER the banner's text is set (banner() replaces the content).
  // Errors, results and questions waiting for you never get one.
  async function _bannerStore(prefix) {
    let user = "";
    try { user = (await memoGet("auth/me")).user || ""; } catch (e) { /* signed out */ }
    const key = `${prefix}:${user}`;
    let ids = [];
    try { ids = JSON.parse(localStorage.getItem(key) || "[]"); } catch (e) { ids = []; }
    const set = new Set(Array.isArray(ids) ? ids : []);
    return {
      key, ids: set,
      add(id) { set.add(id); try { localStorage.setItem(key, JSON.stringify([...set])); } catch (e) { /* no persistence */ } },
    };
  }
  const _hiddenBanners = () => _bannerStore("agenti-hidden-banners");
  const _closedBanners = () => _bannerStore("agenti-closed-banners");
  // Sign-in and sign-out forget which banners were closed with ✕.
  function forgetClosedBanners() {
    try {
      Object.keys(localStorage).filter((k) => k.startsWith("agenti-closed-banners:"))
        .forEach((k) => localStorage.removeItem(k));
    } catch (e) { /* no storage */ }
  }
  async function dismissibleBanner(el, id) {
    if (!el) return false;
    const hidden = await _hiddenBanners(), closed = await _closedBanners();
    const hide = () => { el.hidden = true; el.classList.remove("show"); };
    if (hidden.ids.has(id) || closed.ids.has(id)) { hide(); return false; }
    if (!el.classList.contains("banner-card")) {
      el.classList.add("banner-card");
      const text = document.createElement("div");
      text.className = "banner-text";
      while (el.firstChild) text.appendChild(el.firstChild);
      // The bold lead, when the banner has one, is the card's title line.
      const lead = text.firstElementChild;
      if (lead && lead.tagName === "STRONG" && text.firstChild === lead) {
        lead.classList.add("banner-title");
        if (lead.nextSibling && lead.nextSibling.nodeType === 3) {
          lead.nextSibling.textContent = lead.nextSibling.textContent.replace(/^\s+/, "");
        }
      }
      const ic = document.createElement("span");
      ic.className = "banner-icon";
      ic.innerHTML = icon("warning", 18);
      const x = document.createElement("button");
      x.type = "button";
      x.className = "banner-x";
      x.setAttribute("aria-label", "Close");
      x.title = "Close until you next sign in";
      x.innerHTML = icon("close", 14);
      x.addEventListener("click", () => { closed.add(id); hide(); });
      const never = document.createElement("button");
      never.type = "button";
      never.className = "banner-dismiss";
      never.textContent = "Don't show again";
      never.addEventListener("click", () => { hidden.add(id); hide(); });
      text.appendChild(never);
      el.append(ic, text, x);
    }
    return true;
  }
  async function hiddenBannerCount() { return (await _hiddenBanners()).ids.size; }
  async function showHiddenBanners() {
    const { key } = await _hiddenBanners();
    try { localStorage.removeItem(key); } catch (e) { /* no persistence */ }
  }

  // ---- fold-outs ---------------------------------------------------------
  // Every <details> opens and closes with one quick, fluid motion (height and
  // a soft fade, ~220 ms, interruptible) instead of snapping — operator note
  // 2026-11-06. Delegated, so fold-outs added later get it too. Instant when
  // the person asked for reduced motion, and inside the live console and the
  // team chat, where a step list should simply appear.
  // A soft start and a long settle: smoother than a front-loaded ease-out,
  // which spent most of the motion in its first few frames.
  const FOLD_EASE = "cubic-bezier(0.4, 0, 0.2, 1)";
  // The scroll position moves WITH the fold, every frame (operator note
  // 2026-11-08). Opening: the view glides down so the section's end comes
  // into sight as it grows, but never far enough to push its own title off
  // the top. Closing: as the content above the view's bottom shrinks, the
  // scroll position is clamped each frame here, instead of iOS Safari doing
  // it in one jump when the motion ends (the "snap" on close).
  function scrollParent(el) {
    for (let n = el.parentElement; n; n = n.parentElement) {
      const oy = getComputedStyle(n).overflowY;
      if ((oy === "auto" || oy === "scroll") && n.scrollHeight > n.clientHeight) return n;
    }
    return document.scrollingElement || document.documentElement;
  }
  function followFold(det, anim, opening) {
    const sc = scrollParent(det);
    const isPage = sc === document.scrollingElement || sc === document.documentElement;
    const summary = det.querySelector(":scope > summary") || det;
    const MARGIN = 16;
    // Plain assignment, with any smooth-scroll style held off: a smoothed
    // scroll per frame would lag the fold instead of moving with it.
    const prevBehavior = sc.style.scrollBehavior;
    sc.style.scrollBehavior = "auto";
    const setTop = (y) => { sc.scrollTop = y; };
    let last = false;
    const step = () => {
      if ((det._anim && det._anim !== anim) || (det._anim !== anim && last)) { sc.style.scrollBehavior = prevBehavior; return; }
      if (det._anim !== anim) last = true;             // one last frame at the end size
      const view = isPage
        ? { top: parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--nav-h")) || 0, bottom: window.innerHeight }
        : sc.getBoundingClientRect();
      if (opening) {
        const r = det.getBoundingClientRect();
        const over = r.bottom - (view.bottom - MARGIN);
        const room = summary.getBoundingClientRect().top - (view.top + MARGIN);
        const by = Math.min(over, room);
        if (by > 0.5) setTop(sc.scrollTop + by);
      } else {
        const max = sc.scrollHeight - sc.clientHeight;
        if (sc.scrollTop > max) setTop(max);
      }
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  function animateDetails(det) {
    const going = det._anim ? det._closing : !det.open;     // a second click reverses it
    const startH = det.getBoundingClientRect().height;
    if (det._anim) { det._anim.cancel(); det._anim = null; }
    // Measuring the closed height means closing the section for an instant,
    // and that instant is enough for Safari to clamp the scroll position to
    // the shorter page: closing a fold low in a scrolled box jumped to the
    // top in one frame and the motion ran out of sight (operator video
    // 2026-11-08). Put the scroll position back once it is open again.
    const sc = scrollParent(det);
    const keepTop = sc.scrollTop;
    det.style.height = "";
    det.open = true;
    const openH = det.getBoundingClientRect().height;
    det.open = false;
    const closedH = det.getBoundingClientRect().height;
    det.open = true;
    if (sc.scrollTop !== keepTop) {
      const prev = sc.style.scrollBehavior;
      sc.style.scrollBehavior = "auto";
      sc.scrollTop = keepTop;
      sc.style.scrollBehavior = prev;
    }
    const endH = going ? openH : closedH;
    det._closing = !going;
    // overflow:hidden lets a flex column (most forms here are .stack) squeeze
    // the fold to its padding for the whole motion, then it snapped open at
    // the end (operator note 2026-11-07: "glitches and flashes"). Never shrink.
    det.style.overflow = "hidden";
    det.style.flexShrink = "0";
    // Unhurried, and a closing fold only a little quicker than an opening one.
    const duration = Math.round(Math.min(480, 280 + Math.abs(endH - startH) * 0.15) * (going ? 1 : 0.85));
    const anim = det.animate([{ height: `${startH}px` }, { height: `${endH}px` }], { duration, easing: FOLD_EASE });
    det._anim = anim;
    for (const kid of det.children) {
      if (kid.tagName === "SUMMARY") continue;
      if (kid._fade) kid._fade.cancel();
      kid._fade = kid.animate(going
        ? [{ opacity: 0, transform: "translateY(-6px)" }, { opacity: 1, transform: "none" }]
        : [{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(-6px)" }],
        { duration: going ? duration : Math.round(duration * 0.75), easing: FOLD_EASE, fill: "forwards" });
    }
    followFold(det, anim, going);
    // The fades hold their last frame until the fold itself is done, so a
    // closing section never shows its content again for a frame at the end.
    anim.onfinish = () => {
      det._anim = null;
      det.style.overflow = "";
      det.style.flexShrink = "";
      if (det._closing) det.open = false;
      det._closing = false;
      for (const kid of det.children) { if (kid._fade) { kid._fade.cancel(); kid._fade = null; } }
    };
  }
  document.addEventListener("click", (e) => {
    const summary = e.target.closest("summary");
    if (!summary || e.defaultPrevented || e.button !== 0) return;
    const det = summary.parentElement;
    if (!det || det.tagName !== "DETAILS" || det.firstElementChild !== summary) return;
    if (det.closest(".console, .chat, [data-no-animate]")) return;
    if (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (!det.animate) return;
    e.preventDefault();
    animateDetails(det);
  });

  // The 2FA "already used" wait, shared by the confirm popup and the login page.
  function codeWaitHtml(then) {
    return `2FA code can't be used more than once${tip(`Each code works only once, so a code someone saw or intercepted can't be replayed. Type the next one from your app and ${then}.`, "Why?")}`
      + ` <span class="code-wait-count"></span>`;
  }
  function codeWaitCount() {
    const left = 30 - (Math.floor(Date.now() / 1000) % 30);
    return left > 1 ? `· new code in ${left} s` : "· type the new code";
  }

  // ---- (i) flyouts ---------------------------------------------------------
  // The side note behind a small (i), instead of a line of gray text under
  // every field — operator note 2026-11-07: keep what is on screen short.
  //   <button type="button" class="info-tip" data-tip="Why…" aria-label="More information"></button>
  // or Agenti.tip("Why…") in markup a script builds. Text only (textContent).
  //  * A mouse: hovering shows it; leaving hides it. A click does nothing
  //    (inside a <label> or <summary> it would tick the box / fold the section).
  //  * Touch: a tap opens it; another tap, a tap elsewhere or any scroll closes it.
  //  * Keyboard: focus shows it, Esc or moving on hides it.
  // One bubble for the page, in the top layer (popover) so it shows over an
  // open dialog too; without popover support it goes inside the dialog.
  let tipBubble = null, tipOwner = null, tipHideTimer = null;
  const hoverable = () => !!(window.matchMedia && matchMedia("(hover: hover) and (pointer: fine)").matches);
  function tip(text, label) {
    return `<button type="button" class="info-tip" data-tip="${esc(text)}" aria-label="${esc(label || "More information")}"></button>`;
  }
  function tipEl() {
    if (tipBubble) return tipBubble;
    tipBubble = document.createElement("div");
    tipBubble.className = "info-bubble";
    tipBubble.id = "agenti-info-bubble";
    tipBubble.setAttribute("role", "tooltip");
    if ("popover" in HTMLElement.prototype) tipBubble.popover = "manual";
    tipBubble.addEventListener("mouseenter", () => clearTimeout(tipHideTimer));
    tipBubble.addEventListener("mouseleave", () => hideTip());
    return tipBubble;
  }
  function placeTip(btn) {
    const b = tipEl(), r = btn.getBoundingClientRect(), gap = 8, pad = 10;
    const w = b.offsetWidth, h = b.offsetHeight;
    let left = r.left + r.width / 2 - w / 2;
    left = Math.max(pad, Math.min(left, window.innerWidth - w - pad));
    let top = r.top - h - gap, below = false;
    if (top < pad) { top = r.bottom + gap; below = true; }
    b.style.left = `${Math.round(left)}px`;
    b.style.top = `${Math.round(top)}px`;
    b.classList.toggle("below", below);
    b.style.setProperty("--arrow-x", `${Math.round(r.left + r.width / 2 - left)}px`);
  }
  function showTip(btn) {
    clearTimeout(tipHideTimer);
    const b = tipEl();
    if (tipOwner && tipOwner !== btn) tipOwner.removeAttribute("aria-describedby");
    tipOwner = btn;
    b.textContent = btn.dataset.tip || "";
    const host = b.popover ? document.body : (btn.closest("dialog[open]") || document.body);
    if (b.parentNode !== host) host.appendChild(b);
    if (b.popover && !b.matches(":popover-open")) b.showPopover();
    b.classList.remove("show");
    placeTip(btn);
    requestAnimationFrame(() => b.classList.add("show"));
    btn.setAttribute("aria-describedby", b.id);
    btn.setAttribute("aria-expanded", "true");
  }
  function hideTip(delay) {
    clearTimeout(tipHideTimer);
    const go = () => {
      if (!tipBubble || !tipOwner) return;
      tipBubble.classList.remove("show");
      if (tipBubble.popover && tipBubble.matches(":popover-open")) tipBubble.hidePopover();
      tipOwner.removeAttribute("aria-describedby");
      tipOwner.setAttribute("aria-expanded", "false");
      tipOwner = null;
    };
    if (delay) tipHideTimer = setTimeout(go, delay); else go();
  }
  document.addEventListener("mouseover", (e) => {
    const btn = e.target.closest && e.target.closest(".info-tip");
    if (btn && hoverable() && btn !== tipOwner) showTip(btn);
  });
  document.addEventListener("mouseout", (e) => {
    const btn = e.target.closest && e.target.closest(".info-tip");
    if (!btn || btn !== tipOwner || !hoverable()) return;
    if (e.relatedTarget && (btn.contains(e.relatedTarget) || (tipBubble && tipBubble.contains(e.relatedTarget)))) return;
    hideTip(120);   // time to move onto the bubble
  });
  document.addEventListener("click", (e) => {
    const btn = e.target.closest && e.target.closest(".info-tip");
    if (btn) {
      e.preventDefault();          // never ticks a checkbox or folds a section
      if (!hoverable()) { if (tipOwner === btn) hideTip(); else showTip(btn); }
      return;
    }
    if (tipOwner && !(tipBubble && tipBubble.contains(e.target))) hideTip();
  }, true);
  document.addEventListener("focusin", (e) => {
    const btn = e.target.closest && e.target.closest(".info-tip");
    if (btn && btn.matches(":focus-visible")) showTip(btn);
    else if (tipOwner && e.target !== tipOwner) hideTip();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && tipOwner) { e.preventDefault(); hideTip(); } });
  document.addEventListener("scroll", () => { if (tipOwner) hideTip(); }, { capture: true, passive: true });
  window.addEventListener("resize", () => { if (tipOwner) hideTip(); }, { passive: true });

  // ---- how a run reads on screen -----------------------------------------
  // One copy, shared by the dashboard, the agent page and the team page, so
  // the same run never reads differently in two places. A run's terminal
  // status is completed / incomplete / failed; "canceled" and "paused" are
  // readings of its `reason` (state.py's vocabulary).
  const REASON_WORD = {
    stopped: "Stopped", interrupted: "Interrupted", timeout: "Timed out", error: "Failed",
    max_turns: "Turn limit", max_budget: "Budget limit",
  };
  const run = {
    // "canceled" | "paused" | "completed" | "failed" — the badge class and
    // the Task History filter value.
    outcomeOf(row) {
      if (row.status === "incomplete" && (row.reason === "stopped" || row.reason === "interrupted")) return "canceled";
      if (row.status === "incomplete") return "paused";
      if (row.status === "completed") return "completed";
      return "failed";
    },
    // One word for a badge; the full status rides on the tooltip.
    statusWord(status, reason) {
      if (status === "completed") return "Completed";
      if (status === "failed") return "Failed";
      if (reason && REASON_WORD[reason]) return REASON_WORD[reason];
      if (status === "incomplete") return "Incomplete";
      return status || "unknown";
    },
    statusFull(status, reason) { return reason ? `${status} · ${reason}` : String(status || ""); },
    // [badge class, word, tooltip] for a live slot: {state, freezer, live}.
    badge(st) {
      const live = st.live || {};
      // A question only needs an answer while the run can still receive one;
      // a run that ended with one open reads as its outcome, like any other.
      if (st.state === "active") {
        if (live.awaiting_operator && live.awaiting_operator.question) {
          return ["warn-soft", "Needs input", `waiting on you: ${live.awaiting_operator.question}`];
        }
        if (st.freezer === "frozen") return ["paused", "Paused", "paused"];
        return ["running", "Running", "running"];
      }
      if (live.phase === "finished") {
        return [run.outcomeOf(live), run.statusWord(live.status, live.reason),
                run.statusFull(live.status, live.reason)];
      }
      return ["incomplete", "Idle", st.state || "idle"];
    },
    target(t) { return !t ? "" : String(t); },
  };

  // ---- icons ------------------------------------------------------------
  // One inline-SVG set for every page: 20×20 viewBox, 1.7px round stroke,
  // currentColor — so an icon inherits the color and size of whatever it
  // sits in. Inline on purpose: an icon font or a sprite sheet would be the
  // first third-party asset anywhere in this GUI (§4 item 21 declined one
  // once already). icon(name, size) returns markup; iconEl(name) an element.
  const ICON_PATHS = {
    dashboard: '<rect x="3" y="3" width="6" height="6" rx="1.5"/><rect x="11" y="3" width="6" height="6" rx="1.5"/><rect x="3" y="11" width="6" height="6" rx="1.5"/><rect x="11" y="11" width="6" height="6" rx="1.5"/>',
    outputs: '<path d="M2.5 6.5A1.5 1.5 0 0 1 4 5h3.6l1.6 1.9H16a1.5 1.5 0 0 1 1.5 1.5v6.6a1.5 1.5 0 0 1-1.5 1.5H4a1.5 1.5 0 0 1-1.5-1.5z"/>',
    // A cog with eight teeth (the old rays read as a sun — operator note 2026-11-07).
    settings: '<path d="M8.58 3.86 8.91 1.87h2.18l.33 1.99 1.91.79 1.64-1.17 1.55 1.55-1.17 1.64.79 1.91 1.99.33v2.18l-1.99.33-.79 1.91 1.17 1.64-1.55 1.55-1.64-1.17-1.91.79-.33 1.99H8.91l-.33-1.99-1.91-.79-1.64 1.17-1.55-1.55 1.17-1.64-.79-1.91-1.99-.33V8.91l1.99-.33.79-1.91-1.17-1.64 1.55-1.55 1.64 1.17Z"/><circle cx="10" cy="10" r="2.4"/>',
    logout: '<path d="M8 3.5H4.5A1.5 1.5 0 0 0 3 5v10a1.5 1.5 0 0 0 1.5 1.5H8M12.5 6.5 16 10l-3.5 3.5M16 10H7.5"/>',
    user: '<circle cx="10" cy="6.8" r="3.2"/><path d="M3.8 17c.6-3.4 3.1-5 6.2-5s5.6 1.6 6.2 5"/>',
    users: '<circle cx="7.5" cy="7" r="2.8"/><path d="M2.5 16.5c.5-3 2.6-4.5 5-4.5s4.5 1.5 5 4.5M13.5 4.4a2.6 2.6 0 0 1 0 5.2M15 12.2c1.6.6 2.4 1.9 2.7 4.3"/>',
    shield: '<path d="M10 2.5 16.5 5v4.6c0 3.8-2.6 6.6-6.5 8-3.9-1.4-6.5-4.2-6.5-8V5z"/><path d="M7.3 10.2 9.2 12l3.6-3.8"/>',
    palette: '<path d="M10 2.8a7.2 7.2 0 1 0 0 14.4c1.2 0 1.7-.8 1.4-1.7-.4-1 .1-2 1.2-2h1.6a3 3 0 0 0 3-3A7.7 7.7 0 0 0 10 2.8z"/><circle cx="6.6" cy="9.4" r="1.1" fill="currentColor" stroke="none"/><circle cx="9.2" cy="6.2" r="1.1" fill="currentColor" stroke="none"/><circle cx="13.2" cy="6.8" r="1.1" fill="currentColor" stroke="none"/>',
    building: '<path d="M4 17V4.5A1.5 1.5 0 0 1 5.5 3h6A1.5 1.5 0 0 1 13 4.5V17M13 8h2a1.5 1.5 0 0 1 1.5 1.5V17M2.5 17h15M7 6.5h2.5M7 9.5h2.5M7 12.5h2.5M8.5 17v-2.5"/>',
    sliders: '<path d="M3.5 5H10.5M14.5 5H16.5M12.5 3V7M3.5 10H5.5M9.5 10H16.5M7.5 8V12M3.5 15H8.5M12.5 15H16.5M10.5 13V17"/>',
    wrench: '<path transform="rotate(45 10 10)" d="M8.5 1.8V5h3V1.8a4.1 4.1 0 0 1-.1 7.6V17a1.4 1.4 0 0 1-2.8 0V9.4a4.1 4.1 0 0 1-.1-7.6z"/>',
    send: '<path d="M17 3.5 3 8.6l6 2 2.2 5.9z"/><path d="M17 3.5 9 10.6"/>',
    note: '<path d="M12.8 3.6l3.6 3.6-8.6 8.6H4.2v-3.6z"/><path d="M11 5.4l3.6 3.6"/>',
    bolt: '<path d="M11.5 2.5 4.5 11h4.5l-.8 6.5 7.3-8.8H11z"/>',
    tag: '<path d="M3 4.5A1.5 1.5 0 0 1 4.5 3h5l7.5 7.5-6.5 6.5L3 9.5z"/><circle cx="7" cy="7" r="1.3"/>',
    stop: '<rect x="4.5" y="4.5" width="11" height="11" rx="1.6"/>',
    pause: '<path d="M7 4.5v11M13 4.5v11"/>',
    play: '<path d="M6 4.2v11.6l9-5.8z"/>',
    download: '<path d="M10 3v9.5M6.3 9 10 12.7 13.7 9M4 16h12"/>',
    trash: '<path d="M4 5.5h12M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M5.5 5.5l.8 10a1.5 1.5 0 0 0 1.5 1.4h4.4a1.5 1.5 0 0 0 1.5-1.4l.8-10M8.3 9v5M11.7 9v5"/>',
    edit: '<path d="M4 13.5V16h2.5L15 7.5l-2.5-2.5L4 13.5z"/><path d="M11.5 6 14 8.5"/>',
    open: '<path d="M8 4.5H5A1.5 1.5 0 0 0 3.5 6v9A1.5 1.5 0 0 0 5 16.5h9a1.5 1.5 0 0 0 1.5-1.5v-3M11.5 3.5H16.5v5M16.5 3.5 9.5 10.5"/>',
    check: '<path d="M4 10.5 8 14.5 16 5.5"/>',
    plus: '<path d="M10 4v12M4 10h12"/>',
    history: '<path d="M3.5 10A6.5 6.5 0 1 0 5.4 5.4M3.5 4.5v3.5H7M10 6.8V10l2.4 1.6"/>',
    grid: '<rect x="3" y="3" width="14" height="14" rx="2"/><path d="M3 8.5h14M8.5 8.5V17"/>',
    rocket: '<g transform="rotate(45 10 10)"><path d="M10 2c2.7 2 3.5 5 3.5 8.6L12.3 14H7.7L6.5 10.6C6.5 7 7.3 4 10 2z"/><circle cx="10" cy="8" r="1.5"/><path d="M6.7 11.2C5.1 11.8 4.5 13.2 4.5 15.6l3-1.4M13.3 11.2c1.6.6 2.2 2 2.2 4.4l-3-1.4M10 16.3v1.9"/></g>',
    search: '<circle cx="8.8" cy="8.8" r="5.3"/><path d="M12.8 12.8 17 17"/>',
    key: '<circle cx="7" cy="12.5" r="3.5"/><path d="M9.5 10 16.5 3M13.5 6l2 2M15.5 4l2 2"/>',
    lock: '<rect x="4.5" y="9" width="11" height="8" rx="1.6"/><path d="M7 9V6.5a3 3 0 0 1 6 0V9"/>',
    fingerprint: '<path d="M3.5 12.5v-1.3a6.5 6.5 0 0 1 13 0v.8M6.2 17.4c.4-1.4.6-3.1.6-6.2a3.2 3.2 0 0 1 6.4 0c0 2.3-.2 4-.6 5.6M10 11.2c0 2.5-.3 4.6-.9 6.6"/>',
    sun: '<circle cx="10" cy="10" r="3.6"/><path d="M10 1.8v1.8M10 16.4v1.8M1.8 10h1.8M16.4 10h1.8M4.2 4.2l1.3 1.3M14.5 14.5l1.3 1.3M15.8 4.2l-1.3 1.3M5.5 14.5l-1.3 1.3"/>',
    moon: '<path d="M16.5 12.4A7 7 0 0 1 7.6 3.5a7 7 0 1 0 8.9 8.9z"/>',
    monitor: '<rect x="2.5" y="4" width="15" height="9.5" rx="1.5"/><path d="M7 17h6M10 13.5V17"/>',
    eye: '<path d="M2.5 10s2.8-5 7.5-5 7.5 5 7.5 5-2.8 5-7.5 5-7.5-5-7.5-5z"/><circle cx="10" cy="10" r="2.4"/>',
    "eye-off": '<path d="M2.5 10s2.8-5 7.5-5 7.5 5 7.5 5-2.8 5-7.5 5-7.5-5-7.5-5z"/><circle cx="10" cy="10" r="2.4"/><path d="M3 3l14 14"/>',
    refresh: '<path d="M16.5 8.5A6.5 6.5 0 0 0 5 6.2M3.5 11.5A6.5 6.5 0 0 0 15 13.8M3.5 4.5v3.5H7M16.5 15.5V12H13"/>',
    info: '<circle cx="10" cy="10" r="7"/><path d="M10 9v4.5M10 6.6v.2"/>',
    warning: '<path d="M8.7 4.2a1.5 1.5 0 0 1 2.6 0l6.2 11a1.5 1.5 0 0 1-1.3 2.3H3.8a1.5 1.5 0 0 1-1.3-2.3z"/><path d="M10 8.2v3.6M10 14.4v.1"/>',
    file: '<path d="M11.5 2.5H5.5a1.5 1.5 0 0 0-1.5 1.5v12a1.5 1.5 0 0 0 1.5 1.5h9a1.5 1.5 0 0 0 1.5-1.5V7z"/><path d="M11.5 2.5V7H16M7 11h6M7 14h4"/>',
    book: '<path d="M10 5.6C8.4 4.3 6.2 3.8 3.5 4v11.6c2.7-.2 4.9.3 6.5 1.6 1.6-1.3 3.8-1.8 6.5-1.6V4c-2.7-.2-4.9.3-6.5 1.6z"/><path d="M10 5.6v11.6"/>',
    chat: '<path d="M3.5 5.5A1.5 1.5 0 0 1 5 4h10a1.5 1.5 0 0 1 1.5 1.5v6A1.5 1.5 0 0 1 15 13H8.5L5 16v-3A1.5 1.5 0 0 1 3.5 11.5z"/>',
    team: '<circle cx="6.5" cy="7.5" r="2.5"/><circle cx="13.5" cy="7.5" r="2.5"/><path d="M2.5 16c.4-2.6 2-4 4-4s3.6 1.4 4 4M9.5 16c.4-2.6 2-4 4-4s3.6 1.4 4 4"/>',
    menu: '<path d="M3 5.5h14M3 10h14M3 14.5h14"/>',
    'chevron-down': '<path d="M5 7.5l5 5 5-5"/>',
    'chevron-right': '<path d="M7.5 5l5 5-5 5"/>',
    back: '<path d="M12 4.5 6.5 10l5.5 5.5"/>',
    print: '<path d="M6 7.5V3.5h8v4M6 14.5H4.5A1.5 1.5 0 0 1 3 13V9a1.5 1.5 0 0 1 1.5-1.5h11A1.5 1.5 0 0 1 17 9v4a1.5 1.5 0 0 1-1.5 1.5H14"/><rect x="6" y="11.5" width="8" height="5"/>',
    close: '<path d="M5 5l10 10M15 5 5 15"/>',
    link: '<path d="M8.5 11.5a3 3 0 0 0 4.2 0l2.3-2.3a3 3 0 0 0-4.2-4.2l-1 1M11.5 8.5a3 3 0 0 0-4.2 0L5 10.8a3 3 0 0 0 4.2 4.2l1-1"/>',
    // A wrench (the wrench icon's own shape) crossed with a hammer whose handle
    // breaks where the wrench passes over it, so no lines touch (note 2026-11-08).
    tools: '<path transform="rotate(45 10 10)" d="M8.5 1.33V4.2H11.5V1.33A3.6 3.6 0 0 1 11.4 7.92V15.6a1.4 1.4 0 0 1 -2.8 0V7.92A3.6 3.6 0 0 1 8.5 1.33z"/><g transform="rotate(-45 10 10)"><rect x="7.4" y="1.4" width="5.2" height="3.2" rx="1.1"/><path d="M8.8 4.6V7M11.2 4.6V7M8.8 13V15.8a1.2 1.2 0 0 0 2.4 0V13"/></g>',
    pixel: '<path d="M4 4h3v3H4zM8.5 4h3v3h-3zM13 4h3v3h-3zM4 8.5h3v3H4zM13 8.5h3v3h-3zM4 13h3v3H4zM8.5 13h3v3h-3zM13 13h3v3h-3z"/>',
    star: '<path d="m10 2.8 2.2 4.6 5 .7-3.6 3.5.9 5L10 14.2l-4.5 2.4.9-5L2.8 8.1l5-.7z"/>',
    coin: '<circle cx="10" cy="10" r="7"/><path d="M10 6v8M7.8 8.2c.5-.9 1.4-1.2 2.2-1.2 1.4 0 2.2.7 2.2 1.6 0 2.2-4.4 1-4.4 3.2 0 .9.8 1.6 2.2 1.6.9 0 1.7-.3 2.2-1.2"/>',
    calc: '<rect x="4.5" y="2.5" width="11" height="15" rx="1.6"/><path d="M7 5.5h6M7.5 9.5h.1M10 9.5h.1M12.5 9.5h.1M7.5 12.5h.1M10 12.5h.1M12.5 12.5h.1M7.5 15h5"/>',
    clipboard: '<rect x="4.5" y="4" width="11" height="13" rx="1.5"/><path d="M7.5 4V3h5v1M7 9h6M7 12.5h4"/>',
    // A small set for the launch page's agent cards. Same
    // 20x20/1.7px-stroke/currentColor style as every icon above.
    globe: '<circle cx="10" cy="10" r="7"/><path d="M3 10h14M10 3c2.4 2 2.4 12 0 14M10 3c-2.4 2-2.4 12 0 14"/>',
    activity: '<path d="M2.5 10.5h3l2-5.5 3 11 2-8 1.5 2.5h3.5"/>',
    image: '<rect x="3" y="4.5" width="14" height="11" rx="1.6"/><circle cx="7.2" cy="8.5" r="1.3"/><path d="M4 14l3.8-3.8 2.7 2.7 1.8-1.8 3.7 3.7"/>',
    upload: '<path d="M10 13V3.5M6.3 7 10 3.3 13.7 7M4 16h12"/>',
    paperclip: '<path d="M15.5 9.5l-5.6 5.6a3.6 3.6 0 0 1-5.1-5.1l6-6a2.4 2.4 0 0 1 3.4 3.4l-6 6a1.2 1.2 0 0 1-1.7-1.7L11.9 6.3"/>',
    terminal: '<rect x="2.5" y="3.5" width="15" height="13" rx="1.8"/><path d="M6 8l2.5 2L6 12M10.5 12.5H14"/>',
    target: '<circle cx="10" cy="10" r="7"/><circle cx="10" cy="10" r="3.5"/><circle cx="10" cy="10" r=".6"/>',
    cpu: '<rect x="5" y="5" width="10" height="10" rx="1.6"/><path d="M8 2.5V5M12 2.5V5M8 15v2.5M12 15v2.5M2.5 8H5M2.5 12H5M15 8h2.5M15 12h2.5"/>',
    // The AI providers' own marks, in one color like every icon here, only
    // to name the provider (TRADEMARKS.md). Paths: Simple Icons (CC0), on
    // their own 24×24 grid (ICON_VIEWBOX), filled rather than stroked.
    claude: '<path fill="currentColor" stroke="none" d="m4.7144 15.9555 4.7174-2.6471.079-.2307-.079-.1275h-.2307l-.7893-.0486-2.6956-.0729-2.3375-.0971-2.2646-.1214-.5707-.1215-.5343-.7042.0546-.3522.4797-.3218.686.0608 1.5179.1032 2.2767.1578 1.6514.0972 2.4468.255h.3886l.0546-.1579-.1336-.0971-.1032-.0972L6.973 9.8356l-2.55-1.6879-1.3356-.9714-.7225-.4918-.3643-.4614-.1578-1.0078.6557-.7225.8803.0607.2246.0607.8925.686 1.9064 1.4754 2.4893 1.8336.3643.3035.1457-.1032.0182-.0728-.164-.2733-1.3539-2.4467-1.445-2.4893-.6435-1.032-.17-.6194c-.0607-.255-.1032-.4674-.1032-.7285L6.287.1335 6.6997 0l.9957.1336.419.3642.6192 1.4147 1.0018 2.2282 1.5543 3.0296.4553.8985.2429.8318.091.255h.1579v-.1457l.1275-1.706.2368-2.0947.2307-2.6957.0789-.7589.3764-.9107.7468-.4918.5828.2793.4797.686-.0668.4433-.2853 1.8517-.5586 2.9021-.3643 1.9429h.2125l.2429-.2429.9835-1.3053 1.6514-2.0643.7286-.8196.85-.9046.5464-.4311h1.0321l.759 1.1293-.34 1.1657-1.0625 1.3478-.8804 1.1414-1.2628 1.7-.7893 1.36.0729.1093.1882-.0183 2.8535-.607 1.5421-.2794 1.8396-.3157.8318.3886.091.3946-.3278.8075-1.967.4857-2.3072.4614-3.4364.8136-.0425.0304.0486.0607 1.5482.1457.6618.0364h1.621l3.0175.2247.7892.522.4736.6376-.079.4857-1.2142.6193-1.6393-.3886-3.825-.9107-1.3113-.3279h-.1822v.1093l1.0929 1.0686 2.0035 1.8092 2.5075 2.3314.1275.5768-.3218.4554-.34-.0486-2.2039-1.6575-.85-.7468-1.9246-1.621h-.1275v.17l.4432.6496 2.3436 3.5214.1214 1.0807-.17.3521-.6071.2125-.6679-.1214-1.3721-1.9246L14.38 17.959l-1.1414-1.9428-.1397.079-.674 7.2552-.3156.3703-.7286.2793-.6071-.4614-.3218-.7468.3218-1.4753.3886-1.9246.3157-1.53.2853-1.9004.17-.6314-.0121-.0425-.1397.0182-1.4328 1.9672-2.1796 2.9446-1.7243 1.8456-.4128.164-.7164-.3704.0667-.6618.4008-.5889 2.386-3.0357 1.4389-1.882.929-1.0868-.0062-.1579h-.0546l-6.3385 4.1164-1.1293.1457-.4857-.4554.0608-.7467.2307-.2429 1.9064-1.3114Z"/>',
    openai: '<path fill="currentColor" stroke="none" d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z"/>',
  };
  const ICON_VIEWBOX = { claude: "0 0 24 24", openai: "0 0 24 24" };
  function icon(name, size) {
    const p = ICON_PATHS[name];
    if (!p) return "";
    const s = size || 16;
    return `<svg class="ico ico-${name}" viewBox="${ICON_VIEWBOX[name] || "0 0 20 20"}" width="${s}" height="${s}" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
  }
  // The one title/subtitle item every list on the site uses: an optional
  // icon, a title, and an italic smaller subtitle under it (the role
  // picker's look). Returns markup; `title`/`sub` are escaped here.
  function ti(title, sub, opts) {
    const o = opts || {};
    const e = (x) => String(x == null ? "" : x).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const ic = o.icon ? `<span class="ti-icon">${icon(o.icon, 16)}</span>` : "";
    const t = o.mono ? `<code>${e(title)}</code>` : e(title);
    return `<div class="ti${o.cls ? " " + o.cls : ""}">${ic}<div class="ti-body"><div class="ti-title">${t}${o.badge || ""}</div>${sub ? `<div class="ti-sub">${e(sub)}</div>` : ""}</div>${o.after || ""}</div>`;
  }
  function iconEl(name, size) {
    const t = document.createElement("template");
    t.innerHTML = icon(name, size);
    return t.content.firstElementChild;
  }

  // ---- avatars ----------------------------------------------------------
  // Every avatar renders both an initials span (the Original skin) and a
  // pixel sprite (the Arcade skin); CSS shows one. The sprite is picked and
  // colored deterministically from the name, so an agent has the same face
  // on every page and every device, and a hue may be forced (the team chat
  // gives each member its own color already). Hand-drawn 12×12 creatures,
  // not random noise: '#' body, '+' a second color, 'o' eye-white, 'x' eye
  // or dark detail, '.' empty. Widths are checked at load.
  const SPRITES = [
    [ // invader
      "............",
      "............",
      "...#....#...",
      "....#..#....",
      "...######...",
      "..##x##x##..",
      ".##########.",
      ".#.######.#.",
      ".#.#....#.#.",
      "....##.##...",
      "............",
      "............",
    ],
    [ // ghost
      "............",
      "....####....",
      "...######...",
      "..########..",
      "..#oo##oo#..",
      "..#ox##ox#..",
      "..########..",
      "..########..",
      "..########..",
      "..########..",
      "..#.##.##.#.",
      "............",
    ],
    [ // robot
      ".....##.....",
      ".....##.....",
      "...######...",
      "..########..",
      "..#xx##xx#..",
      "..########..",
      "..#++++++#..",
      "...######...",
      ".#.######.#.",
      ".#.#.##.#.#.",
      "...##..##...",
      "...##..##...",
    ],
    [ // slime
      "............",
      "............",
      "............",
      ".....##.....",
      "...######...",
      "..########..",
      ".##x####x##.",
      ".##########.",
      ".###+##+###.",
      ".##########.",
      "..########..",
      "............",
    ],
    [ // octopus
      "............",
      "....####....",
      "..########..",
      ".##########.",
      ".###x##x###.",
      ".##########.",
      ".##########.",
      "..#.####.#..",
      ".#.#.##.#.#.",
      ".#.#.##.#.#.",
      "....#..#....",
      "............",
    ],
    [ // cat
      "............",
      "..#......#..",
      "..##....##..",
      "..########..",
      "..########..",
      "..#x####x#..",
      "..########..",
      "..###++###..",
      "...######...",
      "..########..",
      "..#.####.#..",
      "............",
    ],
    [ // mushroom
      "............",
      "....####....",
      "..##+###+#..",
      ".##########.",
      ".#+###+###+.",
      ".##########.",
      ".##########.",
      "...######...",
      "...#xo##xo..",
      "...######...",
      "...######...",
      "............",
    ],
    [ // bird
      "............",
      "............",
      ".....###....",
      "....#x###+..",
      "....#####...",
      "..########..",
      ".##########.",
      ".##########.",
      "..########..",
      "...######...",
      ".....#.#....",
      "....##.##...",
    ],
  ];
  SPRITES.forEach((rows, i) => {
    if (rows.length !== 12 || rows.some((r) => r.length !== 12)) console.warn(`sprite ${i} is not 12×12`);
  });
  function nameHash(s) {
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  function avatarHue(name) { return nameHash(String(name || "")) % 360; }
  function spriteSvg(name, hue) {
    const h = hue === undefined || hue === null ? avatarHue(name) : Number(hue);
    const rows = SPRITES[(nameHash(String(name || "")) >>> 8) % SPRITES.length];
    const fill = {
      "#": `hsl(${h} 78% 62%)`,
      "+": `hsl(${(h + 48) % 360} 90% 66%)`,
      "o": "#ffffff",
      "x": "#14102a",
    };
    let rects = "";
    rows.forEach((row, y) => {
      let x = 0;
      while (x < 12) {
        const c = row[x];
        if (!fill[c]) { x++; continue; }
        let w = 1;
        while (x + w < 12 && row[x + w] === c) w++;
        rects += `<rect x="${x}" y="${y}" width="${w}" height="1" fill="${fill[c]}"/>`;
        x += w;
      }
    });
    return `<svg class="av-sprite" viewBox="0 0 12 12" shape-rendering="crispEdges" aria-hidden="true">${rects}</svg>`;
  }
  // The inner markup for a .avatar / .chat-avatar element.
  function avatarInner(name, opts) {
    const o = opts || {};
    const initials = String(o.initials !== undefined ? o.initials : String(name || "?").slice(0, 2)).toUpperCase();
    return `<span class="av-initials">${esc(initials)}</span>${spriteSvg(name, o.hue)}`;
  }

  // ---- roles ------------------------------------------------------------
  // The caller's role (/auth/me `role`): admin, operator, or null. Pages use
  // it to draw only the controls the caller could use; the routes enforce
  // regardless.
  const TIER = { admin: 2, operator: 1 };
  function roleAtLeast(role, want) { return (TIER[role] || 0) >= (TIER[want] || 0); }
  // The one place a raw role slug becomes what a person reads. The system
  // spelling never changes — every CLI verb, API value and stored binding
  // still says exactly that — this only decides how it's WRITTEN on screen.
  const ROLE_LABEL = { admin: "admin" };
  function roleLabel(role) {
    if (!role) return role;
    return ROLE_LABEL[role] || role.replace(/-/g, " ");
  }

  // ---- the one popup frame ---------------------------------------------------
  // Every popup gets the same three parts, so a long one (Engagement) never
  // makes you scroll to find a way out: a header that stays put with the
  // title and an X, a body that scrolls, and — when the popup's last row is
  // its buttons (Save / Cancel) — a footer that stays put too. Applied once,
  // the first time a dialog opens (showModal is wrapped below), so a page
  // builds its popup as a plain <dialog><form>, title first and button row
  // last, and gets the frame without asking for it. A dialog that draws its
  // own frame (the wizards, a user's dashboard) is left alone.
  //
  // The X behaves like Escape: a cancel event the popup may refuse (a step in
  // flight), then close — so every popup's own "on close" cleanup still runs.
  function frameDialog(dlg) {
    if (!dlg || dlg.dataset.framed || dlg.classList.contains("wizard") || dlg.querySelector(".ud-head")) return;
    dlg.dataset.framed = "1";
    const form = dlg.querySelector(":scope > form") || dlg;
    const kids = Array.from(form.children);
    const title = kids.find((el) => el.matches("h1, h2, .approval-head"));
    const last = kids[kids.length - 1];
    const foot = last && last.matches(".btn-row") ? last : null;

    const head = document.createElement("div");
    head.className = "dlg-head";
    const x = document.createElement("button");
    x.type = "button";
    x.className = "dlg-x";
    x.setAttribute("aria-label", "Close");
    x.title = "Close (Esc)";
    x.innerHTML = icon("close", 18);
    x.addEventListener("click", () => {
      const ev = new Event("cancel", { cancelable: true });
      if (dlg.dispatchEvent(ev)) dlg.close();
    });
    if (title) head.appendChild(title);
    head.appendChild(x);

    const body = document.createElement("div");
    body.className = "dlg-body" + (form.classList.contains("stack") ? " stack" : "");
    kids.forEach((el) => { if (el !== title && el !== foot) body.appendChild(el); });

    form.appendChild(head);
    form.appendChild(body);
    if (foot) { foot.classList.add("dlg-foot"); form.appendChild(foot); }
    dlg.classList.add("dlg-framed");
  }
  if (typeof HTMLDialogElement !== "undefined" && !HTMLDialogElement.prototype._agentiFramed) {
    const show = HTMLDialogElement.prototype.showModal;
    HTMLDialogElement.prototype.showModal = function () {
      try { frameDialog(this); } catch (e) { /* the popup still opens, unframed */ }
      return show.call(this);
    };
    HTMLDialogElement.prototype._agentiFramed = true;
  }

  return {
    get: (p, opts) => call("GET", p, undefined, opts),
    post: (p, b, opts) => call("POST", p, b === undefined ? {} : b, opts),
    del: (p, opts) => call("DELETE", p, undefined, opts),
    stream, setCsrf, csrf, clearAuth, ApiError, esc, when, ago, banner, flash, showFlash, errorText, normaliseSecondFactor,
    me: () => memoGet("auth/me"), run,
    copyText, copyButton, copyButtonHtml, wireCopyButtons, qrCode,
    webauthnCreate, webauthnGet, webauthnOriginHint, webauthnConfig, passkeysUsable,
    requireApproval, confirmDanger, frameDialog,
    dismissibleBanner, hiddenBannerCount, showHiddenBanners, forgetClosedBanners, tip, codeWaitHtml, codeWaitCount,
    icon, iconEl, ti, avatarInner, avatarHue, spriteSvg, roleAtLeast, roleLabel,
    userHistory, userLabel,
  };
})();
