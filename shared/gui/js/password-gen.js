// password-gen.js — a password box that comes filled with a strong,
// generated password (operator note 2026-11-06), used wherever someone sets
// a password: sign-up, the reset link, Settings → Security, and an admin
// resetting someone else's.
//
//   const pw = AgentiPassword.attach(inputEl, { username: "alice" });
//   pw.check()          -> "" when it may be submitted, else what to fix
//   pw.value            -> the password
//   pw.saved(username)  -> after a successful save: ask the browser to store it
//
// The box holds three icons: show/hide, copy, and a gear that opens a small
// panel with a length slider (16–64, starting at 64) and a "new password"
// button. Under it: "Secure password auto generated". Typing your own turns
// that into "At least 8 characters" and asks for it a second time.
//
// Generation uses crypto.getRandomValues with rejection sampling (every
// character equally likely), at least one lowercase, uppercase, digit and
// symbol, shuffled the same way. Symbols are a safe set — no quotes,
// backslash or space — and a password never starts with "-" (the server
// reads a leading "-" as a flag and refuses it).
//
// Password managers: the box keeps autocomplete="new-password", the page
// gives each form a username field, and saved() asks Chrome/Edge to offer
// "Save password?" (navigator.credentials.store). A web page cannot open an
// extension's own prompt (1Password, Bitwarden …); those see the sign-up
// form and offer to save it themselves.
window.AgentiPassword = (() => {
  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const DIGITS = "0123456789";
  const SYMBOLS = "!#$%&*+-=?@^_~";
  const ALL = LOWER + UPPER + DIGITS + SYMBOLS;
  const MIN = 16, MAX = 64, MIN_TYPED = 8;
  const LENGTH_KEY = "agenti-password-length";

  function randomBelow(n) {
    // Rejection sampling: drop the top sliver of the 32-bit range that would
    // otherwise make the first characters of a set slightly more likely.
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    for (;;) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return buf[0] % n;
    }
  }
  const pick = (set) => set[randomBelow(set.length)];

  function generate(length) {
    const n = Math.max(MIN, Math.min(MAX, length | 0 || MAX));
    const chars = [pick(LOWER), pick(UPPER), pick(DIGITS), pick(SYMBOLS)];
    while (chars.length < n) chars.push(pick(ALL));
    for (let i = chars.length - 1; i > 0; i--) {          // Fisher–Yates, unbiased
      const j = randomBelow(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    if (chars[0] === "-") {                               // never a leading "-"
      const k = chars.findIndex((c) => LOWER.includes(c) || UPPER.includes(c));
      [chars[0], chars[k]] = [chars[k], chars[0]];
    }
    return chars.join("");
  }

  function savedLength() {
    try {
      const v = parseInt(localStorage.getItem(LENGTH_KEY) || "", 10);
      return v >= MIN && v <= MAX ? v : MAX;
    } catch (e) { return MAX; }
  }

  let seq = 0;
  function attach(input, opts = {}) {
    const id = `pwgen-${++seq}`;
    let length = savedLength();
    let generated = "";

    const box = document.createElement("div");
    box.className = "pw-box";
    input.parentNode.insertBefore(box, input);
    box.appendChild(input);
    input.type = "password";
    input.autocomplete = "new-password";
    input.spellcheck = false;
    input.classList.add("pw-input");

    const actions = document.createElement("div");
    actions.className = "pw-actions";
    actions.innerHTML = `
      <button type="button" class="pw-btn" data-act="show" aria-label="Show password" title="Show password">${Agenti.icon("eye", 16)}</button>
      <span class="pw-copy"></span>
      <button type="button" class="pw-btn" data-act="gear" aria-label="Password options" title="Password options"
              aria-haspopup="true" aria-expanded="false" aria-controls="${id}-panel">${Agenti.icon("settings", 16)}</button>`;
    box.appendChild(actions);
    const copy = Agenti.copyButton(() => input.value, "Copy password");
    copy.classList.add("pw-btn");
    actions.querySelector(".pw-copy").replaceWith(copy);

    const panel = document.createElement("div");
    panel.className = "pw-panel";
    panel.id = `${id}-panel`;
    panel.hidden = true;
    panel.innerHTML = `
      <div class="pw-panel-row">
        <label for="${id}-len">Length</label>
        <output id="${id}-out" for="${id}-len">${length}</output>
      </div>
      <input type="range" id="${id}-len" min="${MIN}" max="${MAX}" value="${length}" aria-describedby="${id}-range">
      <div class="pw-panel-row pw-range" id="${id}-range"><span>${MIN}</span><span>${MAX}</span></div>
      <button type="button" class="btn btn-sm pw-new" data-act="new">${Agenti.icon("refresh", 15)}<span>New password</span></button>`;
    box.appendChild(panel);

    const hint = document.createElement("p");
    hint.className = "hint pw-hint";
    box.insertAdjacentElement("afterend", hint);

    const confirmField = document.createElement("div");
    confirmField.className = "field pw-confirm";
    confirmField.hidden = true;
    confirmField.innerHTML = `<label for="${id}-again">Type it again</label>
      <input type="password" id="${id}-again" autocomplete="new-password" spellcheck="false">`;
    hint.insertAdjacentElement("afterend", confirmField);
    const again = confirmField.querySelector("input");

    const slider = panel.querySelector('input[type="range"]');
    const out = panel.querySelector("output");
    const showBtn = actions.querySelector('[data-act="show"]');
    const gearBtn = actions.querySelector('[data-act="gear"]');

    function paint() {
      const own = input.value !== generated;
      hint.textContent = own ? `At least ${MIN_TYPED} characters.` : "Secure password auto generated";
      hint.classList.toggle("own", own);
      confirmField.hidden = !own;
      if (!own) again.value = "";
    }
    function fill() {
      generated = generate(length);
      input.value = generated;
      paint();
      if (opts.onChange) opts.onChange();
    }
    function setShown(on) {
      input.type = on ? "text" : "password";
      again.type = on ? "text" : "password";
      showBtn.innerHTML = Agenti.icon(on ? "eye-off" : "eye", 16);
      showBtn.setAttribute("aria-label", on ? "Hide password" : "Show password");
      showBtn.title = on ? "Hide password" : "Show password";
    }
    function setPanel(open) {
      panel.hidden = !open;
      gearBtn.setAttribute("aria-expanded", String(open));
      if (open) slider.focus();
    }

    showBtn.addEventListener("click", () => setShown(input.type === "password"));
    gearBtn.addEventListener("click", () => setPanel(panel.hidden));
    slider.addEventListener("input", () => {
      length = parseInt(slider.value, 10);
      out.textContent = String(length);
      try { localStorage.setItem(LENGTH_KEY, String(length)); } catch (e) { /* no persistence */ }
      fill();
    });
    panel.querySelector('[data-act="new"]').addEventListener("click", fill);
    input.addEventListener("input", paint);
    document.addEventListener("click", (e) => { if (!panel.hidden && !box.contains(e.target)) setPanel(false); });
    box.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !panel.hidden) { e.preventDefault(); setPanel(false); gearBtn.focus(); }
    });

    fill();

    return {
      get value() { return input.value; },
      get generated() { return input.value === generated; },
      regenerate: fill,
      check() {
        const n = [...input.value].length;           // characters, as the server counts them
        if (n < MIN_TYPED) return `Use at least ${MIN_TYPED} characters.`;
        if (input.value !== generated && again.value !== input.value) return "Those two passwords don't match.";
        if (input.value.startsWith("-")) return "A password can't start with \"-\".";
        return "";
      },
      async saved(username) {
        // Chrome/Edge: brings up the browser's own "Save password?" prompt.
        if (!username || !window.PasswordCredential || !navigator.credentials) return;
        try {
          await navigator.credentials.store(new PasswordCredential({ id: username, password: input.value, name: username }));
        } catch (e) { /* the browser declined; its own form detection may still offer it */ }
      },
    };
  }

  return { attach, generate, MIN, MAX };
})();
