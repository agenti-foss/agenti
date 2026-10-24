// theme.js — the appearance engine: a THEME (skin) and a MODE (light/dark).
//
// Two independent, per-viewer preferences, both in localStorage — the one
// kind of state this project's own conventions say belongs client-side
// (unlike shared, server-recorded state such as task completion):
//
//   agenti-gui-skin   "original" | "arcade"          (absent = original)
//   agenti-gui-theme  "light" | "dark"               (absent = follow the OS)
//
// They land on <html> as three attributes the stylesheets key on:
//
//   data-skin   the theme — theme.css is the Original skin's own rules and
//               every other skin's base; css/arcade.css is scoped under
//               [data-skin="arcade"] and overrides tokens + a few components;
//   data-theme  the STORED mode, kept exactly as it always was so the
//               existing selectors in theme.css (`:root[data-theme="dark"]`,
//               `:root:not([data-theme="light"])` under the OS media query)
//               keep working untouched;
//   data-mode   the RESOLVED mode ("light" or "dark" — the stored choice, or
//               the OS preference when nothing is stored), maintained live
//               as the OS setting changes. A skin that needs a different
//               rule per mode (a neon glow that only makes sense on a dark
//               background) selects on this rather than repeating the
//               media-query dance for every rule.
//
// This script is loaded WITHOUT `defer`, on purpose: it touches nothing but
// <html>'s attributes, and running it before the body is parsed is what
// stops a page from painting in the Original skin for a frame before
// switching to the one the viewer chose. Everything DOM-dependent is
// exported as functions for nav.js / settings.js to call once the
// elements exist (see the ordering note on agentiWireThemeToggle below).
(function () {
  const MODE_KEY = "agenti-gui-theme";
  const SKIN_KEY = "agenti-gui-skin";

  // The catalogue the Settings page draws its theme cards from. `swatch`
  // holds just enough of each mode's palette to paint a small preview
  // without loading the skin; `display` is the heading font the card's own
  // title is set in, so the preview shows the real thing. Adding a skin is:
  // an entry here, a stylesheet scoped under [data-skin="<id>"], a
  // favicon if it wants one.
  const SKINS = {
    original: {
      label: "Original",
      blurb: "Clean and quiet. Content first, colour only for status and action.",
      display: "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', Roboto, sans-serif",
      favicon: "favicon.svg",
      swatch: {
        light: { bg: "#f6f7f9", panel: "#ffffff", text: "#16181d", dim: "#8b93a1", accent: "#2563eb", border: "#e3e6ec" },
        dark: { bg: "#0f1114", panel: "#191c21", text: "#eceef2", dim: "#6e7683", accent: "#5b8dff", border: "#282d35" },
      },
    },
    arcade: {
      label: "Arcade",
      blurb: "An eighties arcade, kept easy on the eyes: pixel headings, neon status, sprite avatars.",
      display: "'Press Start 2P', monospace",
      favicon: "favicon-arcade.svg",
      swatch: {
        light: { bg: "#f7f1e1", panel: "#fffaee", text: "#23201b", dim: "#9a917f", accent: "#e8542a", border: "#23201b" },
        dark: { bg: "#0b0a1f", panel: "#141235", text: "#eef0ff", dim: "#6f6da3", accent: "#ff3fb0", border: "#4b47a0" },
      },
    },
  };

  const root = document.documentElement;
  const media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  const listeners = [];

  function read(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }
  function write(key, value) {
    try {
      if (value) localStorage.setItem(key, value);
      else localStorage.removeItem(key);
    } catch (e) { /* private window / blocked storage — the choice just won't persist */ }
  }

  // ---- mode --------------------------------------------------------------
  function storedMode() {
    const m = read(MODE_KEY);
    return m === "light" || m === "dark" ? m : "system";
  }
  function resolvedMode() {
    const m = storedMode();
    if (m !== "system") return m;
    return media && media.matches ? "dark" : "light";
  }
  function applyMode() {
    const m = storedMode();
    if (m === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", m);
    root.setAttribute("data-mode", resolvedMode());
    root.style.colorScheme = resolvedMode();
  }
  function setMode(mode) {
    write(MODE_KEY, mode === "light" || mode === "dark" ? mode : "");
    applyMode();
    notify();
  }

  // ---- skin --------------------------------------------------------------
  function storedSkin() {
    const s = read(SKIN_KEY);
    return SKINS[s] ? s : "original";
  }
  function applySkin() {
    root.setAttribute("data-skin", storedSkin());
    applyFavicon();
  }
  function setSkin(skin) {
    write(SKIN_KEY, SKINS[skin] && skin !== "original" ? skin : "");
    applySkin();
    notify();
  }
  // The tab icon follows the skin. The <link rel="icon"> sits in <head>
  // above this script on every page, so it exists by the time this runs;
  // the DOMContentLoaded retry covers a page that orders them differently.
  function applyFavicon() {
    const link = document.querySelector('link[rel="icon"]');
    if (!link) return;
    const want = SKINS[storedSkin()].favicon;
    if (!link.getAttribute("href").endsWith(want)) link.setAttribute("href", want);
  }

  function notify() { listeners.forEach((fn) => { try { fn(); } catch (e) { /* one bad listener must not break the rest */ } }); }

  applyMode();
  applySkin();
  if (media) {
    const onChange = () => { if (storedMode() === "system") { applyMode(); notify(); } };
    if (media.addEventListener) media.addEventListener("change", onChange);
    else if (media.addListener) media.addListener(onChange);
  }
  document.addEventListener("DOMContentLoaded", applyFavicon);

  window.AgentiTheme = {
    SKINS,
    skin: storedSkin, setSkin,
    mode: storedMode, setMode, resolvedMode,
    isDark: () => resolvedMode() === "dark",
    onChange: (fn) => { listeners.push(fn); },
  };

  // ---- the nav's light/dark toggle -----------------------------------------
  // Wiring note: the button lives inside the nav bar, which nav.js injects
  // at runtime. If this file wired it from its own DOMContentLoaded
  // listener, that listener would fire BEFORE nav.js's renderNav() ever
  // runs — renderNav() is called from each page's own, later-registered
  // listener — so the button would silently never get a handler. Instead
  // agentiWireThemeToggle(btn) is exported for nav.js to call right after
  // it creates the button.
  //
  // Inline SVG, not an emoji: an emoji is rendered by the system font at a
  // size and weight nothing here controls, and sat visibly apart from the
  // rest of the nav.
  const SUN = '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><circle cx="10" cy="10" r="3.6"/><path d="M10 1.8v1.8M10 16.4v1.8M1.8 10h1.8M16.4 10h1.8M4.2 4.2l1.3 1.3M14.5 14.5l1.3 1.3M15.8 4.2l-1.3 1.3M5.5 14.5l-1.3 1.3"/></svg>';
  const MOON = '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16.5 12.4A7 7 0 0 1 7.6 3.5a7 7 0 1 0 8.9 8.9z"/></svg>';

  // Every wired button refreshes together (and on any change made from the
  // Settings page's own controls): one silently showing the wrong icon after
  // another was used is exactly the kind of small wrongness that reads as
  // "this app is not quite finished".
  window.agentiWireThemeToggle = function (btn, opts) {
    if (!btn) return;
    const text = opts && opts.text;
    const updateLabel = () => {
      const dark = resolvedMode() === "dark";
      const icon = dark ? SUN : MOON;
      const label = `Switch to ${dark ? "light" : "dark"}`;
      btn.innerHTML = text ? `${icon}<span>${label}</span>` : icon;
      btn.setAttribute("aria-label", `${label} appearance`);
      btn.setAttribute("title", `${label} appearance`);
    };
    listeners.push(updateLabel);
    updateLabel();
    btn.addEventListener("click", function () {
      setMode(resolvedMode() === "dark" ? "light" : "dark");
    });
  };
})();
