// nav.js — the one shared top bar, injected into every page's
// <div id="topnav-mount"></div>.
//
// Left to right: the brand; the page's own back button, once the page has
// scrolled it away; who is signed in; Dashboard; the theme toggle; and a
// menu button holding the pages and Log out. One menu is the same at every
// width, so nothing can scroll off a phone screen. Launch is not in the
// menu: it is the primary button on the dashboard.
//
// The bar stays at the top as the page scrolls (the mount is the sticky
// element: a sticky bar inside a wrapper its own height has nowhere to
// stick), and compacts once the page has moved, to give a phone its screen
// back. --nav-h tracks its height so other sticky things sit under it.
//
// renderNav(active) draws the bar synchronously so the page has its chrome
// at once, then fills the identity from /auth/me (memoised, so
// shared with the page's own calls).
const NAV_ICONS = {
  menu: '<svg viewBox="0 0 20 20" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M3 5.5h14M3 10h14M3 14.5h14"/></svg>',
};

// Any element carrying data-icon="<name>" (a button, a link, a tab) gets
// the shared glyph prepended — markup keeps the words, so nothing is blank
// if a script fails partway; the icon is decoration the page adds once.
// Idempotent, so a page can call it again after building rows with
// innerHTML.
function applyIcons(root) {
  (root || document).querySelectorAll("[data-icon]:not([data-iconed])").forEach((el) => {
    el.dataset.iconed = "1";
    el.insertAdjacentHTML("afterbegin", Agenti.icon(el.dataset.icon));
  });
}

function renderNav(active) {
  const mount = document.getElementById("topnav-mount");
  if (!mount) return;
  applyIcons(document);
  // Each entry carries an icon (Agenti.icon) — a menu scanned by shape
  // reads faster than one scanned by word, and the same glyphs name the
  // same pages on the Settings tabs and the dashboard, so they are learnt
  // once.
  const pages = [
    { id: "dashboard", label: "Dashboard", href: "dashboard.html", icon: "dashboard" },
    { id: "settings", label: "Settings", href: "settings.html", icon: "settings" },
    { id: "docs", label: "Docs", href: "docs.html", icon: "book" },
  ];
  const items = pages.map((p) =>
    `<a role="menuitem" class="menu-item${p.id === active ? " active" : ""}" href="${p.href}">${Agenti.icon(p.icon)}<span>${p.label}</span></a>`
  ).join("");

  const onDashboard = /(^|\/)dashboard\.html$/.test(location.pathname);
  mount.innerHTML = `
    <div class="topnav" id="topnav">
      <a class="brand" href="dashboard.html">Agenti</a>
      <button type="button" class="nav-back" id="nav-back" tabindex="-1" aria-hidden="true">
        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 3 5 8l5 5"/></svg><span id="nav-back-label">Back</span>
      </button>
      <div class="whoami" id="whoami" hidden>
        <span class="whoami-user" id="whoami-user"></span>
      </div>
      <a class="nav-dash" href="dashboard.html" title="Dashboard" aria-label="Dashboard"${onDashboard ? ' aria-current="page"' : ""}>${Agenti.icon("dashboard")}<span class="nav-dash-label">Dashboard</span></a>
      <button id="theme-toggle" type="button" title="Toggle light/dark" aria-label="Toggle theme"></button>
      <div class="dropdown">
        <button id="menu-btn" type="button" class="nav-icon-btn" aria-haspopup="menu"
                aria-expanded="false" aria-controls="menu-panel" aria-label="Menu" title="Menu">${NAV_ICONS.menu}</button>
        <div id="menu-panel" class="dropdown-panel" role="menu" hidden>
          ${items}
          <div class="menu-sep" role="separator"></div>
          <button type="button" role="menuitem" class="menu-item" id="logout-btn">${Agenti.icon("logout")}<span>Log out</span></button>
        </div>
      </div>
    </div>`;

  wireDropdown(document.getElementById("menu-btn"), document.getElementById("menu-panel"));
  const btn = document.getElementById("logout-btn");
  if (btn) btn.addEventListener("click", agentiLogout);
  const btn2 = document.getElementById("logout-btn-2");
  if (btn2) btn2.addEventListener("click", agentiLogout);
  // theme.js can't safely wire this itself (see the ordering note in
  // theme.js) — the button was just created above, so wire it here.
  if (window.agentiWireThemeToggle) {
    window.agentiWireThemeToggle(document.getElementById("theme-toggle"));
  }

  wireStickyBar(mount);

  // The identity, once the memoised call answers. Never fatal: a 401 already
  // went to login inside api.js, and anything else leaves the header blank
  // while the page reports why.
  const who = document.getElementById("whoami");
  Agenti.me().then((m) => {
    document.getElementById("whoami-user").textContent = m.user || "";
    who.hidden = !m.user;
  }).catch(() => { /* the page reports its own errors */ });
}

// The bar's two scroll behaviours, wired once per page.
//  * Compact: past a little scroll the bar slims down (CSS animates it). Two
//    thresholds, so a page resting near the line does not flicker.
//  * The page's back button: when the page's own .back-link scrolls up under
//    the bar, a copy appears in the bar. It clicks the original, so wherever
//    the page pointed it (agent.js and report.js rewrite theirs) is where it goes.
function wireStickyBar(mount) {
  const bar = document.getElementById("topnav");
  if (!bar) return;
  const setHeight = () => document.documentElement.style.setProperty("--nav-h", `${mount.offsetHeight}px`);
  let compact = false, ticking = false;
  const onScroll = () => {
    ticking = false;
    const y = window.scrollY;
    const next = compact ? y > 12 : y > 48;
    if (next !== compact) {
      compact = next;
      bar.classList.toggle("compact", compact);
      // after the transition, so sticky things below line up with the new height
      setTimeout(setHeight, 220);
    }
  };
  window.addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(onScroll); } }, { passive: true });
  window.addEventListener("resize", setHeight, { passive: true });
  setHeight();
  onScroll();

  const orig = document.querySelector("main .back-link");
  const pill = document.getElementById("nav-back");
  if (!orig || !pill || !("IntersectionObserver" in window)) return;
  const label = document.getElementById("nav-back-label");
  pill.addEventListener("click", () => orig.click());
  const show = (on) => {
    if (on) label.textContent = (orig.textContent || "Back").trim();
    bar.classList.toggle("has-back", on);
    pill.tabIndex = on ? 0 : -1;
    pill.setAttribute("aria-hidden", on ? "false" : "true");
    pill.title = on ? label.textContent : "";
  };
  new IntersectionObserver(([e]) => {
    // Only when it left through the TOP (scrolled past), not off the bottom.
    show(!e.isIntersecting && e.boundingClientRect.top < 80);
  }, { rootMargin: "-64px 0px 0px 0px" }).observe(orig);
}

// The menu's dropdown behaviour: click to toggle, click anywhere else or
// press Escape to close, first item focused on open so the keyboard works,
// and only one panel open at a time.
const _openDropdowns = [];
function wireDropdown(btn, panel) {
  if (!btn || !panel) return;
  const close = () => {
    if (panel.hidden) return;
    panel.hidden = true;
    btn.setAttribute("aria-expanded", "false");
  };
  const open = () => {
    _openDropdowns.forEach((c) => c());
    panel.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    const first = panel.querySelector('[role^="menuitem"]');
    if (first) first.focus({ preventScroll: true });
  };
  _openDropdowns.push(close);
  btn.addEventListener("click", (e) => { e.stopPropagation(); panel.hidden ? open() : close(); });
  panel.addEventListener("click", (e) => {
    e.stopPropagation();
    if (e.target.closest('[role^="menuitem"]')) close();
  });
  document.addEventListener("click", close);
  // Only an OPEN dropdown reacts to Escape (every one registers this).
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !panel.hidden) { close(); btn.focus(); } });
}

// POST /auth/logout revokes the server-side session row (sessions are rows,
// not tokens — "log out" means the cookie is dead everywhere, now), then
// clears the cookie. Always 200 by design, so we end on the login page
// whether or not a session existed.
async function agentiLogout() {
  try { await Agenti.post("auth/logout"); } catch (e) { /* ending up logged out either way */ }
  Agenti.clearAuth();
  location.href = "login.html?signedout=1";
}
