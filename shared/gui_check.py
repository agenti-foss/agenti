"""gui_check.py — drive the real web GUI in a real browser and report what
breaks: console errors, missing content, and horizontal overflow.

    AGENTI_GUI_USER=<user> AGENTI_GUI_PW_FILE=<path> \
        [AGENTI_GUI_TOTP_FILE=<path holding the TOTP secret>] \
        python3 shared/gui_check.py [--shots DIR] [--base URL]

With AGENTI_GUI_TOTP_FILE set, the harness completes the real two-step
login — it computes the current code from the secret exactly as an
authenticator app would — so the page under test is the one a 2FA user
sees. Since the require-2fa policy (default on) confines a password-only
session to the enrolment routes, an enrolled user is the normal way
to run this now.

NOT one of the project's test suites, and deliberately kept out of them:
`test_iam.py` and friends need no root, no vault, no network and no
dependencies, which is what makes them runnable anywhere. This needs
chromium, chromedriver, selenium, a RUNNING agenti-api service, and a
user with a password. It is a review tool you run when the GUI
changes, not a gate that runs everywhere.

WHY IT EXISTS: the pages were verified at the route level first — every
endpoint answering correctly with curl — and that proved nothing about
whether the GUI actually worked. The first run of this script found five
real defects that route testing could not see, one of them functional
rather than cosmetic:

  1. `[hidden]` did nothing to buttons. The UA rule `[hidden]{display:none}`
     loses to any author `display`, and `button,.btn{display:inline-flex}`
     is exactly that — so the Pause/Stop/Interrupt controls agent.js hides
     on a finished run stayed on screen, offering actions that could only
     fail.
  2. Text inputs fell back to the browser's default width (~20 characters),
     so the login form's fields were visibly narrower than its button.
  3. The run-history table made the whole PAGE scroll sideways on a phone,
     which hides content rather than merely crowding it.
  4. A status badge reading "incomplete · interrupted" pushed off the right
     edge of a 390px viewport.
  5. The two-up segmented toggle overflowed by 11px once its labels could
     no longer wrap.

Horizontal overflow is the check that earns its keep: it is invisible on a
desktop, silent in every HTTP test, and the one mobile failure mode that
loses content instead of just looking wrong.
"""
import argparse
import subprocess
import os
import sys
import time
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
except ImportError:
    sys.exit("selenium is not installed — this is a review tool, not part of "
             "the dependency-free suites.\n  pip install selenium   (and: "
             "apt install chromium chromium-driver)")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iam  # noqa: E402  — only for totp_code(), the harness's authenticator app

CHROMIUM = os.environ.get("AGENTI_CHROMIUM", "/usr/bin/chromium")
CHROMEDRIVER = os.environ.get("AGENTI_CHROMEDRIVER", "/usr/bin/chromedriver")

VIEWPORTS = [("phone", 390, 844), ("desktop", 1440, 900)]

# (label, path, a selector that must EXIST once the page has settled)
# The marker is the point: a page that renders its shell and then fails to
# load data would otherwise pass. Markers name real content, not containers
# — #history-tbody tr, not #history-table.
# Runs and kept files are private, so whether the logged-in user HAS any is
# not something this harness controls: markers for data-backed views accept
# either real rows or the view's own empty state — both prove the route
# answered and the page rendered.
PAGES = [
    ("dashboard", "dashboard.html", "#active-agents-grid"),
    ("dashboard-history", "dashboard.html#history", "#history-tbody tr, #history-empty:not([hidden])"),
    # The console is the one page whose data is the run ledger; a row in it
    # proves the findings route answered and the rows rendered (every
    # kind, since §4 item 25: narration, calls, results, operator input).
    ("agent", "agent.html?agent=enum", "#ag-feed .act-empty, #ag-feed .say, #ag-feed .steps"),
    # The report page marks its body once the report route has answered —
    # rendered or refused — so the marker is real content, not the shell.
    ("report", "report.html?agent=enum", "#report-body[data-rendered]"),
    # The tools panel loads once agent:read is confirmed; its summary
    # fills only after GET /agents/{a}/tools answers.
    ("agent-tools", "agent.html?agent=enum", "#ag-tools-body .ti-grid"),
    # "Send output to another agent" (js/send-output.js): shown to an operator or admin on their own run.
    ("agent-send", "agent.html?agent=enum", "#ag-send:not([hidden])"),
    # Engagement panel (CLAUDE.md "Current plan": admin-editable
    # engagements) — its read-only summary only renders once
    # GET /agents/{a}/engagement has answered; the edit form beneath it is
    # additionally gated on engagement:manage, checked separately below
    # when AGENTI_GUI_ADMIN=1.
    ("agent-engagement", "agent.html?agent=enum", "#ag-engagement-body dl"),
    # The launch page: a single-agent/team-of-agents switch over one card
    # grid sourced from GET /agents. The marker is a real agent card, which
    # only renders once GET /agents has answered.
    ("launch", "launch.html", "#agent-grid .category-card"),
    # Team-of-agents mode: the switch is a real click (location.hash =
    # "#team"), not just a URL fragment landing on inert markup — the
    # marker requires the team tab to have actually taken the .active
    # class AND the same grid to have repainted for it.
    ("launch-team", "launch.html#team", "#launch-switch button.active[data-mode=\"team\"]"),
    # No team in the URL, so this always shows the "no team named" empty
    # state — same shape as enrol-noToken: it still proves the page's own
    # JS runs without error before ever reaching the network calls a real
    # team would need. The real, populated console needs a fixture team
    # this login-then-visit-static-URLs harness has no way to create;
    # proven live against a real team instead (CLAUDE.md's build log).
    ("team-noTeam", "team.html", ".empty-state"),
    # Outputs is a sub-view of the dashboard's Task History tab now (the
    # #outputs fragment selects it). The quota is rendered as meter bars —
    # the marker is a filled bar, which only exists once the sub-view has
    # been opened AND GET /outputs has answered.
    ("outputs", "dashboard.html#outputs", "#usage-kv .meter"),
    # Bulk-select/delete (CLAUDE.md "Current plan" phase 5, §4 item 46):
    # the header checkbox is rendered but stays [hidden] until output:delete
    # is held AND at least one row exists — both true for an operator/admin
    # user against an account that has ever promoted an output.
    ("outputs-bulk", "dashboard.html#outputs", "#outputs-select-all:not([hidden]), #outputs-empty:not([hidden])"),
    # Settings is sections now (§4 item 41): tabs on a phone, a sidebar on a
    # desktop, the active one in the URL fragment. Each section is visited
    # by its own fragment so the screenshot shows it and the layout checks
    # run against it, not against a hidden pane.
    ("settings", "settings.html", "#account-kv dd"),
    # The Passkeys panel — empty ("no passkeys yet") is a real, valid state
    # for a fresh test user, not a loading failure, so the marker
    # accepts either that hint becoming visible or an actual registered row.
    ("settings-security", "settings.html#security", "#passkey-empty:not([hidden]), #passkey-list .list-row"),
    # The theme cards are built from theme.js's catalogue; one card per skin
    # proves the appearance section rendered and the catalogue loaded.
    ("settings-appearance", "settings.html#appearance", "#theme-cards .theme-card"),
    # No token in the URL, so this always shows the "invalid link" state —
    # it still proves the page itself renders and the JS runs without
    # error. The real accept-a-token path needs a freshly minted token,
    # which this harness (login-then-visit-static-URLs) has no way to get;
    # that flow was proven live over curl instead (CLAUDE.md's build log).
    ("enrol-noToken", "enrol.html", "#enrol-sub"),
]

# The admin-only sections (Agents; Engagement; Users; Platform, with policies,
# the passkey domain wizard and tool requests) exist only for a user
# holding iam:manage — so they are checked when the harness is told it is
# logging in as one. main() checks the actual permissions after logging in
# and skips these rather than crying wolf; ADMIN_PAGE_NAMES is how it knows
# which ones to drop.
ADMIN_PAGE_NAMES = {"settings-users", "settings-policies", "settings-engagement",
                    "settings-tool-requests",
                    "settings-agents", "settings-agents-controls"}
if os.environ.get("AGENTI_GUI_ADMIN") == "1":
    PAGES += [
        ("settings-users", "settings.html#users", "#users-tbody tr"),
        ("settings-policies", "settings.html#platform", "#policy-list .list-row"),
        ("settings-engagement", "settings.html#engagement", "#eng-summary dl, #eng-summary p"),
        # The tool-requests panel renders SOME content even when nothing
        # has been filed (the "Nothing filed yet." hint), so its marker is
        # the panel becoming visible, not a row — an empty admin-reviewed
        # queue is a real, valid state, not a loading failure.
        ("settings-tool-requests", "settings.html#platform", "#tool-requests-panel:not([hidden])"),
        # Settings -> Agents (§4 items 45, 74): the agent-type list (hand-built
        # and built agents) and the control centre. The tab is shown to a
        # platform admin or reader only (settings.js: canManage || canReadIam);
        # there is no saved-types marker any more.
        ("settings-agents", "settings.html#agents", "#deployed-agents-list .agent-type"),
        ("settings-agents-controls", "settings.html#agents", "#agent-controls .list-row"),
    ]
# The Engagement editor (CLAUDE.md "Current plan" phase 1, §4 item 42
# sub-step 1e) lives behind a <dialog> opened by a click, not a URL fragment
# — the PAGES loop's "visit a URL, look for a selector" shape can't reach
# it, so it is checked separately by check_engagement_dialog() below, once,
# as the full-editor caller only (an approve-only caller needs a SECOND
# user with engagement:approve but not engagement:manage, which this
# harness's one-login-per-run shape doesn't cover — proven live instead,
# with a disposable user, alongside the rest of phase 6's scenario).

IGNORE_CONSOLE = ("favicon.ico",)      # not shipped; its 404 is not a finding


def driver_for(width, height):
    opts = Options()
    opts.binary_location = CHROMIUM
    for flag in ("--headless=new", "--no-sandbox", "--disable-gpu",
                 "--disable-dev-shm-usage", f"--window-size={width},{height}",
                 # The LAN install serves a self-signed certificate by
                 # design, so a browser that refuses it cannot check the
                 # install it exists to check. Scoped to this throwaway
                 # headless profile; it changes nothing for real users, who
                 # see the warning and decide for themselves.
                 "--ignore-certificate-errors"):
        opts.add_argument(flag)
    opts.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    d = webdriver.Chrome(service=Service(CHROMEDRIVER), options=opts)
    d.set_window_size(width, height)
    return d


def console_errors(d):
    out = []
    for entry in d.get_log("browser"):
        msg = entry.get("message", "")
        if entry.get("level") in ("SEVERE", "ERROR") and \
                not any(i in msg for i in IGNORE_CONSOLE):
            out.append(msg)
    return out


def overflow_report(d):
    """Page-level horizontal overflow, plus the widest offending elements so
    the result is actionable rather than just a red flag."""
    return d.execute_script("""
      const de = document.documentElement, vw = de.clientWidth, over = [];
      document.querySelectorAll('body *').forEach(el => {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && (r.right > vw + 1 || r.left < -1)) {
          over.push({tag: el.tagName.toLowerCase(),
                     cls: (el.className || '').toString().slice(0, 40),
                     id: el.id || '', right: Math.round(r.right)});
        }
      });
      return {vw, scrollW: de.scrollWidth, clientW: de.clientWidth,
              overflows: over.slice(0, 6)};
    """)


def layout_report(d):
    """Three specific wrongnesses that a page-level overflow number cannot
    see, each one a bug this harness actually missed once:

      spills      — text painting outside its own box. A long, unbreakable
                    meta string used to overflow a dashboard card's title and
                    render UNDER the status badge; the page did not overflow,
                    no console error was logged, and the screenshot was the
                    only evidence. Comparing the two elements' rectangles does
                    NOT find it — an overflowing text node never enlarges its
                    element's rect, which is exactly why the spill is
                    invisible to every other check here. The real signal is a
                    leaf element whose scrollWidth exceeds its clientWidth
                    while its own overflow-x still computes to `visible`:
                    content wider than the box, and nothing clipping it.
      zero_icons  — an inline <svg> inside a button, present in the DOM and
                    drawn at zero width. Chromium flex-shrinks an <svg> whose
                    size is in ATTRIBUTES rather than CSS, so the nav's theme
                    toggle rendered as an empty circle with the icon "there".
      nav         — the header's controls. The menu button and theme toggle
                    must sit inside the viewport (the old tab row could scroll
                    a tab off-screen; a menu cannot, but the row of controls
                    still can if the identity block refuses to shrink), and
                    the menu must open to a panel that is itself inside the
                    viewport, hold the three pages plus Log out, and close on
                    Escape — clicked for real here, not assumed from the CSS.
    """
    return d.execute_script(r"""
      const out = {spills: [], zero_icons: [], nav: []};

      document.querySelectorAll('body *').forEach(el => {
        if (el.children.length) return;                 // leaf text only
        if (!el.textContent.trim()) return;
        if (el.offsetParent === null) return;           // not rendered
        const cs = getComputedStyle(el);
        if (cs.overflowX !== 'visible') return;         // clipped or scrolled: fine
        if (cs.position === 'absolute' || cs.position === 'fixed') return;
        if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0) {
          out.spills.push(el.tagName.toLowerCase() +
            (el.className ? '.' + el.className.toString().trim().split(/\s+/).join('.') : '') +
            ' by ' + (el.scrollWidth - el.clientWidth) + 'px');
        }
      });

      document.querySelectorAll('button svg, .btn svg').forEach(svg => {
        const r = svg.getBoundingClientRect();
        const host = svg.closest('button, .btn');
        if (host && host.offsetParent !== null && (r.width < 1 || r.height < 1)) {
          out.zero_icons.push((host.id || host.className || 'button').toString().slice(0, 40));
        }
      });

      // login.html and enrol.html are deliberately headerless (no session
      // yet to put a user/menu in) — #topnav-mount is nav.js's own
      // injection point, so its absence means this page never loads a
      // header at all, not that the header is broken. Skip the nav check
      // entirely rather than flag menu-btn/theme-toggle as "missing".
      const vw = document.documentElement.clientWidth;
      if (!document.getElementById('topnav-mount')) return out;
      ['menu-btn', 'theme-toggle'].forEach(id => {
        const b = document.getElementById(id);
        if (!b) { out.nav.push(id + ' missing'); return; }
        const r = b.getBoundingClientRect();
        if (r.right > vw + 1 || r.left < -1) out.nav.push(id + ' off-screen');
      });
      const mb = document.getElementById('menu-btn'), mp = document.getElementById('menu-panel');
      if (mb && mp) {
        mb.click();
        if (mp.hidden) out.nav.push('menu did not open');
        else {
          const r = mp.getBoundingClientRect();
          if (r.right > vw + 1 || r.left < -1) out.nav.push('menu panel off-screen');
          // Dashboard, Settings, Log out (§4 item 70 moved Outputs into the dashboard).
          if (mp.querySelectorAll('[role^="menuitem"]').length < 3) out.nav.push('menu items missing');
        }
        document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}));
        if (!mp.hidden) out.nav.push('menu did not close on Escape');
      }
      return out;
    """)


def check_engagement_dialog(d, base):
    """Open the Engagement editor as a full editor (engagement:manage
    held) and confirm it actually renders — the dialog, the approval-status
    banner, and Save both present. Not one of PAGES: it needs a click
    (window.__agentiOpenEngagement, the exact entry point the real
    data-engagement button uses), not a URL visit."""
    d.get(f"{base}/settings.html#engagement")
    time.sleep(1.5)
    opened = d.execute_script("""
      if (typeof window.__agentiOpenEngagement !== 'function') return 'no-fn';
      window.__agentiOpenEngagement();
      return 'called';
    """)
    if opened != "called":
        return ["window.__agentiOpenEngagement is not defined — the Engagement "
                "action never got wired up, or this user can't see the "
                "Engagement tab at all"]
    time.sleep(1.5)
    return d.execute_script("""
      const out = [];
      const dlg = document.getElementById('engagement-dialog');
      if (!dlg || !dlg.open) { out.push('dialog did not open'); return out; }
      const status = document.getElementById('engagement-status');
      if (!status || !status.textContent.trim()) out.push('approval-status banner is empty');
      const save = document.getElementById('engagement-save');
      if (!save || save.hidden) out.push('Save is hidden for a full-editor caller');
      const client = document.getElementById('eng2-client');
      if (!client || client.disabled) out.push('fields are disabled for a full-editor caller');
      // Operational policy fields (CLAUDE.md "Current plan" — caps, models,
      // require-approval, replacing the retired --dev/commercial split)
      // live in the SAME form; confirm they rendered and are editable too.
      const approvalCb = document.getElementById('eng2-require-approval');
      if (!approvalCb || approvalCb.disabled) out.push('policy fields are disabled for a full-editor caller');
      const modelCbs = document.querySelectorAll('.eng2-model');
      if (modelCbs.length !== 3) out.push('expected 3 allowed-model checkboxes, found ' + modelCbs.length);
      document.getElementById('engagement-cancel').click();
      if (dlg.open) out.push('dialog did not close on Cancel');
      return out;
    """)



def expected_cookie_secure(base: str) -> tuple[bool, str]:
    """(should the session cookie carry Secure, and why). The service decides
    this from AGENTI_TLS on its own unit (configure.sh sets it when it serves
    TLS itself OR sits behind an HTTPS proxy), so that is the source of truth;
    the URL under test is only the fallback when the unit cannot be read.
    AGENTI_GUI_EXPECT_SECURE=yes|no overrides both, for an unusual setup."""
    forced = os.environ.get("AGENTI_GUI_EXPECT_SECURE", "").strip().lower()
    if forced in ("yes", "no"):
        return forced == "yes", f"AGENTI_GUI_EXPECT_SECURE={forced}"
    if base.startswith("https://"):
        return True, "the page itself is served over https"
    try:
        out = subprocess.run(["systemctl", "show", "agenti-api", "-p", "Environment"],
                             capture_output=True, text=True, timeout=10).stdout
        if "Environment=" in out:
            if "AGENTI_TLS=1" in out:
                behind = "AGENTI_BEHIND_PROXY=1" in out
                return True, ("the service sits behind an https proxy, so browsers "
                              "are on https even though this hop is plain http"
                              if behind else "the service is configured for tls")
            return False, "the service runs plain http with no proxy in front"
    except (OSError, subprocess.SubprocessError):
        pass
    return False, "the page is plain http and the service's unit could not be read"

def main() -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="gui_check.py", description=__doc__.split("\n")[0])
    ap.add_argument("--base", default=os.environ.get("AGENTI_GUI_BASE",
                                                     "http://127.0.0.1:8420"))
    ap.add_argument("--shots", default=None, metavar="DIR",
                    help="write a PNG per page/viewport here")
    ap.add_argument("--settle", type=float, default=2.2,
                    help="seconds to let a page finish its fetches (default 2.2)")
    args = ap.parse_args()

    try:
        user = os.environ["AGENTI_GUI_USER"]
        pw = Path(os.environ["AGENTI_GUI_PW_FILE"]).read_text().strip()
        totp_secret = (Path(os.environ["AGENTI_GUI_TOTP_FILE"]).read_text().strip()
                       if os.environ.get("AGENTI_GUI_TOTP_FILE") else "")
    except KeyError as e:
        print(f"set {e} — this logs in as a real user, so it needs one.\n"
              f"  AGENTI_GUI_USER=<user> AGENTI_GUI_PW_FILE=<file holding "
              f"the password> python3 shared/gui_check.py", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"could not read AGENTI_GUI_PW_FILE: {e}", file=sys.stderr)
        return 2

    shots = Path(args.shots) if args.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    findings = 0
    used_totp_step = -1
    for label, w, h in VIEWPORTS:
        try:
            d = driver_for(w, h)
        except Exception as e:
            print(f"[{label}] could not start chromium: {e}")
            return 2
        try:
            d.get(f"{args.base}/login.html")
            d.find_element(By.ID, "user").send_keys(user)
            d.find_element(By.ID, "password").send_keys(pw)
            d.find_element(By.ID, "login-btn").click()
            time.sleep(args.settle + 0.3)
            if totp_secret and "login.html" in d.current_url:
                # The second step: the code an authenticator app would show.
                # A code is single-use (iam's replay protection), and the two
                # viewports log in a few seconds apart — so if this 30-second
                # step already produced one, wait for the next step, exactly
                # as a person would wait for their app to roll over.
                step = int(time.time() // iam.TOTP_STEP_S)
                if step == used_totp_step:
                    time.sleep((step + 1) * iam.TOTP_STEP_S - time.time() + 0.5)
                used_totp_step = int(time.time() // iam.TOTP_STEP_S)
                d.find_element(By.ID, "totp").send_keys(iam.totp_code(totp_secret))
                d.find_element(By.ID, "login-btn").click()
                time.sleep(args.settle + 0.3)
                # Something else (a curl check, a real person) may have spent
                # this step's code seconds ago; that is the replay guard
                # working, not a page defect. Wait one step and try once more.
                if "login.html" in d.current_url and \
                        "already been used" in d.find_element(By.TAG_NAME, "body").text:
                    step = int(time.time() // iam.TOTP_STEP_S)
                    time.sleep((step + 1) * iam.TOTP_STEP_S - time.time() + 0.5)
                    used_totp_step = int(time.time() // iam.TOTP_STEP_S)
                    box = d.find_element(By.ID, "totp")
                    box.clear(); box.send_keys(iam.totp_code(totp_secret))
                    d.find_element(By.ID, "login-btn").click()
                    time.sleep(args.settle + 0.3)
            if "login.html" in d.current_url:
                print(f"[{label}] LOGIN FAILED as {user}: "
                      f"{d.find_element(By.TAG_NAME, 'body').text[:200]}")
                findings += 1
                continue
            print(f"[{label}] logged in as {user}")

            # The session cookie's Secure flag, as a BROWSER sees it. This is
            # the only place in the project where a real login happens
            # unattended, so it is the only place this can be asserted —
            # `agenti verify` can check that the unit sets AGENTI_TLS, but not
            # what actually came back over the wire. The cookie must be
            # Secure whenever the BROWSER is on HTTPS: either the service
            # itself serves TLS, or it sits behind a proxy that does (then
            # this hop can be plain loopback HTTP while the cookie is
            # correctly Secure). It must be ABSENT only when nothing on the
            # path is HTTPS, or the cookie would never be sent and login
            # would break.
            cookie = d.get_cookie("agenti_session") or {}
            want_secure, why = expected_cookie_secure(args.base)
            if bool(cookie.get("secure")) != want_secure:
                print(f"[{label}] COOKIE: Secure={cookie.get('secure')} — expected "
                      f"{want_secure} ({why})")
                findings += 1
            else:
                print(f"[{label}] session cookie Secure={bool(cookie.get('secure'))} "
                      f"(correct: {why})")

            pages = PAGES
            if os.environ.get("AGENTI_GUI_ADMIN") == "1":
                # execute_script does not await a promise — it would hand
                # back undefined and every admin page would be skipped.
                d.set_script_timeout(15)
                plat = d.execute_async_script(
                    "const done = arguments[arguments.length - 1];"
                    "fetch('auth/me', {credentials: 'same-origin'})"
                    "  .then(r => r.json())"
                    "  .then(j => done(j.permissions || []))"
                    "  .catch(() => done(null));")
                if "iam:manage" not in (plat or []):
                    pages = [p for p in PAGES if p[0] not in ADMIN_PAGE_NAMES]
                    print(f"[{label}] AGENTI_GUI_ADMIN=1 but this user holds no "
                          f"iam:manage (an operator?) — skipping "
                          f"{len(ADMIN_PAGE_NAMES)} admin-only page checks")

            for name, path, marker in pages:
                d.get(f"{args.base}/{path}")
                time.sleep(args.settle)
                notes = []
                # Wait for the marker rather than trusting the settle alone:
                # a page that chains fetches (Settings → Users: users,
                # then their bindings) can take longer than the
                # settle on a busy box without anything being wrong.
                try:
                    WebDriverWait(d, 10).until(
                        lambda drv: drv.find_elements(By.CSS_SELECTOR, marker))
                except Exception:
                    notes.append(f"expected content {marker} never appeared")
                errs = console_errors(d)
                ov = overflow_report(d)
                lay = layout_report(d)
                wide = ov["scrollW"] > ov["clientW"] + 1
                bad_layout = any(lay[k] for k in lay)
                if shots:
                    d.save_screenshot(str(shots / f"{label}-{name}.png"))
                state = ("OVERFLOW" if wide else "LAYOUT" if bad_layout
                         else "MISSING" if notes else "ok")
                print(f"[{label}] {name:<20} {state:<9} "
                      f"scrollW={ov['scrollW']} clientW={ov['clientW']} errors={len(errs)}")
                for n in notes:
                    print(f"          {n}")
                for e in errs:
                    print(f"          console: {e[:190]}")
                if wide:
                    for o in ov["overflows"]:
                        print(f"          wide: <{o['tag']} id={o['id']} "
                              f"class={o['cls']}> right={o['right']} viewport={ov['vw']}")
                for c in lay["spills"][:6]:
                    print(f"          text spills outside its box: {c}")
                for z in lay["zero_icons"]:
                    print(f"          zero-width icon in: {z}")
                for t in lay["nav"]:
                    print(f"          header/menu: {t}")
                if errs or wide or notes or bad_layout:
                    findings += 1

            if os.environ.get("AGENTI_GUI_ADMIN") == "1" and "iam:manage" in (plat or []):
                eng_notes = check_engagement_dialog(d, args.base)
                print(f"[{label}] {'engagement-dialog':<20} "
                      f"{'MISSING' if eng_notes else 'ok':<9} (full-editor caller)")
                for n in eng_notes:
                    print(f"          {n}")
                if eng_notes:
                    findings += 1
        finally:
            d.quit()

    print(f"\n{'=' * 52}")
    print("  clean" if not findings else f"  {findings} page(s) with findings")
    print(f"{'=' * 52}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
