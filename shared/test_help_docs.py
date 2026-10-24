#!/usr/bin/env python3
"""test_help_docs.py — shared/help_docs.py, the `agenti docs` verb and the
pieces of the Docs page that depend on them. No root, no network.

    python3 shared/test_help_docs.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HELP = REPO / "docs" / "help"
sys.path.insert(0, str(HERE))
import help_docs as hd  # noqa: E402

PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  [ OK ] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}\n         got  {got!r}\n         want {want!r}")


def raises(fn, needle):
    try:
        fn()
    except hd.DocsError as e:
        return needle in str(e)
    return False


def write_pages(d, pages, index=None):
    for name, text in pages.items():
        (Path(d) / f"{name}.md").write_text(text, encoding="utf-8")
    if index is not None:
        (Path(d) / "index.json").write_text(index, encoding="utf-8")


print("the shipped pages")
pages = hd.load(HELP)
slugs = [p.slug for p in pages]
check("every page loads (at least the 12 shipped)", len(pages) >= 12, True)
check("listed alphabetically, like the website", slugs, sorted(slugs))
check("every page has a title", [p.slug for p in pages if not p.title], [])
check("every page has a summary", [p.slug for p in pages if not p.summary], [])
index = json.loads((HELP / "index.json").read_text())["pages"]
check("index.json names no page that does not exist", sorted(set(index) - set(slugs)), [])
check("every page has an index.json entry, or (a plugin's page) its own <page>.json",
      sorted(s for s in set(slugs) - set(index) if not (HELP / f"{s}.json").is_file()), [])
icons = set(re.findall(r"^\s+'?([a-z-]+)'?: '<", (HERE / "gui/js/api.js").read_text(), re.M))
check("every icon index.json names exists in the GUI's icon set",
      sorted(p.slug for p in pages if p.icon and p.icon not in icons), [])
check("no page calls itself a draft (operator decision 2026-10-20)",
      [p.slug for p in pages if re.search(r"\bdraft help page\b", p.markdown, re.I)], [])
check("no page uses a name `agenti docs` reserves",
      [s for s in slugs if s in hd.RESERVED_PAGES], [])

by_slug = {p.slug: p for p in pages}
broken = []
for p in pages:
    for target in re.findall(r"\]\(([^)\s]+)\)", p.markdown):
        if target.startswith(("http://", "https://")):
            continue
        m = re.match(r"^([a-z0-9-]+)\.md(?:#([a-z0-9-]+))?$", target)
        if not m or m.group(1) not in by_slug:
            broken.append(f"{p.slug} -> {target}")
        elif m.group(2) and m.group(2) not in {h["anchor"] for h in by_slug[m.group(1)].headings}:
            broken.append(f"{p.slug} -> {target} (no such section)")
check("every link between help pages resolves (page and section)", broken, [])
dupes = [p.slug for p in pages
         if len([h["anchor"] for h in p.headings if h["anchor"]]) != len({h["anchor"] for h in p.headings if h["anchor"]})]
check("section anchors are unique within each page", dupes, [])

print("\nparsing")
md = "# Title\n\n*For admins.*\n\nFirst para. Second sentence.\n\n## Setup\n\n```\n# not a heading\n```\n\n## Setup\n\nText.\n"
p = hd.parse("demo", md, {})
check("the H1 is the title", p.title, "Title")
check("a '#' line inside a code fence is not a heading",
      [h["text"] for h in p.headings], ["Title", "Setup", "Setup"])
check("repeated headings get distinct anchors", [h["anchor"] for h in p.headings], ["", "setup", "setup-2"])
check("the summary skips the italic audience line and keeps one sentence", p.summary, "First para.")
check("index.json's summary wins over the derived one", hd.parse("demo", md, {"summary": "Given."}).summary, "Given.")
check("an icon name that is not a plain word is dropped", hd.parse("demo", md, {"icon": "x\"><script>"}).icon, "")
check("plain text drops Markdown syntax but keeps the words",
      hd.plain_line("- **Bold** and `code` and [a link](x.md) | cell"), "Bold and code and a link cell")
check("a page with no H1 is titled from its name", hd.parse("my-page", "Body.\n", {}).title, "My page")

print("\nsearch")
r = hd.search(pages, "pass")
check("part of a word is enough ('pass' finds passkey/password)", r["count"] > 0, True)
check("every result names its page, title, section and snippet",
      all({"page", "title", "icon", "anchor", "heading", "snippet", "score"} <= set(x) for x in r["results"]), True)
check("at most 20 results", r["count"] <= hd.MAX_RESULTS, True)
per = {}
for x in r["results"]:
    per[x["page"]] = per.get(x["page"], 0) + 1
check("at most 3 sections from any one page", max(per.values()) <= hd.PER_PAGE, True)
check("case does not matter", [x["anchor"] for x in hd.search(pages, "PASSKEY")["results"]],
      [x["anchor"] for x in hd.search(pages, "passkey")["results"]])
check("every word must appear (a nonsense second word empties the results)",
      hd.search(pages, "passkey zzqxv")["count"], 0)
check("no match is an empty result, not an error", hd.search(pages, "zzqxv")["results"], [])

with tempfile.TemporaryDirectory() as d:
    write_pages(d, {
        "alpha": "# Alpha\n\nIntro.\n\n## Widgets\n\nHow widgets work.\n\n## Other\n\nWidgets again, widgets.\n",
        "beta": "# Beta widgets\n\nIntro about nothing.\n\n## One\n\nNothing here.\n\n## Two\n\nStill nothing.\n",
    })
    tp = hd.load(Path(d))
    res = hd.search(tp, "widgets")["results"]
    check("a heading match outranks a body-only match", res[0]["anchor"], "widgets")
    beta = [x for x in res if x["page"] == "beta"]
    check("a match in the page title alone is one result for the page, not one per section",
          [(x["anchor"], x["heading"]) for x in beta], [("", "")])
    check("the snippet is cut around the first match",
          hd.snippet("x " * 200 + "needle " + "y " * 200, ["needle"]).startswith("…"), True)
    check("terms are lower-cased, de-duplicated and stripped of punctuation",
          hd.terms_of('"Widgets," widgets (setup)'), ["widgets", "setup"])
    check("at most 8 terms are used", len(hd.terms_of(" ".join(f"w{i}" for i in range(20)))), 8)
    check("an over-long search is refused with the limit",
          raises(lambda: hd.terms_of("a" * 201), "200 or fewer"), True)
    check("an empty search says what to type", raises(lambda: hd.terms_of("  ...  "), "nothing to search for"), True)

print("\nfinding a page, and broken installs")
check("a path is not a page name", raises(lambda: hd.find(pages, "../etc/passwd"), "not a page name"), True)
check("a near miss suggests the right page", raises(lambda: hd.find(pages, "signing"), "agenti docs signing-in"), True)
check("a missing folder names the reinstall command",
      raises(lambda: hd.load(Path("/nonexistent/help")), "sudo apt install --reinstall agenti"), True)
with tempfile.TemporaryDirectory() as d:
    write_pages(d, {"ok": "# Ok\n\nFine.\n", "README": "# no\n", "list": "# reserved\n"}, index="{not json")
    check("a broken index.json is reported, not ignored", raises(lambda: hd.load(Path(d)), "not valid JSON"), True)
    (Path(d) / "index.json").unlink()
    check("uppercase files and reserved names are not pages", [p.slug for p in hd.load(Path(d))], ["ok"])

print("\nthe module's own CLI")
run = lambda *a: subprocess.run([sys.executable, str(HERE / "help_docs.py"), "--dir", str(HELP), *a],
                                capture_output=True, text=True)
c = run("--json", "search", "--query=-x --help")
check("a query that looks like a flag is just words (exit 0, one JSON document)",
      (c.returncode, json.loads(c.stdout)["query"]), (0, "-x --help"))
c = run("show", "--page=nope")
check("an unknown page exits 1 with the reason on stderr", (c.returncode, "no help page" in c.stderr), (1, True))
c = run("list")
check("the human list ends with how to read and search", "agenti docs search <words>" in c.stdout, True)

print("\nthe `agenti docs` verb (from the source tree)")
env = {**os.environ, "AGENTI_LIBDIR": "/nonexistent"}
cli = lambda *a: subprocess.run(["bash", str(HERE / "agenti"), *a], capture_output=True, text=True, env=env)
c = cli("--json", "docs", "search", "pass", "key")
doc = json.loads(c.stdout) if c.returncode == 0 else {}
check("docs search joins the words and answers in JSON", (c.returncode, doc.get("query")), (0, "pass key"))
c = cli("--json", "docs", "teams")
check("docs <page> is the same as docs show <page>", json.loads(c.stdout).get("page") if c.returncode == 0 else c.stderr, "teams")
c = cli("--json", "docs", "nope")
check("an unknown page is one JSON error and a failing exit",
      (c.returncode != 0, "error" in json.loads(c.stdout or "{}")), (True, True))
c = cli("docs", "--help")
check("docs --help shows the docs usage, not the generic banner", "agenti docs search <words...>" in c.stdout, True)
c = cli("docs", "search")
check("docs search with no words says what to type", "needs one or more words" in (c.stdout + c.stderr), True)
check("the top-level usage lists the docs verb", "agenti docs [<page> | search <words>]" in cli("--help").stdout, True)

print("\nthe API and the GUI depend on it")
bridge = (HERE / "api/cli_bridge.py").read_text()
check("'docs' is a reserved agent name in the API bridge",
      '"docs"' in re.search(r"RESERVED_NAMES = frozenset\(\{(.*?)\}\)", bridge, re.S).group(1), True)
check("...in the agent builder", '"docs"' in re.search(r"RESERVED = frozenset\(\{(.*?)\}\)",
                                                      (HERE / "agent_builder.py").read_text(), re.S).group(1), True)
check("...and in `agenti new`", '"docs"' in re.search(r"reserved = \{(.*?)\}",
                                                    (HERE / "new_agent.py").read_text(), re.S).group(1), True)
main = (HERE / "api/main.py").read_text()
check("FastAPI's explorer and route map are switched off",
      all(f"{k}=None" in main for k in ("docs_url", "redoc_url", "openapi_url")), True)
routes = []
for m in re.finditer(r'@app\.get\("(/docs[^"]*)"\)\n(.*?)\n\n', main, re.S):
    dep = re.search(r"Depends\((\w+)\(", m.group(2))
    routes.append((m.group(1), dep.group(1) if dep else None))
check("the three docs routes exist and need a signed-in user",
      sorted(routes), [("/docs", "authenticated"), ("/docs/search", "authenticated"), ("/docs/{page}", "authenticated")])
check("/docs/search is declared before /docs/{page}, so 'search' is never read as a page name",
      main.index('@app.get("/docs/search")') < main.index('@app.get("/docs/{page}")'), True)
check("the menu links the Docs page", 'href: "docs.html"' in (HERE / "gui/js/nav.js").read_text(), True)
page = (HERE / "gui/docs.html").read_text()
check("docs.html loads the renderer and its script", all(s in page for s in ("js/markdown.js", "js/docs.js")), True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
