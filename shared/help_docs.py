#!/usr/bin/env python3
"""help_docs.py — list, read and search the user help pages.

The one implementation behind `agenti docs`, the API's /docs routes (which
shell to that verb) and the GUI's Docs page. Pages are Markdown files in one
directory; an optional index.json there gives each page a summary and an
icon. A package that adds an agent may drop its own page into the directory.

    help_docs.py [--dir D] [--json] list
    help_docs.py [--dir D] [--json] show --page=<page>
    help_docs.py [--dir D] [--json] search --query=<words>
"""
import argparse
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

INSTALLED_DIR = Path(os.environ.get("AGENTI_LIBDIR", "/usr/lib/agenti")) / "help"
SOURCE_DIR = Path(__file__).resolve().parent.parent / "docs" / "help"

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
ICON_RE = re.compile(r"^[a-z][a-z-]{0,23}$")
# A page with one of these names could never be opened as `agenti docs <page>`.
RESERVED_PAGES = frozenset({"list", "show", "search", "help"})
MAX_QUERY = 200
MAX_TERMS = 8
MAX_RESULTS = 20
PER_PAGE = 3
SNIPPET = 180
SUMMARY = 140

# Heading and fence rules match shared/gui/js/markdown.js, so the anchors
# computed here line up with the headings the browser renders.
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
HR = re.compile(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$")
LINK = re.compile(r"\[([^\]\n]+)\]\([^)\s]+\)")
ITALIC_LINE = re.compile(r"^\*[^*].*\*$")


class DocsError(Exception):
    pass


@dataclass
class Section:
    anchor: str
    heading: str
    level: int
    lines: list = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(x for x in (plain_line(ln) for ln in self.lines) if x)


@dataclass
class Page:
    slug: str
    title: str
    summary: str
    icon: str
    markdown: str
    sections: list
    headings: list


def plain_line(line: str) -> str:
    st = line.strip()
    if not st or HR.match(st) or TABLE_SEP.match(st):
        return ""
    st = re.sub(r"^>\s?", "", st)
    st = re.sub(r"^(?:[-*+]|\d+[.)])\s+", "", st)
    st = LINK.sub(r"\1", st)
    st = st.replace("**", "").replace("`", "").replace("|", " ")
    st = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"\1", st)
    return " ".join(st.split())


def slugify(text: str, used: set) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", plain_line(text).lower()).strip("-") or "section"
    anchor, n = base, 2
    while anchor in used:
        anchor, n = f"{base}-{n}", n + 1
    used.add(anchor)
    return anchor


def parse(slug: str, md: str, meta: dict) -> Page:
    title = ""
    sections = [Section("", "", 1)]
    headings = []
    used: set = set()
    fence = False
    for line in md.replace("\r\n", "\n").split("\n"):
        if line.strip().startswith("```"):
            fence = not fence
            continue
        m = None if fence else HEADING.match(line)
        if not m:
            sections[-1].lines.append(line)
            continue
        level, text = len(m.group(1)), m.group(2)
        if level == 1 and not title:
            title = plain_line(text)
            headings.append({"level": 1, "text": text, "anchor": ""})
            continue
        anchor = slugify(text, used)
        headings.append({"level": level, "text": text, "anchor": anchor})
        sections.append(Section(anchor, plain_line(text), level))
    title = title or slug.replace("-", " ").capitalize()
    summary = str(meta.get("summary") or "").strip() or derive_summary(sections)
    icon = str(meta.get("icon") or "")
    return Page(slug, title, summary, icon if ICON_RE.match(icon) else "", md, sections, headings)


def derive_summary(sections: list) -> str:
    for sec in sections:
        para = []
        for line in sec.lines:
            st = line.strip()
            if not st:
                if para:
                    break
                continue
            if ITALIC_LINE.match(st) and not para:
                continue
            para.append(plain_line(st))
        text = " ".join(x for x in para if x)
        if text:
            first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
            return first if len(first) <= SUMMARY else first[:SUMMARY - 1].rsplit(" ", 1)[0] + "…"
    return ""


def resolve_dir(given: str | None) -> Path:
    if given:
        return Path(given)
    return INSTALLED_DIR if INSTALLED_DIR.is_dir() else SOURCE_DIR


def load(directory: Path) -> list:
    if not directory.is_dir():
        raise DocsError(f"the help pages are not installed (no folder at {directory}).\n"
                        "reinstall them:  sudo apt install --reinstall agenti")
    meta: dict = {}
    index = directory / "index.json"
    if index.is_file():
        try:
            meta = json.loads(index.read_text(encoding="utf-8")).get("pages", {})
        except (ValueError, AttributeError) as e:
            raise DocsError(f"{index} is not valid JSON ({e}).\n"
                            "fix the file, or reinstall it:  sudo apt install --reinstall agenti")
    pages = []
    for f in sorted(directory.glob("*.md")):
        if not SLUG_RE.match(f.stem) or f.stem in RESERVED_PAGES:
            continue
        info = meta.get(f.stem) if isinstance(meta.get(f.stem), dict) else {}
        if not info:
            # A plugin's page (agenti-exploit, ...) brings its own entry beside it.
            own = directory / f"{f.stem}.json"
            try:
                info = json.loads(own.read_text(encoding="utf-8")) if own.is_file() else {}
            except ValueError:
                info = {}
            info = info if isinstance(info, dict) else {}
        pages.append(parse(f.stem, f.read_text(encoding="utf-8"), info))
    return pages


def find(pages: list, slug: str) -> Page:
    if not SLUG_RE.match(slug or ""):
        raise DocsError(f"'{slug}' is not a page name (lowercase letters, digits and dashes).\n"
                        "list the pages:  agenti docs")
    for p in pages:
        if p.slug == slug:
            return p
    close = difflib.get_close_matches(slug, [p.slug for p in pages], n=1)
    hint = f"did you mean:  agenti docs {close[0]}\n" if close else ""
    raise DocsError(f"there is no help page called '{slug}'.\n{hint}list the pages:  agenti docs")


def terms_of(query: str) -> list:
    q = " ".join((query or "").split())
    if len(q) > MAX_QUERY:
        raise DocsError(f"the search is {len(q)} characters long; keep it to {MAX_QUERY} or fewer.")
    terms: list = []
    for word in q.lower().split():
        word = word.strip(".,;:!?\"'()[]{}<>")
        if word and word not in terms:
            terms.append(word)
    if not terms:
        raise DocsError("there is nothing to search for. Give one or more words, "
                        "e.g.  agenti docs search passkey")
    return terms[:MAX_TERMS]


def snippet(text: str, terms: list) -> str:
    low = text.lower()
    found = [t for t in terms if t in low]
    if not found:
        return text if len(text) <= SNIPPET else text[:SNIPPET].rsplit(" ", 1)[0] + "…"
    # Centre on the whole phrase if it is there, else on the rarest word.
    phrase = " ".join(terms)
    at = low.find(phrase) if len(terms) > 1 else -1
    if at < 0:
        at = low.find(min(found, key=low.count))
    start = max(0, at - 60)
    if start:
        start = text.rfind(" ", 0, start) + 1
    end = min(len(text), start + SNIPPET)
    if end < len(text):
        cut = text.rfind(" ", start, end)
        end = cut if cut > start else end
    return ("…" if start else "") + text[start:end].strip() + ("…" if end < len(text) else "")


def search(pages: list, query: str) -> dict:
    terms = terms_of(query)
    phrase = " ".join(terms)
    hits = []
    for order, page in enumerate(pages):
        title = page.title.lower()
        for idx, sec in enumerate(page.sections):
            text = sec.text
            head, body = sec.heading.lower(), text.lower()
            score, body_hit = 0, False
            for t in terms:
                in_title, in_head, n = t in title, t in head, body.count(t)
                if not (in_title or in_head or n):
                    break
                body_hit = body_hit or in_head or n > 0
                score += 4 * in_title + 6 * in_head + min(n, 5)
                if re.search(r"\b" + re.escape(t) + r"\b", f"{title} {head} {body}"):
                    score += 2
            else:
                if not body_hit and idx != 0:
                    continue
                if len(terms) > 1 and phrase in f"{head} {body}":
                    score += 6
                hits.append((score, order, idx, page, sec, text))
    hits.sort(key=lambda h: (-h[0], h[1], h[2]))
    results, per_page = [], {}
    for score, _, _, page, sec, text in hits:
        if per_page.get(page.slug, 0) >= PER_PAGE:
            continue
        per_page[page.slug] = per_page.get(page.slug, 0) + 1
        results.append({"page": page.slug, "title": page.title, "icon": page.icon, "anchor": sec.anchor,
                        "heading": sec.heading, "snippet": snippet(text, terms), "score": score})
        if len(results) >= MAX_RESULTS:
            break
    return {"query": " ".join(query.split()), "terms": terms, "count": len(results), "results": results}


def page_list(pages: list) -> dict:
    return {"count": len(pages),
            "pages": [{"page": p.slug, "title": p.title, "summary": p.summary, "icon": p.icon}
                      for p in pages]}


def page_show(page: Page) -> dict:
    return {"page": page.slug, "title": page.title, "summary": page.summary, "icon": page.icon,
            "markdown": page.markdown, "headings": page.headings}


def print_list(data: dict) -> None:
    print(f"Agenti help pages ({data['count']}):\n")
    width = max((len(p["page"]) for p in data["pages"]), default=10) + 2
    for p in data["pages"]:
        print(f"  {p['page']:<{width}}{p['title']}")
        if p["summary"]:
            print(f"  {'':<{width}}{p['summary']}")
    print("\nread one:   agenti docs <page>\nsearch:     agenti docs search <words>")


def print_search(data: dict) -> None:
    quoted = f"\"{data['query']}\""
    if not data["results"]:
        print(f"No help page mentions {quoted}.\n"
              "Try fewer or different words, or list every page:  agenti docs")
        return
    noun = "result" if data["count"] == 1 else "results"
    print(f"{data['count']} {noun} for {quoted}:\n")
    for r in data["results"]:
        where = f"{r['title']} › {r['heading']}" if r["heading"] else r["title"]
        print(f"  {where}\n    {r['snippet']}\n    agenti docs {r['page']}\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="agenti docs", description="List, read and search the help pages.")
    ap.add_argument("--dir", help="the help-page folder (default: the installed one)")
    ap.add_argument("--json", action="store_true", help="print one JSON document")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", allow_abbrev=False, help="every page, with a one-line summary")
    s = sub.add_parser("show", allow_abbrev=False, help="print one page")
    s.add_argument("--page", required=True)
    q = sub.add_parser("search", allow_abbrev=False, help="find pages and sections that mention every word")
    q.add_argument("--query", required=True)
    a = ap.parse_args(argv)
    try:
        pages = load(resolve_dir(a.dir))
        if a.cmd == "list":
            data = page_list(pages)
        elif a.cmd == "show":
            data = page_show(find(pages, a.page))
        else:
            data = search(pages, a.query)
    except DocsError as e:
        print(str(e), file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(data, ensure_ascii=False))
    elif a.cmd == "list":
        print_list(data)
    elif a.cmd == "show":
        print(data["markdown"].rstrip("\n"))
    else:
        print_search(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
