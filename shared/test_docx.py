#!/usr/bin/env python3
"""test_docx.py — the report's Markdown grammar and its Word rendering
(shared/api/docx.py).

    python3 shared/test_docx.py

No dependencies. The block parser is the contract shared with the browser
renderer (shared/gui/js/markdown.js mirrors it), so the cases here are the
shapes the agents' write_report() functions actually emit — a `**Key:**`
header run, `##` sections, `> **Note:**`, bullet and numbered lists, a pipe
table whose cells contain escaped pipes and inline code, and a fenced
block — plus the inline grammar. The document checks prove every part is
well-formed XML and that headings, list styles and tables landed where the
Markdown said, since a .docx that opens with "unreadable content" is the
failure mode here and it is invisible from Python without these.
"""
import io
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "api"))
import docx  # noqa: E402

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def section(t): print(f"\n=== {t} ===")


REPORT = """# Assessment Report — LAB-DEV

**Status:** incomplete
**Agent:** enum (dev profile)
**Scope scanned (this run):** 192.0.2.199/32

> **Note:** Run was stopped before completion. Findings may be incomplete.

---

## Operator input

_Messages steer what the agent attempts._

- **note** 2026-09-21, from `alice` (via cli): client confirmed scope
- **message** 2026-09-21, from `alice` (via cli): focus on Tomcat
  and keep going

## Findings

The host exposes **30 services**. See [the scan](https://example.com/s) for detail.

1. Anonymous FTP
2. Samba r/w share

## Commands executed

| # | Verdict | Command | Raw output |
|---|---------|---------|------------|
| 1 | ALLOWED | `nmap -sV 10.0.0.5` | `scan.txt` |
| 2 | DENIED | `cat /etc/passwd \\| grep root` | — |

```
raw text
  kept as-is
```

_Generated 2026-09-22._
"""

section("parse_blocks: the report shape")
B = docx.parse_blocks(REPORT)
kinds = [b.kind for b in B]
check("block sequence",
      kinds, ["heading", "para", "para", "para", "quote", "hr", "heading", "para", "ul",
              "heading", "para", "ol", "heading", "table", "code", "para"])
check("h1 text", (B[0].level, B[0].text), (1, "Assessment Report — LAB-DEV"))
check("each **Key:** header line is its own paragraph", [b.text.split("**")[1] for b in B[1:4]],
      ["Status:", "Agent:", "Scope scanned (this run):"])
check("quote text keeps its inline markup", B[4].text, "**Note:** Run was stopped before completion. Findings may be incomplete.")
check("h2", (B[6].level, B[6].text), (2, "Operator input"))
check("bullet items, continuation line joined", B[8].items[1].endswith("focus on Tomcat and keep going"), True)
check("numbered items", B[11].items, ["Anonymous FTP", "Samba r/w share"])
tbl = B[13]
check("table: header + 2 rows, 4 cols", (len(tbl.rows), len(tbl.rows[0])), (3, 4))
check("table: escaped pipe stays in the cell", tbl.rows[2][2], "`cat /etc/passwd | grep root`")
check("fenced code kept verbatim", B[14].text, "raw text\n  kept as-is")

section("parse_blocks: edge cases")
check("empty input", docx.parse_blocks(""), [])
check("plain lines fold into one paragraph", docx.parse_blocks("a\nb\n\nc")[0].text, "a b")
check("two paragraphs", len(docx.parse_blocks("a\nb\n\nc")), 2)
check("unterminated fence still yields a code block", docx.parse_blocks("```\nx")[0].kind, "code")
check("a lone pipe line without a separator is a paragraph", docx.parse_blocks("a | b")[0].kind, "para")
check("*** is a rule, not a list", docx.parse_blocks("***")[0].kind, "hr")
check("'* item' is a bullet", docx.parse_blocks("* item")[0].kind, "ul")
check("'1) item' is numbered", docx.parse_blocks("1) item")[0].kind, "ol")
check("heading with trailing #s", docx.parse_blocks("## Title ##")[0].text, "Title")
check("h6 clamps to Heading3 in the document", "Heading3" in docx._body(docx.parse_blocks("###### deep")), True)
check("crlf input", [b.kind for b in docx.parse_blocks("# a\r\n\r\nb\r\n")], ["heading", "para"])

section("inline runs")
runs = docx.inline_runs("a **b** _c_ `d` [e](https://x.y/z) *f* g")
check("segments", [t for t, _ in runs], ["a ", "b", " ", "c", " ", "d", " ", "e", " (https://x.y/z)", " ", "f", " g"])
check("formats", [sorted(k for k, v in f.items() if v) for _, f in runs],
      [[], ["bold"], [], ["italic"], [], ["code"], [], [], ["code"], [], ["italic"], []])
check("a lone asterisk in prose is literal", [t for t, _ in docx.inline_runs("2 * 3 = 6")], ["2 * 3 = 6"])
check("snake_case is not italic", [t for t, _ in docx.inline_runs("run_scan and read_scan")], ["run_scan and read_scan"])
check("a javascript: link is not linkified", [t for t, _ in docx.inline_runs("[x](javascript:alert(1))")], ["[x](javascript:alert(1))"])
check("xml special characters are escaped in runs", "&lt;b&gt;&amp;" in docx._run("<b>&", {}), True)

section("the document")
data = docx.markdown_to_docx(REPORT, title="LAB-DEV", creator="alice")
z = zipfile.ZipFile(io.BytesIO(data))
names = z.namelist()
check("[Content_Types].xml is the first entry", names[0], "[Content_Types].xml")
check("all seven parts present", sorted(names),
      sorted(["[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml",
              "word/_rels/document.xml.rels", "docProps/core.xml", "docProps/app.xml"]))
ok = True
for n in names:
    try:
        ET.fromstring(z.read(n))
    except ET.ParseError as e:
        ok = False; print(f"         {n}: {e}")
check("every part is well-formed XML", ok, True)
check("zip test passes", z.testzip(), None)
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
doc = ET.fromstring(z.read("word/document.xml"))
body = doc.find(f"{W}body")
styles = [p.find(f"{W}pPr/{W}pStyle").get(f"{W}val") for p in body.iter(f"{W}p")
          if p.find(f"{W}pPr/{W}pStyle") is not None]
check("heading styles in order", [s for s in styles if s.startswith("Heading")], ["Heading1", "Heading2", "Heading2", "Heading2"])
check("list styles", (styles.count("ListBullet"), styles.count("ListNumber")), (2, 2))
check("quote and code styles", (styles.count("Quote"), styles.count("Code")), (1, 1))
tbls = list(body.iter(f"{W}tbl"))
check("one table with three rows", (len(tbls), len(list(tbls[0].iter(f"{W}tr")))), (1, 3))
check("table cells: four per row", len(list(list(tbls[0].iter(f"{W}tr"))[0].iter(f"{W}tc"))), 4)
texts = "".join(t.text or "" for t in doc.iter(f"{W}t"))
check("text survives, markup consumed", ("Assessment Report — LAB-DEV" in texts, "**" in texts, "30 services" in texts), (True, False, True))
check("link shows its URL", "(https://example.com/s)" in texts, True)
check("escaped pipe is a pipe in the cell text", "cat /etc/passwd | grep root" in texts, True)
check("section properties present (page size/margins)", body.find(f"{W}sectPr") is not None, True)
core = ET.fromstring(z.read("docProps/core.xml"))
check("core title and creator", (core.find("{http://purl.org/dc/elements/1.1/}title").text,
                                 core.find("{http://purl.org/dc/elements/1.1/}creator").text), ("LAB-DEV", "alice"))
check("an empty report still produces a valid document",
      zipfile.ZipFile(io.BytesIO(docx.markdown_to_docx(""))).testzip(), None)
check("styles part declares the styles the body uses",
      all(f'w:styleId="{s}"' in z.read("word/styles.xml").decode() for s in set(styles)), True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
