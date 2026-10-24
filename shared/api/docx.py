"""
docx.py — the run report as a Word document, from the standard library.

A report (`agenti <agent> report`) is Markdown: a header of
**Key:** value lines, `##` sections, bullet lists, pipe tables, fenced or
inline code, and the model's own prose. This module turns that subset into
a .docx — a zip of a few XML parts — with `zipfile` and hand-written
WordprocessingML, so the API's venv stays fastapi+uvicorn and nothing here
can differ from what the browser shows: shared/gui/js/markdown.js parses the
SAME grammar for the on-screen rendering, and shared/test_docx.py pins both
ends of it (the block parser here, and the document's structure).

WHAT IS SUPPORTED — exactly what the agents write, nothing speculative:
  #..### headings, paragraphs, > blockquotes, - / * / 1. lists (one level),
  | pipe | tables |, ``` fenced code, --- rules, and inline **bold**,
  _italic_ / *italic*, `code`, and [text](http(s) links) shown as text plus
  the URL. Anything else is a paragraph, which is the safe failure.

The document is deliberately plain: real styles (Heading 1–3, List Bullet,
List Number, Quote, Code) so Word's navigation pane, table of contents and
theme fonts all work, and nothing that needs a numbering part or an image
part — both are where hand-written docx files usually go wrong.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml_escape

__all__ = ["parse_blocks", "markdown_to_docx", "Block"]


# ---------------------------------------------------------------------------
# Block parser — the grammar markdown.js mirrors
# ---------------------------------------------------------------------------
@dataclass
class Block:
    kind: str                      # heading|para|quote|ul|ol|table|code|hr
    text: str = ""                 # heading/para/quote text, code body
    level: int = 0                 # heading level
    items: list[str] = field(default_factory=list)   # list items
    rows: list[list[str]] = field(default_factory=list)  # table rows (first = header)


_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_UL = re.compile(r"^\s{0,3}[-*+]\s+(.*)$")
_OL = re.compile(r"^\s{0,3}\d+[.)]\s+(.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_HR = re.compile(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$")
_KV = re.compile(r"^\*\*[^*\n]{1,40}:\*\*\s")


def _split_row(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells, cur, i = [], [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            cur.append("|"); i += 2; continue
        if c == "|":
            cells.append("".join(cur).strip()); cur = []
        else:
            cur.append(c)
        i += 1
    cells.append("".join(cur).strip())
    return cells


def parse_blocks(markdown: str) -> list[Block]:
    lines = markdown.replace("\r\n", "\n").split("\n")
    blocks: list[Block] = []
    i = 0
    para: list[str] = []

    def flush_para() -> None:
        if para:
            blocks.append(Block("para", " ".join(x.strip() for x in para)))
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("```"):
            flush_para()
            j = i + 1
            body = []
            while j < len(lines) and not lines[j].strip().startswith("```"):
                body.append(lines[j]); j += 1
            blocks.append(Block("code", "\n".join(body)))
            i = j + 1
            continue
        if not stripped:
            flush_para(); i += 1; continue
        m = _HEADING.match(line)
        if m:
            flush_para()
            blocks.append(Block("heading", m.group(2), level=len(m.group(1))))
            i += 1; continue
        if _HR.match(line):
            flush_para(); blocks.append(Block("hr")); i += 1; continue
        if stripped.startswith(">"):
            flush_para()
            q = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                q.append(lines[i].strip()[1:].strip()); i += 1
            blocks.append(Block("quote", " ".join(x for x in q if x)))
            continue
        if _UL.match(line) or _OL.match(line):
            flush_para()
            kind = "ul" if _UL.match(line) else "ol"
            rx = _UL if kind == "ul" else _OL
            items = []
            while i < len(lines) and rx.match(lines[i]):
                items.append(rx.match(lines[i]).group(1).strip()); i += 1
                # a continuation line indented under the item joins it
                while i < len(lines) and lines[i].startswith("  ") and lines[i].strip() \
                        and not _UL.match(lines[i]) and not _OL.match(lines[i]):
                    items[-1] += " " + lines[i].strip(); i += 1
            blocks.append(Block(kind, items=items))
            continue
        if "|" in stripped and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush_para()
            rows = [_split_row(line)]
            i += 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                rows.append(_split_row(lines[i])); i += 1
            blocks.append(Block("table", rows=rows))
            continue
        # The report header is a run of `**Key:** value` lines with no blank
        # line between them; Markdown would fold them into one paragraph,
        # which reads as a wall. Each starts its own block instead.
        if _KV.match(line) and para:
            flush_para()
        para.append(line); i += 1
    flush_para()
    return blocks


# ---------------------------------------------------------------------------
# Inline runs
# ---------------------------------------------------------------------------
_INLINE = re.compile(
    r"(`[^`\n]+`)"                      # code
    r"|(\*\*[^*\n]+?\*\*)"              # bold
    r"|(\[[^\]\n]+\]\((?:https?://)[^)\s]+\))"   # link
    r"|((?<![\w*])[*_][^*_\n]+?[*_](?![\w*]))"   # italic (either marker)
)


def inline_runs(text: str) -> list[tuple[str, dict]]:
    """[(text, {bold, italic, code}), ...] — links become 'text (url)'."""
    runs: list[tuple[str, dict]] = []
    pos = 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            runs.append((text[pos:m.start()], {}))
        code, bold, link, italic = m.groups()
        if code:
            runs.append((code[1:-1], {"code": True}))
        elif bold:
            runs.append((bold[2:-2], {"bold": True}))
        elif link:
            lm = re.match(r"\[([^\]]+)\]\(([^)]+)\)", link)
            runs.append((lm.group(1), {"bold": False}))
            runs.append((f" ({lm.group(2)})", {"code": True}))
        elif italic:
            runs.append((italic[1:-1], {"italic": True}))
        pos = m.end()
    if pos < len(text):
        runs.append((text[pos:], {}))
    return runs


# ---------------------------------------------------------------------------
# WordprocessingML
# ---------------------------------------------------------------------------
_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def _t(text: str) -> str:
    # xml:space="preserve" keeps leading/trailing spaces between runs.
    return f'<w:t xml:space="preserve">{_xml_escape(text)}</w:t>'


def _run(text: str, fmt: dict) -> str:
    props = ""
    if fmt.get("bold"):
        props += "<w:b/>"
    if fmt.get("italic"):
        props += "<w:i/>"
    if fmt.get("code"):
        props += '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="19"/>'
    rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
    return f"<w:r>{rpr}{_t(text)}</w:r>"


def _para(text: str, style: str | None = None, *, literal: bool = False) -> str:
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    if literal:
        # code: keep line breaks, no inline parsing
        parts = []
        for k, line in enumerate(text.split("\n")):
            if k:
                parts.append("<w:r><w:br/></w:r>")
            parts.append(_run(line, {"code": True}))
        body = "".join(parts)
    else:
        body = "".join(_run(t, f) for t, f in inline_runs(text))
    return f"<w:p>{ppr}{body}</w:p>"


def _table(rows: list[list[str]]) -> str:
    ncols = max(len(r) for r in rows) if rows else 1
    out = ['<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/>'
           '<w:tblBorders>'
           + "".join(f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
                     for side in ("top", "left", "bottom", "right", "insideH", "insideV"))
           + '</w:tblBorders><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr>'
           '<w:tblGrid>' + "".join('<w:gridCol/>' for _ in range(ncols)) + '</w:tblGrid>']
    for ri, row in enumerate(rows):
        out.append("<w:tr>")
        for ci in range(ncols):
            cell = row[ci] if ci < len(row) else ""
            runs = "".join(_run(t, {**f, "bold": f.get("bold") or ri == 0})
                           for t, f in inline_runs(cell)) or _run("", {})
            shade = '<w:shd w:val="clear" w:color="auto" w:fill="EEEEEE"/>' if ri == 0 else ""
            out.append(f"<w:tc><w:tcPr>{shade}</w:tcPr><w:p>{runs}</w:p></w:tc>")
        out.append("</w:tr>")
    out.append("</w:tbl><w:p/>")
    return "".join(out)


def _body(blocks: list[Block]) -> str:
    out = []
    for b in blocks:
        if b.kind == "heading":
            out.append(_para(b.text, f"Heading{min(b.level, 3)}"))
        elif b.kind == "para":
            out.append(_para(b.text))
        elif b.kind == "quote":
            out.append(_para(b.text, "Quote"))
        elif b.kind == "ul":
            out.extend(_para(f"•  {it}", "ListBullet") for it in b.items)
        elif b.kind == "ol":
            out.extend(_para(f"{n}.  {it}", "ListNumber") for n, it in enumerate(b.items, 1))
        elif b.kind == "table":
            out.append(_table(b.rows))
        elif b.kind == "code":
            out.append(_para(b.text, "Code", literal=True))
        elif b.kind == "hr":
            out.append('<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="6" w:space="1" w:color="BBBBBB"/></w:pBdr></w:pPr></w:p>')
    return "".join(out)


_STYLES = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {_W}>
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault>
    <w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="1F3864"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="100"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="2F5496"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="480" w:hanging="300"/><w:spacing w:after="60"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="ListNumber"><w:name w:val="List Number"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="480" w:hanging="300"/><w:spacing w:after="60"/></w:pPr></w:style>
  <w:style w:type="paragraph" w:styleId="Quote"><w:name w:val="Quote"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="480"/><w:pBdr><w:left w:val="single" w:sz="12" w:space="8" w:color="BBBBBB"/></w:pBdr></w:pPr><w:rPr><w:i/><w:color w:val="555555"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/><w:spacing w:after="120" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="18"/></w:rPr></w:style>
  <w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:left w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:right w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="auto"/></w:tblBorders></w:tblPr></w:style>
</w:styles>'''

_CONTENT_TYPES = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>'''

_RELS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''

_DOC_RELS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>'''

_APP = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Agenti</Application></Properties>'''


def _core(title: str, creator: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            f'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            f'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_xml_escape(title)}</dc:title><dc:creator>{_xml_escape(creator)}</dc:creator>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
            f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified></cp:coreProperties>')


def markdown_to_docx(markdown: str, *, title: str = "Report", creator: str = "Agenti") -> bytes:
    """The whole document as bytes, ready to send with the .docx media type."""
    blocks = parse_blocks(markdown)
    document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<w:document {_W}><w:body>{_body(blocks)}'
                f'<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
                f'<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="708" w:footer="708" w:gutter="0"/>'
                f'</w:sectPr></w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # [Content_Types].xml must be the first entry for some readers.
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", _STYLES)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        z.writestr("docProps/core.xml", _core(title, creator))
        z.writestr("docProps/app.xml", _APP)
    return buf.getvalue()
