// markdown.js — render a run report (Markdown) as HTML.
//
// This mirrors shared/api/docx.py's parse_blocks()/inline_runs() — the SAME
// grammar, so what the browser shows and what the .docx export contains are
// the same document. Keep the two in step: a construct added here must be
// added there, or the Word file silently differs from the page.
//
// Output is built from escaped text only; the input is a document the
// agent wrote and the model's own prose is in it, so nothing from it is
// ever inserted as markup. Links are rendered only for http(s) URLs and
// open in a new tab with rel=noopener.
//
// render(md, opts) — opts is only for trusted pages (the help docs), never
// reports: opts.docLink(href) turns a relative link into a same-tab URL (or
// returns "" to leave it as text), opts.headingId(text) names a heading's id.
const AgentiMarkdown = (() => {
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
  const UL = /^\s{0,3}[-*+]\s+(.*)$/;
  const OL = /^\s{0,3}\d+[.)]\s+(.*)$/;
  const TABLE_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
  const HR = /^\s*(-{3,}|\*{3,}|_{3,})\s*$/;
  const KV = /^\*\*[^*\n]{1,40}:\*\*\s/;

  function splitRow(line) {
    let s = line.trim();
    if (s.startsWith("|")) s = s.slice(1);
    if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1);
    const cells = []; let cur = "";
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === "\\" && s[i + 1] === "|") { cur += "|"; i++; continue; }
      if (c === "|") { cells.push(cur.trim()); cur = ""; } else cur += c;
    }
    cells.push(cur.trim());
    return cells;
  }

  function parseBlocks(md) {
    const lines = String(md ?? "").replace(/\r\n/g, "\n").split("\n");
    const blocks = []; let para = []; let i = 0;
    const flush = () => { if (para.length) { blocks.push({ kind: "para", text: para.map((x) => x.trim()).join(" ") }); para = []; } };
    while (i < lines.length) {
      const line = lines[i]; const st = line.trim();
      if (st.startsWith("```")) {
        flush(); let j = i + 1; const body = [];
        while (j < lines.length && !lines[j].trim().startsWith("```")) { body.push(lines[j]); j++; }
        blocks.push({ kind: "code", text: body.join("\n") }); i = j + 1; continue;
      }
      if (!st) { flush(); i++; continue; }
      let m = HEADING.exec(line);
      if (m) { flush(); blocks.push({ kind: "heading", level: m[1].length, text: m[2] }); i++; continue; }
      if (HR.test(line)) { flush(); blocks.push({ kind: "hr" }); i++; continue; }
      if (st.startsWith(">")) {
        flush(); const q = [];
        while (i < lines.length && lines[i].trim().startsWith(">")) { q.push(lines[i].trim().slice(1).trim()); i++; }
        blocks.push({ kind: "quote", text: q.filter(Boolean).join(" ") }); continue;
      }
      if (UL.test(line) || OL.test(line)) {
        flush(); const kind = UL.test(line) ? "ul" : "ol"; const rx = kind === "ul" ? UL : OL; const items = [];
        while (i < lines.length && rx.test(lines[i])) {
          items.push(rx.exec(lines[i])[1].trim()); i++;
          while (i < lines.length && lines[i].startsWith("  ") && lines[i].trim() && !UL.test(lines[i]) && !OL.test(lines[i])) {
            items[items.length - 1] += " " + lines[i].trim(); i++;
          }
        }
        blocks.push({ kind, items }); continue;
      }
      if (st.includes("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
        flush(); const rows = [splitRow(line)]; i += 2;
        while (i < lines.length && lines[i].includes("|") && lines[i].trim()) { rows.push(splitRow(lines[i])); i++; }
        blocks.push({ kind: "table", rows }); continue;
      }
      if (KV.test(line) && para.length) flush();
      para.push(line); i++;
    }
    flush();
    return blocks;
  }

  const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+?\*\*)|(\[[^\]\n]+\]\((?:https?:\/\/)[^)\s]+\))|((?<![\w*])[*_][^*_\n]+?[*_](?![\w*]))/g;
  const INLINE_DOCS = /(`[^`\n]+`)|(\*\*[^*\n]+?\*\*)|(\[[^\]\n]+\]\([^)\s]+\))|((?<![\w*])[*_][^*_\n]+?[*_](?![\w*]))/g;

  function inline(text, opts) {
    const o = opts || {};
    const rx = o.docLink ? INLINE_DOCS : INLINE;
    let out = ""; let pos = 0; let m;
    rx.lastIndex = 0;
    while ((m = rx.exec(text)) !== null) {
      if (m.index > pos) out += esc(text.slice(pos, m.index));
      const [, code, bold, link, italic] = m;
      if (code) out += `<code>${esc(code.slice(1, -1))}</code>`;
      else if (bold) out += `<strong>${esc(bold.slice(2, -2))}</strong>`;
      else if (link) {
        const lm = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(link);
        if (/^https?:\/\//.test(lm[2])) {
          out += `<a href="${esc(lm[2])}" target="_blank" rel="noopener noreferrer">${esc(lm[1])}</a>`;
        } else {
          const local = o.docLink(lm[2]);
          out += local ? `<a href="${esc(local)}">${esc(lm[1])}</a>` : esc(lm[1]);
        }
      } else if (italic) out += `<em>${esc(italic.slice(1, -1))}</em>`;
      pos = m.index + m[0].length;
    }
    if (pos < text.length) out += esc(text.slice(pos));
    return out;
  }

  function render(md, opts) {
    const o = opts || {};
    const il = (s) => inline(s, o);
    const parts = [];
    for (const b of parseBlocks(md)) {
      switch (b.kind) {
        case "heading": {
          const lv = Math.min(b.level, 4);
          const id = o.headingId ? o.headingId(b.text) : "";
          parts.push(`<h${lv}${id ? ` id="${esc(id)}"` : ""}>${il(b.text)}</h${lv}>`);
          break;
        }
        case "para": parts.push(KV.test(b.text) ? `<p class="kv-line">${il(b.text)}</p>` : `<p>${il(b.text)}</p>`); break;
        case "quote": parts.push(`<blockquote>${il(b.text)}</blockquote>`); break;
        case "ul": parts.push(`<ul>${b.items.map((it) => `<li>${il(it)}</li>`).join("")}</ul>`); break;
        case "ol": parts.push(`<ol>${b.items.map((it) => `<li>${il(it)}</li>`).join("")}</ol>`); break;
        case "code": parts.push(`<pre><code>${esc(b.text)}</code></pre>`); break;
        case "hr": parts.push("<hr>"); break;
        case "table": {
          const [head, ...rows] = b.rows;
          const n = Math.max(...b.rows.map((r) => r.length));
          const cells = (r, tag) => Array.from({ length: n }, (_, k) => `<${tag}>${il(r[k] ?? "")}</${tag}>`).join("");
          parts.push(`<div class="table-scroll"><table><thead><tr>${cells(head, "th")}</tr></thead><tbody>${rows.map((r) => `<tr>${cells(r, "td")}</tr>`).join("")}</tbody></table></div>`);
          break;
        }
        default: break;
      }
    }
    return parts.join("\n");
  }

  return { render, parseBlocks, inline };
})();
