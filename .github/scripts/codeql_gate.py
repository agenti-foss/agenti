#!/usr/bin/env python3
"""codeql_gate.py — the Security workflow's CodeQL gate.

    python3 .github/scripts/codeql_gate.py <sarif-dir> .github/codeql-reviewed.json

Fails on every finding nobody has reviewed. A reviewed finding is listed in
codeql-reviewed.json with its rule, file and the exact source line it points
at (whitespace-trimmed), plus the reason it is intended. Matching on the line's
text, not its number, keeps a review attached when code above it moves, and
drops it the moment the line itself changes, so a changed line is reviewed
again. Reviewed entries that no longer match anything are reported, so the
list never keeps excuses for code that is gone.

Code scanning (the GitHub UI) is a paid feature on a private repository, so
this file is where triage lives until the repository is public.
"""
import json
import pathlib
import sys


def line_text(path: str, line: int) -> str:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8").splitlines()[line - 1].strip()
    except (OSError, IndexError, UnicodeDecodeError):
        return ""


def main(sarif_dir: str, reviewed_file: str) -> int:
    reviewed = json.loads(pathlib.Path(reviewed_file).read_text(encoding="utf-8"))["reviewed"]
    for e in reviewed:
        if not (e.get("rule") and e.get("path") and e.get("line") and e.get("reason")):
            print(f"::error::codeql-reviewed.json: every entry needs rule, path, line and reason: {e}")
            return 2
    used = set()
    unreviewed = 0
    total = 0
    langs = set()               # each CodeQL job sees one language's results only
    for f in sorted(pathlib.Path(sarif_dir).rglob("*.sarif")):
        langs.add({"python": "py/", "javascript": "js/"}.get(f.stem.split("-")[0], f.stem))
        for run in json.loads(f.read_text(encoding="utf-8")).get("runs", []):
            for r in run.get("results", []):
                if r.get("suppressions"):
                    continue
                total += 1
                loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                path = loc.get("artifactLocation", {}).get("uri", "?")
                line = loc.get("region", {}).get("startLine", 0)
                text = line_text(path, line)
                hit = next((i for i, e in enumerate(reviewed)
                            if e["rule"] == r.get("ruleId") and e["path"] == path and e["line"] == text), None)
                if hit is not None:
                    used.add(hit)
                    continue
                unreviewed += 1
                print(f'::error file={path},line={line}::{r.get("ruleId")}: {r.get("message", {}).get("text", "")[:300]}')
                print(f'UNREVIEWED  {r.get("ruleId")}  {path}:{line}  {text[:120]}')
    for i, e in enumerate(reviewed):
        if i not in used and any(e["rule"].startswith(lg) for lg in langs):
            print(f'::warning::codeql-reviewed.json entry matches nothing any more (remove it): {e["rule"]} {e["path"]}: {e["line"][:80]}')
    print(f"{total} finding(s): {total - unreviewed} reviewed as intended, {unreviewed} not reviewed. "
          f"Full results: this job's codeql-* artifact. Reasons: .github/codeql-reviewed.json")
    return 1 if unreviewed else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
