#!/usr/bin/env python3
"""team_report.py — the team document: one readable account of a project that
several agents worked on together.

It is ASSEMBLED, never written by a model: the roster and each member's task
come from the kickoff entry on the team channel, each member's conclusions are
the Findings section of its own report, and the story of how they worked
together is the channel itself (introductions, questions, answers, who said
the project was done and why). Nothing here calls an AI, so the document can
only say what the agents actually said and did.

What is deliberately LEFT OUT, because a person reading a project summary does
not want it: the per-run command tables, the lists of pages and scan files,
the instruction hashes, and the "agent has ended" bookkeeping. Those stay in
each agent's own report, one click away from the agent's page.

    team_report.py --team NAME --channel FILE [--owner USER] [--acknowledged-by USER]
                   AGENT=REPORT_PATH ...        # prints Markdown on stdout
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

# Sections of an agent report that follow its Findings.
_AFTER_FINDINGS = ("Commands executed", "Actions taken", "Raw scan files",
                   "Outside sites read", "Pages saved", "Evidence", "Capture",
                   "Instructions used", "Operator input")
_END_OF_FINDINGS = re.compile(r"\n-{3,}\s*\n+## (?:%s)\b" % "|".join(map(re.escape, _AFTER_FINDINGS)))
_FIELD = r"^\*\*%s:\*\*\s*(.+?)\s*$"


def read_channel(path: Path) -> list[dict]:
    """The whole channel: the operator's file and every member's, merged in
    time order, a member line's author taken from its file (audit run 1, N02).
    One reader for the agents, the CLI and this report: agent_runtime's."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import agent_runtime as ar
    return [{k: v for k, v in e.items() if not k.startswith("_")} for e in ar.read_team_channel(Path(path))]


def report_field(text: str, name: str) -> str:
    m = re.search(_FIELD % re.escape(name), text, re.MULTILINE)
    return m.group(1) if m else ""


def findings_of(text: str) -> str:
    """The body of an agent report's "## Findings" section, headings demoted so
    they sit beneath the member's own heading."""
    m = re.search(r"^## Findings\s*$", text, re.MULTILINE)
    if not m:
        return ""
    rest = text[m.end():]
    end = _END_OF_FINDINGS.search(rest)
    body = (rest[:end.start()] if end else rest).strip()
    lines = []
    for ln in body.split("\n"):
        h = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", ln)
        lines.append(f"#### {h.group(2)}" if h else ln)
    body = "\n".join(lines).strip()
    # The model often opens with its own title line; the member heading above
    # already says whose findings these are.
    body = re.sub(r"^#### [^\n]*(findings|assessment|summary)[^\n]*\n+", "", body,
                  count=1, flags=re.IGNORECASE)
    return body


MAX_FINDINGS_LINES = 45


def clip_findings(body: str, agent: str, limit: int = MAX_FINDINGS_LINES) -> str:
    """A very long findings section would bury the rest of the document, so it is
    cut at a paragraph break, never mid-table or mid-list, with a pointer to the
    agent's own report, which always has all of it."""
    lines = body.split("\n")
    if sum(1 for ln in lines if ln.strip()) <= limit:
        return body
    kept, n = [], 0
    for ln in lines:
        if ln.strip():
            n += 1
        if n > limit and not ln.strip() and not (kept and kept[-1].lstrip().startswith(("|", "-", "*"))):
            break
        kept.append(ln)
    return ("\n".join(kept).rstrip()
            + f"\n\n_The rest of what {agent} found is in its own report, on its page._")


def count_steps(text: str) -> int:
    """How many commands/actions the run made, from whichever section it has."""
    for title in ("Commands executed", "Actions taken"):
        m = re.search(r"^## %s\s*$" % title, text, re.MULTILINE)
        if not m:
            continue
        rest = text[m.end():]
        nxt = re.search(r"^## ", rest, re.MULTILINE)
        block = rest[:nxt.start()] if nxt else rest
        rows = [ln for ln in block.split("\n") if ln.startswith("| ") and not re.match(r"^\|[\s:|-]+\|?$", ln)]
        if rows:
            return max(len(rows) - 1, 0)          # the header row
        return sum(1 for ln in block.split("\n") if ln.startswith("- "))
    return 0


def _when(ts) -> str:
    try:
        return time.strftime("%H:%M", time.gmtime(float(ts)))
    except (TypeError, ValueError):
        return ""


def _quote(text: str) -> str:
    return "\n".join(f"> {ln}" if ln.strip() else ">" for ln in str(text).strip().split("\n"))


def build(team: str, entries: list[dict], members: list[tuple[str, str]], *,
          owner: str = "", acknowledged_by: str = "", generated: float | None = None) -> str:
    """The Markdown document. `members` is [(agent, path-to-its-latest-report)]."""
    generated = generated or time.time()
    kickoffs = [e for e in entries if e.get("kind") == "kickoff"]
    kick = kickoffs[-1] if kickoffs else {}
    details = kick.get("details") if isinstance(kick.get("details"), dict) else {}
    roster = kick.get("roster") if isinstance(kick.get("roster"), dict) else {}

    info: dict[str, dict] = {}
    for agent, report_path in members:
        text = ""
        if report_path:
            # Never follow a link the member's run planted in reports/ (F16).
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import run_files
            rp = Path(report_path)
            try:
                fh, _ = run_files.open_in_slot(rp.parent.parent, Path(rp.parent.name) / rp.name)
                with fh:
                    text = fh.read().decode("utf-8", errors="replace")
            except (run_files.FilesError, OSError):
                text = ""
        d = details.get(agent) if isinstance(details.get(agent), dict) else {}
        info[agent] = {
            "title": d.get("title") or agent, "target": d.get("target") or "",
            "role": d.get("role") or roster.get(agent) or "",
            "summary": d.get("summary") or "",
            "status": report_field(text, "Status") or "no report yet",
            "duration": report_field(text, "Duration"),
            "cost": report_field(text, "Cost"),
            "steps": count_steps(text),
            "findings": clip_findings(findings_of(text), agent),
            "has_report": bool(text),
        }
    names = [a for a, _ in members]
    chat = [e for e in entries if e.get("kind") == "message"]
    agent_msgs = [e for e in chat if str(e.get("author", "")).startswith("agent:")]
    directed = [e for e in agent_msgs if e.get("to")]

    L = [f"# {team}", "",
         "_Project report · prepared " + time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(generated))
         + (f" · started by {owner}" if owner else "")
         + (f" · marked complete by {acknowledged_by}" if acknowledged_by else "") + "_", ""]

    # ---- summary ----------------------------------------------------------
    L += ["## Summary", ""]
    if names:
        parts = []
        for a in names:
            i = info[a]
            what = i["title"] if i["title"] != a else "its work"
            on = f" on {i['target']}" if i["target"] else ""
            parts.append(f"**{a}** ({what}{on})")
        joined = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
        L.append(f"{len(names)} agent{'s' if len(names) != 1 else ''} worked on this project: {joined}.")
        done = [a for a in names if info[a]["status"].lower() == "completed"]
        if len(done) == len(names):
            L.append("Every agent finished its work.")
        else:
            odd = [f"{a} ({info[a]['status']})" for a in names if a not in done]
            L.append("Not every agent ran to completion: " + ", ".join(odd) + ".")
        if agent_msgs:
            L.append(f"They exchanged {len(agent_msgs)} message{'s' if len(agent_msgs) != 1 else ''}"
                     + (f", {len(directed)} of them addressed to a specific teammate." if directed else "."))
        else:
            L.append("They did not exchange any messages with each other during this project.")
    else:
        L.append("This project has no members.")
    L.append("")
    # Each agent's own closing statement (its latest vote) is the plain-language
    # gist, so a reader gets the result before any detail.
    closing = {}
    for e in entries:
        if e.get("kind") == "vote_complete" and str(e.get("author", "")).startswith("agent:"):
            closing[str(e["author"])[6:]] = str(e.get("body") or "").strip()
    brief = [(a, closing[a]) for a in names if closing.get(a)]
    if brief:
        L += ["**In brief**", ""]
        for a, text in brief:
            short = " ".join(text.split())
            L.append(f"- **{a}:** " + (short if len(short) <= 420 else short[:417].rstrip() + "…"))
        L.append("")

    # ---- who did what -----------------------------------------------------
    L += ["## The team", ""]
    for a in names:
        i = info[a]
        line = f"- **{a}** — {i['title']}"
        if i["target"]:
            line += f" · {i['target']}"
        bits = [b for b in (i["status"], i["duration"], (f"{i['steps']} step{'s' if i['steps'] != 1 else ''}" if i["steps"] else "")) if b]
        if bits:
            line += " · " + " · ".join(bits)
        L.append(line)
        if i["role"]:
            L.append(f"  - Focus: {i['role']}")
    L.append("")

    # ---- findings ---------------------------------------------------------
    L += ["## What each agent found", ""]
    for a in names:
        i = info[a]
        L += [f"### {a}", ""]
        if i["findings"]:
            L += [i["findings"], ""]
        elif i["has_report"]:
            L += ["_Its report has no findings section._", ""]
        else:
            L += ["_No report yet — this agent has not finished a run._", ""]

    # ---- the conversation -------------------------------------------------
    L += ["## How the team worked together", ""]
    story = []
    # An agent re-confirms its vote whenever a teammate posts something new;
    # only the latest is kept — the earlier ones say the same thing again.
    last_vote = {}
    for e in entries:
        if e.get("kind") == "vote_complete":
            last_vote[e.get("author")] = e.get("id")
    for e in entries:
        if e.get("kind") == "vote_complete" and e.get("id") != last_vote.get(e.get("author")):
            continue
        kind, who, body = e.get("kind"), str(e.get("author", "?")), str(e.get("body", "")).strip()
        is_agent = who.startswith("agent:")
        name = who[6:] if is_agent else who
        when = _when(e.get("ts"))
        if kind == "kickoff":
            story.append(f"**{when}** · The project started.")
        elif kind == "message":
            to = e.get("to")
            head = f"**{name}**" + (f" → **{to}**" if to else ("" if is_agent else " (operator)"))
            story.append(f"**{when}** · {head}\n\n{_quote(body)}")
        elif kind == "vote_complete":
            story.append(f"**{when}** · **{name}** said the project is complete:\n\n{_quote(body)}")
        elif kind == "note":
            story.append(f"**{when}** · {name} left a note (not shown to the agents): {body}")
        elif kind == "member_ended":
            m = re.search(r"\(status: ([^,)]+)", body)
            story.append(f"**{when}** · {name} finished" + (f" ({m.group(1)})." if m else "."))
    if not story:
        L += ["_Nothing was posted to the team channel._", ""]
    else:
        for item in story:
            L += [item, ""]

    L += ["---", "",
          "_Each agent's complete report (commands, pages, raw output) is on that agent's page._"]
    return "\n".join(L).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    ap.add_argument("--team", required=True)
    ap.add_argument("--channel", required=True)
    ap.add_argument("--owner", default="")
    ap.add_argument("--acknowledged-by", default="")
    ap.add_argument("member", nargs="*", help="AGENT=path/to/its/latest/report.md (path may be empty)")
    args = ap.parse_args(argv)
    members = []
    for item in args.member:
        agent, _, path = item.partition("=")
        members.append((agent, path))
    sys.stdout.write(build(args.team, read_channel(Path(args.channel)), members,
                           owner=args.owner, acknowledged_by=args.acknowledged_by))
    return 0


if __name__ == "__main__":
    sys.exit(main())
