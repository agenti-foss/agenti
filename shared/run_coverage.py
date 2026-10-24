#!/usr/bin/env python3
"""run_coverage.py — does the engagement, as it stands now, still cover a live
run? Root runs this after every engagement or agent-scope change and stops the
runs that lost cover (audit run 1, F04; operator decision 2026-10-23: stop only
what lost cover, let a run the new record still covers finish).

A run has lost cover when:
  - its target is no longer inside the agent's ceiling (scope cut, an
    exclusion added, the agent's own scope narrowed), or
  - (domain runs) an exclusion now lies at or UNDER its target that was not
    in force when it started: the run's cached ceiling would never apply it
    (audit run 2). The start-time list is root's run-excluded marker; a
    missing one counts as "nothing was excluded", so the run is stopped, or
  - today is outside the engagement's window, or
  - it is an agent gated on an engagement capability (exploit) and that
    capability was switched off.
An edit that still covers the run (notes, a wider scope awaiting approval)
does not stop it. A file-analysis run has no target scope and is never stopped.

    run_coverage.py check --org-dir DIR --agent NAME --kind cidr|domain \\
                          --target-file FILE [--excluded-file FILE]
Exit 0 and print "covered", or exit 3 and print why not.

    run_coverage.py exclusions --org-dir DIR --agent NAME
Prints a domain agent's effective exclusions now, one per line (root writes
them to run-excluded at every start and resume).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engagement_context as ec  # noqa: E402

# Agents that may run only while the engagement enables a capability.
CAPABILITY_GATED = {"exploit": "exploit"}


def why_uncovered(org_dir: Path, agent: str, kind: str, target_text: str,
                  started_excluded: frozenset[str] = frozenset()) -> str:
    """'' while the run is covered, else a one-line reason."""
    if kind == "cidr":
        from scope_cidr import CIDRScope as Scope
    elif kind == "domain":
        from scope_domain import DomainScope as Scope
    else:
        return ""
    scope = Scope(agent)
    try:
        eng = ec.load_engagement(kind, org_dir=org_dir, agent=agent)
    except ec.EngagementError as e:
        return f"the engagement no longer authorizes it: {str(e).splitlines()[0]}"
    try:
        ec.assert_in_window(eng)
    except RuntimeError as e:
        return str(e).replace(" Refusing to run.", "")
    cap = CAPABILITY_GATED.get(agent)
    if cap and cap not in eng.enabled_capabilities:
        return f"the engagement no longer enables '{cap}'"
    try:
        ceiling = scope.ceiling_from_engagement(eng)
        scope.narrow(ceiling, target_text, required=False)
        if kind == "domain":
            from scope_domain import domain_in
            for ex in getattr(ceiling, "excluded", ()):
                if ex in started_excluded:
                    continue
                for t in scope.parse_targets(target_text) or list(ceiling):
                    if domain_in(ex, t):
                        return f"{ex} is now excluded, and it is part of its target {t}"
    except SystemExit as e:
        first = str(e.code).splitlines()[0].replace("REFUSING: ", "")
        return f"its target is no longer in scope: {first}"
    except Exception as e:
        return f"its target is no longer in scope: {e}"
    return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="run_coverage.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", allow_abbrev=False, help="does the engagement still cover this run?")
    c.add_argument("--org-dir", required=True)
    c.add_argument("--agent", required=True)
    c.add_argument("--kind", required=True)
    c.add_argument("--target-file", default="")
    c.add_argument("--excluded-file", default="",
                   help="root's run-excluded marker: the exclusions in force when the run started")
    x = sub.add_parser("exclusions", allow_abbrev=False, help="a domain agent's effective exclusions now, one per line")
    x.add_argument("--org-dir", required=True)
    x.add_argument("--agent", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "exclusions":
        from scope_domain import DomainScope
        try:
            eng = ec.load_engagement("domain", org_dir=Path(a.org_dir), agent=a.agent)
        except ec.EngagementError as e:
            print(f"the engagement cannot be read: {e}")
            return 1
        try:
            ceiling = DomainScope(a.agent).ceiling_from_engagement(eng)
        except SystemExit as e:
            print(e.code)
            return 1
        for ex in getattr(ceiling, "excluded", ()):
            print(ex)
        return 0
    text = _read(a.target_file)
    started = frozenset(line.strip() for line in _read(a.excluded_file).splitlines() if line.strip())
    reason = why_uncovered(Path(a.org_dir), a.agent, a.kind, text, started)
    print(reason or "covered")
    return 3 if reason else 0


def _read(path: str) -> str:
    p = Path(path) if path else None
    return p.read_text() if p and p.is_file() and not p.is_symlink() else ""


if __name__ == "__main__":
    sys.exit(main())
