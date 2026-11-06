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
    capability was switched off, or
  - it started with payload capture permitted and that was switched off
    (root's run-payloads marker records the start-time setting).
While a change waits for a second admin, all of this is judged against the
STRICTER of the approved record and the change (engagement_context), so
what a change takes away applies at once, and the reason names the change.
An edit that still covers the run (notes, a wider scope awaiting approval)
does not stop it. A file-analysis run has no target scope and is never stopped.

    run_coverage.py check --org-dir DIR --agent NAME --kind cidr|domain \\
                          --target-file FILE [--excluded-file FILE] [--payloads-file FILE]
Exit 0 and print "covered", or exit 3 and print why not.

    run_coverage.py payloads --org-dir DIR --agent NAME --kind cidr|domain
Prints "on" or "off": may a run starting now capture payloads (root writes it
to run-payloads at every start and resume).

    run_coverage.py exclusions --org-dir DIR --agent NAME
Prints a domain agent's effective exclusions now, one per line (root writes
them to run-excluded at every start and resume).

    run_coverage.py precheck --org-dir DIR --agent NAME --kind cidr|domain|files
                             [--target TEXT] [--model NAME]
Before a start (and for --dry-run): would preflight and the harness accept
this target and model? Exit 0 and print "ok", or exit 3 and print each reason
on its own line. Saying no here only saves making a run slot that would be
refused a moment later; preflight and the harness still decide.
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
                  started_excluded: frozenset[str] = frozenset(), *, starting: bool = False,
                  started_payloads: str = "") -> str:
    """'' while the run is covered, else a one-line reason. While a change
    waits for a second admin, a run must fit BOTH versions; when only the
    change refuses it, the reason says so (who made it, that it awaits
    approval) rather than leaving the reader to guess."""
    why = _why_uncovered(org_dir, agent, kind, target_text, started_excluded,
                         starting=starting, started_payloads=started_payloads, with_pending=True)
    if why and "waiting for another admin" not in why and (org_dir / ec.PENDING_FILENAME).exists():
        try:
            pending = ec.read_pending(org_dir / ec.PENDING_FILENAME)
        except ec.EngagementError:
            return why
        if pending is not None and not _why_uncovered(
                org_dir, agent, kind, target_text, started_excluded, starting=starting,
                started_payloads=started_payloads, with_pending=False):
            return (f"the engagement change by {pending.get('author') or 'an admin'}, waiting for "
                    f"another admin's approval, does not cover it ({why}); until it is approved, "
                    f"a run must fit both versions")
    return why


def _why_uncovered(org_dir: Path, agent: str, kind: str, target_text: str,
                   started_excluded: frozenset[str], *, starting: bool, started_payloads: str,
                   with_pending: bool) -> str:
    """`starting`: a run about to start, so the reasons say "not" rather than
    "no longer", and an exclusion under the target is simply applied (it goes
    in run-excluded)."""
    longer = "not" if starting else "no longer"
    if kind == "cidr":
        from scope_cidr import CIDRScope as Scope
    elif kind == "domain":
        from scope_domain import DomainScope as Scope
    else:
        return ""
    scope = Scope(agent)
    try:
        eng = ec.load_engagement(kind, org_dir=org_dir, agent=agent, with_pending=with_pending)
    except ec.EngagementError as e:
        # A start shows the whole message: its last line is the command that fixes it.
        text = " ".join(ln.strip() for ln in str(e).splitlines() if ln.strip()) if starting else str(e).splitlines()[0]
        return f"the engagement {'does not authorize' if starting else 'no longer authorizes'} it: {text}"
    try:
        ec.assert_in_window(eng)
    except RuntimeError as e:
        return str(e).replace(" Refusing to run.", "")
    cap = CAPABILITY_GATED.get(agent)
    if cap and cap not in eng.enabled_capabilities:
        return f"the engagement {'does not enable' if starting else 'no longer enables'} '{cap}'"
    if started_payloads == "on" and not eng.capture_payloads:
        # Taking a permission away applies at once (operator decision
        # 2026-11-06): a capture that started with payloads permitted stops.
        return "the engagement no longer permits capturing payload contents"
    try:
        ceiling = scope.ceiling_from_engagement(eng)
        scope.narrow(ceiling, target_text, required=False)
        if kind == "domain" and not starting:
            from scope_domain import domain_in
            for ex in getattr(ceiling, "excluded", ()):
                if ex in started_excluded:
                    continue
                for t in scope.parse_targets(target_text) or list(ceiling):
                    if domain_in(ex, t):
                        return f"{ex} is now excluded, and it is part of its target {t}"
    except SystemExit as e:
        first = str(e.code).splitlines()[0].replace("REFUSING: ", "")
        return f"its target is {longer} in scope: {first}"
    except Exception as e:
        return f"its target is {longer} in scope: {e}"
    return ""


def why_refused(org_dir: Path, agent: str, kind: str, target_text: str, model: str,
                owner: str | None = None) -> list[str]:
    """Every reason a start of `agent` against `target_text` with `model`
    would be refused by preflight or the harness, in plain words."""
    reasons: list[str] = []
    try:
        record = ec.read_record(org_dir / ec.ORG_ENGAGEMENT_FILENAME)
    except Exception:
        record = None
    policy = ec.resolve_policy(record)
    if model and not ec.model_allowed(ec.canonical_model(model), policy):
        reasons.append(f"model '{model}' is not allowed here. Allowed: "
                       f"{', '.join(policy['allowed_models']) or '(none configured)'} "
                       f"(an admin changes this in Settings → Engagement)")
    elif model:
        import model_registry as mr
        provider = mr.provider_of(model)
        if provider.engine == "openai" and mr.price_for(model, policy.get("model_prices")) is None:
            reasons.append(f"no price configured for '{model}'; set USD per million input/output tokens: "
                           f"sudo agenti engagement set --model-price {model}=INPUT,OUTPUT")
        if owner is not None:
            if owner in (".", "..") or not owner or Path(owner).name != owner:
                reasons.append("invalid run owner; use an existing Agenti username with --owner")
            else:
                from agent_runtime import read_secrets
                tiers = [org_dir / "users" / owner / "secrets.env",
                         org_dir / agent / "secrets.env", org_dir / "secrets.env",
                         org_dir.parent / "shared" / "secrets.env"]
                try:
                    # systemd loads the files, not the launching shell's environment.
                    values = read_secrets(tiers)
                    flag = f" --provider {provider.name}"
                    if provider.key_required and not values.get(provider.key_env):
                        reasons.append(f"no {provider.label} API key for this run; set one with: "
                                       f"sudo /usr/lib/agenti/set-secret.sh{flag}")
                    if provider.base_url_env:
                        try:
                            mr.validate_base_url(values.get(provider.base_url_env, ""))
                            valid = True
                        except ValueError:
                            valid = False
                        if not valid:
                            reasons.append(f"no valid {provider.label} address; set one with: "
                                           f"sudo /usr/lib/agenti/set-secret.sh{flag} "
                                           "--base-url http://<host>:<port>/v1")
                except (OSError, SystemExit) as e:
                    reasons.append(f"could not load this run's provider settings: {e}")
    if kind not in ("cidr", "domain"):
        return reasons
    why = why_uncovered(org_dir, agent, kind, target_text, starting=True)
    if why:
        reasons.append(why.replace("its target is", "the target is", 1))
    if record is not None:
        status = ec.approval_status(record, ec.read_approval(org_dir / ec.APPROVAL_FILENAME))
        if not status["current"]:
            reasons.append(f"the engagement is not approved as it stands ({status['reason']}). "
                           f"An admin approves it in Settings → Engagement (Save and close), or: "
                           f"sudo agenti engagement approve")
    return reasons


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
    c.add_argument("--payloads-file", default="",
                   help="root's run-payloads marker: whether payload capture was permitted at start")
    x = sub.add_parser("exclusions", allow_abbrev=False, help="a domain agent's effective exclusions now, one per line")
    x.add_argument("--org-dir", required=True)
    x.add_argument("--agent", required=True)
    pl = sub.add_parser("payloads", allow_abbrev=False, help="may a run starting now capture payloads? on/off")
    pl.add_argument("--org-dir", required=True)
    pl.add_argument("--agent", required=True)
    pl.add_argument("--kind", required=True)
    pc = sub.add_parser("precheck", allow_abbrev=False, help="would a start with this target and model be accepted?")
    pc.add_argument("--org-dir", required=True)
    pc.add_argument("--agent", required=True)
    pc.add_argument("--kind", required=True)
    pc.add_argument("--target", default="")
    pc.add_argument("--model", default="")
    pc.add_argument("--owner", required=True, help="run owner whose provider keys take priority")
    a = ap.parse_args(argv)
    if a.cmd == "precheck":
        reasons = why_refused(Path(a.org_dir), a.agent, a.kind, a.target, a.model, a.owner)
        print("\n".join(reasons) if reasons else "ok")
        return 3 if reasons else 0
    if a.cmd == "payloads":
        try:
            eng = ec.load_engagement(a.kind, org_dir=Path(a.org_dir), agent=a.agent)
        except ec.EngagementError:
            print("off")      # the start itself is refused, and says why
            return 0
        print("on" if eng.capture_payloads else "off")
        return 0
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
    reason = why_uncovered(Path(a.org_dir), a.agent, a.kind, text, started,
                           started_payloads=_read(a.payloads_file).strip())
    print(reason or "covered")
    return 3 if reason else 0


def _read(path: str) -> str:
    p = Path(path) if path else None
    return p.read_text() if p and p.is_file() and not p.is_symlink() else ""


if __name__ == "__main__":
    sys.exit(main())
