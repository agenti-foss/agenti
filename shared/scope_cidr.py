"""
scope_cidr.py — the CIDR scope boundary.

One implementation of the pluggable scope interface `agent_runtime.py`
expects (see CLAUDE.md §3f: "scope is pluggable, but never optional"). Every
network-facing agent (enum, trafficmon, ...) has authorization expressed as a
set of IP/CIDR ranges, so that logic lives here rather than in the generic
harness — a future research agent's scope might be a domain allow-list, a log
agent's might be a set of source hostnames, and neither belongs in this file
or depends on it. The harness only ever calls the small interface below.

THE NARROWING RULE, enforced identically for every agent that uses this
module: the engagement's `in_scope` MINUS its `out_of_scope` is the CEILING —
what the client authorized. A run-target file narrows it for one run. Every
requested network must sit INSIDE the ceiling; anything else refuses the run
outright, so a run can only ever shrink the blast radius, never grow it.

Exclusions are subtracted here, once, so every later check (narrow, contains,
the run_scan validator) inherits them: an excluded host inside an authorized
range is simply not part of any ceiling network. Before 2026-10-22 the list
was shown to the model and never enforced (audit run 1, F05).
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from typing import ClassVar

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def network(text: str) -> IPNetwork:
    """Parse one IP/CIDR. An IPv4-mapped IPv6 spelling (::ffff:10.0.0.5) is the
    same host as 10.0.0.5, so it becomes that IPv4 network: two spellings of
    one host must never be two unrelated networks (an exclusion written one
    way would silently miss the other; audit run 2)."""
    net = ipaddress.ip_network(text, strict=False)
    if net.version == 6 and net.prefixlen >= 96 and net.subnet_of(_MAPPED):
        return ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    return net


def _within(net: IPNetwork, outer: IPNetwork) -> bool:
    """`net.subnet_of(outer)` across IP versions: an IPv6 target is never
    inside an IPv4 network (subnet_of raises TypeError instead of saying so)."""
    return net.version == outer.version and net.subnet_of(outer)


def subtract(allowed: list[IPNetwork], excluded: list[IPNetwork]) -> list[IPNetwork]:
    """`allowed` minus every network in `excluded`, as the smallest list of
    networks that covers exactly what is left. An exclusion outside every
    allowed network changes nothing; one that covers an allowed network
    removes it entirely."""
    result = list(allowed)
    for ex in excluded:
        nxt: list[IPNetwork] = []
        for net in result:
            if net.version != ex.version or not net.overlaps(ex):
                nxt.append(net)
            elif _within(net, ex):
                continue
            else:
                nxt.extend(net.address_exclude(ex))
        result = nxt
    # collapse_addresses refuses a mixed list, so tidy each IP version alone.
    return [n for v in (4, 6)
            for n in ipaddress.collapse_addresses(x for x in result if x.version == v)]


@dataclass(frozen=True)
class CIDRScope:
    """A CIDR-boundaried scope.

    `agent_name` is only used in refusal messages, so they name the right
    CLI verb ("agenti enum start -t ..." vs "agenti trafficmon start -t ...").
    """

    agent_name: str
    # The scope KIND this boundary implements — the key an agent uses to ask
    # the engagement record for its own view (engagement_context.
    # load_engagement) and the key agent_contract's manifest loader matches
    # tools against. A ClassVar, not a field: it is a property of the
    # implementation, never of an instance.
    kind: ClassVar[str] = "cidr"

    # -- engagement -> ceiling -------------------------------------------
    def ceiling_from_engagement(self, engagement) -> list[IPNetwork]:
        """Parse `engagement.in_scope` into networks and subtract every
        `engagement.out_of_scope` network. Each entry starts with a CIDR,
        optionally followed by a human label, e.g.
        '10.0.0.0/24 (internal server VLAN)' — the leading token is parsed,
        the rest is for humans. An exclusion that cannot be parsed refuses the
        run: an exclusion that cannot be honoured must not be ignored."""
        if not engagement.in_scope:
            sys.exit("REFUSING: in_scope is empty — nothing is authorized.")
        try:
            allowed = [network(entry.split()[0]) for entry in engagement.in_scope]
        except ValueError as e:
            sys.exit(f"REFUSING: malformed in_scope entry: {e}")
        try:
            excluded = [network(entry.split()[0])
                        for entry in getattr(engagement, "out_of_scope", None) or []
                        if entry.strip()]
        except ValueError as e:
            sys.exit(f"REFUSING: malformed out_of_scope entry: {e}\n"
                     f"Every exclusion must start with an IP or CIDR, e.g. "
                     f"'10.0.5.0/24 (payroll)'. Fix it: Settings → Engagement, or "
                     f"sudo agenti engagement set --help")
        ceiling = subtract(allowed, excluded)
        if not ceiling:
            sys.exit("REFUSING: the out_of_scope list excludes everything in_scope "
                     "authorizes — nothing is left to act on.")
        return ceiling

    # -- run-target -> narrowed scope ------------------------------------
    def parse_targets(self, text: str) -> list[IPNetwork]:
        """IPs/CIDRs, one per line or comma/space separated. Blank lines and
        # comments ignored."""
        nets = []
        for token in re.split(r"[,\s]+", text.strip()):
            if not token or token.startswith("#"):
                continue
            if "%" in token:
                sys.exit(f"REFUSING: '{token}' in run-target carries an IPv6 zone id; give the plain address")
            try:
                nets.append(network(token))
            except ValueError as e:
                sys.exit(f"REFUSING: '{token}' in run-target is not a valid IP/CIDR ({e})")
        return nets

    def narrow(self, ceiling: list[IPNetwork], run_target_text: str,
              *, required: bool) -> list[IPNetwork]:
        """Apply the narrowing rule to a run-target file's contents.

        `required=True` (an active scanner must always be pointed at
        something explicit, e.g. enum) refuses an empty/missing run-target.
        `required=False` (a passive collector can legitimately observe the
        whole engagement scope by default, e.g. trafficmon) falls back to the
        ceiling itself when nothing was set.
        """
        requested = self.parse_targets(run_target_text)
        if not requested:
            if required:
                sys.exit(
                    f"REFUSING: no target set for this run.\n"
                    f"  authorized scope: {', '.join(str(c) for c in ceiling)}\n"
                    f"  set one with:     agenti {self.agent_name} start -t <ip-or-cidr>\n"
                    f"A target is always required — the agent never scans a whole "
                    f"engagement scope by default."
                )
            return ceiling
        for net in requested:
            if not any(_within(net, c) for c in ceiling):
                sys.exit(
                    f"REFUSING: target {net} is outside the authorized engagement scope.\n"
                    f"  authorized : {', '.join(str(c) for c in ceiling)}\n"
                    f"  requested  : {net}\n"
                    f"A target may only NARROW the engagement scope, never widen it, and "
                    f"never cover an excluded address. To scan {net}, it must first be "
                    f"authorized (and not excluded) in the engagement."
                )
        return requested

    # -- the dev-mode fence -----------------------------------------------
    def enforce_lab_fence(self, scope: list[IPNetwork], lab_networks: list[IPNetwork]) -> None:
        """Dev mode's structural fence: every network in `scope` must sit
        inside `lab_networks`, whatever the loaded engagement config claims.
        Two independent things must agree before dev mode runs anything: it
        loads a SEPARATE lab engagement file, AND every network in that file
        must be a subset of `lab_networks` — so a client engagement config
        cannot be scanned in dev mode even if pointed at deliberately."""
        for net in scope:
            if not any(_within(net, lab) for lab in lab_networks):
                labs = ", ".join(str(n) for n in lab_networks)
                sys.exit(
                    f"REFUSING: {net} is outside LAB_NETWORKS ({labs}).\n"
                    f"Dev mode cannot act on non-lab targets. Use the commercial "
                    f"profile for client work, or widen LAB_NETWORKS if this "
                    f"really is your lab."
                )

    # -- per-call validation (used by a tool's own validator, not just at
    #    startup) -----------------------------------------------------------
    def contains(self, target: str, scope: list[IPNetwork]) -> tuple[bool, str]:
        """Is `target` (a single IP/CIDR string) inside `scope`? Fails closed
        on an empty scope or an unparseable target."""
        if "%" in target or any(ord(c) < 33 for c in target):
            # An IPv6 zone id ("fe80::1%<anything>") is accepted by ipaddress
            # and carries arbitrary text, newlines included (audit run 1, F22).
            return False, "a target may not carry a zone id or control characters"
        try:
            net = network(target)
        except ValueError as e:
            return False, f"'{target}' is not a valid IP/CIDR ({e})"
        if not scope:
            return False, "scope is empty — failing closed"
        if any(_within(net, s) for s in scope):
            return True, "in scope"
        allowed = ", ".join(str(s) for s in scope)
        return False, f"{target} is outside this run's scope ({allowed})"

    # -- presentation -------------------------------------------------------
    def describe(self, scope: list[IPNetwork]) -> str:
        return ", ".join(str(n) for n in scope)


def backstop_networks(org_dir, agent: str, target_text: str, *, required: bool) -> list[IPNetwork]:
    """The networks the kernel lets this run reach (audit run 1, fix 1b): the
    engagement's ceiling for `agent` (agent scope and exclusions applied)
    narrowed by the run's target — the same functions the runner itself uses,
    so the fence and the in-process checks can never disagree. Exits with the
    runner's own refusal when the target is not allowed."""
    from pathlib import Path
    import engagement_context as ec
    scope = CIDRScope(agent)
    try:
        eng = ec.load_engagement(scope.kind, org_dir=Path(org_dir), agent=agent)
    except ec.EngagementError as e:
        sys.exit(f"REFUSING: {e}")
    return scope.narrow(scope.ceiling_from_engagement(eng), target_text, required=required)


if __name__ == "__main__":
    # scope_cidr.py backstop --org-dir DIR --agent NAME --target-file FILE [--optional]
    # Prints one network per line. Run by root (the CLI) before a start/resume.
    import argparse
    ap = argparse.ArgumentParser(allow_abbrev=False, prog="scope_cidr.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backstop", allow_abbrev=False, help="the networks a run's kernel fence allows")
    b.add_argument("--org-dir", required=True)
    b.add_argument("--agent", required=True)
    b.add_argument("--target-file", default="")
    b.add_argument("--optional", action="store_true",
                   help="no target means the whole ceiling (a passive collector like trafficmon)")
    a = ap.parse_args()
    from pathlib import Path as _P
    text = _P(a.target_file).read_text() if a.target_file and _P(a.target_file).exists() else ""
    for net in backstop_networks(a.org_dir, a.agent, text, required=not a.optional):
        print(net)
