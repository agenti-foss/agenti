"""
scope_domain.py — the domain scope boundary.

A second implementation of the `ScopeBoundary` interface (shared/agent_contract.py),
alongside shared/scope_cidr.py — built for `research`, the non-network agent
CLAUDE.md §3f calls the sharp test for whether the scope interface is really
pluggable or just "CIDR with extra steps." `trafficmon` doesn't actually test
this: it uses CIDRScope too, same as enum. This module is what proves (or
would have disproved) the abstraction, by implementing it against domain
names instead of IP networks — a genuinely different containment rule
(hostname suffix matching on label boundaries, not subnet arithmetic) behind
the exact same four methods.

THE NARROWING RULE is the same shape as scope_cidr.py: the engagement's
`in_scope` is the CEILING — the domains the client authorized. A run-target
file narrows it for one run. Every requested domain must be the ceiling
itself or a subdomain of it; anything else refuses the run outright.

THE CONTAINMENT RULE is where domains genuinely differ from CIDR: "is `host`
inside `parent`?" means `host == parent or host ends with "." + parent` —
label-boundary suffix matching, NOT raw string suffix matching. Getting this
wrong is a classic bug class: a naive `host.endswith(parent)` check would let
"evil-example.com" match a scope of "example.com". This module exists partly
to make sure that distinction is enforced once, correctly, rather than
reimplemented (and possibly gotten wrong) by every web-touching agent.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlparse

# Lenient but not wide open: rejects empty strings, whitespace, bare labels
# with no dot, and leading/trailing hyphens. Does not try to distinguish "a
# real domain" from "an IP address typed here by mistake" — dotted-decimal
# text matches this pattern too, and that's fine: the containment rule below
# still behaves sanely on it (it just won't equal any real domain in scope),
# and rejecting it isn't a safety boundary the way the syntax check itself is.
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _normalize(d: str) -> str:
    return d.strip().lower().rstrip(".")


def _valid_domain(d: str) -> bool:
    return bool(d) and len(d) <= 253 and bool(_DOMAIN_RE.match(d))


def _domain_in(host: str, parent: str) -> bool:
    """Label-boundary containment: host == parent, or host is a subdomain of
    parent. NOT a raw string suffix check — see module docstring for why that
    distinction matters."""
    return host == parent or host.endswith("." + parent)


def domain_in(host: str, parent: str) -> bool:
    """Public wrapper around the label-boundary containment rule above, for
    reuse by other modules (network_policy.py, phase 3 of the
    generic-launcher arc) that need the exact same "is X a subdomain of Y"
    rule without reimplementing — and possibly getting subtly wrong a
    second time — the label-boundary distinction this module exists for.
    Normalizes both sides first, unlike the private `_domain_in` this wraps,
    which assumes its caller already did."""
    return _domain_in(_normalize(host), _normalize(parent))


class DomainCeiling(list):
    """The allowed domains, plus the `excluded` ones that are never in scope
    even under an allowed parent (engagement and per-agent out_of_scope). A
    list subclass, so every caller that treats a ceiling as a list of domains
    keeps working; contains() and narrow() also honour `excluded`."""

    def __init__(self, domains=(), excluded=()):
        super().__init__(domains)
        self.excluded: tuple[str, ...] = tuple(excluded)


def _excluded(host: str, scope) -> str | None:
    """The exclusion `host` falls under, or None."""
    for ex in getattr(scope, "excluded", ()):
        if _domain_in(host, ex):
            return ex
    return None


@dataclass(frozen=True)
class DomainScope:
    agent_name: str
    # The scope KIND this boundary implements — the key an agent uses to ask
    # the engagement record for its own view (engagement_context.
    # load_engagement) and the key agent_contract's manifest loader matches
    # tools against. A ClassVar, not a field: it is a property of the
    # implementation, never of an instance.
    kind: ClassVar[str] = "domain"

    # -- engagement -> ceiling -------------------------------------------
    def ceiling_from_engagement(self, engagement) -> list[str]:
        """The allowed domains, carrying the excluded ones (out_of_scope) with
        them. An exclusion that does not start with a domain refuses the run:
        an exclusion that cannot be honoured must not be ignored."""
        if not engagement.in_scope:
            sys.exit("REFUSING: in_scope is empty — nothing is authorized.")
        domains = []
        for entry in engagement.in_scope:
            token = _normalize(entry.split()[0])
            if not _valid_domain(token):
                sys.exit(f"REFUSING: in_scope entry does not look like a domain: {entry!r}")
            domains.append(token)
        excluded = []
        for entry in getattr(engagement, "out_of_scope", None) or []:
            if not entry.strip():
                continue
            token = _normalize(entry.split()[0])
            if not _valid_domain(token):
                sys.exit(f"REFUSING: out_of_scope entry does not start with a domain: {entry!r}\n"
                         f"Every exclusion must start with a domain, e.g. 'payroll.acme.example "
                         f"(production)'. Fix it: Settings → Engagement, or "
                         f"sudo agenti engagement set --help")
            excluded.append(token)
        return DomainCeiling(domains, excluded)

    # -- run-target -> narrowed scope ------------------------------------
    def parse_targets(self, text: str) -> list[str]:
        """Domains, one per line or comma/space separated. Blank lines and
        # comments ignored."""
        domains = []
        for token in re.split(r"[,\s]+", text.strip()):
            if not token or token.startswith("#"):
                continue
            d = _normalize(token)
            if not _valid_domain(d):
                sys.exit(f"REFUSING: '{token}' in run-target is not a valid domain")
            domains.append(d)
        return domains

    def narrow(self, ceiling: list[str], run_target_text: str,
              *, required: bool) -> list[str]:
        """Same shape as CIDRScope.narrow — see that module for the full
        rationale. `required=True` for research: like enum, it actively
        reaches out and touches external infrastructure, so (matching enum,
        not trafficmon) it must always be pointed at something explicit."""
        requested = self.parse_targets(run_target_text)
        if not requested:
            if required:
                sys.exit(
                    f"REFUSING: no target set for this run.\n"
                    f"  authorized scope: {', '.join(ceiling)}\n"
                    f"  set one with:     agenti {self.agent_name} start -t <domain>\n"
                    f"A target is always required — the agent never researches a "
                    f"whole engagement scope by default."
                )
            return ceiling
        for d in requested:
            ex = _excluded(d, ceiling)
            if ex:
                sys.exit(
                    f"REFUSING: target {d} is excluded from the engagement ({ex} is out of scope).\n"
                    f"Pick a target that is not excluded, or have an admin change the engagement."
                )
            if not any(_domain_in(d, c) for c in ceiling):
                sys.exit(
                    f"REFUSING: target {d} is outside the authorized engagement scope.\n"
                    f"  authorized : {', '.join(ceiling)}\n"
                    f"  requested  : {d}\n"
                    f"A target may only NARROW the engagement scope, never widen it. "
                    f"To research {d}, it must first be authorized in the engagement "
                    f"config."
                )
        return DomainCeiling(requested, getattr(ceiling, "excluded", ()))

    # -- the dev-mode fence -----------------------------------------------
    def enforce_lab_fence(self, scope: list[str], lab_domains: list[str]) -> None:
        for d in scope:
            if not any(_domain_in(d, lab) for lab in lab_domains):
                labs = ", ".join(lab_domains)
                sys.exit(
                    f"REFUSING: {d} is outside LAB_DOMAINS ({labs}).\n"
                    f"Dev mode cannot act on non-lab targets. Use the commercial "
                    f"profile for client work, or widen LAB_DOMAINS if this "
                    f"really is your lab."
                )

    # -- per-call validation ------------------------------------------------
    def _extract_host(self, target: str) -> str | None:
        """Accepts either a bare domain or a full URL — fetch_page passes a
        URL, run-target/engagement entries pass bare domains."""
        target = target.strip()
        if "://" in target:
            try:
                host = urlparse(target).hostname
            except ValueError:
                return None
            return _normalize(host) if host else None
        host = _normalize(target.split("/")[0].split(":")[0])
        return host or None

    def contains(self, target: str, scope: list[str]) -> tuple[bool, str]:
        host = self._extract_host(target)
        if host is None:
            return False, f"'{target}' is not a valid host or URL"
        if not scope:
            return False, "scope is empty — failing closed"
        ex = _excluded(host, scope)
        if ex:
            return False, f"{host} is excluded from the engagement ({ex} is out of scope)"
        if any(_domain_in(host, d) for d in scope):
            return True, "in scope"
        allowed = ", ".join(scope)
        return False, f"{host} is outside this run's scope ({allowed})"

    # -- presentation -------------------------------------------------------
    def describe(self, scope: list[str]) -> str:
        text = ", ".join(scope)
        excluded = getattr(scope, "excluded", ())
        return f"{text} (excluding {', '.join(excluded)})" if excluded else text
