"""
scope_files.py — the scope boundary for a file-analysis agent: the files
attached to THIS run, and nothing else.

A network agent's boundary is a list of addresses and a domain agent's is a
list of hostnames; both come from the engagement. A file-analysis agent has
neither. It touches no network and no client asset, so there is no ceiling to
narrow. Its whole world is the run's attached files (shared/run_files.py),
which only an operator can add: the agent can read them and cannot create,
rename or widen them.

This implements the same small interface as scope_cidr.CIDRScope (the
harness only ever calls these four methods), so AgentContract treats it like
any other boundary:

  * ceiling_from_engagement() — there is no engagement for this kind; it
    returns an empty ceiling and the runner never calls it;
  * narrow() — REFUSES a target. Nobody passes `-t` to an agent that has no
    network, and silently ignoring one would hide a mistake;
  * contains(name, attached) — is this one of the run's attached files;
  * describe() — how the run's scope reads in a report.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class FilesScope:
    """`agent_name` is only used in refusal messages."""

    agent_name: str
    kind: ClassVar[str] = "files"

    def ceiling_from_engagement(self, engagement) -> list[str]:
        return []

    def narrow(self, ceiling, run_target_text: str, *, required: bool) -> list[str]:
        if run_target_text and run_target_text.strip():
            sys.exit(
                f"REFUSING: '{self.agent_name}' analyses attached files and takes no target.\n"
                f"  start it without -t:   agenti {self.agent_name} start --model <model>\n"
                f"  give it files with:    agenti {self.agent_name} attach <file>")
        return []

    def contains(self, target: str, scope) -> tuple[bool, str]:
        """`scope` is the run's attached file names."""
        if target in set(scope or ()):
            return True, "attached to this run"
        return False, (f"'{target}' is not a file attached to this run "
                       f"(attached: {', '.join(sorted(scope or ())) or 'none'})")

    def describe(self, scope=None) -> str:
        if scope:
            return f"{len(scope)} attached file(s): {', '.join(sorted(scope))}"
        return "the files attached to this run"
