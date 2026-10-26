# Agenti

Agentic security tooling for your own team. Agenti is a free, self-hosted tool
that lets one organisation's security team run AI agents for network
enumeration, OSINT and traffic analysis, on its own Kali Linux (or Debian 13 /
Ubuntu 24.04) machine. It is built on the Claude Agent SDK.

An administrator records and approves the engagement's scope. Every command an
agent wants to run is checked against that scope by the system, not by the AI
model, and every decision is logged. We describe Agenti as **auditable,
bounded, isolated and admin-authorised for real targets**. We do not call it
"safe": a tool like this is only as safe as the people configuring it.

## How a run works

1. An admin records the engagement (client, approved targets, dates, allowed
   models, spending limits) and approves it.
2. An operator starts an agent with a target and a model. The target can only
   narrow the approved scope.
3. The agent works through a fixed list of reviewed programs. Each command is
   checked against the scope before it runs, and the kernel fences the run's
   network to that scope as well.
4. The operator can steer it. Messages redirect effort; they never grant new
   permissions.
5. A report records every command, every operator message and every attached
   file (with its SHA-256).

## The agents

| Agent | What it does |
|---|---|
| `enum` | Network enumeration against an approved address range |
| `research` | Open-source intelligence against an approved domain |
| `trafficmon` | Passive packet capture, analysed and summarised |
| your own | Admins build recon and file-analysis agents in Settings; a built agent is configuration, not code |

Hash cracking (`agenti-cracker`) and approval-gated exploitation
(`agenti-exploit`) are separately licensed agents, not part of this repository.

## Install

Download the packages for your CPU from
[Releases](https://github.com/agenti-foss/agenti/releases), check them, and:

```
sudo apt update          # a fresh Kali's package lists are often out of date
sudo apt install ./agenti-runtime_<version>_<cpu>.deb ./agenti_<version>_all.deb
sudo agenti setup
```

Installing downloads one more file, Anthropic's Claude Code program, from PyPI,
checked against its pinned SHA-256. You need an Anthropic API key. Full guide:
[docs/install.md](docs/install.md). Checking a release's provenance:
[docs/packaging.md](docs/packaging.md).

## Documentation

- User help: [docs/help/](docs/help/) (also `agenti docs`, the GUI's Docs page
  and [agenti-foss.org](https://agenti-foss.org))
- Threat model: [docs/threat-model.md](docs/threat-model.md)
- How it is security-tested, and what the audits found:
  [docs/help/security-testing.md](docs/help/security-testing.md)
- Building an agent in code: [docs/contributing-agents.md](docs/contributing-agents.md)
- CI and packaging: [docs/ci.md](docs/ci.md), [docs/packaging.md](docs/packaging.md)

## Security

Please report vulnerabilities privately through this repository's
**Security → Report a vulnerability**, never in a public issue.

## Licence

The open core (web interface, command line, safety harness and the agents
above) is licensed under the GNU Affero General Public License v3.0
([LICENSE](LICENSE)). Contributions need the contributor agreement in
[CONTRIBUTING.md](CONTRIBUTING.md). The name and logo: [TRADEMARKS.md](TRADEMARKS.md).
