# Building your own agent

*For global admins (Settings → Agents).*

## The short version

- **Settings → Agents → Build an agent** creates a new agent in four
  steps: basics, programs, instructions, review. No code is involved.
- **It's ready straight away.** Operators see it on their
  Launch page.
- **You choose a kind** on the first step:
  - **Network recon** does what Network enumeration does: it runs reviewed
    command-line programs against a target, checked on every command against
    the engagement's scope. It can only run the programs you tick, and it can
    never exploit anything: the denied patterns and the scope check are fixed.
  - **File analysis** analyses files an operator attaches, such as a packet
    capture, with `tshark`, `capinfos` and `suricata` in a sandbox. It has no target, no
    network and needs no engagement. See **Analysing a file**.
  The kind is fixed once the agent is built.
- **Only global admins** can build or remove agents. Both actions ask for your
  password and a fresh 2FA code (or a passkey).

## The four steps

1. **Basics.**
   - **Kind:** Network recon or File analysis.
   - **Name:** what people see, e.g. *Web server check*.
   - **Short name:** filled in from the name as you type, e.g.
     `web-server-check`. It's used in commands and links and can't be changed
     later.
   - **What it does:** one sentence.
2. **Programs.** Tick the programs it may run. Search by name or purpose. A
   program that isn't installed on the server is greyed out and shows the
   `sudo apt install …` command. Only reviewed programs are listed. For network
   recon that is the baseline recon set and the program catalog (see below). For
   file analysis it is the short list a developer has written option rules for
   (`tshark`, `capinfos`, `suricata`); the catalog doesn't apply to it.
3. **Instructions.** This is the agent's *system prompt*: what it's for, the
   steps, what to produce, and what it must not do. A template is filled in
   from your earlier answers. Replace the line `<describe the job, step by
   step>` with the real steps.
4. **Review.** Check the summary, then press **Build agent** and confirm with
   your password and 2FA code.

## What a built agent can and can't do

| It can | It can't |
|---|---|
| Run the programs you ticked, one command at a time, against a target inside the scope | Run any other program, a shell, or an interpreter |
| Save raw output and read it back | Chain commands, redirect output or substitute commands (always refused) |
| Ask the operator a question, message a team | Widen its own scope, programs or limits |

Scope, approval and the model/caps limits come from the organisation's
engagement and policy, exactly as for Network enumeration. Nothing typed into
the builder can change them.

## Changing a built agent

- **Name, description, programs:** press **Edit** on its card. The wizard opens
  filled in; the short name is fixed. It skips the instructions step. A run
  already going keeps what it started with; the next run uses the changes.
- **Instructions:** edit them in the **Agent control centre** further down the
  same page. Every edit is kept and can be reverted.

## Removing a built agent

Press **Remove** on its card. You'll be shown what will be deleted, then asked
to type `DELETE` and confirm with your password and 2FA code.

- Removal is **permanent**. It deletes the agent's runs, reports and history in
  everywhere.
- **Kept files (Outputs) are not touched.**
- You can't remove an agent while it is running anywhere, or while a team still
  lists it as a member. The message tells you which runs or teams.
- Hand-built agents (OSINT research, Traffic monitor) have no Remove button.
  They're retired from a terminal.

## The program catalog

The list of programs comes from the **program catalog**, which an admin keeps
in **Controls → Edit this agent's tool allow-list** (the same catalog serves
every agent).

- **Add a program:** press **Add a program**. The server checks, as you type,
  that it is installed and allowed. Shells, interpreters, privilege and system
  tools (bash, python, sudo, find, rm, ssh, sqlite3, git …) can **never** be added,
  under any name: a version or variant of one (python3.14, vim.basic, nc.openbsd)
  is refused too, and so is a name that is really a link to one. A program
  can only be added if Agenti has **reviewed rules** for it: a list of the
  options it may be given (see below). You can also add blocked-argument
  patterns (regular expressions) as an extra net.

### Every command is checked option by option

A recon agent can't hand a program just anything. For each program Agenti keeps
a reviewed list of the options it may use; any other option is refused by name,
and the refusal lists what is allowed. Every address a command names must be a
plain IP address or range (`192.0.2.5`, `192.0.2.0/24`) or a web address whose
host is one (`http://192.0.2.5:8080/`), inside the engagement's scope and not on
its **out of scope** list. Host names, ranges like `192.0.2.1-20`, proxies,
target-list files and anything that follows redirects are refused, because they
could reach a machine the scope check never saw. The command that was checked
is exactly the command that runs.

Underneath that, Linux itself fences every run of an IP-scoped agent (enum,
exploit, trafficmon): the run can only exchange traffic with its approved
addresses and this machine, whatever any program in it does. The agent reaches
Anthropic through a small local relay, **agenti-relay**, that forwards to the
Anthropic API and nowhere else. It starts with the first such run.
- **Edit or remove:** only programs an admin added. A removal is refused while
  an agent still has the program switched on. Every change is kept in history.
- **Not installed?** Anyone can file a request on the Launch page ("A
  command-line program installed on the server"). Admins see it under
  Settings → Platform with the install command to run at the server. The
  website never installs software.

## From a terminal

```
sudo agenti admin agent-build tools               # the programs on offer
sudo agenti admin agent-build check  < spec.json  # validate without building
sudo agenti admin agent-build create < spec.json  # build it
sudo agenti admin agent-build preview <name>      # what removing would delete
sudo agenti admin agent-build remove  <name>      # asks you to type the name
```

`spec.json` looks like:

```json
{"kind": "recon", "name": "web-server-check", "title": "Web server check",
 "description": "Looks at a web server's headers and open ports.",
 "programs": ["nmap", "curl", "whatweb"],
 "system_prompt": "You are Web server check. ..."}
```

For a file-analysis agent use `"kind": "analysis"` and `"programs": ["tshark",
"capinfos", "suricata"]`; leave `"kind"` out and it is a recon agent.

## Messages you may see

| Message | What it means |
|---|---|
| *An agent called "x" already exists* | Pick another short name. |
| *'x' is reserved* | The CLI or web address already uses that word. Pick another. |
| *'x' is not a program a built agent may run* | It isn't in the baseline list or the catalog. An admin can add it to the catalog if it isn't blocked. |
| *Agenti has no reviewed argument rules for 'x'* | Agenti can only offer a recon program whose options have been reviewed. Ask for it by opening an issue; a developer adds its rules in `shared/recon_programs.py`. |
| *option '-x' is not allowed for <program>* | The agent tried an option outside that program's reviewed list. The message lists the allowed ones; the agent usually corrects itself. |
| *target 'name' is not a literal IP or CIDR* | Commands must name addresses, not host names or ranges, so the scope check sees exactly what the program will contact. |
| *'x' is not a program a file-analysis agent may run* | File analysis only offers programs with reviewed option rules. A developer adds one in `shared/analysis_programs.py`. |
| *its kind cannot be changed* | A recon agent can't become a file-analysis agent or the reverse. Build a new one. |
| *'x' is not installed on this server* | Run the `sudo apt install x` command shown, or leave it out. |
| *Can't remove it yet: it is running in …* | Stop those runs first. |
| *…these teams list it as a member* | Remove it from those teams first. |
| *'enum' was not built in Settings → Agents* | Hand-built agents can't be removed here. |
| *…'s program settings cannot be applied* (a run refuses to start) | The agent's tool allow-list or the program catalog could not be read, so the run stops rather than ignore an admin's changes. An admin opens **Controls → Edit this agent's tool allow-list** and saves it again. If it says the catalog is missing, reinstall: `sudo apt install --reinstall agenti`. |

## Writing an agent in code

If you need something a program list can't express (a different scope kind, a
custom tool, a protocol client), write a hand-built agent. `agenti new <name>`
scaffolds one; see `docs/contributing-agents.md`.
