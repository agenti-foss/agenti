# Sending output to another agent

*For anyone who runs agents.*

## The short version

- Any run can hand its results to a different agent. Click **Send output to
  another agent** on an agent's page, on a report, or on a row in Task History.
- You tick what to send, pick the agent that should get it, and choose how to
  start: **Open Launch** or **Start now**.
- What you send arrives as **files attached to your next run** of that agent.
  The agent reads them with its normal file tools. It gets no extra access from
  them: a file is information, nothing more.

## What you can send

| Kind | What it is |
|---|---|
| **Reports** | The run's written report. The newest one is ticked for you. |
| **Saved outputs** | The raw results the agent's tools saved (scan output, a packet capture's decoded text, pages it fetched). |
| **Files attached to this run** | Files you gave the run when you started it. |

Tick as many as you like. Each file can be up to 100 MB, and a run holds at most
50 files and 500 MB, the same as any other attachment.

## Choosing how to start

| Button | What happens |
|---|---|
| **Open Launch** | The items are attached, Launch opens with the agent chosen and the note filled in, and you pick the model, add a target if it needs one, and press **Run**. |
| **Start now** | A small window asks for a note, a model and the limits, then starts the run straight away. |

**Start now** fills in what the sending run used: the same model, and the same
turn, budget and time limits (held to the new agent's own ceilings if they are
lower). You can change any of them. The note starts as *"Complete your task
with this output from …"*; edit it freely. The same note is the default in
Launch.

An agent that works against a **target** (a network address or a domain) needs
one. When the agent you are sending from takes the **same kind of target** — for
example Network enumeration to the exploit agent, both network addresses —
**Start now** uses the sending run's own target. It appears in the window so you
can narrow it first (a whole subnet down to one host, say); the engagement still
decides what is in scope, exactly as for any launch.

When the two take different kinds (a domain-based agent to a network one),
**Start now** is switched off with a note saying why. Use **Open Launch**, where
you pick the target.

## Good to know

- **It is yours.** Only the person who ran something can send its output.
  An admin looking at your dashboard can't send it on your behalf.
- **Nothing is lost if you change your mind.** The files wait with your next run
  of that agent. In Launch they appear under *Already waiting for this run*,
  where you can take any of them back.
- **If that agent is already running**, the files join the run going now and it
  is told, the same as attaching a file by hand.
- **The record travels with it.** Each file lists who sent it and from which
  agent, and its SHA-256, in the receiving run's report.
- **Files are deleted with the run** after 30 days, like every attachment.

## From a terminal

```
sudo agenti <agent> send-list                       # what this run could send
sudo agenti <agent> send --to <other-agent> \
     --item report:<name> --item output:<name> --item file:<name>
```

## Messages you may see

| Message | What it means |
|---|---|
| *This run has nothing to send yet.* | It has no report, saved output or attached file. Run it first. |
| *This agent needs a target, so use Open Launch.* | The run you are sending from has no target to carry over. |
| *… takes a network address, which … target (…) is not.* | The two agents take different kinds of target, so there is nothing to carry over. Use Open Launch. |
| *nothing was sent …* | Every chosen item failed. The reasons are listed (a file removed since, or over the size limit). |
| *The files are attached and will go with your next run …* | The files were sent but the run could not start (for example, it is already running). Start it from Launch. |
| *bad item …* | A name that isn't a plain file name was given on the command line. |
