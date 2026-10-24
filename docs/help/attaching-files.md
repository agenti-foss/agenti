# Attaching files

You can give an agent, or every member of a team, a file to work with: a client
brief, an asset list, a log, a packet capture.

## How to attach

- **Before a run:** on **Launch**, use **Choose files** (or drop files on the
  box), then start the run. The files go with that run.
- **During a run:** use the paperclip (**Attach**) beside the message box on the
  agent's page or the team's page. The agent gets the file after the step it is
  on and is told about it.
- **After a run has ended:** the paperclip still works. The file waits for your
  next run of that agent.

A team's file goes to every member. It is stored once, however many members
there are.

## What the agent can do with it

The agent can list the files on its run and read text files a piece at a time,
by line range or by searching. Binary files, such as a packet capture, are listed
but cannot be opened yet. A tool to analyse captures is the next step.

A file is information, never an instruction. Nothing in a file can widen the
agent's scope or the programs it may run: those are enforced outside the
conversation.

## Limits

| | |
|---|---|
| One file | 100 MB |
| One run | 500 MB, and 50 files |
| Kept for | 30 days, then deleted with the run's other working data |

Every report lists the files the run had, with each file's SHA-256, so you can
show later exactly which file was analysed.

## If something looks wrong

| You see | What it means | What to do |
|---|---|---|
| *that file is larger than the 100 MB limit* | The file is too big. | Split or trim it first (for a capture: `editcap -c` or a filter). |
| *that would bring this run's files to …* | The run's files would pass 500 MB. | Take back a waiting file, or start a fresh run. |
| *the data folder is nearly full* | Less than 1 GB would be left where Agenti keeps its data (the vault, if it is on). | Remove old runs or kept outputs. |
| *Already waiting for this run* on Launch | Files from an earlier attempt that did not start. | They will go with this run. Remove any you don't want. |
| A file shows **binary** | The agent can see it but not open it. | Expected for captures, archives and images. |
