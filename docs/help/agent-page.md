# The agent page

The page you see when you open one of your runs. Its title is the run's name,
with the kind of agent under it in italics; the pencil beside it renames the
run (display only). Its parts, from top to bottom:

## Console

A conversation, not a log:

- What the agent says appears as short messages. A long one is folded with
  **Show more**; the closing message of a finished run is its **Summary**, with a
  link to the full report.
- What the agent does in between is folded into one line, "Ran 6 steps". Open it
  to see each step, and open a step to see what it returned. Failed steps are
  counted in red. While a run is live the line reads "Working · …".
- What you or a teammate said to the agent appears as a message too.
- The live feed keeps checking that you may still see it: if you sign out, your
  session ends, or an admin's access to someone else's run is removed, it stops
  within half a minute and says why. You can have up to six live feeds open at
  once (one per tab); a seventh tab says so instead of opening.

- **Send** puts your message in the agent's queue. It arrives after the agent's
  next step. A message never interrupts a step that is running, so a scan is
  never left half-done.
- **Note** is saved in the run's record and its report. It never reaches the agent.
- **Attach** gives the run a file. A run that is going gets it after its current
  step; a finished run's file goes with your next run. See
  [Attaching files](attaching-files.md).
- Neither one can widen what the agent may do. The tool allow-list and the scope
  are enforced outside the conversation, where nothing you type can change them.
- The agent's narration is its own account of what it's doing. It is useful, but it
  is not a trace of how the agent actually reached its answer.

The buttons beside the message box:

| Button | What it does |
|---|---|
| Pause | Freezes the run where it is. Resume continues it. |
| Resume | Continues a paused run, or restarts a stopped one with the same conversation. |
| Interrupt | Stops the step in progress now and ends the run. A partial report is still written. |
| Stop | Ends the run once the step in progress finishes. A partial report is written. |
| Switch model | Changes the model at the next turn boundary. |

If the agent asks you a question, a yellow banner shows it. Answer with **Send**.
The agent waits for your answer for up to 24 hours, and the time it spends waiting does
not use up the run's time limit (that limit counts only the time the agent is working).
If nobody answers within 24 hours the run ends as incomplete, and its report names the
question that was left unanswered.
If the agent asks to use an extra program, **Allow for this run** applies to this
run only. Scope and safety checks still apply to every command.

## Report and marking a run complete

**Report** shows this run's report, and lets you open it full-page, save it as PDF or
download it as a Word file. When the run has finished, **Mark complete** moves it
to **Task History** on the dashboard, which lists every run you have completed.
This page is about one run only; there is no list of earlier runs here.

## Tools & permissions

Each tool and program is listed by name, with a short description of what it does.

- **Scope boundary** (for example `CIDRScope`) is the kind of target the agent works
  on. A target you give it can only narrow the engagement's authorized scope, never
  widen it.
- **Tools** are the actions the agent itself can take.
- **Programs it may run** is the agent's command-line allow-list. It can run these
  programs and no others, and every command is checked against the scope first.
  Each program has a reviewed list of options: an option may be given once, every
  value that names a machine is checked, a username or password option takes plain
  text (never a file), and an IPv6 address goes in brackets (`[2001:db8::5]:443`).
  The command runs exactly as checked, in an empty folder.
- **Always refused** lists patterns that are blocked even inside an allowed program,
  such as shell chaining or redirection.

The agent never gets a raw shell.

## Engagement

Your organisation's authorization record: the client, who authorized the work, the dates,
and the scope this agent may use. Every agent shares it. Admins edit and approve
it under **Settings → Engagement**.

## My preferences

Notes the agent reads at the start of each run you launch, for example how you like
reports laid out. They affect style only, never scope, tools or limits. Each user has
their own preferences, and an admin can view yours but not change them.

The agent may suggest something to remember. Nothing is saved unless you choose
**Add to my preferences**.

## Team chat

See [Teams](teams.md). On a team page, **Send** reaches every member after its next
step. A team member's page has a **Team** link back to the group chat.
