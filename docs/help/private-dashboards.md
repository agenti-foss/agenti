# Your dashboard is private

*For everyone who signs in to Agenti.*

## The short version

- **Only you can see the agents you launch.** Their live activity, Task
  History, reports and kept files (Outputs) all belong to you.
- **There is one organisation.** The header shows your name. Everyone you
  work with is in the same organisation; only your runs are yours.
- **Admins can look, but they can't act for you.** An admin may open your
  dashboard from **Settings → Users**. There they can stop a run, mark it
  complete, and download or delete kept files. They can never launch, send a
  message or note, pause, resume, or switch the model on your behalf.

## Who can open whose dashboard

| You are… | You can open the dashboard of… |
|---|---|
| an operator | nobody but yourself |
| an admin | any operator |
| anyone | **never** an admin's dashboard |

Only some rows in **Settings → Users** have a **View dashboard** button:
the users you are allowed to open. Clicking it opens **"\<name\>'s dashboard"**
in a window over the page. That window holds an exact copy of their landing
page: Active Agents, Task History and Outputs. Close it with the **×** in
its corner.

On a phone the button shows only the dashboard icon. The user's name is
in the first column of the same row.

## Running the same agent twice

Every time you start an agent it is its own run, completely separate from any
other run of that agent, yours or anyone else's. Nothing carries over from one
run to the next, and you can have as many going at once as you like (for example,
two scans of different hosts). Each run gets its own card on your dashboard.

Runs are kept apart by the operating system, not just by the app: a run can see
only its own working folder, and only its own processes, so even an agent that
misbehaved could not read another run's files, settings or messages. (This needs
systemd 257 or newer, which current Kali has; `sudo agenti verify` says
"each run of … has its own PID namespace" when it is in force.)

A finished run stays on your dashboard, waiting for you, until you mark it
complete. Then it moves to Task History.

**Every run has a name.** Type one in **Name this run** on Launch, or leave it
blank and it gets two random words, like *amber-falcon*. The card shows the
name, with the kind of agent under it in italics. Rename a run with the pencil
next to its name on the agent page (from a terminal: `agenti <agent> rename
"new name"`). A name is only a label: commands still find a run by its id.

**Telling running from finished.** A running card has a blue **Running** badge
whose dot pulses, and a light that moves along its top edge. A finished run's
badge says how it ended: a check for **Completed**, or **Stopped**, **Turn
limit** and so on.

**Sorting.** With two or more cards, **Sort** (above the cards) orders them:
newest launched first (the default), oldest first, the ones that need you first
(a question, or a finished run to review), by agent type, or by name. Your
choice is remembered in this browser.

**Getting back here.** The bar at the top of every page stays put as you
scroll, and slims down to give the page more room. **Dashboard** in it brings
you here from anywhere. When a page's own back link scrolls out of sight, a copy
of it appears in the bar.

## Teams

A team belongs to the person who starts it. Its members run as that
person's agents, and the team page appears only on their dashboard (and,
through the View dashboard button, to an admin allowed to open it). Someone else
can't see your team, even if they know its name.

The same holds for the agents themselves: an agent on your team can read and
post only to your team's chat. An agent running on its own can't see any team
chat at all, and no agent can see another team's.

## FAQ

**My dashboard is empty. Where did my agents go?**
A new account starts with nothing. Runs you launch appear under **Active Agents**, then **Task History** when they finish.

**Can an admin see another admin's dashboard?**
No. An admin can open only operators' dashboards.

**Can an admin message my agent or change its model?**
No. From your dashboard an admin may only stop a run, mark it complete, and
download or delete kept files.

**I renamed a user. What happens to their runs?**
They move with the user. Their dashboard, history, reports and teams follow
the new name. A rename is refused while one of their agents is running, so
stop it first.

## Messages you may see

| Message | What it means | What to do |
|---|---|---|
| *you may not open \<name\>'s dashboard — runs are private to the user who launched them…* | That user is not below you on the ladder above. | Ask an admin. |
| *you may not open \<name\>'s dashboard — an admin's dashboard is private to them* | Nobody can open an admin's dashboard. | Nothing to fix. This is by design. |
| *team '\<name\>' already exists — it's yours.* | You already have a team with that name. | Open it from your dashboard, or start it again. |
| *the team name '\<name\>' is taken — pick another.* | Someone else uses that name. | Choose a different name. |
| *'\<name\>' has no runs of '\<agent\>' yet.* | That user hasn't launched this agent. | Nothing to fix. |
| *No reports yet.* | This agent hasn't finished a run on your dashboard. | A report is written when a run ends: finished, stopped or interrupted. |
