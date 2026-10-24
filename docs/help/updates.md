# Checking for updates

*For admins.*

## The short version

- **Settings → Platform → Updates → Check for updates** tells you whether a newer
  Agenti has been released. It only reports. **Nothing is downloaded or installed.**
- It is **off by default**. Until you allow it, Agenti never contacts GitHub, and the
  button just shows you the command to allow it.
- To install an update, run on the host: `sudo apt update && sudo apt install --only-upgrade agenti`.

## Turning it on or off

On the host: `sudo agenti admin set-policy update-check on` (or `off`). It is a host
command, not a button, on purpose: the web interface can never change this setting.

## What is sent

One plain request to GitHub's public releases page when you click the button. No
installation id, hostname, version or account name is sent. GitHub sees the server's
IP address, like any web request.

## From a terminal

`sudo agenti admin update-check` (add `--json` for scripts).

## If it says it couldn't check

It names the reason: no release published yet, or GitHub unreachable. Check the
server's internet access and try again.
