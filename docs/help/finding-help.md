# Finding help

*For everyone who uses Agenti.*

## The short version

In Agenti, open the menu at the top right and choose **Docs**. Every help page is listed
with a one-line summary. Type in the search bar to find the page, and the
section, that mentions what you are looking for.

## Searching

- Results appear as you type, from the second letter.
- A section matches only when it contains **every** word you typed. Add a word
  to narrow the results; remove one to widen them.
- Part of a word is enough: `pass` finds both *password* and *passkey*.
- Opening a result takes you straight to that section with your words
  highlighted. **Clear** removes the highlighting.
- On the Docs page, press `/` to jump to the search bar, **Enter** to open the
  first result, the arrow keys to move between results, and **Esc** to clear
  the search.

## From the command line

The same pages and the same search work on the Agenti host. No root is needed.

- `agenti docs` lists every page, with its summary.
- `agenti docs signing-in` prints one page.
- `agenti docs search passkey` searches every page.

Add `--json` to any of them for output a script can read.
