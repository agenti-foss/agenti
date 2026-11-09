// slash.js — "/" commands in a message box, the way a Claude Code session
// takes them: type "/" and a list of what you may do opens above the box;
// type on to narrow it, arrows to move, Enter or Tab to pick, Escape to close.
// A command that takes a choice (/model) lists its choices the same way.
//
//   const slash = AgentiSlash.attach(input, {
//     commands: () => [{ name, args, about, run(arg), options?(typed) }],
//     onError: (text) => ...,
//   });
//   slash.handle(text)  -> true when text was a command (run or refused)
//
// Only what commands() returns is offered, so a command the caller may not
// use is never listed. Running one calls the same routes as the buttons;
// nothing here grants anything.
window.AgentiSlash = (() => {
  function attach(input, { commands, onError }) {
    const esc = Agenti.esc;
    const id = "slash-" + crypto.randomUUID();
    const menu = document.createElement("div");
    menu.className = "slash-menu";
    menu.id = id;
    menu.setAttribute("role", "listbox");
    menu.setAttribute("aria-label", "Commands");
    menu.hidden = true;
    input.parentElement.insertBefore(menu, input);
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-controls", id);
    input.setAttribute("aria-expanded", "false");

    let items = [];          // [{label, hint, pick()}]
    let active = 0;
    let request = 0;

    const find = (name) => commands().find((c) => c.name === name);

    function close() {
      menu.hidden = true;
      items = [];
      input.setAttribute("aria-expanded", "false");
      input.removeAttribute("aria-activedescendant");
    }
    function paint(title) {
      if (!items.length) { close(); return; }
      active = Math.min(active, items.length - 1);
      menu.innerHTML = (title ? `<div class="slash-title">${esc(title)}</div>` : "") + items.map((it, i) => `
        <div class="slash-item${i === active ? " active" : ""}" role="option" id="${id}-${i}" data-i="${i}" aria-selected="${i === active}">
          <span class="slash-label">${esc(it.label)}</span><span class="slash-hint">${esc(it.hint || "")}</span>
        </div>`).join("");
      menu.hidden = false;
      input.setAttribute("aria-expanded", "true");
      input.setAttribute("aria-activedescendant", `${id}-${active}`);
      const el = menu.querySelector(".slash-item.active");
      if (el) el.scrollIntoView({ block: "nearest" });
    }

    async function update() {
      const text = input.value;
      if (!text.startsWith("/")) { close(); return; }
      const space = text.indexOf(" ");
      const ask = ++request;
      if (space < 0) {
        // Still typing the command's name.
        const typed = text.slice(1).toLowerCase();
        items = commands().filter((c) => c.name.startsWith(typed)).map((c) => ({
          label: `/${c.name}${c.args ? " " + c.args : ""}`, hint: c.about,
          pick: () => {
            if (c.args || c.options) { input.value = `/${c.name} `; update(); }
            else { input.value = ""; close(); c.run(""); }
          },
        }));
        active = 0;
        paint();
        return;
      }
      const c = find(text.slice(1, space).toLowerCase());
      if (!c || !c.options) { close(); return; }
      const typed = text.slice(space + 1).trim().toLowerCase();
      let options = [];
      try { options = await c.options(); } catch (e) { options = []; }
      if (ask !== request) return;
      const match = options.filter((o) => o.value.toLowerCase().includes(typed));
      match.sort((a, b) => (b.value.toLowerCase() === typed) - (a.value.toLowerCase() === typed));
      items = match.map((o) => ({
        label: o.label || o.value, hint: o.hint,
        pick: () => { input.value = ""; close(); c.run(o.value); },
      }));
      active = 0;
      paint(c.optionsTitle);
    }

    input.addEventListener("input", update);
    input.addEventListener("focus", update);
    // Closed when focus really leaves the box (not when something hands it
    // straight back, as the model chip does).
    input.addEventListener("blur", () => setTimeout(() => { if (document.activeElement !== input) close(); }, 150));
    input.addEventListener("keydown", (e) => {
      if (menu.hidden || !items.length) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        active = (active + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
        paint(menu.querySelector(".slash-title") && menu.querySelector(".slash-title").textContent);
      } else if (e.key === "Tab" || (e.key === "Enter" && !e.isComposing)) {
        // With the list open, Enter takes the highlighted entry (an exact
        // match is always first). With it closed, Enter sends the line as typed.
        e.preventDefault();
        items[active].pick();
      } else if (e.key === "Escape") {
        e.preventDefault();
        close();
      }
    });
    menu.addEventListener("mousedown", (e) => {
      const el = e.target.closest(".slash-item");
      if (!el) return;
      e.preventDefault();
      items[Number(el.dataset.i)].pick();
    });

    // The form was submitted with a "/" line typed out in full.
    function handle(text) {
      if (!text.startsWith("/")) return false;
      const m = /^\/(\S+)\s*([\s\S]*)$/.exec(text.trim());
      const c = m && find(m[1].toLowerCase());
      if (!c) {
        onError(`There is no command ${m ? "/" + m[1] : text} here. Type / to see the ones you can use.`);
        return true;
      }
      input.value = "";
      close();
      c.run(m[2].trim());
      return true;
    }

    return { handle, open: (text) => { input.value = text; input.focus(); update(); } };
  }

  return { attach };
})();
