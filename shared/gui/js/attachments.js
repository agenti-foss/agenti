// attachments.js — files an operator gives a run, in one place for every
// page: a picker (choose or drop files), an uploader with progress, the list
// of what a run has, and the composer's paperclip. Launch uses the picker
// before a run starts; the agent and team pages use the paperclip while one
// runs. The server enforces every rule (shared/run_files.py); the size check
// here only saves waiting for an upload it would refuse.
const AgentiFiles = (() => {
  const MAX = 100 * 1024 * 1024;
  const esc = (s) => Agenti.esc(s);

  function size(n) {
    if (n < 1024) return `${n} bytes`;
    const units = ["KB", "MB", "GB"];
    let v = n, u = -1;
    do { v /= 1024; u++; } while (v >= 1024 && u < units.length - 1);
    return `${v.toFixed(1).replace(/\.0$/, "")} ${units[u]}`;
  }

  function problem(file) {
    if (!file.size) return `${file.name} is empty.`;
    if (file.size > MAX) return `${file.name} is ${size(file.size)} — the limit is 100 MB a file.`;
    return "";
  }

  // POST one file's raw bytes to `path` (e.g. "agents/enum/files?copy=b").
  // XHR rather than fetch, for the progress events.
  function upload(path, file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${path}${path.includes("?") ? "&" : "?"}name=${encodeURIComponent(file.name)}`);
      xhr.setRequestHeader("X-Agenti-CSRF", Agenti.csrf());
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.setRequestHeader("Accept", "application/json");
      if (onProgress) xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
      xhr.onload = () => {
        let data = null;
        try { data = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) return resolve(data);
        if (xhr.status === 401) {
          location.href = "login.html?next=" + encodeURIComponent(location.pathname.split("/").pop() + location.search);
        }
        const d = data && (data.detail !== undefined ? data.detail : data.error);
        reject(new Error(typeof d === "string" ? d
          : xhr.status === 413 ? "that file is larger than the 100 MB limit."
          : `the upload failed (HTTP ${xhr.status}).`));
      };
      xhr.onerror = () => reject(new Error("could not reach the server — the upload did not finish."));
      xhr.send(file);
    });
  }

  // Several files, one at a time; `status(text)` is told the progress.
  async function uploadAll(path, files, status) {
    const out = [];
    for (const [i, f] of files.entries()) {
      const label = files.length > 1 ? `${f.name} (${i + 1} of ${files.length})` : f.name;
      const show = (p) => status && status(`Uploading ${label} — ${Math.round(p * 100)}%`);
      show(0);
      out.push(await upload(path, f, show));
    }
    return out;
  }

  // A drop zone plus the list of chosen files, mounted into `root`.
  // `onChange` (optional) is called whenever the chosen files change.
  // Returns { files(), clear() }.
  function picker(root, { onChange } = {}) {
    let chosen = [];
    root.classList.add("file-drop");
    root.innerHTML = `
      <input type="file" multiple hidden>
      <div class="file-drop-row">
        <button type="button" class="btn btn-sm">${Agenti.icon("paperclip", 16)}<span>Choose files</span></button>
        <span class="hint">or drop them here · up to 100 MB each</span>
      </div>
      <ul class="file-list" hidden></ul>
      <p class="hint file-problem" hidden></p>`;
    const input = root.querySelector("input");
    const list = root.querySelector("ul");
    const err = root.querySelector(".file-problem");
    function paint() {
      if (onChange) onChange();
      list.hidden = !chosen.length;
      list.innerHTML = chosen.map((f, i) => `<li class="file-row">
          ${Agenti.ti(f.name, size(f.size), { icon: "file" })}
          <button type="button" class="icon-btn" data-drop="${i}" aria-label="Remove ${esc(f.name)}" title="Remove">${Agenti.icon("close", 16)}</button>
        </li>`).join("");
      list.querySelectorAll("[data-drop]").forEach((b) => b.addEventListener("click", () => {
        chosen.splice(Number(b.dataset.drop), 1);
        paint();
      }));
    }
    function add(files) {
      const bad = [];
      for (const f of files) {
        const why = problem(f);
        if (why) bad.push(why);
        else if (!chosen.some((c) => c.name === f.name && c.size === f.size)) chosen.push(f);
      }
      err.hidden = !bad.length;
      err.textContent = bad.join(" ");
      paint();
    }
    root.querySelector("button").addEventListener("click", () => input.click());
    input.addEventListener("change", () => { add(Array.from(input.files)); input.value = ""; });
    root.addEventListener("dragover", (e) => { e.preventDefault(); root.classList.add("drag"); });
    root.addEventListener("dragleave", () => root.classList.remove("drag"));
    root.addEventListener("drop", (e) => {
      e.preventDefault();
      root.classList.remove("drag");
      add(Array.from((e.dataTransfer && e.dataTransfer.files) || []));
    });
    return { files: () => chosen.slice(), clear() { chosen = []; err.hidden = true; paint(); } };
  }

  // A team's listing is per member ({members: {agent: listing}}); one file
  // is shared by every member, so show each name once.
  function merge(listing) {
    if (!listing || !listing.members) return listing || {};
    const out = { run: [], pending: [] };
    for (const l of Object.values(listing.members)) {
      for (const k of ["run", "pending"]) {
        for (const f of l[k] || []) if (!out[k].some((g) => g.name === f.name)) out[k].push(f);
      }
    }
    return out;
  }

  // One run's files: those it has, and those waiting for its next run (which
  // `onRemove(name)`, if given, may take back). Returns how many there are.
  function render(el, listing, { onRemove } = {}) {
    const l = merge(listing);
    const run = l.run || [], pending = l.pending || [];
    if (!run.length && !pending.length) {
      el.innerHTML = `<p class="hint">No files yet. Use the paperclip to give the run one.</p>`;
      return 0;
    }
    const row = (f, waiting) => `<li class="file-row">
        ${Agenti.ti(f.name, `${size(f.bytes)} · ${f.text ? "text" : "binary"}`
          + (waiting ? " · waiting for the next run" : ""), { icon: "file" })}
        ${waiting && onRemove ? `<button type="button" class="icon-btn" data-remove="${esc(f.name)}"
           aria-label="Take back ${esc(f.name)}" title="Take it back">${Agenti.icon("close", 16)}</button>` : ""}
      </li>`;
    el.innerHTML = `<ul class="file-list">${run.map((f) => row(f, false)).join("")}`
      + `${pending.map((f) => row(f, true)).join("")}</ul>`;
    el.querySelectorAll("[data-remove]").forEach((b) => b.addEventListener("click", () => onRemove(b.dataset.remove)));
    return run.length + pending.length;
  }

  // The composer's paperclip: choose files, upload them to path(), report
  // through say(kind, text), then call done().
  function wireAttachButton(button, { path, say, done }) {
    const input = document.createElement("input");
    input.type = "file"; input.multiple = true; input.hidden = true;
    button.after(input);
    button.addEventListener("click", () => input.click());
    input.addEventListener("change", async () => {
      const files = Array.from(input.files);
      input.value = "";
      const bad = files.map(problem).filter(Boolean);
      if (bad.length) { say("err", bad.join(" ")); return; }
      if (!files.length) return;
      button.disabled = true;
      try {
        const results = await uploadAll(path(), files, (t) => say("info", t));
        const live = results.some((r) => r && r.live);
        say("ok", files.length === 1
          ? `Attached ${results[0].name}. ${live ? "The agent sees it after the step it is on." : "It goes with the next run."}`
          : `Attached ${files.length} files. ${live ? "The agent sees it after the step it is on." : "They go with the next run."}`);
        if (done) done(results);
      } catch (e) {
        say("err", Agenti.errorText(e));
      } finally {
        button.disabled = false;
      }
    });
  }

  return { MAX, size, upload, uploadAll, picker, merge, render, wireAttachButton };
})();
