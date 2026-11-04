// One model picker for a solo run and each member of a mixed-provider team.
window.AgentiModels = {
  mount(host, { agent = "", remembered = "" } = {}) {
    const esc = Agenti.esc;
    const id = "models-" + crypto.randomUUID();
    host.innerHTML = `<div class="field"><label for="${id}-provider">Provider</label>
      <select id="${id}-provider"><option value="anthropic">Claude (Anthropic)</option>
      <option value="openai">ChatGPT (OpenAI)</option><option value="local">Self-hosted</option></select></div>
      <div class="field"><label for="${id}">Model</label>
      <input id="${id}" type="text" list="${id}-list" required autocomplete="off" placeholder="Choose or type a model name">
      <datalist id="${id}-list"></datalist><p class="hint" aria-live="polite"></p>
      <button type="button" class="btn btn-sm">Refresh models</button></div>`;
    const provider = host.querySelector("select"), input = host.querySelector("input");
    const list = host.querySelector("datalist"), hint = host.querySelector("p"), refresh = host.querySelector("button");
    const known = ["anthropic", "openai", "local"];
    const prefix = remembered.split(":", 1)[0];
    provider.value = known.includes(prefix) ? prefix : "anthropic";
    input.value = known.includes(prefix) ? remembered.slice(prefix.length + 1) : remembered;
    let sequence = 0;
    async function load() {
      const request = ++sequence, chosen = provider.value;
      list.innerHTML = ""; hint.textContent = "Loading models from this provider…";
      refresh.disabled = true;
      try {
        const params = new URLSearchParams({ provider: chosen });
        if (agent) params.set("agent", agent);
        const result = await Agenti.get("models?" + params);
        if (request !== sequence) return;
        list.innerHTML = (result.models || []).map((name) => {
          const value = name.startsWith(chosen + ":") ? name.slice(chosen.length + 1) : name;
          return `<option value="${esc(value)}"></option>`;
        }).join("");
        hint.textContent = result.models.length ? "Live models within the organisation's policy. You can also type a name."
          : "No models returned within the allowed list. An admin can edit allowed models in Settings → Engagement.";
      } catch (err) {
        if (request === sequence) hint.textContent = Agenti.errorText(err) + " You can type a model name; launch checks still apply.";
      } finally { if (request === sequence) refresh.disabled = false; }
    }
    input.addEventListener("input", () => {
      const typedProvider = input.value.trim().split(":", 1)[0];
      input.setCustomValidity(known.includes(typedProvider) && typedProvider !== provider.value
        ? "Choose the provider that matches this model name." : "");
    });
    provider.addEventListener("change", () => { input.value = ""; input.setCustomValidity(""); load(); });
    refresh.addEventListener("click", load);
    load();
    return { get value() { const value = input.value.trim(); return value ? (value.startsWith(provider.value + ":") ? value : provider.value + ":" + value) : ""; },
             reportValidity: () => input.reportValidity() };
  },
};
