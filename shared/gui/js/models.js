// The AI providers a run can use (Claude, ChatGPT, a self-hosted model), and
// one picker for a solo run and for each member of a mixed-provider team.
// Settings → AI providers reads the same list (settings.js).
//
// Only providers that are set up are offered. With exactly one, the question
// is not asked at all: the model field just names it ("Claude model"). With
// several, the last provider this browser launched with is chosen first
// (remember(), called by launch.js after a start).
//
// Readiness comes from GET models?status=true: whether this caller's runs
// would find a key (or, self-hosted, an address). It never contacts a
// provider and never returns a key. The model list comes from GET models,
// which asks the provider live and keeps only what the policy allows.
window.AgentiModels = (() => {
  const PROVIDERS = [
    { id: "anthropic", name: "Claude", by: "Anthropic", icon: "star",
      blurb: "Anthropic's Claude models, through the Claude Agent SDK.",
      keyHint: "sk-ant-…", keyUrl: "https://console.anthropic.com/settings/keys" },
    { id: "openai", name: "ChatGPT", by: "OpenAI", icon: "chat",
      blurb: "OpenAI's GPT models, through Agenti's own run loop.",
      keyHint: "sk-…", keyUrl: "https://platform.openai.com/api-keys" },
    { id: "local", name: "Self-hosted", by: "Your own model server", icon: "cpu",
      blurb: "Any server speaking the OpenAI-compatible API: Ollama, vLLM, LM Studio, llama.cpp, LiteLLM.",
      keyHint: "optional" },
  ];
  const IDS = PROVIDERS.map((p) => p.id);
  const LAST_PROVIDER_KEY = "agenti-last-provider";
  const providerOf = (model) => {
    const prefix = String(model || "").split(":", 1)[0];
    if (IDS.includes(prefix)) return prefix;
    return model && (String(model).startsWith("claude-") || ["haiku", "sonnet", "opus"].includes(model)) ? "anthropic" : "";
  };
  function remember(model) {
    const p = providerOf(model);
    try { if (p) localStorage.setItem(LAST_PROVIDER_KEY, p); } catch (e) { /* no persistence */ }
  }
  function lastProvider() {
    try { return localStorage.getItem(LAST_PROVIDER_KEY) || ""; } catch (e) { return ""; }
  }

  // One readiness request per page, shared by every picker on it.
  let statusRequest = null;
  function status({ fresh = false } = {}) {
    if (fresh || !statusRequest) {
      statusRequest = Agenti.get("models?status=true")
        .then((d) => d.providers || {})
        .catch(() => null);   // unknown: every provider stays choosable, the launch check still applies
    }
    return statusRequest;
  }

  function mount(host, { agent = "", remembered = "", compact = false } = {}) {
    const esc = Agenti.esc;
    const id = "models-" + crypto.randomUUID();
    const prefix = remembered.split(":", 1)[0];
    const rememberedProvider = providerOf(remembered);
    const preferred = rememberedProvider || lastProvider();
    host.innerHTML = `
      <fieldset class="provider-picker${compact ? " compact" : ""}">
        <legend class="${compact ? "sr-only" : "provider-legend"}">${compact ? "AI provider" : "Which AI should run it?"}</legend>
        <div class="provider-choices" hidden>
          ${PROVIDERS.map((p) => `
          <label class="provider-choice" data-provider="${p.id}">
            <input type="radio" name="${id}-provider" value="${p.id}">
            <span class="cat-icon" aria-hidden="true">${Agenti.icon(p.icon, compact ? 14 : 16)}</span>
            <span class="pc-text"><span class="pc-name">${esc(p.name)}</span><span class="pc-by">${esc(p.by)}</span></span>
            <span class="pc-state" data-state>…</span>
          </label>`).join("")}
        </div>
        <div class="field provider-model">
          <label for="${id}" data-model-label>Model</label>
          <div class="input-with-button">
            <input id="${id}" type="text" list="${id}-list" required autocomplete="off" spellcheck="false" placeholder="Choose or type a model name">
            <button type="button" class="btn btn-sm icon-only" aria-label="Refresh the model list" title="Refresh the model list">${Agenti.icon("refresh", 14)}</button>
          </div>
          <datalist id="${id}-list"></datalist>
          <p class="hint" aria-live="polite"></p>
        </div>
      </fieldset>`;
    const radios = [...host.querySelectorAll('input[type="radio"]')];
    const input = host.querySelector(`#${CSS.escape(id)}`);
    const list = host.querySelector("datalist"), hint = host.querySelector(".provider-model .hint");
    const refresh = host.querySelector(".input-with-button button");
    let ready = {};          // provider id -> true/false; empty = unknown
    let sequence = 0;
    const choices = host.querySelector(".provider-choices"), legend = host.querySelector("legend");
    const modelLabel = host.querySelector("[data-model-label]");
    const chosen = () => (radios.find((r) => r.checked) || radios[0]).value;
    const notReadyText = (p) => p === "local"
      ? "No model server is set up yet. An admin adds its address in Settings → AI providers."
      : `No ${PROVIDERS.find((x) => x.id === p).name} key is set up yet. An admin adds one in Settings → AI providers.`;

    function choose(p) { radios.forEach((r) => { r.checked = r.value === p; }); }
    choose(IDS.includes(preferred) ? preferred : "anthropic");
    const fillRemembered = () => {
      if (rememberedProvider && chosen() === rememberedProvider) {
        input.value = rememberedProvider === prefix ? remembered.slice(prefix.length + 1) : remembered;
      }
    };

    async function load() {
      const request = ++sequence, p = chosen();
      list.innerHTML = "";
      if (ready[p] === false) { hint.textContent = notReadyText(p); refresh.disabled = false; return; }
      hint.textContent = "Loading this provider's models…";
      refresh.disabled = true;
      try {
        const params = new URLSearchParams({ provider: p });
        if (agent) params.set("agent", agent);
        const result = await Agenti.get("models?" + params);
        if (request !== sequence) return;
        const models = result.models || [];
        list.innerHTML = models.map((name) => {
          const value = name.startsWith(p + ":") ? name.slice(p.length + 1) : name;
          return `<option value="${esc(value)}"></option>`;
        }).join("");
        hint.textContent = models.length
          ? `${models.length} model${models.length === 1 ? "" : "s"} allowed for this organisation. Pick one, or type a name.`
          : "This provider offers no model on the organisation's allowed list. An admin can change the list in Settings → Engagement.";
      } catch (err) {
        if (request === sequence) hint.textContent = Agenti.errorText(err) + " You can still type a model name; the launch checks it.";
      } finally { if (request === sequence) refresh.disabled = false; }
    }

    input.addEventListener("input", () => {
      const typed = input.value.trim().split(":", 1)[0];
      input.setCustomValidity(IDS.includes(typed) && typed !== chosen()
        ? "Choose the provider that matches this model name." : "");
    });
    radios.forEach((r) => r.addEventListener("change", () => {
      input.value = ""; input.setCustomValidity(""); load();
    }));
    refresh.addEventListener("click", async () => { await paintReadiness(true); load(); });

    async function paintReadiness(fresh) {
      const providers = await status({ fresh });
      ready = {};
      for (const p of PROVIDERS) {
        const label = host.querySelector(`.provider-choice[data-provider="${p.id}"]`);
        const state = label.querySelector("[data-state]");
        const info = providers && providers[p.id];
        if (!info) { state.textContent = ""; label.classList.remove("not-ready"); label.hidden = false; continue; }
        ready[p.id] = !!info.ready;
        label.classList.toggle("not-ready", !info.ready);
        state.textContent = info.ready ? "Ready" : "Not set up";
      }
      const offered = PROVIDERS.filter((p) => ready[p.id]);
      // Readiness unknown, or nothing set up: show every provider, so the
      // tiles themselves say what is missing. Otherwise offer only the ready ones.
      const shown = offered.length ? offered : PROVIDERS;
      for (const p of PROVIDERS) host.querySelector(`.provider-choice[data-provider="${p.id}"]`).hidden = !shown.includes(p);
      if (offered.length && !offered.some((p) => p.id === chosen())) {
        const order = [rememberedProvider, lastProvider()];
        choose((order.map((id) => offered.find((p) => p.id === id)).find(Boolean) || offered[0]).id);
      }
      const single = offered.length === 1;
      choices.hidden = single;
      host.classList.toggle("single-provider", single);
      choices.style.setProperty("--n", String(shown.length));
      legend.classList.toggle("sr-only", single || compact);
      modelLabel.textContent = single ? `${offered[0].name} model` : "Model";
      fillRemembered();
    }
    paintReadiness(false).then(load);

    return {
      get value() {
        const value = input.value.trim(), p = chosen();
        return value ? (value.startsWith(p + ":") ? value : p + ":" + value) : "";
      },
      reportValidity: () => input.reportValidity(),
    };
  }

  return { PROVIDERS, status, mount, remember };
})();
