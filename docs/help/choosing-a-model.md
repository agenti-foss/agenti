# Choosing a model and connecting providers

Every launch needs a model. On **Launch**, pick one from the provider's live
list of allowed models. A model that isn't listed? Choose **Other model…** at
the end of the list and type its name. Only providers an administrator has set
up are offered:

- **One provider set up:** Launch does not ask; the field is named after it
  (for example **Claude model**).
- **Several:** Launch asks **Which AI should run it?** and starts on the
  provider you launched with last in this browser.

A team has a separate choice for each member, so its members can use
different providers.

- **Claude (Anthropic):** uses an Anthropic API key.
- **ChatGPT (OpenAI):** uses an OpenAI API key, billed through the API.
  A ChatGPT subscription or ChatGPT sign-in cannot be used instead.
- **Self-hosted:** uses your own OpenAI-compatible model server, such as
  Ollama or vLLM. Its address is required; its API key is optional.

An administrator connects providers in **Settings → AI providers**: one
card each for Claude, ChatGPT and a self-hosted server. Saving requires a
fresh approval. Keys are never shown again; replacing one affects future
runs. **Check connection** asks the provider which of its models are on the
allowed list, without starting a run. For a self-hosted server, the card
shows the relay command for the address you type. Provider keys resolve independently:
user, agent, organization, then shared. Setting a user's Claude key does
not hide the organization's OpenAI key.

At the server, keys are entered at a hidden prompt:

```sh
sudo /usr/lib/agenti/set-secret.sh --provider anthropic
sudo /usr/lib/agenti/set-secret.sh --provider openai
sudo /usr/lib/agenti/set-secret.sh --provider local --base-url http://model.example.com:11434/v1
```

Add `--org`, `--agent enum`, or `--user alice` to choose a narrower key tier.
Do not put a key on the command line. For a self-hosted server, root must
also permit its endpoint through the relay:

```sh
sudo agenti admin relay allow model.example.com:11434
```

This keeps the existing destinations, or the cloud defaults when no custom
list exists. It restarts an active relay; let current model requests finish
before changing it. The web interface cannot add relay destinations.

**Settings → Engagement → Allowed models** accepts one name or wildcard
per line: `anthropic:*`, `openai:gpt-5.1`, `local:*`. Existing Claude aliases
`haiku`, `sonnet`, and `opus` still work. A provider's live list is filtered
by this policy. A typed name still goes through the same server checks.

OpenAI models need a configured price to enforce a run's budget. In
**Model prices**, enter one `provider:model=input,output` line per model,
in USD per million tokens. Use the provider's current prices. At a terminal:

```sh
sudo agenti engagement set --model-price openai:YOUR_MODEL=INPUT,OUTPUT
sudo agenti models --provider openai --agent enum --json
sudo agenti enum start -t 192.0.2.50 --model openai:YOUR_MODEL
```

Claude reports its cost through its engine. Self-hosted models count as
zero dollars; turn and time limits still apply. A missing cloud price, key,
or self-hosted address is refused before a solo run's slot is created.

For a team at a terminal, use `--model` for a common default, or repeat
`--member-model enum=openai:YOUR_MODEL` for individual members.

To change the model of a run that is going, tap the model chip at the top of
its console and pick one (or type `/model`); at a terminal,
`sudo agenti enum set-model sonnet`. The switch happens after the step in
progress, and the console says when it does. A run keeps its provider: a Claude
run can switch to another Claude model, but not to a ChatGPT one. The new model
must be on the allowed list at the moment of the switch, and an OpenAI model
needs a price.

If the live list fails, check the provider key, server availability and relay
allow-list. A key does not override allowed models, scope, budgets, tool
validation, or operator approvals. Exploit runs use the same gates on every
provider: approved scope, the exploit capability, and per-action approval.
