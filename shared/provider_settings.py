"""Root's provider views: resolve keys once, return only status or model names."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import engagement_context as ec
import model_registry as mr
from agent_runtime import read_secrets


def settings(root: Path, owner: str, agent: str = "") -> dict:
    for name in (owner, agent):
        if name and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name):
            raise ValueError("use an Agenti username and an installed agent name")
    org = root / "org"
    return read_secrets([org / "users" / owner / "secrets.env" if owner else None,
                         org / agent / "secrets.env" if agent else None,
                         org / "secrets.env", root / "shared" / "secrets.env"])


def status(root: Path, owner: str, agent: str = "") -> dict:
    values = settings(root, owner, agent)
    address = values.get("LOCAL_LLM_BASE_URL", "")
    if address:
        try:
            mr.validate_base_url(address)
        except ValueError:
            values["LOCAL_LLM_BASE_URL"] = ""
    return {p.name: {"label": p.label, "key": "set" if values.get(p.key_env) else "missing",
                     "ready": bool(values.get(p.key_env)) if p.key_required else bool(values.get(p.base_url_env))}
            for p in mr.PROVIDERS.values()}


def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False, description="List live provider models allowed by this organisation; keys are never displayed.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--owner", default="")
    ap.add_argument("--agent", default="")
    ap.add_argument("--provider", choices=list(mr.PROVIDERS), default="anthropic")
    ap.add_argument("--status", action="store_true", help="provider readiness only; do not contact providers")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root)
    try:
        if args.status:
            result = {"providers": status(root, args.owner, args.agent)}
        else:
            values = settings(root, args.owner, args.agent)
            p = mr.PROVIDERS[args.provider]
            if p.key_required and not values.get(p.key_env):
                raise ValueError(f"no {p.label} key for this run; set one: sudo /usr/lib/agenti/set-secret.sh --provider {p.name}")
            if p.base_url_env and not values.get(p.base_url_env):
                raise ValueError("no self-hosted model address; set one: sudo /usr/lib/agenti/set-secret.sh --provider local --base-url http://model.example.com:11434/v1")
            policy = ec.resolve_policy(ec.read_record(root / "org" / "engagement.json") if (root / "org" / "engagement.json").exists() else None)
            models = mr.list_models(p.name, api_key=values.get(p.key_env, ""),
                                    base_url=values.get(p.base_url_env, "") if p.base_url_env else "",
                                    relay=os.environ.get("AGENTI_RELAY", "http://127.0.0.1:8429"))
            result = {"provider": p.name, "models": [m for m in models if mr.allowed(m, policy["allowed_models"])],
                      "allowed_models": policy["allowed_models"]}
        print(json.dumps(result) if args.json or args.status else "\n".join(result["models"]) or "No models returned within the organisation's allowed list.")
        return 0
    except (OSError, RuntimeError, ValueError, SystemExit) as e:
        print(json.dumps({"error": str(e)}) if args.json else f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
