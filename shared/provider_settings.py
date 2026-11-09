"""Root's provider views: resolve keys once, return only status or model names."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import engagement_context as ec
import model_registry as mr
import paths
from agent_runtime import read_secrets
from context_store import NAME_RE


def settings(root: Path, owner: str, agent: str = "") -> dict:
    for name in (owner, agent):
        if name and not NAME_RE.fullmatch(name):
            raise ValueError("use an Agenti username and an installed agent name")
    import keystore
    locked = keystore.locked_reason()
    if locked:
        raise ValueError(locked)
    return read_secrets(keystore.tier_paths(root, owner or None, agent or None))


def status(root: Path, owner: str, agent: str = "") -> dict:
    values = settings(root, owner, agent)
    return {p.name: {"label": p.label, "key": "set" if values.get(p.key_env) else "missing",
                     "ready": not mr.setup_problems(p, values)}
            for p in mr.PROVIDERS.values()}


def main(argv=None):
    ap = argparse.ArgumentParser(allow_abbrev=False, description="List live provider models allowed by this organization; keys are never displayed.")
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
            problems = mr.setup_problems(p, values)
            if problems:
                raise ValueError(problems[0])
            record_path = root / "org" / ec.ORG_ENGAGEMENT_FILENAME
            policy = ec.resolve_policy(ec.read_record(record_path) if record_path.exists() else None)
            models = mr.list_models(p.name, api_key=values.get(p.key_env, ""),
                                    base_url=values.get(p.base_url_env, "") if p.base_url_env else "",
                                    relay="http://" + paths.relay_addr())
            result = {"provider": p.name, "models": [m for m in models if mr.allowed(m, policy["allowed_models"])],
                      "allowed_models": policy["allowed_models"]}
        print(json.dumps(result) if args.json or args.status else "\n".join(result["models"]) or "No models returned within the organization's allowed list.")
        return 0
    except (OSError, RuntimeError, ValueError, SystemExit) as e:
        print(json.dumps({"error": str(e)}) if args.json else f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
