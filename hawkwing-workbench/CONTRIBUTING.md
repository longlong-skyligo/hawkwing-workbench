# Contributing

Thank you for improving HawkWing.

## Development Principles

- Keep the API container focused on orchestration, not tool execution.
- Add tools through Runner Profiles and Tool Catalog entries.
- Preserve human approval for high-risk workflows.
- Keep runner outputs structured:

```text
/out/result.json
/out/commands.log
/out/timeline.json
/out/evidence/
```

- Do not add malware/webshell generation, phishing kits, DDoS tooling, RAT frameworks, or unapproved persistence features.

## Adding a Tool

1. Add the tool to `config/tool-catalog.yaml`.
2. Assign a risk level and status: `enabled`, `approval`, or `disabled`.
3. Map it to a Runner Profile in `config/runner-profiles.yaml`.
4. Add or update the runner Dockerfile under `runners/`.
5. Add a Skill/Runbook entry if AI planning should use it.
6. Document expected output files.

## Local Checks

```bash
python -m py_compile apps/api/app/main.py
python -c "import yaml, pathlib; [yaml.safe_load(p.read_text()) for p in pathlib.Path('config').glob('*.yaml')]"
docker compose -f deploy/docker-compose.yml config
```

