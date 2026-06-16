# GitHub Publish Checklist

Before pushing this project to GitHub:

## Repository Metadata

- Choose a repository name, for example `hawkwing-workbench`.
- Decide whether the repository is public or private.
- Choose a license if public reuse is intended.
- Add repository topics:

```text
cyber-range
ctf
blue-team
security-training
fastapi
docker
ai
```

## Secrets

Confirm these files are not committed:

```text
deploy/.env
data/artifacts/*
data/reports/*
data/workspaces/*
```

Commit only:

```text
deploy/.env.example
data/artifacts/.gitkeep
data/reports/.gitkeep
data/workspaces/.gitkeep
```

## Safety Review

- Confirm prohibited categories remain disabled in `config/tool-catalog.yaml`.
- Confirm dynamic runner policy blocks Docker socket, host networking, privileged execution indicators, and `curl | bash` patterns.
- Confirm README and SECURITY clearly state authorized-use boundaries.
- Review runner Dockerfiles before public release.

## Smoke Checks

From `hawkwing-workbench`:

```bash
python -m py_compile apps/api/app/main.py apps/api/app/models.py apps/api/app/schemas.py
python -c "import yaml, pathlib; [yaml.safe_load(p.read_text(encoding='utf-8')) for p in pathlib.Path('config').glob('*.yaml')]; print('yaml ok')"
cd deploy
cp .env.example .env
docker compose config
```

## First Commit Suggestion

```bash
git add hawkwing-workbench
git commit -m "Initial HawkWing workbench scaffold"
```

If this folder is its own repository, run the commands inside `hawkwing-workbench`.

