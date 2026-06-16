# HawkWing External Range AI Workbench

HawkWing is an AI-assisted workbench for authorized external cyber ranges, CTF-style exercises, and blue-team training where defenders practice attacker workflows in a controlled environment.

It helps operators import temporary range targets, scan and rank findings, review them manually, assess an execution plan, launch isolated runner containers, collect evidence, and generate a final report.

> Safety boundary: HawkWing is intended only for authorized labs, cyber ranges, and competitions. It does not ship malware/webshell generation, phishing kits, DDoS tooling, RAT frameworks, or automatic covert access deployment.

## Features

- Workspace and temporary target import
- Scan job orchestration
- Finding ranking and manual review
- Execution Plan Assessment before launching containers
- Stock runner image library by challenge type
- Dynamic runner proposal policy with human approval
- Tool Catalog with risk levels and allow/approval/disabled states
- AI Skill / Runbook registry
- Shared state and evidence event bus
- Evidence indexing with SHA256
- Approved session/pivot reference registry
- Stage visualization for the full workflow
- Markdown report generation
- OpenAI-compatible AI API configuration
- Linux / WSL2 Docker Compose deployment

## Architecture

```text
Web Console
  -> FastAPI API
    -> PostgreSQL
    -> Redis / Celery
    -> Execution Planner
    -> Tool Catalog / Skill Registry
    -> Docker Runner Manager
      -> Temporary Runner Containers
        -> Evidence Artifacts
    -> Markdown Report
```

Core flow:

```text
Import targets
-> Scan
-> Review findings
-> Assess execution plan
-> Approve plan
-> Launch stock or approved dynamic runner containers
-> Collect evidence
-> Register approved sessions if needed
-> Generate report
```

## Runner Library

Stock runner profiles:

```text
runner-recon-basic              Reconnaissance and service discovery
runner-web-basic                Web crawl, content discovery, template validation
runner-web-advanced             Approved deeper web validation
runner-traffic-basic            Pcap and traffic analysis
runner-ad-basic                 Authorized Active Directory enumeration
runner-linux-privesc            Linux privilege escalation enumeration
runner-windows-privesc          Windows privilege escalation enumeration support
runner-forensics-basic          Memory, disk, firmware, and file forensics
runner-pwn-rev-basic            Pwn and reverse engineering support
runner-cloud-container-basic    Cloud, container, SBOM, and Kubernetes checks
runner-pivot-proxy              Approved session/pivot metadata support
runner-report                   Report conversion support
```

Configuration files:

```text
config/tool-catalog.yaml
config/runner-profiles.yaml
config/skill-registry.yaml
config/dynamic-runner-policy.yaml
config/evidence-bus-schema.yaml
```

## Quick Start

Linux or Windows WSL2:

```bash
cd hawkwing-workbench/deploy
cp .env.example .env
docker compose --profile build-runners build
docker compose up
```

Open:

```text
Web Console: http://localhost:3000
API Docs:    http://localhost:8000/docs
Health:      http://localhost:8000/api/health
```

To start only the control plane first:

```bash
cd hawkwing-workbench/deploy
cp .env.example .env
docker compose up --build
```

## AI API Configuration

Edit `deploy/.env`:

```env
AI_PROVIDER=openai-compatible
AI_API_BASE=https://api.example.com/v1
AI_API_KEY=replace-with-your-key
AI_MODEL=gpt-4.1-mini
AI_TIMEOUT_SECONDS=60
```

If no AI key is configured, the platform still runs with rule-based planning and placeholder summaries.

## Repository Layout

```text
apps/api       FastAPI backend, Celery workers, AI client, runner orchestration
apps/web       React/Vite web console
config         Tool catalog, runner profiles, skill registry, policies, templates
data           Local artifacts, reports, workspace data
deploy         Docker Compose deployment
docs           Architecture, deployment, user, and runner guides
runners        Stock runner image library
scripts        Helper scripts for Linux/WSL deployment
```

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)
- [Advanced Orchestration](docs/advanced-orchestration.md)
- [Runner Plugin Guide](docs/runner-plugin-guide.md)
- [User Guide](docs/user-guide.md)
- [Full Chinese Project Description](项目全面说明.md)
- [GitHub Publish Checklist](docs/github-publish-checklist.md)

## Security Model

HawkWing uses:

- Human approval for high-risk runners and execution plans
- Tool risk levels and disabled categories
- Temporary runner containers instead of installing tools in the API container
- Evidence hashing and audit events
- Session registration rather than automatic covert channel deployment
- Dynamic runner policy checks before build/pull proposals

See [SECURITY.md](SECURITY.md) and [DISCLAIMER.md](DISCLAIMER.md).

## Current Status

This is a deployable project scaffold with advanced orchestration architecture. Some runner workflows are baseline placeholders and should be extended with authorized, competition-specific runbooks before production use.

## License

No open-source license has been selected yet. Before publishing publicly, choose a license that matches your intended sharing model. See `docs/github-publish-checklist.md`.

