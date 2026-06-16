# Advanced Orchestration Guide

This version adds four major platform layers:

```text
Runner tool layering
Shared state and evidence bus
AI Skill / Runbook registry
Dynamic runner build policy
```

## 1. Runner Tool Layering

The platform uses stock runner images instead of one large all-in-one tool image.

```text
runner-recon-basic              external and internal reconnaissance
runner-web-basic                web crawl, content discovery, template validation
runner-web-advanced             approved deeper web validation
runner-traffic-basic            pcap and traffic analysis
runner-ad-basic                 approved Active Directory enumeration
runner-linux-privesc            Linux privilege escalation enumeration
runner-windows-privesc          Windows privilege escalation enumeration
runner-forensics-basic          memory, file, disk, firmware forensics
runner-pwn-rev-basic            pwn and reverse engineering support
runner-cloud-container-basic    cloud, container, SBOM, Kubernetes checks
```

The tool catalog was inspired by broad tool collections such as `Z4nzu/hackingtool`, but high-risk categories are disabled by default:

```text
DDoS tooling
phishing kits
RAT frameworks
payload creation
uncontrolled post-exploitation
```

## 2. Execution Plan Assessment

After scanning and manual review, the operator selects findings and asks the platform to assess an execution plan.

The planner decides:

```text
how many containers to start
which stock runner profile to use
which tools are expected
which findings map to which runner
whether a dynamic runner proposal is needed
parallelism limits
risk and approval needs
```

The plan must be approved before execution.

## 3. Shared State and Evidence Bus

Multiple containers for the same target should not directly read or write each other's files. They exchange information through:

```text
workspace_state_events
evidence_files
findings
attack_path_nodes
attack_path_edges
```

This lets a web runner, AD runner, forensics runner, and privilege-enumeration runner cooperate without losing auditability.

## 4. AI Skill / Runbook Registry

The skill registry tells AI and the planner:

```text
what the task is
which runner profile should execute it
which tools are allowed
what output schema is expected
whether approval is required
what runbook steps should be followed
```

The file is:

```text
config/skill-registry.yaml
```

## 5. Dynamic Runner Builds

Dynamic runners are a fallback for special challenges, such as firmware, IoT, Android, ICS, or custom reverse engineering.

Default control rules:

```text
prefer stock runners
require human approval
deny latest tags where possible
allow only configured registries
deny Docker socket mounts
deny host networking
deny privileged execution
limit CPU, memory, pids, and timeout
preserve Dockerfile and build logs
```

The policy file is:

```text
config/dynamic-runner-policy.yaml
```

## 6. Operational Flow

```text
1. Import targets.
2. Start scan.
3. Review ranked findings.
4. Select findings.
5. Fill scenario notes.
6. Generate execution plan.
7. Review stock and dynamic runner proposals.
8. Approve plan.
9. Execute plan.
10. Review runner jobs and evidence.
11. Generate report.
```

## 7. Internal Range Safety Boundary

For internal network challenges, HawkWing supports:

```text
approved enumeration
privilege escalation enumeration
webshell detection
controlled proof markers
traffic and forensic analysis
approved session reference registration
evidence hashing
stage visualization
reporting
```

HawkWing does not include stock support for:

```text
Behinder/Godzilla webshell generation
webshell deployment
automated persistence
unapproved privilege escalation exploitation
unregistered covert reverse proxy establishment
```

Use `pivot-session-registration` to record approved pivot/proxy metadata, not to bypass operator approval.
