# Security Policy

## Intended Use

HawkWing is intended for:

- Authorized cyber ranges
- Internal training labs
- CTF-style exercises
- Blue-team attack-path demonstrations
- Educational environments with explicit permission

Do not use this project against systems you do not own or do not have explicit authorization to test.

## Safety Boundaries

The stock project does not provide:

- Malware or webshell generation
- Behinder/Godzilla-style webshell deployment
- Phishing kits
- DDoS tooling
- RAT frameworks
- Automatic persistence
- Unapproved privilege escalation exploitation
- Unregistered covert reverse proxy establishment

Supported alternatives include:

- WebShell detection and evidence review
- Controlled proof markers
- Privilege escalation enumeration
- Approved session metadata registration
- Evidence hashing and reporting

## Reporting Security Issues

If you find a security issue in the project itself, open a private security advisory on GitHub if enabled, or contact the repository owner directly.

When reporting, include:

- Affected component
- Reproduction steps
- Expected and actual behavior
- Potential impact
- Suggested remediation, if known

## Dependency and Image Hygiene

Before using HawkWing in an event:

- Build runner images ahead of time
- Pin or mirror dependencies where possible
- Review Dockerfiles and tool catalogs
- Confirm disabled categories remain disabled
- Rotate any AI API keys or secrets after testing

