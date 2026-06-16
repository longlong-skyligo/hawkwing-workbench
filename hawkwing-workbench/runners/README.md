# HawkWing Runner Image Library

The runner library turns a broad hacking-tool style catalog into controlled stock images.

Default stock runners:

```text
runner-recon-basic
runner-web-basic
runner-web-advanced
runner-traffic-basic
runner-ad-basic
runner-linux-privesc
runner-windows-privesc
runner-forensics-basic
runner-pwn-rev-basic
runner-cloud-container-basic
runner-pivot-proxy
runner-report
```

High-risk categories such as DDoS, phishing kits, RAT frameworks, and payload creation are intentionally not included in stock images.

WebShell payload generation, including Behinder/Godzilla-style webshell generation, is intentionally not included. Use webshell detection, controlled proof markers, and approved session registration instead.

Each runner must preserve the contract:

```text
/out/input.json
/out/result.json
/out/commands.log
/out/evidence/
```

The current Dockerfiles install a practical baseline and leave room for pinned tool additions. In air-gapped competitions, mirror package repositories and prebuild these images before the event.
