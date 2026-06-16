FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-ad-basic

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq git ldap-utils smbclient krb5-user dnsutils nmap \
    && pip install --no-cache-dir impacket bloodhound certipy-ad netexec enum4linux-ng || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
