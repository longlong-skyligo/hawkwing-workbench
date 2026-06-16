FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-web-advanced

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq git nmap nikto default-jre \
    && pip install --no-cache-dir sqlmap arjun || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
