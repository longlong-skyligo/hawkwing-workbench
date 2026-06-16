FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-traffic-basic

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq python3 tshark tcpdump wireshark-common \
    && apt-get install -y --no-install-recommends suricata || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
