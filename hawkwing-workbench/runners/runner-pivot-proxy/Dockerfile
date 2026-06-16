FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-pivot-proxy

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq python3 proxychains4 socat netcat-openbsd iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]

