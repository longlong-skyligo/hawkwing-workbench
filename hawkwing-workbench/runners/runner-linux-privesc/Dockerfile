FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-linux-privesc

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq python3 procps psmisc findutils util-linux sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tools
RUN curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh \
    && chmod +x linpeas.sh || true

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
