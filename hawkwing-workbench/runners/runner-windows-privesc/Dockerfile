FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-windows-privesc

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq python3 unzip p7zip-full \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tools
RUN curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -o winPEASx64.exe || true

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
