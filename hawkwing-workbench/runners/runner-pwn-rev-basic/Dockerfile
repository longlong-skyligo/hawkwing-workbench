FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-pwn-rev-basic

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq file binutils gdb radare2 checksec patchelf strace ltrace \
    && pip install --no-cache-dir pwntools ROPGadget || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
