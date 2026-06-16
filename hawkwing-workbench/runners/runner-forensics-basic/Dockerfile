FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-forensics-basic

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq file binutils binwalk sleuthkit foremost bulk-extractor exiftool p7zip-full \
    && pip install --no-cache-dir volatility3 || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
