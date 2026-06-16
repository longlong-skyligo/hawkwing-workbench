FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends pandoc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh

ENTRYPOINT ["/runner/entrypoint.sh"]

