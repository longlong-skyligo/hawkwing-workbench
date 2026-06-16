FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-cloud-container-basic

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq git \
    && pip install --no-cache-dir prowler || true \
    && curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -o /tmp/install-trivy.sh \
    && sh /tmp/install-trivy.sh -b /usr/local/bin || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
