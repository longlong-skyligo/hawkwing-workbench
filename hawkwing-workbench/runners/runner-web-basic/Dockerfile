FROM golang:1.23-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-web-basic
ENV PATH="/root/go/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq python3 python3-pip git ruby nmap openssl \
    && pip3 install --break-system-packages dirsearch uro || true \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.9.0 || true \
    && go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1 || true \
    && go install github.com/ffuf/ffuf/v2@v2.1.0 || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
