FROM golang:1.23-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-recon-basic
ENV PATH="/root/go/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq python3 python3-pip nmap dnsutils whois netcat-openbsd ruby \
    && gem install --no-document whatweb || true \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 || true \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 || true \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 || true \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
