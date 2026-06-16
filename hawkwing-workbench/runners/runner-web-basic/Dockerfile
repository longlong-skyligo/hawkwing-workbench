FROM golang:1.23-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_NAME=runner-web-basic
ENV PATH="/root/go/bin:${PATH}"
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl jq python3 python3-pip git ruby nmap openssl \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
        libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 \
    && pip3 install --break-system-packages --no-cache-dir dirsearch uro playwright \
    && python3 -m playwright install chromium \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.9.0 || true \
    && go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1 || true \
    && go install github.com/ffuf/ffuf/v2@v2.1.0 || true \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /runner
COPY _shared/entrypoint.sh /runner/entrypoint.sh
RUN chmod +x /runner/entrypoint.sh
ENTRYPOINT ["/runner/entrypoint.sh"]
