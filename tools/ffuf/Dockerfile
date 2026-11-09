# tool-ffuf — fuzzer directory / parameter discovery (ffuf/ffuf)
FROM alpine:3.20

ARG FFUF_VERSION=2.1.0

RUN apk add --no-cache curl ca-certificates \
    && curl -sSL -o /tmp/ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && chmod 0755 /usr/local/bin/ffuf \
    && rm -f /tmp/ffuf.tar.gz \
    && mkdir -p /usr/share/wordlists \
    && adduser -D -u 10000 scanner

# Wordlist common.txt (SecLists "Discovery/Web-Content/common.txt")
COPY wordlists/common.txt /usr/share/wordlists/common.txt

USER scanner

ENTRYPOINT ["/usr/local/bin/ffuf"]
