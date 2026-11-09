# tool-nmap — pemindaian port & reconnaissance (ephemeral, dijalankan sebagai non-root)
FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts \
    && adduser -D -u 10000 scanner

USER scanner

ENTRYPOINT ["nmap"]
