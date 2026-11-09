# tool-nuclei — vulnerability scanning berbasis template (versi gratis/community)
FROM alpine:3.20

ARG NUCLEI_VERSION=3.11.1

RUN apk add --no-cache curl ca-certificates unzip \
    && curl -sSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /tmp/nuclei-bin \
    && install -m 0755 /tmp/nuclei-bin/nuclei /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei-bin \
    && adduser -D -u 10000 scanner \
    && mkdir -p /home/scanner \
    && chown scanner:scanner /home/scanner

USER scanner
ENV HOME=/home/scanner

# Bake template resmi projectdiscovery ke dalam image agar runtime offline-friendly.
# -ut membuat direktori dengan mode owner-only (0700) — wajib chmod a+rX agar
# uid acak non-root yang dipakai worker saat runtime tetap bisa MEMBACA template.
RUN nuclei -ut -silent && chmod -R a+rX /home/scanner/nuclei-templates

ENTRYPOINT ["nuclei"]
