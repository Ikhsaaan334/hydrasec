# tool-xray — deep web security assessment (chaitin/xray)
# Base Debian (glibc): binary xray 1.9.11 ter-link dinamis ke glibc,
# tidak jalan di Alpine/musl ("sh: ./xray: not found").
# License komunitas: letakkan file `license` di host pada ./data/xray/license
# (worker akan me-mount-nya ke /opt/xray/license; lihat README bagian xray).
FROM debian:bookworm-slim

ARG XRAY_VERSION=1.9.11

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip libpcap0.8 \
    && curl -sSL -o /tmp/xray.zip "https://github.com/chaitin/xray/releases/download/${XRAY_VERSION}/xray_linux_amd64.zip" \
    && unzip -o /tmp/xray.zip -d /tmp/xray-bin \
    && rm -rf /tmp/xray-bin/*.exe /tmp/xray-bin/*.md /tmp/xray-bin/config \
    && mkdir -p /opt/xray \
    && install -m 0755 /tmp/xray-bin/xray_linux_amd64 /opt/xray/xray \
    && rm -rf /tmp/xray.zip /tmp/xray-bin /var/lib/apt/lists/* \
    && useradd -u 10000 -M -d /tmp scanner \
    && chown -R scanner:scanner /opt/xray

COPY entrypoint.sh /opt/xray/entrypoint.sh
# Run pertama xray hanya men-generate config lalu exit — bake config ke image
# sebagai REFERENSI read-only (/opt/xray-default). Saat runtime, entrypoint
# menyalinnya ke working dir yang writable (/tmp/xray-work) karena xray
# menulis config secara atomik (butuh izin tulis DIREKTORI, bukan cuma file).
RUN chmod 0755 /opt/xray/entrypoint.sh \
    && cd /opt/xray && ./xray webscan --url "http://127.0.0.1:9" --json-output /tmp/init.json >/dev/null 2>&1 || true \
    && mkdir -p /opt/xray-default \
    && cp /opt/xray/*.yaml /opt/xray-default/ \
    && chmod -R a+rX /opt/xray-default

USER scanner
ENV HOME=/tmp

WORKDIR /opt/xray
ENTRYPOINT ["/opt/xray/entrypoint.sh"]
