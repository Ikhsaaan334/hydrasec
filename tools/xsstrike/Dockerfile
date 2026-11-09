# tool-xsstrike — deteksi & eksploitasi XSS (s0md3v/XSStrike)
FROM python:3.11-alpine

RUN apk add --no-cache git \
    && git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/XSStrike \
    && pip install --no-cache-dir -r /opt/XSStrike/requirements.txt \
    && adduser -D -u 10000 scanner

USER scanner
ENV HOME=/tmp

WORKDIR /opt/XSStrike
ENTRYPOINT ["python3", "-u", "/opt/XSStrike/xsstrike.py"]
