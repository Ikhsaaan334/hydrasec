# tool-sqlmap — deteksi & eksploitasi SQL injection (sqlmapproject/sqlmap)
FROM python:3.11-alpine

RUN apk add --no-cache git \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap \
    && adduser -D -u 10000 scanner

USER scanner
ENV HOME=/tmp

ENTRYPOINT ["python3", "-u", "/opt/sqlmap/sqlmap.py"]
