FROM ghcr.io/esphome/esphome:2026.6.5

ARG BUILD_VERSION=0.1.0
ARG BUILD_ARCH=amd64
LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir rfc8785==0.1.4

COPY rootfs/app /app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=3)"

USER root
WORKDIR /app
ENTRYPOINT ["/run.sh"]
