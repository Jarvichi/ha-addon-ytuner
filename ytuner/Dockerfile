ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    ffmpeg \
    python3 \
    sqlite3 \
    libsqlite3-0 \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download YTuner binary (detect architecture from running system)
RUN YTUNER_VER="1.2.6" && \
    MACHINE="$(uname -m)" && \
    case "${MACHINE}" in \
      x86_64)  ASSET="ytuner-${YTUNER_VER}-x86_64-linux.zip" ;; \
      aarch64) ASSET="ytuner-${YTUNER_VER}-aarch64-arm64-armv7-armv8-armv9-linux.zip" ;; \
      *)       echo "Unsupported architecture: ${MACHINE}" && exit 1 ;; \
    esac && \
    wget -q "https://github.com/coffeegreg/YTuner/releases/download/${YTUNER_VER}/${ASSET}" \
      -O /tmp/ytuner.zip && \
    mkdir -p /opt/ytuner && \
    unzip -q /tmp/ytuner.zip -d /tmp/ytuner-extract && \
    cp -a /tmp/ytuner-extract/ytuner-*/* /opt/ytuner/ && \
    mkdir -p /opt/ytuner/config /opt/ytuner/cache /opt/ytuner/db && \
    chmod +x /opt/ytuner/ytuner && \
    rm -rf /tmp/ytuner.zip /tmp/ytuner-extract

# Copy rootfs overlay (S6 services, nginx config, Python scripts)
COPY rootfs /
