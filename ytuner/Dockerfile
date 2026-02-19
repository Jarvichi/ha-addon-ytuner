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
    libarchive-tools \
    && rm -rf /var/lib/apt/lists/*

# Download YTuner binary (detect architecture from running system)
RUN YTUNER_VER="1.2.6" && \
    MACHINE="$(uname -m)" && \
    case "${MACHINE}" in \
      x86_64)  ARCH="amd64" ;; \
      aarch64) ARCH="aarch64" ;; \
      armv7l)  ARCH="armhf" ;; \
      *)       echo "Unsupported architecture: ${MACHINE}" && exit 1 ;; \
    esac && \
    wget -q "https://github.com/coffeegreg/YTuner/releases/download/v${YTUNER_VER}/ytuner-${YTUNER_VER}-linux-${ARCH}.tar.xz" \
      -O /tmp/ytuner.tar.xz && \
    mkdir -p /opt/ytuner/config /opt/ytuner/cache /opt/ytuner/db && \
    bsdtar -xf /tmp/ytuner.tar.xz -C /opt/ytuner --strip-components=1 && \
    chmod +x /opt/ytuner/ytuner && \
    rm /tmp/ytuner.tar.xz

# Copy rootfs overlay (S6 services, nginx config, Python scripts)
COPY rootfs /
