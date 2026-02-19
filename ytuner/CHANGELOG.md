# Changelog

## 1.0.2

- Fix speaker discovery: write YTuner log to /data/ytuner.log so the web UI can tail it for preset detection
- Discovery was failing because LOG_FILE pointed to /proc/1/fd/1 (container stdout) which can't be tailed

## 1.0.1

- Fix YTuner binding to listen on 127.0.0.1 (nginx proxy was getting "Connection refused")
- Fix release download URLs and archive format (zip, correct tag names)
- Fix S6 environment variable path (/run/s6/ not /var/run/s6/)

## 1.0.0

- Initial release
- YTuner v1.2.6 binary
- Nginx reverse proxy with per-device Host header
- Transcoding proxy (FFmpeg) for non-MP3 and HTTPS streams
- Web management UI for speakers, presets, and station library
- S6-overlay service management
- Persistent configuration across updates
- Support for aarch64 and amd64 architectures
