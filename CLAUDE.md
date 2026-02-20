# CLAUDE.md

## Project Overview

YTuner Home Assistant Add-on — a vTuner internet radio replacement for AVR devices (Yamaha, Denon, Pioneer, Marantz) and Libratone speakers. Runs as an HA add-on container with S6-overlay process management.

**Current version:** 1.1.0
**Repository:** https://github.com/Jarvichi/ha-addon-ytuner
**Architectures:** aarch64, amd64

## Architecture

Four services managed by S6-overlay, all in one container:

```
init-config (oneshot) — generates ytuner.ini, symlinks /data/, exports env vars
    ├→ svc-ytuner  (longrun) — Free Pascal vTuner server on 127.0.0.1:18081
    │   └→ svc-nginx (longrun) — reverse proxy on port 80, sets Host: $remote_addr
    ├→ svc-transcode (longrun) — Python FFmpeg proxy on port 8888
    └→ svc-webui (longrun) — Python web UI on port 8080
```

**Network ports:** 80 (AVR devices), 8080 (web UI + HA ingress), 8888 (transcode proxy), 18081 (internal YTuner)

**Critical nginx behavior:** Sets `Host: $remote_addr` so YTuner identifies devices by IP for per-device bookmarks. This is required for Libratone multi-speaker support.

## Directory Structure

```
ha-addon-ytuner/
├── repository.yaml                    # HA add-on repo metadata
└── ytuner/
    ├── config.yaml                    # HA add-on manifest (version, ports, options)
    ├── build.yaml                     # Base Docker images per arch
    ├── Dockerfile                     # Installs nginx, ffmpeg, python3, downloads YTuner v1.2.6
    ├── CHANGELOG.md                   # Version history
    ├── DOCS.md                        # User documentation
    └── rootfs/
        ├── etc/
        │   ├── nginx/nginx.conf       # Reverse proxy config
        │   └── s6-overlay/s6-rc.d/    # S6 service definitions
        │       ├── init-config/run    # Startup: generates ytuner.ini, sets up /data/ symlinks
        │       ├── svc-ytuner/run     # Starts YTuner binary
        │       ├── svc-nginx/run      # Starts nginx (depends on svc-ytuner)
        │       ├── svc-transcode/run  # Starts transcode-proxy.py
        │       └── svc-webui/run      # Starts webui.py
        └── opt/ytuner/
            ├── webui.py               # Web management UI (~3000 lines, single-file)
            └── transcode-proxy.py     # FFmpeg transcoding proxy (~155 lines)
```

## Key Files

| File | Purpose |
|------|---------|
| `ytuner/config.yaml` | HA add-on manifest — version, ports, options schema |
| `ytuner/Dockerfile` | Container build — downloads YTuner binary, installs deps |
| `ytuner/rootfs/opt/ytuner/webui.py` | **Main development file** — entire web UI (Python + embedded HTML/CSS/JS) |
| `ytuner/rootfs/opt/ytuner/transcode-proxy.py` | FFmpeg transcoding proxy |
| `ytuner/rootfs/etc/s6-overlay/s6-rc.d/init-config/run` | Startup config generation script |
| `ytuner/rootfs/etc/nginx/nginx.conf` | Nginx reverse proxy with Host:$remote_addr trick |
| `ytuner/CHANGELOG.md` | Must be updated with every version bump |

## Persistent Data (Container /data/ Volume)

| Path | Format | Purpose |
|------|--------|---------|
| `/data/config/stations.ini` | INI | Station library (categories + stream URLs) |
| `/data/config/<ip>.xml` | XML | Libratone speaker preset mappings |
| `/data/config/avr.ini` | INI | AVR device preferences |
| `/data/speakers.json` | JSON | Speaker IP-to-name mappings |
| `/data/links.json` | JSON | Quick links for web UI |
| `/data/ytuner.log` | Text | YTuner server log (tailed by web UI) |
| `/data/nginx-access.log` | Text | Nginx access log (used by speaker discovery) |
| `/data/db/` | SQLite | Radio-browser.info cache |

## webui.py Architecture

Single-file Python HTTP server (stdlib only, no pip dependencies). All HTML/CSS/JS is embedded in a `HTML_PAGE` raw string constant.

**Backend structure:**
- Config helpers: `read_stations_ini()`, `write_stations_ini()`, `read_speaker_xml()`, `write_speaker_xml()`, etc.
- `WebUIHandler(BaseHTTPRequestHandler)` with `do_GET`, `do_POST`, `do_DELETE` routing to `_handle_*` methods
- Background threads for speaker discovery and station health checks
- Stream probing via HEAD/GET requests

**API endpoints:**
- `/api/speakers` — CRUD for Libratone speaker configs
- `/api/speakers/<ip>/presets` — Save preset assignments
- `/api/stations` — Read/write station library
- `/api/stations/search` — Radio-browser.info search proxy
- `/api/stations/probe` — Test stream URL accessibility
- `/api/stations/healthcheck` — Background health check (POST=start, GET=status)
- `/api/stations/import` — Parse M3U/OPML files
- `/api/discovery/*` — Speaker preset ID discovery wizard
- `/api/services/*` — Service status and restart
- `/api/backup` — Export/import full config bundle
- `/api/logs` — Tail log files
- `/api/links` — Quick links management

**Frontend tabs:** Speakers, Station Library, Services, Logs, Links

**HA Ingress compatibility:** API paths are resolved relative to page base URL (not absolute `/api/...`) to work inside HA's ingress iframe proxy.

## Add-on Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `transcode_bitrate` | str | "192k" | MP3 encoding bitrate |
| `transcode_max_concurrent` | int(1-16) | 4 | Max simultaneous FFmpeg processes |
| `log_level` | list | "info" | none/info/warning/error/debug |

## Version Bumping

When releasing a new version, update **both**:
1. `ytuner/config.yaml` — `version: "X.Y.Z"`
2. `ytuner/CHANGELOG.md` — Add new section at top

## Common Commands

```bash
# Validate webui.py syntax
python3 -c "import py_compile; py_compile.compile('ytuner/rootfs/opt/ytuner/webui.py', doraise=True)"

# Run web UI locally for testing (uses defaults, needs config files)
cd ha-addon-ytuner && python3 ytuner/rootfs/opt/ytuner/webui.py

# Inside running container
s6-svc -r /run/service/svc-ytuner     # restart ytuner
s6-svstat /run/service/svc-ytuner     # check status
tail -f /data/ytuner.log              # view logs
curl http://localhost:8888/health      # test transcode proxy
```

## Important Constraints

- **No pip dependencies** — webui.py and transcode-proxy.py use Python stdlib only
- **Single-file web UI** — all HTML/CSS/JS is embedded in webui.py's `HTML_PAGE` string
- **Host networking required** — AVR devices must reach the container directly on port 80
- **DNS redirection required** — `*.vtuner.com` must resolve to the HA server IP
- **Streams must be HTTP + MP3** for Libratone — use transcode proxy for HTTPS/non-MP3
- **CommonBookmark=0** in ytuner.ini — enables per-device presets (required for Libratone)
- **Speaker XML format** — StationId must be `UNB` + firmware preset ID (discovered via web UI wizard)

## Libratone Speaker Integration

Libratone speakers have firmware-hardcoded preset IDs. The web UI's discovery wizard:
1. Tails nginx access log for `sSearchtype=3&search=<id>` patterns
2. User presses preset buttons 1-5 on the physical speaker
3. Captures the unique IDs, creates `<ip>.xml` mapping UNB IDs to station URLs

Each speaker gets a device-specific XML at `/data/config/<speaker-ip>.xml`.
