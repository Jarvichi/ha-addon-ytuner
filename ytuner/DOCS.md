# YTuner Home Assistant Add-on

## Overview

YTuner is a vTuner internet radio replacement service for AVR devices (Yamaha, Denon, Pioneer, Marantz) and Libratone speakers. This add-on packages the entire YTuner stack into a single Home Assistant add-on.

## Services

The add-on runs four services:

| Service | Port | Description |
|---------|------|-------------|
| **Nginx** | 80 | Reverse proxy that forwards AVR requests to YTuner, setting the client IP as the Host header for per-device bookmarks |
| **YTuner** | 18081 (internal) | The vTuner-compatible radio directory server |
| **Web UI** | 8080 | Web interface for managing speakers, presets, and station library |
| **Transcode Proxy** | 8888 | Converts non-MP3 streams to MP3 on-the-fly via FFmpeg |

## Configuration

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `transcode_bitrate` | `192k` | MP3 bitrate for transcoded streams (e.g., `128k`, `192k`, `320k`) |
| `transcode_max_concurrent` | `4` | Maximum simultaneous transcode streams (1-16) |
| `log_level` | `info` | YTuner log level: `none`, `info`, `warning`, `error`, `debug` |

### Network

The add-on uses **host networking** so AVR devices on your LAN can reach the HTTP server on port 80. This is required because AVR devices expect to connect to `vtuner.com` which must resolve to your server's IP.

### DNS Setup

For AVR devices to find YTuner, you need to redirect vTuner DNS queries to your Home Assistant server. Options:

1. **Router DNS override** — configure your router to resolve `*.vtuner.com` to your HA server IP
2. **Pi-hole / AdGuard Home** — add a DNS rewrite rule for `*.vtuner.com`
3. **dnsmasq** — add `address=/vtuner.com/<HA-IP>` to your config

The add-on's built-in DNS server is disabled by default in container mode (it would conflict with HA's DNS).

## Persistent Data

All configuration survives add-on updates and restarts:

| Data | Location |
|------|----------|
| Station library | `/data/config/stations.ini` |
| AVR device config | `/data/config/avr.ini` |
| Speaker XML files | `/data/config/*.xml` |
| Bookmark files | `/data/config/bookmark*.xml` |
| Radio browser cache | `/data/db/` |
| Speaker names | `/data/speakers.json` |
| Web UI links | `/data/links.json` |

## Libratone Speakers

Libratone speakers have firmware-hardcoded preset IDs. Use the Web UI's **Add New Speaker** wizard to discover preset IDs automatically:

1. Open the Web UI (port 8080 or via the HA sidebar)
2. Click **Add New Speaker**
3. Turn on the Libratone speaker and press each preset button 1-5
4. The wizard captures the preset IDs and lets you assign stations

### Requirements for Libratone

- Streams must be HTTP (not HTTPS) and MP3 codec
- Use the transcode proxy (`http://<HA-IP>:8888/transcode?url=...`) for HTTPS or non-MP3 streams
- The `CommonBookmark` setting is automatically set to `0` (per-device bookmarks)

## Station Library

Manage stations via the Web UI or by editing `stations.ini` directly.

### INI Format

```ini
[Category Name]
Station Name=http://stream-url
Another Station=http://stream-url|http://logo-url
```

### Transcoded Streams

For streams that need transcoding (HTTPS or non-MP3):

```
http://<HA-IP>:8888/transcode?url=https%3A%2F%2Fexample.com%2Fstream.aac&bitrate=192k
```

The Web UI handles this automatically when adding stations from Radio Browser search.

## Troubleshooting

### AVR devices can't find radio stations
- Verify DNS is redirecting `*.vtuner.com` to your HA server IP
- Check that port 80 is not used by another service on the host
- View the add-on logs for connection attempts

### Streams don't play
- Verify the stream URL is accessible: `curl -I http://stream-url`
- For HTTPS streams, use the transcode proxy
- Check FFmpeg is working: visit `http://<HA-IP>:8888/health`

### Web UI not accessible
- Try `http://<HA-IP>:8080` directly
- Check the add-on logs for startup errors
