# Changelog

## 1.1.1

- Remove URL column from speaker preset table for a cleaner view
- Sort station library alphabetically by station name and category
- Remove manual station reorder controls (drag-and-drop, up/down arrows)

## 1.1.0

- Add Backup & Restore: export/import all config (stations, speakers, links) as a single JSON file
- Add Copy Presets Between Speakers: copy station assignments from one speaker to another
- Add Log Viewer tab: view YTuner and Nginx logs with line count selector and refresh
- Add Station Health Check: probe all stations for connectivity, mark dead stations inline
- Add M3U/OPML Import: import station lists from .m3u, .m3u8, and .opml files with preview
- Add Station & Category Reordering: up/down arrows and drag-and-drop to reorder stations and categories
- Fix mobile responsiveness: header tabs wrap, preset table uses stacked layout, station items wrap, modals fit screen

## 1.0.5

- Fix JS syntax error that broke the entire web UI
  - Regex in Python raw string produced invalid JS (`/^\\/` instead of `/^\/`)
  - This caused a parse error preventing all JavaScript from executing
  - Tabs, buttons, and all UI interactions were non-functional
- Add console logging for debugging API base path detection

## 1.0.4

- Fix web UI not working inside Home Assistant ingress iframe
  - API calls used absolute paths (`/api/speakers`) which broke under ingress proxy
  - Now resolves API paths relative to the page base URL
- Fix duplicate preset IDs during speaker discovery
  - Cycling through presets no longer records the same ID multiple times
  - Only unique preset IDs are added to the discovery list

## 1.0.3

- Fix speaker discovery: parse nginx access log instead of YTuner debug log
  - YTuner log shows hostname (company2.vtuner.com) not IP, so the old regex never matched
  - Nginx access log has both client IP and search ID on one line — much more reliable
  - Falls back to YTuner debug log parsing for non-container installs
- Write nginx access log to /data/nginx-access.log for discovery to tail

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
