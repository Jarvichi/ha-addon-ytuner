#!/usr/bin/env python3
"""
YTuner Web Management Interface.
Single-file web app for managing Libratone speaker presets and station library.
Serves on port 8080 — stdlib only, no pip installs needed.
"""

import collections
import configparser
import datetime
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote
from urllib.request import urlopen, Request
from urllib.error import URLError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger("webui")

HOST = "0.0.0.0"
PORT = int(os.environ.get("WEBUI_PORT", "8080"))
CONFIG_DIR = "/opt/ytuner/config"
DATA_DIR = os.environ.get("YTUNER_DATA_DIR", "/opt/ytuner")
STATIONS_INI = os.path.join(CONFIG_DIR, "stations.ini")
SPEAKERS_JSON = os.path.join(DATA_DIR, "speakers.json")
LINKS_JSON = os.path.join(DATA_DIR, "links.json")
LOG_FILE = os.environ.get("YTUNER_LOG_FILE", "/proc/1/fd/1")  # container stdout
TRANSCODE_PORT = os.environ.get("TRANSCODE_PORT", "8888")


def _detect_ip():
    """Auto-detect the server's LAN IP address."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


SERVER_IP = os.environ.get("YTUNER_SERVER_IP") or _detect_ip()
TRANSCODE_PROXY = f"http://{SERVER_IP}:{TRANSCODE_PORT}/transcode?url="

DEFAULT_LINKS = []

# ── Discovery state (shared across threads) ─────────────────────────────────

discovery_lock = threading.Lock()
discovery_state = {
    "active": False,
    "ip": None,
    "presets": [],        # list of {"id": "12345", "index": 1}
    "expected": 1,        # next preset number we expect
    "done": False,
    "error": None,
    "tail_proc": None,
    "thread": None,
}


def reset_discovery():
    with discovery_lock:
        if discovery_state["tail_proc"]:
            try:
                discovery_state["tail_proc"].kill()
            except Exception:
                pass
        discovery_state.update({
            "active": False, "ip": None, "presets": [],
            "expected": 1, "done": False, "error": None,
            "tail_proc": None, "thread": None,
        })


def _discovery_log_file():
    """Return the best log file for discovery: nginx access log or ytuner log."""
    for path in ["/data/nginx-access.log", LOG_FILE]:
        if os.path.exists(path):
            return path
    return LOG_FILE


def discovery_watcher():
    """Background thread: tail nginx access log for speaker preset requests."""
    try:
        log_path = _discovery_log_file()
        proc = subprocess.Popen(
            ["tail", "-F", "-n", "0", log_path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True,
        )
        with discovery_lock:
            discovery_state["tail_proc"] = proc

        # Matches nginx access log: "192.168.5.31 - - [...] "GET /...?search=80195 ..."
        nginx_re = re.compile(r"^([\d.]+)\s.*sSearchtype=3&search=(\d+)")
        # Fallback: YTuner debug log (two-line: Device then search)
        device_re = re.compile(r"Device : \? -> ([\d.]+)\.")
        search_re = re.compile(r"search=(\d+)")

        pending_ip = None

        for line in proc.stdout:
            with discovery_lock:
                if not discovery_state["active"]:
                    break

            # Try nginx access log format first (IP + search on same line)
            m_nginx = nginx_re.search(line)
            if m_nginx:
                client_ip = m_nginx.group(1)
                station_id = m_nginx.group(2)
                with discovery_lock:
                    if discovery_state["ip"] is None:
                        xml_path = os.path.join(CONFIG_DIR, f"{client_ip}.xml")
                        if os.path.exists(xml_path):
                            continue
                        discovery_state["ip"] = client_ip

                    if client_ip == discovery_state["ip"]:
                        existing_ids = {p["id"] for p in discovery_state["presets"]}
                        if station_id not in existing_ids:
                            idx = discovery_state["expected"]
                            discovery_state["presets"].append({
                                "id": station_id,
                                "index": idx,
                            })
                            discovery_state["expected"] = idx + 1
                            if idx >= 5:
                                discovery_state["done"] = True

                    if discovery_state["done"]:
                        break
                continue

            # Fallback: YTuner debug log (two separate lines)
            m_dev = device_re.search(line)
            if m_dev:
                pending_ip = m_dev.group(1)
                continue

            m_search = search_re.search(line)
            if m_search and pending_ip:
                station_id = m_search.group(1)
                with discovery_lock:
                    if discovery_state["ip"] is None:
                        xml_path = os.path.join(CONFIG_DIR, f"{pending_ip}.xml")
                        if os.path.exists(xml_path):
                            pending_ip = None
                            continue
                        discovery_state["ip"] = pending_ip

                    if pending_ip == discovery_state["ip"]:
                        existing_ids = {p["id"] for p in discovery_state["presets"]}
                        if station_id not in existing_ids:
                            idx = discovery_state["expected"]
                            discovery_state["presets"].append({
                                "id": station_id,
                                "index": idx,
                            })
                            discovery_state["expected"] = idx + 1
                            if idx >= 5:
                                discovery_state["done"] = True

                pending_ip = None

                with discovery_lock:
                    if discovery_state["done"]:
                        break

    except Exception as e:
        with discovery_lock:
            discovery_state["error"] = str(e)
    finally:
        with discovery_lock:
            if discovery_state["tail_proc"]:
                try:
                    discovery_state["tail_proc"].kill()
                except Exception:
                    pass


# ── Config helpers ───────────────────────────────────────────────────────────

def validate_ip(ip):
    """Validate IP address format to prevent path traversal."""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip))


def read_speaker_names():
    """Read speaker IP-to-name mappings from speakers.json."""
    if os.path.exists(SPEAKERS_JSON):
        try:
            with open(SPEAKERS_JSON, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def write_speaker_names(names):
    """Write speaker IP-to-name mappings to speakers.json."""
    with open(SPEAKERS_JSON, "w") as f:
        json.dump(names, f, indent=2)


def read_links():
    """Read links from links.json, or return defaults."""
    if os.path.exists(LINKS_JSON):
        try:
            with open(LINKS_JSON, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return list(DEFAULT_LINKS)


def write_links(links):
    """Write links to links.json."""
    with open(LINKS_JSON, "w") as f:
        json.dump(links, f, indent=2)


def read_speaker_xml(ip):
    """Parse a speaker XML config, return list of 5 presets."""
    path = os.path.join(CONFIG_DIR, f"{ip}.xml")
    if not os.path.exists(path):
        return None
    tree = ET.parse(path)
    root = tree.getroot()
    presets = []
    for item in root.findall("Item"):
        presets.append({
            "id": item.findtext("StationId", ""),
            "name": item.findtext("StationName", ""),
            "url": item.findtext("StationUrl", ""),
            "desc": item.findtext("StationDesc", ""),
            "format": item.findtext("StationFormat", ""),
            "logo": item.findtext("Logo", ""),
            "mime": item.findtext("StationMime", ""),
        })
    return presets


def write_speaker_xml(ip, presets):
    """Write 5-preset XML config for a speaker."""
    root = ET.Element("ListOfItems")
    ET.SubElement(root, "ItemCount").text = "5"
    for i, p in enumerate(presets):
        item = ET.SubElement(root, "Item")
        ET.SubElement(item, "ItemType").text = "Station"
        ET.SubElement(item, "StationId").text = p.get("id", f"UNB{i}")
        ET.SubElement(item, "StationName").text = p.get("name", "")
        ET.SubElement(item, "StationUrl").text = p.get("url", "")
        ET.SubElement(item, "StationDesc").text = p.get("desc", f"Preset {i+1}")
        ET.SubElement(item, "Logo").text = p.get("logo", "")
        ET.SubElement(item, "StationFormat").text = p.get("format", "")
        ET.SubElement(item, "StationLocation")
        ET.SubElement(item, "StationBandWidth")
        ET.SubElement(item, "StationMime").text = p.get("mime", "")
        ET.SubElement(item, "Relia").text = "3"
        ET.SubElement(item, "Bookmark")

    ET.indent(root, space="  ")
    path = os.path.join(CONFIG_DIR, f"{ip}.xml")
    tree = ET.ElementTree(root)
    tree.write(path, encoding="unicode", xml_declaration=True)
    # Add trailing newline
    with open(path, "a") as f:
        f.write("\n")


def list_speakers():
    """Return list of speaker IPs from XML config files."""
    speakers = []
    for fname in sorted(os.listdir(CONFIG_DIR)):
        if fname.endswith(".xml"):
            name = fname[:-4]
            if validate_ip(name):
                speakers.append(name)
    return speakers


def read_stations_ini():
    """Parse stations.ini into {category: [{name, url}, ...]}."""
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str  # preserve case
    config.read(STATIONS_INI, encoding="utf-8")
    result = {}
    for section in config.sections():
        stations = []
        for name, url in config.items(section):
            stations.append({"name": name, "url": url})
        result[section] = stations
    return result


def write_stations_ini(data):
    """Write stations.ini from {category: [{name, url}, ...]}."""
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    for section, stations in data.items():
        config.add_section(section)
        for s in stations:
            config.set(section, s["name"], s["url"])
    with open(STATIONS_INI, "w", encoding="utf-8") as f:
        config.write(f)


def needs_transcode(url):
    """Check if a URL needs transcoding (HTTPS or non-MP3 indicators)."""
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return True
    path_lower = parsed.path.lower()
    for ext in [".aac", ".ogg", ".flac", ".m4a", ".opus", ".wma"]:
        if path_lower.endswith(ext):
            return True
    return False


def wrap_transcode(url):
    """Wrap a URL through the transcode proxy if needed."""
    if needs_transcode(url):
        return TRANSCODE_PROXY + quote(url, safe="")
    return url


def probe_stream(url):
    """Probe a stream URL to detect content type and whether transcoding is needed."""
    parsed = urlparse(url)
    result = {"url": url, "content_type": None, "needs_transcode": False, "reason": ""}

    # HTTPS always needs transcoding (devices can't handle it)
    if parsed.scheme == "https":
        result["needs_transcode"] = True
        result["reason"] = "HTTPS stream — devices require HTTP"

    # Try HEAD first, fall back to GET
    content_type = None
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "YTuner-WebUI/1.0"})
        with urlopen(req, timeout=5) as resp:
            content_type = resp.headers.get("Content-Type", "").lower().split(";")[0].strip()
    except Exception:
        try:
            req = Request(url, headers={"User-Agent": "YTuner-WebUI/1.0", "Range": "bytes=0-0"})
            with urlopen(req, timeout=5) as resp:
                content_type = resp.headers.get("Content-Type", "").lower().split(";")[0].strip()
        except Exception as e:
            result["content_type"] = "unknown"
            if not result["reason"]:
                result["reason"] = f"Could not probe stream: {e}"
                result["needs_transcode"] = True
            return result

    result["content_type"] = content_type or "unknown"

    mp3_types = {"audio/mpeg", "audio/mp3"}
    transcode_types = {"audio/aac", "audio/aacp", "audio/ogg", "audio/flac",
                       "audio/x-flac", "application/ogg", "audio/opus",
                       "audio/x-ms-wma", "audio/wav", "audio/x-wav",
                       "audio/mp4", "audio/x-m4a"}

    if content_type in mp3_types:
        if not result["needs_transcode"]:
            result["needs_transcode"] = False
            result["reason"] = "MP3 stream — no transcoding needed"
        else:
            result["reason"] += "; content is MP3 but HTTPS requires proxy"
    elif content_type in transcode_types:
        result["needs_transcode"] = True
        reason = f"Non-MP3 format ({content_type}) — transcoding needed"
        if result["reason"]:
            result["reason"] += "; " + reason
        else:
            result["reason"] = reason
    elif content_type and content_type != "unknown":
        if not result["needs_transcode"]:
            result["reason"] = f"Content type: {content_type} — may or may not need transcoding"
    else:
        if not result["needs_transcode"]:
            result["needs_transcode"] = True
            result["reason"] = "Unknown content type — transcoding recommended"

    return result


# ── Health check state (shared across threads) ───────────────────────────────

healthcheck_lock = threading.Lock()
healthcheck_state = {
    "running": False,
    "total": 0,
    "checked": 0,
    "results": [],  # list of {"category", "name", "url", "alive": bool, "error": str}
}


def _healthcheck_worker():
    """Background thread: probe all stations for health."""
    try:
        stations = read_stations_ini()
        items = []
        for cat, stns in stations.items():
            for s in stns:
                items.append((cat, s["name"], s["url"]))
        with healthcheck_lock:
            healthcheck_state["total"] = len(items)
            healthcheck_state["checked"] = 0
            healthcheck_state["results"] = []

        for cat, name, url in items:
            alive = False
            error = ""
            try:
                # Strip transcode wrapper to probe the actual stream
                probe_url = url
                try:
                    u = urlparse(url)
                    if u.path == "/transcode" and "url=" in (u.query or ""):
                        qs = parse_qs(u.query)
                        if "url" in qs:
                            probe_url = qs["url"][0]
                except Exception:
                    pass
                req = Request(probe_url, method="HEAD",
                              headers={"User-Agent": "YTuner-WebUI/1.0"})
                with urlopen(req, timeout=5) as resp:
                    alive = resp.status < 400
            except Exception as e:
                try:
                    req = Request(probe_url,
                                  headers={"User-Agent": "YTuner-WebUI/1.0",
                                           "Range": "bytes=0-0"})
                    with urlopen(req, timeout=5) as resp:
                        alive = resp.status < 400
                except Exception as e2:
                    error = str(e2)

            result = {"category": cat, "name": name, "url": url,
                      "alive": alive, "error": error}
            with healthcheck_lock:
                healthcheck_state["results"].append(result)
                healthcheck_state["checked"] += 1
    except Exception as e:
        log.error("Health check failed: %s", e)
    finally:
        with healthcheck_lock:
            healthcheck_state["running"] = False


def _is_container():
    """Detect if running inside a container (HA add-on)."""
    return os.path.exists("/run/s6/container_environment")


def restart_ytuner():
    """Restart the ytuner service."""
    try:
        if _is_container():
            # S6-overlay: restart the service via s6-svc
            subprocess.run(
                ["s6-svc", "-r", "/run/service/svc-ytuner"],
                capture_output=True, timeout=10,
            )
        else:
            subprocess.run(
                ["sudo", "systemctl", "restart", "ytuner"],
                capture_output=True, timeout=10,
            )
    except Exception:
        pass


def get_service_status(service):
    """Get service status (S6 or systemd)."""
    if _is_container():
        svc_map = {"ytuner": "svc-ytuner", "transcode-proxy": "svc-transcode"}
        svc_name = svc_map.get(service, service)
        try:
            result = subprocess.run(
                ["s6-svstat", f"/run/service/{svc_name}"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.strip()
            if "up" in output:
                return f"Active: active (running) - {output}"
            return f"Active: inactive - {output}"
        except Exception as e:
            return f"error: {e}"
    else:
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "status", service],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Active:"):
                    return line
            return "unknown"
        except Exception as e:
            return f"error: {e}"


# ── HTTP Handler ─────────────────────────────────────────────────────────────

class WebUIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[{self.client_address[0]}] {fmt % args}", flush=True)

    def _send_json(self, data, status=200):
        if status >= 400:
            log.error("HTTP %d %s — %s", status, self.path, data.get("error", data))
            if status >= 500:
                log.error("Traceback:\n%s", traceback.format_exc())
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            config_script = (
                f'<script>const SERVER_IP="{SERVER_IP}";'
                f'const TRANSCODE_PORT="{TRANSCODE_PORT}";</script>'
            )
            self._send_html(HTML_PAGE.replace("</head>", config_script + "</head>"))
        elif path == "/api/speakers":
            self._handle_list_speakers()
        elif path.startswith("/api/speakers/"):
            ip = path.split("/")[3]
            self._handle_get_speaker(ip)
        elif path == "/api/stations":
            self._handle_list_stations()
        elif path == "/api/stations/search":
            self._handle_search_stations(params)
        elif path == "/api/stations/probe":
            self._handle_probe_station(params)
        elif path == "/api/discovery/status":
            self._handle_discovery_status()
        elif path == "/api/services/status":
            self._handle_services_status()
        elif path == "/api/links":
            self._handle_list_links()
        elif path == "/api/backup":
            self._handle_backup_export()
        elif path == "/api/logs":
            self._handle_logs(params)
        elif path == "/api/stations/healthcheck":
            self._handle_healthcheck_status()
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/speakers/") and path.endswith("/presets"):
            ip = path.split("/")[3]
            self._handle_save_presets(ip)
        elif path.startswith("/api/speakers/") and path.endswith("/name"):
            ip = path.split("/")[3]
            self._handle_rename_speaker(ip)
        elif path == "/api/speakers":
            self._handle_add_speaker()
        elif path == "/api/stations":
            self._handle_save_stations()
        elif path == "/api/discovery/start":
            self._handle_discovery_start()
        elif path == "/api/discovery/stop":
            self._handle_discovery_stop()
        elif path == "/api/services/restart":
            self._handle_service_restart()
        elif path == "/api/links":
            self._handle_save_links()
        elif path == "/api/backup/restore":
            self._handle_backup_restore()
        elif path == "/api/stations/healthcheck":
            self._handle_healthcheck_start()
        elif path == "/api/stations/import":
            self._handle_station_import()
        else:
            self.send_error(404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/speakers/"):
            ip = path.split("/")[3]
            self._handle_delete_speaker(ip)
        else:
            self.send_error(404)

    # ── Speaker endpoints ────────────────────────────────────────────────

    def _handle_list_speakers(self):
        names = read_speaker_names()
        speakers = []
        for ip in list_speakers():
            presets = read_speaker_xml(ip)
            speakers.append({
                "ip": ip,
                "name": names.get(ip, ""),
                "presets": presets,
            })
        self._send_json(speakers)

    def _handle_get_speaker(self, ip):
        if not validate_ip(ip):
            self._send_json({"error": "Invalid IP"}, 400)
            return
        presets = read_speaker_xml(ip)
        if presets is None:
            self._send_json({"error": "Speaker not found"}, 404)
            return
        names = read_speaker_names()
        self._send_json({"ip": ip, "name": names.get(ip, ""), "presets": presets})

    def _handle_save_presets(self, ip):
        if not validate_ip(ip):
            self._send_json({"error": "Invalid IP"}, 400)
            return
        try:
            data = json.loads(self._read_body())
            presets = data["presets"]
            write_speaker_xml(ip, presets)
            threading.Thread(target=restart_ytuner, daemon=True).start()
            self._send_json({"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_rename_speaker(self, ip):
        if not validate_ip(ip):
            self._send_json({"error": "Invalid IP"}, 400)
            return
        try:
            data = json.loads(self._read_body())
            name = data.get("name", "").strip()
            names = read_speaker_names()
            if name:
                names[ip] = name
            else:
                names.pop(ip, None)
            write_speaker_names(names)
            self._send_json({"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_add_speaker(self):
        try:
            data = json.loads(self._read_body())
            ip = data["ip"]
            if not validate_ip(ip):
                self._send_json({"error": "Invalid IP"}, 400)
                return
            presets = data["presets"]
            write_speaker_xml(ip, presets)
            # Save name if provided
            speaker_name = data.get("name", "").strip()
            if speaker_name:
                names = read_speaker_names()
                names[ip] = speaker_name
                write_speaker_names(names)
            threading.Thread(target=restart_ytuner, daemon=True).start()
            self._send_json({"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_delete_speaker(self, ip):
        if not validate_ip(ip):
            self._send_json({"error": "Invalid IP"}, 400)
            return
        path = os.path.join(CONFIG_DIR, f"{ip}.xml")
        if not os.path.exists(path):
            self._send_json({"error": "Not found"}, 404)
            return
        try:
            os.remove(path)
        except PermissionError:
            self._send_json({"error": f"Permission denied: cannot delete {path}"}, 500)
            return
        # Remove name mapping too
        names = read_speaker_names()
        names.pop(ip, None)
        write_speaker_names(names)
        threading.Thread(target=restart_ytuner, daemon=True).start()
        self._send_json({"ok": True})

    # ── Station library endpoints ────────────────────────────────────────

    def _handle_list_stations(self):
        self._send_json(read_stations_ini())

    def _handle_save_stations(self):
        try:
            data = json.loads(self._read_body())
            write_stations_ini(data)
            self._send_json({"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_search_stations(self, params):
        query = params.get("q", [""])[0]
        if not query or len(query) < 2:
            self._send_json({"error": "Query too short"}, 400)
            return
        try:
            api_url = (
                f"https://de1.api.radio-browser.info/json/stations/byname/{quote(query)}"
                f"?limit=30&order=clickcount&reverse=true&hidebroken=true"
            )
            req = Request(api_url, headers={"User-Agent": "YTuner-WebUI/1.0"})
            with urlopen(req, timeout=8) as resp:
                results = json.loads(resp.read())

            stations = []
            for r in results:
                url = r.get("url_resolved") or r.get("url", "")
                stations.append({
                    "name": r.get("name", "").strip(),
                    "url": url,
                    "codec": r.get("codec", ""),
                    "bitrate": r.get("bitrate", 0),
                    "country": r.get("country", ""),
                    "tags": r.get("tags", ""),
                    "favicon": r.get("favicon", ""),
                    "needs_transcode": needs_transcode(url),
                })
            self._send_json(stations)
        except Exception as e:
            self._send_json({"error": str(e)}, 502)

    def _handle_probe_station(self, params):
        url = params.get("url", [""])[0]
        if not url:
            self._send_json({"error": "URL required"}, 400)
            return
        try:
            result = probe_stream(url)
            self._send_json(result)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # ── Discovery endpoints ──────────────────────────────────────────────

    def _handle_discovery_start(self):
        reset_discovery()
        with discovery_lock:
            discovery_state["active"] = True
        t = threading.Thread(target=discovery_watcher, daemon=True)
        with discovery_lock:
            discovery_state["thread"] = t
        t.start()
        self._send_json({"ok": True})

    def _handle_discovery_stop(self):
        reset_discovery()
        self._send_json({"ok": True})

    def _handle_discovery_status(self):
        with discovery_lock:
            self._send_json({
                "active": discovery_state["active"],
                "ip": discovery_state["ip"],
                "presets": list(discovery_state["presets"]),
                "expected": discovery_state["expected"],
                "done": discovery_state["done"],
                "error": discovery_state["error"],
            })

    # ── Services endpoints ───────────────────────────────────────────────

    def _handle_services_status(self):
        self._send_json({
            "ytuner": get_service_status("ytuner"),
            "transcode-proxy": get_service_status("transcode-proxy"),
        })

    def _handle_service_restart(self):
        try:
            data = json.loads(self._read_body())
            service = data.get("service", "")
            if service not in ("ytuner", "transcode-proxy"):
                self._send_json({"error": "Invalid service"}, 400)
                return
            if _is_container():
                svc_map = {"ytuner": "svc-ytuner", "transcode-proxy": "svc-transcode"}
                svc_name = svc_map.get(service, service)
                subprocess.run(
                    ["s6-svc", "-r", f"/run/service/{svc_name}"],
                    capture_output=True, timeout=10,
                )
            else:
                subprocess.run(
                    ["sudo", "systemctl", "restart", service],
                    capture_output=True, timeout=10,
                )
            time.sleep(1)
            status = get_service_status(service)
            self._send_json({"ok": True, "status": status})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # ── Links endpoints ──────────────────────────────────────────────────

    def _handle_list_links(self):
        self._send_json(read_links())

    def _handle_save_links(self):
        try:
            data = json.loads(self._read_body())
            write_links(data)
            self._send_json({"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # ── Backup & Restore endpoints ────────────────────────────────────

    def _handle_backup_export(self):
        try:
            bundle = {
                "version": 1,
                "date": datetime.datetime.now().isoformat(),
                "stations_ini": "",
                "speakers_json": {},
                "links_json": [],
                "speaker_xmls": {},
            }
            if os.path.exists(STATIONS_INI):
                with open(STATIONS_INI, "r", encoding="utf-8") as f:
                    bundle["stations_ini"] = f.read()
            bundle["speakers_json"] = read_speaker_names()
            bundle["links_json"] = read_links()
            for ip in list_speakers():
                xml_path = os.path.join(CONFIG_DIR, f"{ip}.xml")
                if os.path.exists(xml_path):
                    with open(xml_path, "r", encoding="utf-8") as f:
                        bundle["speaker_xmls"][ip] = f.read()
            body = json.dumps(bundle, indent=2).encode()
            datestamp = datetime.datetime.now().strftime("%Y%m%d")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition",
                             f'attachment; filename="ytuner-backup-{datestamp}.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_backup_restore(self):
        try:
            data = json.loads(self._read_body())
            if data.get("version") != 1:
                self._send_json({"error": "Unknown backup version"}, 400)
                return
            # Restore stations.ini
            if data.get("stations_ini"):
                with open(STATIONS_INI, "w", encoding="utf-8") as f:
                    f.write(data["stations_ini"])
            # Restore speakers.json
            if "speakers_json" in data:
                write_speaker_names(data["speakers_json"])
            # Restore links.json
            if "links_json" in data:
                write_links(data["links_json"])
            # Restore speaker XMLs
            for ip, xml_content in data.get("speaker_xmls", {}).items():
                if validate_ip(ip):
                    xml_path = os.path.join(CONFIG_DIR, f"{ip}.xml")
                    with open(xml_path, "w", encoding="utf-8") as f:
                        f.write(xml_content)
            threading.Thread(target=restart_ytuner, daemon=True).start()
            self._send_json({"ok": True})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # ── Log Viewer endpoint ───────────────────────────────────────────

    def _handle_logs(self, params):
        file_key = params.get("file", ["ytuner"])[0]
        lines = min(int(params.get("lines", ["100"])[0]), 500)
        log_paths = {
            "ytuner": LOG_FILE,
            "nginx": "/data/nginx-access.log",
        }
        path = log_paths.get(file_key)
        if not path:
            self._send_json({"error": "Unknown log file"}, 400)
            return
        if not os.path.exists(path):
            self._send_json({"lines": [], "file": file_key,
                             "error": f"Log file not found: {path}"})
            return
        try:
            with open(path, "rb") as f:
                dq = collections.deque(f, maxlen=lines)
            log_lines = []
            for raw in dq:
                try:
                    log_lines.append(raw.decode("utf-8", errors="replace").rstrip("\n"))
                except Exception:
                    log_lines.append(raw.decode("latin-1").rstrip("\n"))
            self._send_json({"lines": log_lines, "file": file_key})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # ── Health Check endpoints ────────────────────────────────────────

    def _handle_healthcheck_start(self):
        with healthcheck_lock:
            if healthcheck_state["running"]:
                self._send_json({"error": "Health check already running"}, 409)
                return
            healthcheck_state["running"] = True
            healthcheck_state["total"] = 0
            healthcheck_state["checked"] = 0
            healthcheck_state["results"] = []
        t = threading.Thread(target=_healthcheck_worker, daemon=True)
        t.start()
        self._send_json({"ok": True})

    def _handle_healthcheck_status(self):
        with healthcheck_lock:
            self._send_json({
                "running": healthcheck_state["running"],
                "total": healthcheck_state["total"],
                "checked": healthcheck_state["checked"],
                "results": list(healthcheck_state["results"]),
            })

    # ── M3U / OPML Import endpoint ────────────────────────────────────

    def _handle_station_import(self):
        try:
            data = json.loads(self._read_body())
            fmt = data.get("format", "").lower()
            content = data.get("content", "")
            if not content:
                self._send_json({"error": "No content provided"}, 400)
                return

            stations = []
            if fmt == "m3u":
                stations = self._parse_m3u(content)
            elif fmt == "opml":
                stations = self._parse_opml(content)
            else:
                self._send_json({"error": f"Unknown format: {fmt}"}, 400)
                return

            self._send_json({"stations": stations})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _parse_m3u(self, content):
        stations = []
        lines = content.splitlines()
        name = None
        for line in lines:
            line = line.strip()
            if line.startswith("#EXTINF:"):
                # #EXTINF:duration,Station Name
                parts = line.split(",", 1)
                name = parts[1].strip() if len(parts) > 1 else "Unknown"
            elif line and not line.startswith("#"):
                stations.append({
                    "name": name or "Unknown",
                    "url": line,
                })
                name = None
        return stations

    def _parse_opml(self, content):
        stations = []
        try:
            root = ET.fromstring(content)
            for outline in root.iter("outline"):
                url = (outline.get("URL") or outline.get("url") or
                       outline.get("xmlUrl") or outline.get("xmlurl") or "")
                text = (outline.get("text") or outline.get("title") or
                        "Unknown")
                otype = (outline.get("type") or "").lower()
                if url and (otype in ("audio", "link", "") or url.startswith("http")):
                    stations.append({"name": text.strip(), "url": url.strip()})
        except ET.ParseError as e:
            raise ValueError(f"Invalid OPML XML: {e}")
        return stations


# ── Embedded HTML/CSS/JS ─────────────────────────────────────────────────────

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>YTuner Manager</title>
<style>
:root {
  --bg: #1a1b2e;
  --surface: #252740;
  --surface2: #2d2f4a;
  --border: #3a3d5c;
  --text: #e0e0f0;
  --text2: #9a9dba;
  --accent: #6c7eff;
  --accent2: #4e5bcc;
  --green: #4caf88;
  --red: #e05555;
  --orange: #e0a050;
  --radius: 8px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  min-height: 100vh;
}
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
header h1 { font-size: 1.3rem; font-weight: 600; }
header h1 span { color: var(--accent); }
.tabs {
  display: flex;
  gap: 4px;
  margin-left: auto;
  flex-wrap: wrap;
}
.tab {
  padding: 8px 20px;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--radius);
  color: var(--text2);
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.15s;
}
.tab:hover { background: var(--surface2); color: var(--text); }
.tab.active {
  background: var(--accent);
  color: #fff;
  border-color: var(--accent);
}
main { max-width: 1100px; margin: 0 auto; padding: 24px; }
.panel { display: none; }
.panel.active { display: block; }

/* Cards */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 16px;
  overflow-x: auto;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.card-header h2 { font-size: 1.1rem; font-weight: 600; }
.card-header h3 { font-size: 1rem; font-weight: 500; }
.ip-badge {
  background: var(--surface2);
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 0.8rem;
  color: var(--text2);
  font-family: monospace;
}

/* Speaker name */
.speaker-title {
  display: flex;
  align-items: center;
  gap: 10px;
}
.speaker-name {
  font-size: 1.1rem;
  font-weight: 600;
}
.speaker-name-input {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 4px 10px;
  color: var(--text);
  font-size: 1rem;
  font-weight: 600;
  width: 220px;
}
.speaker-name-input:focus { outline: none; border-color: var(--accent); }

/* Preset table */
.preset-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.preset-table th {
  text-align: left;
  padding: 6px 10px;
  font-size: 0.75rem;
  text-transform: uppercase;
  color: var(--text2);
  border-bottom: 1px solid var(--border);
}
.preset-table td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  font-size: 0.9rem;
}
.preset-table tr:last-child td { border-bottom: none; }
.preset-num {
  width: 36px;
  text-align: center;
  font-weight: 600;
  color: var(--accent);
}
.unb-badge {
  font-size: 0.65rem;
  font-family: monospace;
  background: var(--surface2);
  color: var(--text2);
  padding: 1px 5px;
  border-radius: 4px;
  margin-left: 4px;
  vertical-align: middle;
}
.btn-move {
  padding: 2px 7px;
  font-size: 0.75rem;
  line-height: 1;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface2);
  color: var(--text);
  cursor: pointer;
  transition: background 0.15s;
}
.btn-move:hover { background: var(--border); }
.preset-url {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text2);
  font-size: 0.8rem;
  font-family: monospace;
  word-break: break-all;
}

/* Buttons */
.btn {
  padding: 6px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface2);
  color: var(--text);
  cursor: pointer;
  font-size: 0.85rem;
  transition: all 0.15s;
  white-space: nowrap;
}
.btn:hover { background: var(--border); }
.btn-primary {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.btn-primary:hover { background: var(--accent2); }
.btn-danger { background: var(--red); border-color: var(--red); color: #fff; }
.btn-danger:hover { opacity: 0.85; }
.btn-sm { padding: 4px 10px; font-size: 0.8rem; }
.btn-group { display: flex; gap: 8px; flex-wrap: wrap; }

/* Forms */
input[type="text"], input[type="url"], select {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 7px 12px;
  color: var(--text);
  font-size: 0.9rem;
  width: 100%;
}
input:focus, select:focus { outline: none; border-color: var(--accent); }
label { font-size: 0.8rem; color: var(--text2); margin-bottom: 4px; display: block; }
.form-row { display: flex; gap: 12px; align-items: end; margin-bottom: 12px; }
.form-group { flex: 1; }

/* Station library */
.category-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
  cursor: pointer;
}
.category-header h3 { font-size: 1rem; }
.category-count {
  font-size: 0.8rem;
  color: var(--text2);
  margin-left: 8px;
}
.station-item {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  gap: 12px;
}
.station-item:last-child { border-bottom: none; }
.station-name { flex: 1; font-size: 0.9rem; }
.station-url {
  flex: 2;
  font-size: 0.8rem;
  color: var(--text2);
  font-family: monospace;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.transcode-badge {
  font-size: 0.7rem;
  background: var(--orange);
  color: #000;
  padding: 2px 6px;
  border-radius: 4px;
  white-space: nowrap;
}

/* Search results */
.search-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}
.search-bar input { flex: 1; }
.search-result {
  display: flex;
  align-items: center;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  gap: 12px;
}
.search-meta { font-size: 0.75rem; color: var(--text2); }

/* Services */
.service-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
}
.service-row:last-child { border-bottom: none; }
.service-name { font-weight: 600; font-size: 1rem; }
.service-status { font-size: 0.85rem; font-family: monospace; }
.status-active { color: var(--green); }
.status-inactive { color: var(--red); }

/* Links */
.link-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 12px;
  transition: border-color 0.15s;
}
.link-card:hover { border-color: var(--accent); }
.link-info { flex: 1; }
.link-info a {
  color: var(--accent);
  text-decoration: none;
  font-size: 1.05rem;
  font-weight: 600;
}
.link-info a:hover { text-decoration: underline; }
.link-desc { color: var(--text2); font-size: 0.85rem; margin-top: 2px; }
.link-url { color: var(--text2); font-size: 0.8rem; font-family: monospace; margin-top: 2px; }

/* Modal */
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  z-index: 100;
  justify-content: center;
  align-items: center;
}
.modal-overlay.open { display: flex; }
.modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  width: 90%;
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
}
.modal h2 { margin-bottom: 16px; }

/* Discovery wizard */
.wizard-step {
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
}
.wizard-step:last-child { border-bottom: none; }
.step-label {
  font-size: 0.8rem;
  text-transform: uppercase;
  color: var(--text2);
  margin-bottom: 4px;
}
.pulse {
  display: inline-block;
  width: 10px;
  height: 10px;
  background: var(--accent);
  border-radius: 50%;
  animation: pulse 1.2s infinite;
  margin-right: 8px;
  vertical-align: middle;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

/* Library picker modal */
.lib-station {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  cursor: pointer;
  border-radius: var(--radius);
}
.lib-station:hover { background: var(--surface2); }

/* Toast */
.toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  background: var(--green);
  color: #fff;
  padding: 12px 20px;
  border-radius: var(--radius);
  font-size: 0.9rem;
  z-index: 200;
  opacity: 0;
  transition: opacity 0.3s;
}
.toast.show { opacity: 1; }
.toast.error { background: var(--red); }

/* Utility */
.mt { margin-top: 16px; }
.mb { margin-bottom: 16px; }
.text-muted { color: var(--text2); font-size: 0.85rem; }
.flex-between { display: flex; justify-content: space-between; align-items: center; }

/* Audio preview */
.btn-play {
  width: 30px;
  height: 30px;
  padding: 0;
  border-radius: 50%;
  background: var(--accent);
  border: none;
  color: #fff;
  cursor: pointer;
  font-size: 0.8rem;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: background 0.15s;
}
.btn-play:hover { background: var(--accent2); }
.btn-play.playing { background: var(--red); }

/* Stream probe result */
.probe-result {
  margin-top: 8px;
  padding: 8px 12px;
  border-radius: var(--radius);
  font-size: 0.85rem;
  background: var(--surface2);
  border: 1px solid var(--border);
}
.probe-result.ok { border-color: var(--green); }
.probe-result.warn { border-color: var(--orange); }

/* Log viewer */
.log-viewer {
  background: #0d0e1a;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  font-family: "Consolas", "Monaco", monospace;
  font-size: 0.8rem;
  line-height: 1.6;
  max-height: 60vh;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: #c0c0d0;
}
.log-controls {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.log-controls select {
  width: auto;
  min-width: 80px;
}

/* Health check */
.health-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}
.health-badge.alive { background: var(--green); color: #fff; }
.health-badge.dead { background: var(--red); color: #fff; }
.health-progress {
  height: 4px;
  background: var(--surface2);
  border-radius: 2px;
  margin: 8px 0;
  overflow: hidden;
}
.health-progress-bar {
  height: 100%;
  background: var(--accent);
  transition: width 0.3s;
}

/* Import preview */
.import-preview {
  max-height: 300px;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin: 12px 0;
}
.import-item {
  display: flex;
  align-items: center;
  padding: 6px 12px;
  border-bottom: 1px solid var(--border);
  gap: 8px;
}
.import-item:last-child { border-bottom: none; }
.import-item label { display: flex; align-items: center; gap: 8px; flex: 1; margin: 0; font-size: 0.9rem; color: var(--text); }
.import-item .station-url { flex: 1; }

/* Backup section */
.backup-section {
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
}

/* Station drag */
.station-item.dragging { opacity: 0.4; }
.station-item.drag-over { border-top: 2px solid var(--accent); }

/* Copy presets modal */
.speaker-pick {
  display: flex;
  align-items: center;
  padding: 12px;
  cursor: pointer;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  margin-bottom: 8px;
  transition: border-color 0.15s;
}
.speaker-pick:hover { border-color: var(--accent); background: var(--surface2); }

/* ── Mobile responsive ─────────────────────────────── */
@media (max-width: 768px) {
  header {
    padding: 10px 12px;
    gap: 8px;
  }
  header h1 { font-size: 1.1rem; }
  .tabs { margin-left: 0; width: 100%; }
  .tab { padding: 6px 10px; font-size: 0.8rem; flex: 1; text-align: center; }
  main { padding: 12px; }
  .card { padding: 12px; }
  .card-header { flex-direction: column; align-items: flex-start; gap: 8px; }
  .flex-between { flex-direction: column; align-items: flex-start; gap: 8px; }
  .btn-group { flex-wrap: wrap; }
  .speaker-title { flex-wrap: wrap; }
  .speaker-name-input { width: 100%; }

  /* Switch preset table to stacked card layout on mobile */
  .preset-table { table-layout: auto; }
  .preset-table thead { display: none; }
  .preset-table tr {
    display: flex;
    flex-wrap: wrap;
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    gap: 4px;
    align-items: center;
  }
  .preset-table tr:last-child { border-bottom: none; }
  .preset-table td { border-bottom: none; padding: 2px 4px; font-size: 0.85rem; }
  .preset-num { width: auto; text-align: left; }
  .preset-url {
    width: 100%;
    max-width: none;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 0.75rem;
  }

  /* Station items stack on mobile */
  .station-item {
    flex-wrap: wrap;
    gap: 6px;
    padding: 8px 6px;
  }
  .station-name { flex: 1 1 60%; min-width: 0; }
  .station-url {
    flex: 1 1 100%;
    order: 10;
    font-size: 0.75rem;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .search-result { flex-wrap: wrap; gap: 8px; }
  .search-bar { flex-direction: column; }
  .form-row { flex-direction: column; }
  .modal { width: 95%; padding: 16px; max-height: 90vh; }
  .log-viewer { font-size: 0.7rem; max-height: 50vh; }
  .log-controls { gap: 6px; }
  .link-card { flex-direction: column; align-items: flex-start; gap: 8px; }
  .link-url { word-break: break-all; }
}

@media (max-width: 480px) {
  .tab { padding: 5px 6px; font-size: 0.75rem; }
  main { padding: 8px; }
  .card { padding: 10px; }
  .btn { padding: 5px 10px; font-size: 0.8rem; }
  .btn-sm { padding: 3px 8px; font-size: 0.75rem; }
}
</style>
</head>
<body>

<header>
  <h1><span>YTuner</span> Manager</h1>
  <div class="tabs">
    <button class="tab active" data-panel="speakers">Speakers</button>
    <button class="tab" data-panel="stations">Station Library</button>
    <button class="tab" data-panel="services">Services</button>
    <button class="tab" data-panel="logs">Logs</button>
    <button class="tab" data-panel="links">Links</button>
  </div>
</header>

<main>
  <!-- Speakers Panel -->
  <div id="speakers" class="panel active">
    <div class="flex-between mb">
      <h2>Configured Speakers</h2>
      <button class="btn btn-primary" onclick="startDiscovery()">Add New Speaker</button>
    </div>
    <div id="speakers-list"></div>
  </div>

  <!-- Station Library Panel -->
  <div id="stations" class="panel">
    <div class="flex-between mb">
      <h2>Station Library</h2>
      <div class="btn-group">
        <button class="btn" onclick="showAddStation()">Add Station</button>
        <button class="btn" onclick="showImportModal()">Import</button>
        <button class="btn" onclick="startHealthCheck()" id="btn-healthcheck">Check Health</button>
        <button class="btn btn-primary" onclick="showSearchRadio()">Search Radio Browser</button>
      </div>
    </div>
    <div id="stations-list"></div>
  </div>

  <!-- Services Panel -->
  <div id="services" class="panel">
    <h2 class="mb">System Services</h2>
    <div class="card">
      <div id="services-list"></div>
      <div class="backup-section">
        <h3 style="margin-bottom:12px">Backup &amp; Restore</h3>
        <p class="text-muted mb">Export all stations, speakers, and links as a single JSON file. Import to restore.</p>
        <div class="btn-group">
          <button class="btn btn-primary" onclick="exportBackup()">Export Backup</button>
          <button class="btn" onclick="document.getElementById('restore-file').click()">Import Backup</button>
          <input type="file" id="restore-file" accept=".json" style="display:none" onchange="importBackup(this)">
        </div>
      </div>
    </div>
  </div>

  <!-- Logs Panel -->
  <div id="logs" class="panel">
    <h2 class="mb">Log Viewer</h2>
    <div class="card">
      <div class="log-controls">
        <button class="btn btn-sm btn-primary" onclick="loadLogs('ytuner')" id="btn-log-ytuner">YTuner Log</button>
        <button class="btn btn-sm" onclick="loadLogs('nginx')" id="btn-log-nginx">Nginx Access Log</button>
        <select id="log-lines" onchange="loadLogs()">
          <option value="50">50 lines</option>
          <option value="100" selected>100 lines</option>
          <option value="200">200 lines</option>
        </select>
        <button class="btn btn-sm" onclick="loadLogs()">Refresh</button>
      </div>
      <div id="log-content" class="log-viewer">Select a log file above.</div>
    </div>
  </div>

  <!-- Links Panel -->
  <div id="links" class="panel">
    <div class="flex-between mb">
      <h2>Server Links</h2>
      <button class="btn btn-primary" onclick="showAddLink()">Add Link</button>
    </div>
    <div id="links-list"></div>
  </div>
</main>

<!-- Edit Preset Modal -->
<div id="edit-modal" class="modal-overlay">
  <div class="modal">
    <h2>Edit Preset</h2>
    <input type="hidden" id="edit-speaker-ip">
    <input type="hidden" id="edit-preset-idx">
    <div class="form-group mb">
      <label>Station Name</label>
      <input type="text" id="edit-name">
    </div>
    <div class="form-group mb">
      <label>Stream URL</label>
      <input type="url" id="edit-url">
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Genre / Format</label>
        <input type="text" id="edit-format">
      </div>
      <div class="form-group">
        <label>Station ID</label>
        <input type="text" id="edit-id" readonly style="opacity:0.6">
      </div>
    </div>
    <div class="btn-group mt">
      <button class="btn btn-primary" onclick="savePreset()">Save</button>
      <button class="btn" onclick="pickFromLibrary()">Pick from Library</button>
      <button class="btn" onclick="closeModal('edit-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Library Picker Modal -->
<div id="picker-modal" class="modal-overlay">
  <div class="modal">
    <h2>Pick from Station Library</h2>
    <div id="picker-list"></div>
    <div class="mt">
      <button class="btn" onclick="closeModal('picker-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Add/Edit Station Modal -->
<div id="station-modal" class="modal-overlay">
  <div class="modal">
    <h2 id="station-modal-title">Add Station</h2>
    <input type="hidden" id="stn-edit-cat">
    <input type="hidden" id="stn-edit-orig-name">
    <div class="form-group mb">
      <label>Category</label>
      <input type="text" id="stn-category" list="cat-list">
      <datalist id="cat-list"></datalist>
    </div>
    <div class="form-group mb">
      <label>Station Name</label>
      <input type="text" id="stn-name">
    </div>
    <div class="form-group mb">
      <label>Stream URL</label>
      <div style="display:flex;gap:8px">
        <input type="url" id="stn-url" style="flex:1">
        <button class="btn btn-sm" onclick="probeStream()">Check Stream</button>
      </div>
      <div id="stn-probe-result"></div>
    </div>
    <p class="text-muted mb" id="stn-transcode-hint" style="display:none">
      This URL will be auto-wrapped through the transcode proxy.
    </p>
    <div class="btn-group mt">
      <button class="btn btn-primary" onclick="saveStation()">Save</button>
      <button class="btn" onclick="closeModal('station-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Radio Browser Search Modal -->
<div id="search-modal" class="modal-overlay">
  <div class="modal">
    <h2>Search Radio Browser</h2>
    <div class="search-bar">
      <input type="text" id="search-query" placeholder="Search stations..." onkeydown="if(event.key==='Enter')searchRadio()">
      <button class="btn btn-primary" onclick="searchRadio()">Search</button>
    </div>
    <div id="search-results"></div>
    <div class="mt">
      <button class="btn" onclick="closeModal('search-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Discovery Wizard Modal -->
<div id="discovery-modal" class="modal-overlay">
  <div class="modal">
    <h2>Add New Speaker</h2>
    <div id="discovery-content"></div>
    <div class="btn-group mt" id="discovery-buttons">
      <button class="btn btn-danger" onclick="stopDiscovery()">Cancel</button>
    </div>
  </div>
</div>

<!-- Discovery: Assign Stations Modal -->
<div id="assign-modal" class="modal-overlay">
  <div class="modal">
    <h2>Assign Stations to Presets</h2>
    <div class="form-group mb">
      <label>Speaker Name</label>
      <input type="text" id="assign-speaker-name" placeholder="e.g. Bathroom Speaker">
    </div>
    <p class="text-muted mb">Speaker IP: <span id="assign-ip" class="ip-badge"></span></p>
    <div id="assign-presets"></div>
    <div class="btn-group mt">
      <button class="btn btn-primary" onclick="saveNewSpeaker()">Save Speaker</button>
      <button class="btn" onclick="closeModal('assign-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Add/Edit Link Modal -->
<div id="link-modal" class="modal-overlay">
  <div class="modal">
    <h2 id="link-modal-title">Add Link</h2>
    <input type="hidden" id="link-edit-idx" value="-1">
    <div class="form-group mb">
      <label>Name</label>
      <input type="text" id="link-name" placeholder="e.g. Pi-hole">
    </div>
    <div class="form-group mb">
      <label>URL</label>
      <input type="url" id="link-url" placeholder="e.g. http://192.168.1.100:8081/admin">
    </div>
    <div class="form-group mb">
      <label>Description (optional)</label>
      <input type="text" id="link-desc" placeholder="e.g. DNS ad blocker">
    </div>
    <div class="btn-group mt">
      <button class="btn btn-primary" onclick="saveLink()">Save</button>
      <button class="btn" onclick="closeModal('link-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Copy Presets Modal -->
<div id="copy-presets-modal" class="modal-overlay">
  <div class="modal">
    <h2>Copy Presets From Another Speaker</h2>
    <p class="text-muted mb">Select a speaker to copy all preset stations from. The UNB IDs on the current speaker will be preserved.</p>
    <div id="copy-speakers-list"></div>
    <div class="mt">
      <button class="btn" onclick="closeModal('copy-presets-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Import Stations Modal -->
<div id="import-modal" class="modal-overlay">
  <div class="modal">
    <h2>Import Stations</h2>
    <div class="form-group mb">
      <label>File (M3U, M3U8, or OPML)</label>
      <input type="file" id="import-file" accept=".m3u,.m3u8,.opml,.xml" style="background:var(--bg);padding:8px;border:1px solid var(--border);border-radius:var(--radius);width:100%;color:var(--text);">
    </div>
    <div class="btn-group mb">
      <button class="btn btn-primary" onclick="parseImportFile()">Parse File</button>
    </div>
    <div id="import-preview-area" style="display:none">
      <div class="form-group mb">
        <label>Target Category</label>
        <input type="text" id="import-category" list="import-cat-list" placeholder="Enter category name">
        <datalist id="import-cat-list"></datalist>
      </div>
      <div class="flex-between mb">
        <span class="text-muted" id="import-count"></span>
        <div class="btn-group">
          <button class="btn btn-sm" onclick="importSelectAll(true)">Select All</button>
          <button class="btn btn-sm" onclick="importSelectAll(false)">Select None</button>
        </div>
      </div>
      <div id="import-preview" class="import-preview"></div>
      <div class="btn-group mt">
        <button class="btn btn-primary" onclick="commitImport()">Import Selected</button>
      </div>
    </div>
    <div class="mt">
      <button class="btn" onclick="closeModal('import-modal')">Cancel</button>
    </div>
  </div>
</div>

<audio id="audio-preview" preload="none"></audio>
<div id="toast" class="toast"></div>

<script>
// ── State ───────────────────────────────────────────────
let speakersData = [];
let stationsData = {};
let linksData = [];
let discoveryPoll = null;

// ── Tab switching ───────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.panel).classList.add('active');
    if (tab.dataset.panel === 'speakers') loadSpeakers();
    if (tab.dataset.panel === 'stations') loadStations();
    if (tab.dataset.panel === 'services') loadServices();
    if (tab.dataset.panel === 'logs') loadLogs();
    if (tab.dataset.panel === 'links') loadLinks();
  });
});

// ── Toast ────────────────────────────────────────────────
function toast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isError ? ' error' : '');
  setTimeout(() => t.className = 'toast', 3000);
}

// ── Modal helpers ────────────────────────────────────────
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── API helpers ──────────────────────────────────────────
const _apiBase = (() => {
  // Detect base path for HA ingress compatibility
  let p = window.location.pathname;
  if (!p.endsWith('/')) p += '/';
  return p;
})();
async function api(path, opts) {
  const url = _apiBase + path.replace(/^\//, '');
  const resp = await fetch(url, opts);
  return resp.json();
}

// ── Speakers ─────────────────────────────────────────────
async function loadSpeakers() {
  speakersData = await api('/api/speakers');
  renderSpeakers();
}

function renderSpeakers() {
  const el = document.getElementById('speakers-list');
  if (!speakersData.length) {
    el.innerHTML = '<div class="card"><p class="text-muted">No speakers configured.</p></div>';
    return;
  }
  el.innerHTML = speakersData.map((s, si) => `
    <div class="card">
      <div class="card-header">
        <div class="speaker-title">
          <input class="speaker-name-input" type="text" value="${esc(s.name)}"
            placeholder="Unnamed Speaker" data-ip="${esc(s.ip)}"
            onchange="renameSpeaker('${esc(s.ip)}', this.value)"
            onkeydown="if(event.key==='Enter'){this.blur();}">
          <span class="ip-badge">${esc(s.ip)}</span>
        </div>
        <div class="btn-group">
          <button class="btn btn-sm" onclick="showCopyPresets('${esc(s.ip)}')">Copy From...</button>
          <button class="btn btn-sm btn-danger" onclick="deleteSpeaker('${esc(s.ip)}')">Delete</button>
        </div>
      </div>
      <table class="preset-table">
        <tr><th>#</th><th>Station</th><th>URL</th><th>Format</th><th></th></tr>
        ${s.presets.map((p, pi) => `
          <tr>
            <td class="preset-num">${pi+1} <span class="unb-badge">${esc(p.id)}</span></td>
            <td>${esc(p.name) || '<span class="text-muted">Empty</span>'}</td>
            <td class="preset-url" title="${esc(p.url)}">${esc(p.url)}</td>
            <td><span class="text-muted">${esc(p.format)}</span></td>
            <td style="white-space:nowrap">
              ${pi > 0 ? `<button class="btn-move" onclick="movePreset('${esc(s.ip)}',${pi},${pi-1})" title="Move up">&#9650;</button>` : ''}
              ${pi < s.presets.length - 1 ? `<button class="btn-move" onclick="movePreset('${esc(s.ip)}',${pi},${pi+1})" title="Move down">&#9660;</button>` : ''}
              <button class="btn btn-sm" onclick="editPreset('${esc(s.ip)}',${pi})">Edit</button>
            </td>
          </tr>
        `).join('')}
      </table>
    </div>
  `).join('');
}

async function renameSpeaker(ip, name) {
  const result = await api(`/api/speakers/${ip}/name`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name}),
  });
  if (result.ok) {
    // Update local state
    const s = speakersData.find(x => x.ip === ip);
    if (s) s.name = name;
    toast('Speaker renamed');
  } else {
    toast(result.error || 'Rename failed', true);
  }
}

function editPreset(ip, idx) {
  const speaker = speakersData.find(s => s.ip === ip);
  if (!speaker) return;
  const p = speaker.presets[idx];
  document.getElementById('edit-speaker-ip').value = ip;
  document.getElementById('edit-preset-idx').value = idx;
  document.getElementById('edit-name').value = p.name;
  document.getElementById('edit-url').value = p.url;
  document.getElementById('edit-format').value = p.format;
  document.getElementById('edit-id').value = p.id;
  openModal('edit-modal');
}

async function savePreset() {
  const ip = document.getElementById('edit-speaker-ip').value;
  const idx = parseInt(document.getElementById('edit-preset-idx').value);
  const speaker = speakersData.find(s => s.ip === ip);
  if (!speaker) return;

  speaker.presets[idx].name = document.getElementById('edit-name').value;
  speaker.presets[idx].url = document.getElementById('edit-url').value;
  speaker.presets[idx].format = document.getElementById('edit-format').value;

  const result = await api(`/api/speakers/${ip}/presets`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({presets: speaker.presets}),
  });
  closeModal('edit-modal');
  if (result.ok) {
    toast('Preset saved. YTuner restarting...');
    renderSpeakers();
  } else {
    toast(result.error || 'Save failed', true);
  }
}

async function deleteSpeaker(ip) {
  const speaker = speakersData.find(s => s.ip === ip);
  const label = (speaker && speaker.name) ? `"${speaker.name}" (${ip})` : ip;
  if (!confirm(`Delete speaker ${label}? This removes its preset config.`)) return;
  const result = await api(`/api/speakers/${ip}`, {method: 'DELETE'});
  if (result.ok) {
    toast('Speaker deleted');
    loadSpeakers();
  } else {
    toast(result.error || 'Delete failed', true);
  }
}

// ── Move preset (swap station data, keep UNB IDs fixed) ──
async function movePreset(ip, fromIdx, toIdx) {
  const speaker = speakersData.find(s => s.ip === ip);
  if (!speaker) return;
  const a = speaker.presets[fromIdx];
  const b = speaker.presets[toIdx];
  // Swap station data but keep IDs in place
  const fields = ['name', 'url', 'format', 'desc', 'logo', 'mime'];
  for (const f of fields) {
    const tmp = a[f]; a[f] = b[f]; b[f] = tmp;
  }
  const result = await api(`/api/speakers/${ip}/presets`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({presets: speaker.presets}),
  });
  if (result.ok) {
    toast('Preset moved. YTuner restarting...');
    renderSpeakers();
  } else {
    toast(result.error || 'Move failed', true);
  }
}

// ── Pick from library ────────────────────────────────────
async function pickFromLibrary() {
  if (!Object.keys(stationsData).length) {
    stationsData = await api('/api/stations');
  }
  const el = document.getElementById('picker-list');
  let html = '';
  for (const [cat, stations] of Object.entries(stationsData)) {
    if (cat === 'Presets') continue;
    html += `<div style="margin-top:12px"><strong>${esc(cat)}</strong></div>`;
    for (const s of stations) {
      html += `<div class="lib-station" onclick="pickStation(this)" data-name="${esc(s.name)}" data-url="${esc(s.url)}">
        <span class="station-name">${esc(s.name)}</span>
      </div>`;
    }
  }
  el.innerHTML = html;
  openModal('picker-modal');
}

function pickStation(el) {
  document.getElementById('edit-name').value = el.dataset.name;
  document.getElementById('edit-url').value = el.dataset.url;
  closeModal('picker-modal');
}

// ── Station Library ──────────────────────────────────────
async function loadStations() {
  stationsData = await api('/api/stations');
  renderStations();
}

function renderStations() {
  const el = document.getElementById('stations-list');
  const cats = Object.entries(stationsData);
  if (!cats.length) {
    el.innerHTML = '<div class="card"><p class="text-muted">No stations configured.</p></div>';
    return;
  }
  const catKeys = cats.map(c => c[0]);
  el.innerHTML = cats.map(([cat, stations], ci) => `
    <div class="card">
      <div class="card-header">
        <div style="display:flex;align-items:center;gap:8px">
          ${ci > 0 ? `<button class="btn-move" onclick="moveCat(${ci},${ci-1})" title="Move category up">&#9650;</button>` : ''}
          ${ci < cats.length - 1 ? `<button class="btn-move" onclick="moveCat(${ci},${ci+1})" title="Move category down">&#9660;</button>` : ''}
          <h3>${esc(cat)} <span class="category-count">(${stations.length})</span></h3>
        </div>
        <div class="btn-group">
          <button class="btn btn-sm" onclick="addStationToCat('${escAttr(cat)}')">Add</button>
          ${cat !== 'Presets' ? `<button class="btn btn-sm btn-danger" onclick="deleteCategory('${escAttr(cat)}')">Delete Category</button>` : ''}
        </div>
      </div>
      ${stations.map((s, si) => `
        <div class="station-item" draggable="true"
             ondragstart="stationDragStart(event,'${escAttr(cat)}',${si})"
             ondragover="stationDragOver(event)"
             ondragenter="stationDragEnter(event)"
             ondragleave="stationDragLeave(event)"
             ondrop="stationDrop(event,'${escAttr(cat)}',${si})"
             ondragend="stationDragEnd(event)">
          ${si > 0 ? `<button class="btn-move" onclick="moveStation('${escAttr(cat)}',${si},${si-1})" title="Move up">&#9650;</button>` : '<span style="width:22px;display:inline-block"></span>'}
          ${si < stations.length - 1 ? `<button class="btn-move" onclick="moveStation('${escAttr(cat)}',${si},${si+1})" title="Move down">&#9660;</button>` : '<span style="width:22px;display:inline-block"></span>'}
          <button class="btn-play" onclick="previewStation('${escAttr(s.url)}', this)" title="Preview">&#9654;</button>
          <span class="station-name">${esc(s.name)}${s._dead ? ' <span class=\"health-badge dead\">offline</span>' : ''}</span>
          <span class="station-url" title="${esc(s.url)}">${esc(s.url)}</span>
          ${s.url.includes('/transcode?') ? '<span class="transcode-badge">transcoded</span>' : ''}
          <button class="btn btn-sm" onclick="editStation('${escAttr(cat)}','${escAttr(s.name)}','${escAttr(s.url)}')">Edit</button>
          <button class="btn btn-sm btn-danger" onclick="deleteStation('${escAttr(cat)}','${escAttr(s.name)}')">Del</button>
        </div>
      `).join('')}
    </div>
  `).join('');
}

function showAddStation() {
  document.getElementById('station-modal-title').textContent = 'Add Station';
  document.getElementById('stn-edit-cat').value = '';
  document.getElementById('stn-edit-orig-name').value = '';
  document.getElementById('stn-category').value = '';
  document.getElementById('stn-name').value = '';
  document.getElementById('stn-url').value = '';
  document.getElementById('stn-transcode-hint').style.display = 'none';
  updateCatDatalist();
  openModal('station-modal');
}

function addStationToCat(cat) {
  document.getElementById('station-modal-title').textContent = 'Add Station';
  document.getElementById('stn-edit-cat').value = '';
  document.getElementById('stn-edit-orig-name').value = '';
  document.getElementById('stn-category').value = cat;
  document.getElementById('stn-name').value = '';
  document.getElementById('stn-url').value = '';
  document.getElementById('stn-transcode-hint').style.display = 'none';
  updateCatDatalist();
  openModal('station-modal');
}

function editStation(cat, name, url) {
  document.getElementById('station-modal-title').textContent = 'Edit Station';
  document.getElementById('stn-edit-cat').value = cat;
  document.getElementById('stn-edit-orig-name').value = name;
  document.getElementById('stn-category').value = cat;
  document.getElementById('stn-name').value = name;
  document.getElementById('stn-url').value = url;
  document.getElementById('stn-transcode-hint').style.display = 'none';
  updateCatDatalist();
  openModal('station-modal');
}

function updateCatDatalist() {
  const dl = document.getElementById('cat-list');
  dl.innerHTML = Object.keys(stationsData).map(c => `<option value="${esc(c)}">`).join('');
}

// URL change handler for transcode hint
document.getElementById('stn-url').addEventListener('input', function() {
  const hint = document.getElementById('stn-transcode-hint');
  const url = this.value;
  hint.style.display = (url.startsWith('https://') || /\.(aac|ogg|flac|m4a|opus|wma)$/i.test(url)) ? 'block' : 'none';
});

async function saveStation() {
  const cat = document.getElementById('stn-category').value.trim();
  const name = document.getElementById('stn-name').value.trim();
  const url = document.getElementById('stn-url').value.trim();
  const editCat = document.getElementById('stn-edit-cat').value;
  const editOrigName = document.getElementById('stn-edit-orig-name').value;

  if (!cat || !name || !url) {
    toast('All fields required', true);
    return;
  }

  // Remove old entry if editing
  if (editCat && editOrigName) {
    if (stationsData[editCat]) {
      stationsData[editCat] = stationsData[editCat].filter(s => s.name !== editOrigName);
      if (!stationsData[editCat].length && editCat !== cat) delete stationsData[editCat];
    }
  }

  if (!stationsData[cat]) stationsData[cat] = [];
  stationsData[cat].push({name, url});

  const result = await api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
  closeModal('station-modal');
  if (result.ok) {
    toast('Station saved');
    renderStations();
  } else {
    toast(result.error || 'Save failed', true);
  }
}

async function deleteStation(cat, name) {
  if (!confirm(`Delete "${name}"?`)) return;
  if (stationsData[cat]) {
    stationsData[cat] = stationsData[cat].filter(s => s.name !== name);
    if (!stationsData[cat].length) delete stationsData[cat];
  }
  const result = await api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
  if (result.ok) {
    toast('Station deleted');
    renderStations();
  }
}

async function deleteCategory(cat) {
  if (!confirm(`Delete entire "${cat}" category and all its stations?`)) return;
  delete stationsData[cat];
  const result = await api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
  if (result.ok) {
    toast('Category deleted');
    renderStations();
  }
}

// ── Radio Browser Search ─────────────────────────────────
function showSearchRadio() {
  document.getElementById('search-query').value = '';
  document.getElementById('search-results').innerHTML = '<p class="text-muted">Enter a search term above.</p>';
  openModal('search-modal');
  document.getElementById('search-query').focus();
}

async function searchRadio() {
  const q = document.getElementById('search-query').value.trim();
  if (q.length < 2) { toast('Enter at least 2 characters', true); return; }
  document.getElementById('search-results').innerHTML = '<p class="text-muted">Searching...</p>';
  const results = await api(`/api/stations/search?q=${encodeURIComponent(q)}`);
  if (results.error) {
    document.getElementById('search-results').innerHTML = `<p class="text-muted">${esc(results.error)}</p>`;
    return;
  }
  if (!results.length) {
    document.getElementById('search-results').innerHTML = '<p class="text-muted">No results found.</p>';
    return;
  }
  document.getElementById('search-results').innerHTML = results.map((s, i) => `
    <div class="search-result">
      <button class="btn-play" onclick="previewStation('${escAttr(s.url)}', this)" title="Preview">&#9654;</button>
      <div style="flex:1">
        <div>${esc(s.name)}</div>
        <div class="search-meta">${esc(s.codec)} ${s.bitrate}kbps &middot; ${esc(s.country)}</div>
      </div>
      ${s.needs_transcode ? '<span class="transcode-badge">needs transcode</span>' : ''}
      <button class="btn btn-sm btn-primary" onclick="addSearchResult(${i})">Add to Library</button>
    </div>
  `).join('');
  window._searchResults = results;
}

function addSearchResult(idx) {
  const s = window._searchResults[idx];
  if (!s) return;
  document.getElementById('station-modal-title').textContent = 'Add Station to Library';
  document.getElementById('stn-edit-cat').value = '';
  document.getElementById('stn-edit-orig-name').value = '';
  document.getElementById('stn-category').value = '';
  document.getElementById('stn-name').value = s.name;
  if (s.needs_transcode) {
    document.getElementById('stn-url').value = `http://${SERVER_IP}:${TRANSCODE_PORT}/transcode?url=${encodeURIComponent(s.url)}`;
  } else {
    document.getElementById('stn-url').value = s.url;
  }
  updateCatDatalist();
  closeModal('search-modal');
  openModal('station-modal');
  document.getElementById('stn-transcode-hint').style.display = s.needs_transcode ? 'block' : 'none';
}

// ── Services ─────────────────────────────────────────────
async function loadServices() {
  const data = await api('/api/services/status');
  const el = document.getElementById('services-list');
  el.innerHTML = ['ytuner', 'transcode-proxy'].map(svc => {
    const status = data[svc] || 'unknown';
    const isActive = status.includes('active (running)');
    return `
      <div class="service-row">
        <div>
          <div class="service-name">${esc(svc)}</div>
          <div class="service-status ${isActive ? 'status-active' : 'status-inactive'}">${esc(status)}</div>
        </div>
        <button class="btn btn-sm" onclick="restartService('${svc}')">Restart</button>
      </div>
    `;
  }).join('');
}

async function restartService(svc) {
  toast(`Restarting ${svc}...`);
  const result = await api('/api/services/restart', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({service: svc}),
  });
  if (result.ok) {
    toast(`${svc} restarted`);
    loadServices();
  } else {
    toast(result.error || 'Restart failed', true);
  }
}

// ── Links ────────────────────────────────────────────────
async function loadLinks() {
  linksData = await api('/api/links');
  renderLinks();
}

function renderLinks() {
  const el = document.getElementById('links-list');
  if (!linksData.length) {
    el.innerHTML = '<div class="card"><p class="text-muted">No links configured. Add links to other web services on this server.</p></div>';
    return;
  }
  el.innerHTML = linksData.map((l, i) => `
    <div class="link-card">
      <div class="link-info">
        <a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.name)}</a>
        ${l.desc ? `<div class="link-desc">${esc(l.desc)}</div>` : ''}
        <div class="link-url">${esc(l.url)}</div>
      </div>
      <div class="btn-group">
        <button class="btn btn-sm" onclick="editLink(${i})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteLink(${i})">Delete</button>
      </div>
    </div>
  `).join('');
}

function showAddLink() {
  document.getElementById('link-modal-title').textContent = 'Add Link';
  document.getElementById('link-edit-idx').value = '-1';
  document.getElementById('link-name').value = '';
  document.getElementById('link-url').value = '';
  document.getElementById('link-desc').value = '';
  openModal('link-modal');
}

function editLink(idx) {
  const l = linksData[idx];
  document.getElementById('link-modal-title').textContent = 'Edit Link';
  document.getElementById('link-edit-idx').value = idx;
  document.getElementById('link-name').value = l.name;
  document.getElementById('link-url').value = l.url;
  document.getElementById('link-desc').value = l.desc || '';
  openModal('link-modal');
}

async function saveLink() {
  const idx = parseInt(document.getElementById('link-edit-idx').value);
  const name = document.getElementById('link-name').value.trim();
  const url = document.getElementById('link-url').value.trim();
  const desc = document.getElementById('link-desc').value.trim();

  if (!name || !url) { toast('Name and URL required', true); return; }

  const link = {name, url, desc};
  if (idx >= 0) {
    linksData[idx] = link;
  } else {
    linksData.push(link);
  }

  const result = await api('/api/links', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(linksData),
  });
  closeModal('link-modal');
  if (result.ok) {
    toast('Link saved');
    renderLinks();
  } else {
    toast(result.error || 'Save failed', true);
  }
}

async function deleteLink(idx) {
  if (!confirm(`Delete "${linksData[idx].name}"?`)) return;
  linksData.splice(idx, 1);
  const result = await api('/api/links', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(linksData),
  });
  if (result.ok) {
    toast('Link deleted');
    renderLinks();
  }
}

// ── Discovery Wizard ─────────────────────────────────────
async function startDiscovery() {
  await api('/api/discovery/start', {method: 'POST'});
  document.getElementById('discovery-content').innerHTML = `
    <div class="wizard-step">
      <div class="step-label">Step 1: Waiting for speaker</div>
      <p><span class="pulse"></span> Watching YTuner log for a new speaker...</p>
      <p class="text-muted mt">Turn on an unconfigured Libratone speaker and let it connect to YTuner.
      Then press preset button 1 on the speaker.</p>
    </div>
  `;
  document.getElementById('discovery-buttons').innerHTML = '<button class="btn btn-danger" onclick="stopDiscovery()">Cancel</button>';
  openModal('discovery-modal');
  discoveryPoll = setInterval(pollDiscovery, 1000);
}

async function pollDiscovery() {
  const s = await api('/api/discovery/status');
  if (!s.active) { clearInterval(discoveryPoll); return; }

  let html = '';
  if (s.ip) {
    html += `<div class="wizard-step">
      <div class="step-label">Speaker detected</div>
      <p>IP: <span class="ip-badge">${esc(s.ip)}</span></p>
    </div>`;
  }

  if (s.presets.length > 0) {
    html += '<div class="wizard-step"><div class="step-label">Captured presets</div>';
    s.presets.forEach(p => {
      html += `<p>Preset ${p.index}: ID <code>${esc(p.id)}</code></p>`;
    });
    html += '</div>';
  }

  if (s.done) {
    clearInterval(discoveryPoll);
    html += '<div class="wizard-step"><div class="step-label">All 5 presets captured!</div></div>';
    document.getElementById('discovery-content').innerHTML = html;
    document.getElementById('discovery-buttons').innerHTML = `
      <button class="btn btn-primary" onclick="showAssignPresets()">Assign Stations</button>
      <button class="btn btn-danger" onclick="stopDiscovery()">Cancel</button>
    `;
    return;
  }

  if (!s.done && s.ip) {
    html += `<div class="wizard-step">
      <p><span class="pulse"></span> Press preset button <strong>${s.expected}</strong> on the speaker...</p>
    </div>`;
  }

  document.getElementById('discovery-content').innerHTML = html;
}

async function showAssignPresets() {
  const s = await api('/api/discovery/status');
  if (!Object.keys(stationsData).length) {
    stationsData = await api('/api/stations');
  }
  closeModal('discovery-modal');
  document.getElementById('assign-ip').textContent = s.ip;
  document.getElementById('assign-speaker-name').value = '';

  let options = '<option value="">-- Select station --</option>';
  for (const [cat, stations] of Object.entries(stationsData)) {
    if (cat === 'Presets') continue;
    for (const st of stations) {
      options += `<option value="${esc(st.url)}" data-name="${esc(st.name)}">${esc(cat)}: ${esc(st.name)}</option>`;
    }
  }

  document.getElementById('assign-presets').innerHTML = s.presets.map(p => `
    <div class="form-group mb">
      <label>Preset ${p.index} (ID: ${esc(p.id)})</label>
      <input type="hidden" class="assign-id" value="${esc(p.id)}">
      <select class="assign-select" onchange="assignSelectChanged(this)">
        ${options}
      </select>
      <input type="text" class="assign-name" placeholder="Station name" style="margin-top:6px">
      <input type="url" class="assign-url" placeholder="Stream URL" style="margin-top:6px">
    </div>
  `).join('');

  openModal('assign-modal');
}

function assignSelectChanged(sel) {
  const container = sel.closest('.form-group');
  const opt = sel.selectedOptions[0];
  if (opt && opt.value) {
    container.querySelector('.assign-name').value = opt.dataset.name || '';
    container.querySelector('.assign-url').value = opt.value;
  }
}

async function saveNewSpeaker() {
  const s = await api('/api/discovery/status');
  const speakerName = document.getElementById('assign-speaker-name').value.trim();
  const groups = document.querySelectorAll('#assign-presets .form-group');
  const presets = [];
  groups.forEach((g, i) => {
    presets.push({
      id: 'UNB' + g.querySelector('.assign-id').value,
      name: g.querySelector('.assign-name').value,
      url: g.querySelector('.assign-url').value,
      desc: `Preset ${i+1}`,
      format: '',
    });
  });

  const result = await api('/api/speakers', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip: s.ip, name: speakerName, presets}),
  });

  closeModal('assign-modal');
  stopDiscovery();
  if (result.ok) {
    toast('Speaker added! YTuner restarting...');
    loadSpeakers();
  } else {
    toast(result.error || 'Failed to save speaker', true);
  }
}

async function stopDiscovery() {
  clearInterval(discoveryPoll);
  await api('/api/discovery/stop', {method: 'POST'});
  closeModal('discovery-modal');
}

// ── Audio Preview ────────────────────────────────────
let activePreviewBtn = null;

function unwrapTranscodeUrl(url) {
  // Transcoded URLs look like http://SERVER_IP:8888/transcode?url=ENCODED
  // Browser can play the original stream natively (AAC, OGG, etc.)
  // so unwrap to avoid cross-origin issues with the transcode proxy.
  try {
    const u = new URL(url);
    if (u.pathname === '/transcode' && u.searchParams.has('url')) {
      return u.searchParams.get('url');
    }
  } catch (e) {}
  return url;
}

function previewStation(url, btn) {
  const audio = document.getElementById('audio-preview');
  // If clicking the same button, stop
  if (activePreviewBtn === btn) {
    stopPreview();
    return;
  }
  stopPreview();
  audio.src = unwrapTranscodeUrl(url);
  audio.play().catch(() => toast('Could not play stream', true));
  btn.innerHTML = '&#9632;';
  btn.classList.add('playing');
  activePreviewBtn = btn;
}

function stopPreview() {
  const audio = document.getElementById('audio-preview');
  audio.pause();
  audio.src = '';
  if (activePreviewBtn) {
    activePreviewBtn.innerHTML = '&#9654;';
    activePreviewBtn.classList.remove('playing');
    activePreviewBtn = null;
  }
}

// Stop preview when switching tabs or closing modals
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', stopPreview);
});

// ── Stream Probing ───────────────────────────────────
async function probeStream() {
  const url = document.getElementById('stn-url').value.trim();
  const el = document.getElementById('stn-probe-result');
  if (!url) { toast('Enter a URL first', true); return; }
  el.innerHTML = '<div class="probe-result">Checking stream...</div>';
  try {
    const result = await api(`/api/stations/probe?url=${encodeURIComponent(url)}`);
    if (result.error) {
      el.innerHTML = `<div class="probe-result warn">${esc(result.error)}</div>`;
      return;
    }
    const cls = result.needs_transcode ? 'warn' : 'ok';
    el.innerHTML = `<div class="probe-result ${cls}">
      <strong>Content-Type:</strong> ${esc(result.content_type)}<br>
      <strong>Needs transcode:</strong> ${result.needs_transcode ? 'Yes' : 'No'}<br>
      ${esc(result.reason)}
    </div>`;
    // Update transcode hint
    const hint = document.getElementById('stn-transcode-hint');
    hint.style.display = result.needs_transcode ? 'block' : 'none';
  } catch (e) {
    el.innerHTML = `<div class="probe-result warn">Probe failed: ${esc(String(e))}</div>`;
  }
}

// ── Utility ──────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function escAttr(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/'/g,'&#39;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\\/g,'\\\\');
}

// ── Copy Presets Between Speakers ─────────────────────────
function showCopyPresets(targetIp) {
  const el = document.getElementById('copy-speakers-list');
  const others = speakersData.filter(s => s.ip !== targetIp);
  if (!others.length) {
    el.innerHTML = '<p class="text-muted">No other speakers to copy from.</p>';
    openModal('copy-presets-modal');
    return;
  }
  el.innerHTML = others.map(s => `
    <div class="speaker-pick" onclick="doCopyPresets('${esc(s.ip)}','${esc(targetIp)}')">
      <div style="flex:1">
        <strong>${esc(s.name || 'Unnamed')}</strong>
        <span class="ip-badge" style="margin-left:8px">${esc(s.ip)}</span>
        <div class="text-muted" style="margin-top:4px">${s.presets.filter(p=>p.name).map(p=>esc(p.name)).join(', ') || 'No stations'}</div>
      </div>
    </div>
  `).join('');
  openModal('copy-presets-modal');
}

async function doCopyPresets(sourceIp, targetIp) {
  const source = speakersData.find(s => s.ip === sourceIp);
  const target = speakersData.find(s => s.ip === targetIp);
  if (!source || !target) return;
  if (!confirm(`Copy all presets from ${source.name || sourceIp} to ${target.name || targetIp}?`)) return;

  const fields = ['name', 'url', 'format', 'desc', 'logo', 'mime'];
  for (let i = 0; i < target.presets.length && i < source.presets.length; i++) {
    for (const f of fields) {
      target.presets[i][f] = source.presets[i][f];
    }
  }
  const result = await api(`/api/speakers/${targetIp}/presets`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({presets: target.presets}),
  });
  closeModal('copy-presets-modal');
  if (result.ok) {
    toast('Presets copied. YTuner restarting...');
    renderSpeakers();
  } else {
    toast(result.error || 'Copy failed', true);
  }
}

// ── Backup & Restore ─────────────────────────────────────
function exportBackup() {
  window.location.href = _apiBase + 'api/backup';
}

async function importBackup(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (data.version !== 1) {
      toast('Unknown backup version', true);
      return;
    }
    const items = [];
    if (data.stations_ini) items.push('stations');
    if (data.speakers_json && Object.keys(data.speakers_json).length) items.push('speaker names');
    if (data.links_json && data.links_json.length) items.push(`${data.links_json.length} links`);
    if (data.speaker_xmls) items.push(`${Object.keys(data.speaker_xmls).length} speaker XMLs`);
    const summary = items.length ? items.join(', ') : 'empty backup';
    if (!confirm(`Restore backup from ${data.date || 'unknown date'}?\n\nContains: ${summary}\n\nThis will overwrite current configuration.`)) return;

    const result = await api('/api/backup/restore', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: text,
    });
    if (result.ok) {
      toast('Backup restored. YTuner restarting...');
      setTimeout(() => {
        loadSpeakers();
        loadStations();
        loadLinks();
      }, 1500);
    } else {
      toast(result.error || 'Restore failed', true);
    }
  } catch (e) {
    toast('Invalid backup file: ' + e.message, true);
  }
}

// ── Log Viewer ───────────────────────────────────────────
let currentLogFile = 'ytuner';

async function loadLogs(file) {
  if (file) currentLogFile = file;
  const lines = document.getElementById('log-lines').value;
  // Update button styles
  document.getElementById('btn-log-ytuner').className = 'btn btn-sm' + (currentLogFile === 'ytuner' ? ' btn-primary' : '');
  document.getElementById('btn-log-nginx').className = 'btn btn-sm' + (currentLogFile === 'nginx' ? ' btn-primary' : '');

  const el = document.getElementById('log-content');
  el.textContent = 'Loading...';
  const data = await api(`/api/logs?file=${currentLogFile}&lines=${lines}`);
  if (data.error && !data.lines) {
    el.textContent = 'Error: ' + data.error;
    return;
  }
  if (data.error) {
    el.textContent = data.error;
    return;
  }
  el.textContent = data.lines.join('\n') || '(empty)';
  el.scrollTop = el.scrollHeight;
}

// ── Station Health Check ─────────────────────────────────
let healthPoll = null;

async function startHealthCheck() {
  const btn = document.getElementById('btn-healthcheck');
  btn.textContent = 'Checking...';
  btn.disabled = true;
  const result = await api('/api/stations/healthcheck', {method: 'POST'});
  if (result.error) {
    toast(result.error, true);
    btn.textContent = 'Check Health';
    btn.disabled = false;
    return;
  }
  healthPoll = setInterval(pollHealthCheck, 1000);
}

async function pollHealthCheck() {
  const data = await api('/api/stations/healthcheck');
  const btn = document.getElementById('btn-healthcheck');
  if (data.total > 0) {
    btn.textContent = `Checking ${data.checked}/${data.total}...`;
  }
  if (!data.running) {
    clearInterval(healthPoll);
    healthPoll = null;
    btn.textContent = 'Check Health';
    btn.disabled = false;
    // Mark dead stations in stationsData
    const deadSet = new Set();
    for (const r of data.results) {
      if (!r.alive) deadSet.add(r.category + '::' + r.name);
    }
    for (const [cat, stations] of Object.entries(stationsData)) {
      for (const s of stations) {
        s._dead = deadSet.has(cat + '::' + s.name);
      }
    }
    renderStations();
    const deadCount = data.results.filter(r => !r.alive).length;
    if (deadCount > 0) {
      toast(`Health check done: ${deadCount} station(s) offline`, true);
    } else {
      toast(`Health check done: all ${data.total} stations OK`);
    }
  }
}

// ── M3U / OPML Import ────────────────────────────────────
let importedStations = [];

function showImportModal() {
  document.getElementById('import-file').value = '';
  document.getElementById('import-preview-area').style.display = 'none';
  document.getElementById('import-category').value = '';
  // Populate category datalist
  const dl = document.getElementById('import-cat-list');
  dl.innerHTML = Object.keys(stationsData).map(c => `<option value="${esc(c)}">`).join('');
  openModal('import-modal');
}

async function parseImportFile() {
  const fileInput = document.getElementById('import-file');
  const file = fileInput.files[0];
  if (!file) { toast('Select a file first', true); return; }

  const text = await file.text();
  const name = file.name.toLowerCase();
  let fmt = 'm3u';
  if (name.endsWith('.opml') || name.endsWith('.xml')) fmt = 'opml';

  const result = await api('/api/stations/import', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({format: fmt, content: text}),
  });

  if (result.error) {
    toast(result.error, true);
    return;
  }

  importedStations = result.stations || [];
  if (!importedStations.length) {
    toast('No stations found in file', true);
    return;
  }

  document.getElementById('import-preview-area').style.display = 'block';
  document.getElementById('import-count').textContent = `${importedStations.length} stations found`;
  const el = document.getElementById('import-preview');
  el.innerHTML = importedStations.map((s, i) => `
    <div class="import-item">
      <label><input type="checkbox" checked data-idx="${i}"> ${esc(s.name)}</label>
      <span class="station-url" title="${esc(s.url)}">${esc(s.url)}</span>
    </div>
  `).join('');
}

function importSelectAll(checked) {
  document.querySelectorAll('#import-preview input[type=checkbox]').forEach(cb => cb.checked = checked);
}

async function commitImport() {
  const cat = document.getElementById('import-category').value.trim();
  if (!cat) { toast('Enter a category name', true); return; }

  const selected = [];
  document.querySelectorAll('#import-preview input[type=checkbox]:checked').forEach(cb => {
    const idx = parseInt(cb.dataset.idx);
    selected.push(importedStations[idx]);
  });

  if (!selected.length) { toast('No stations selected', true); return; }

  if (!stationsData[cat]) stationsData[cat] = [];
  for (const s of selected) {
    stationsData[cat].push({name: s.name, url: s.url});
  }

  const result = await api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
  closeModal('import-modal');
  if (result.ok) {
    toast(`Imported ${selected.length} station(s) to "${cat}"`);
    renderStations();
  } else {
    toast(result.error || 'Import failed', true);
  }
}

// ── Station Reordering ───────────────────────────────────
async function moveStation(cat, fromIdx, toIdx) {
  const stations = stationsData[cat];
  if (!stations || toIdx < 0 || toIdx >= stations.length) return;
  const [item] = stations.splice(fromIdx, 1);
  stations.splice(toIdx, 0, item);
  renderStations();
  await api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
}

async function moveCat(fromIdx, toIdx) {
  const entries = Object.entries(stationsData);
  const [item] = entries.splice(fromIdx, 1);
  entries.splice(toIdx, 0, item);
  stationsData = Object.fromEntries(entries);
  renderStations();
  await api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
}

// Drag-and-drop for stations within same category
let dragCat = null, dragIdx = null;
function stationDragStart(e, cat, idx) {
  dragCat = cat; dragIdx = idx;
  e.target.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
}
function stationDragOver(e) { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; }
function stationDragEnter(e) { e.preventDefault(); e.currentTarget.classList.add('drag-over'); }
function stationDragLeave(e) { e.currentTarget.classList.remove('drag-over'); }
function stationDragEnd(e) {
  e.target.classList.remove('dragging');
  document.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
}
function stationDrop(e, targetCat, targetIdx) {
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  if (dragCat !== targetCat || dragIdx === null || dragIdx === targetIdx) return;
  const stations = stationsData[dragCat];
  const [item] = stations.splice(dragIdx, 1);
  stations.splice(targetIdx, 0, item);
  renderStations();
  api('/api/stations', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(stationsData),
  });
  dragCat = null; dragIdx = null;
}

// ── Init ─────────────────────────────────────────────────
console.log('[YTuner] apiBase=' + _apiBase, 'pathname=' + window.location.pathname);
loadSpeakers().catch(e => console.error('[YTuner] loadSpeakers failed:', e));
</script>
</body>
</html>
"""


# ── Server ───────────────────────────────────────────────────────────────────

class WebUIServer(HTTPServer):
    allow_reuse_address = True


def main():
    server = WebUIServer((HOST, PORT), WebUIHandler)
    log.info("YTuner WebUI listening on %s:%d", HOST, PORT)
    log.info("Data dir: %s (links.json, speakers.json)", DATA_DIR)

    def shutdown_handler(signum, frame):
        print("Shutting down...", flush=True)
        reset_discovery()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    server.serve_forever()


if __name__ == "__main__":
    main()
