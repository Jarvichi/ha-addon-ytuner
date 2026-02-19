#!/usr/bin/env python3
"""
Audio Transcoding Proxy for YTuner/Libratone speakers.
Transcodes non-MP3 audio streams to MP3 on-the-fly using FFmpeg.

Usage:
  /transcode?url=<encoded_stream_url>[&bitrate=128k]
"""

import os
import signal
import subprocess
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

HOST = "0.0.0.0"
PORT = int(os.environ.get("TRANSCODE_PORT", "8888"))
DEFAULT_BITRATE = os.environ.get("TRANSCODE_BITRATE", "128k")
SAMPLE_RATE = "44100"
CHANNELS = "2"
MAX_CONCURRENT = int(os.environ.get("TRANSCODE_MAX_CONCURRENT", "4"))

active_streams = threading.Semaphore(MAX_CONCURRENT)


class TranscodeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format, *args):
        print(f"[{self.client_address[0]}] {format % args}", flush=True)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path != "/transcode":
            self.send_error(404, "Use /transcode?url=<stream_url>")
            return

        params = parse_qs(parsed.query)
        url_list = params.get("url")
        if not url_list:
            self.send_error(400, "Missing 'url' parameter")
            return

        stream_url = unquote(url_list[0])
        bitrate = params.get("bitrate", [DEFAULT_BITRATE])[0]

        if not active_streams.acquire(blocking=False):
            self.send_error(503, "Too many concurrent streams")
            return

        try:
            self._transcode(stream_url, bitrate)
        finally:
            active_streams.release()

    def _transcode(self, stream_url, bitrate):
        self.log_message("Transcoding: %s (bitrate=%s)", stream_url, bitrate)

        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel", "warning",
            "-reconnect", "1",
            "-reconnect_streamed", "1",
            "-reconnect_delay_max", "5",
            "-i", stream_url,
            "-vn",
            "-codec:a", "libmp3lame",
            "-b:a", bitrate,
            "-ar", SAMPLE_RATE,
            "-ac", CHANNELS,
            "-f", "mp3",
            "-fflags", "+nobuffer",
            "-flush_packets", "1",
            "pipe:1",
        ]

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Read a small chunk first to confirm ffmpeg started OK
            initial = proc.stdout.read(4096)
            if not initial:
                stderr_out = proc.stderr.read(2048).decode(errors="replace")
                self.log_message("FFmpeg failed to start: %s", stderr_out)
                self.send_error(502, "Failed to transcode stream")
                return

            self.protocol_version = "HTTP/1.0"
            self.send_response(200)
            self.send_header("Content-Type", "audio/mpeg")
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-cache, no-store")
            self.send_header("icy-name", "Transcoded Stream")
            self.end_headers()

            self.wfile.write(initial)
            while True:
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)

        except (BrokenPipeError, ConnectionResetError):
            self.log_message("Client disconnected: %s", stream_url)
        except Exception as e:
            self.log_message("Error transcoding %s: %s", stream_url, e)
        finally:
            if proc:
                proc.kill()
                proc.wait()
            self.log_message("Stream ended: %s", stream_url)


class TranscodeServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 10


def main():
    server = TranscodeServer((HOST, PORT), TranscodeHandler)
    print(f"Transcode proxy listening on {HOST}:{PORT}", flush=True)
    print(f"Default bitrate: {DEFAULT_BITRATE}, max concurrent: {MAX_CONCURRENT}", flush=True)

    def shutdown_handler(signum, frame):
        print("Shutting down...", flush=True)
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    server.serve_forever()


if __name__ == "__main__":
    main()
