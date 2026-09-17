#!/usr/bin/env python3
"""Serve the static site with the deployment routes used by local checks."""

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8794
PLAIN_TEXT_PATHS = {"/iscooked.com", "/llms.txt"}


class PreviewRequestHandler(SimpleHTTPRequestHandler):
    """Serve site files without directory listings or generic error pages."""

    def _request_path(self):
        return urlsplit(self.path).path

    def guess_type(self, path):
        if self._request_path() in PLAIN_TEXT_PATHS:
            return "text/plain; charset=utf-8"
        return super().guess_type(path)

    def end_headers(self):
        if self._request_path() in PLAIN_TEXT_PATHS:
            self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def do_GET(self):
        if self._request_path() == "/i":
            self.send_response(301)
            self.send_header("Location", "/iscooked.com")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_GET()

    def do_HEAD(self):
        if self._request_path() == "/i":
            self.send_response(301)
            self.send_header("Location", "/iscooked.com")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_HEAD()

    def list_directory(self, path):
        self.send_error(404)
        return None

    def send_error(self, code, message=None, explain=None):
        if code != 404:
            return super().send_error(code, message, explain)

        error_page = Path(self.directory) / "404.html"
        try:
            body = error_page.read_bytes()
        except OSError:
            body = b"<!doctype html><title>Page not found</title>"

        self.send_response(404, "File not found")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def create_server(site_dir, bind=DEFAULT_BIND, port=DEFAULT_PORT):
    """Create a threaded preview server rooted at ``site_dir``."""

    root = Path(site_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"site directory does not exist: {root}")
    handler = partial(PreviewRequestHandler, directory=str(root))
    return ThreadingHTTPServer((bind, port), handler)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default=DEFAULT_BIND, help="bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    site_dir = Path(__file__).resolve().parents[1] / "site"
    server = create_server(site_dir, bind=args.bind, port=args.port)
    host, port = server.server_address
    print(f"Serving {site_dir} at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
