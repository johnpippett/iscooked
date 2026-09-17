"""Integration checks for the local static-site preview server."""

from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
import sys
import tempfile
from threading import Thread
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.preview import DEFAULT_BIND, DEFAULT_PORT, create_server


@contextmanager
def running_preview(site_root):
    server = create_server(site_root, bind="127.0.0.1", port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def request(address, path):
    connection = HTTPConnection(address[0], address[1], timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        return response.status, headers, response.read()
    finally:
        connection.close()


def make_site_fixture(base):
    site = base / "site"
    site.mkdir()
    (site / "index.html").write_text("<h1>preview</h1>\n", encoding="utf-8")
    (site / "iscooked.com").write_text("#!/usr/bin/env bash\necho scanner\n", encoding="utf-8")
    (site / "llms.txt").write_text("# guide\n", encoding="utf-8")
    (site / "404.html").write_text("<h1>Page not found</h1>\n", encoding="utf-8")
    assets = site / "assets"
    assets.mkdir()
    (assets / "private.txt").write_text("do not list\n", encoding="utf-8")
    (base / "outside.txt").write_text("outside root\n", encoding="utf-8")
    return site


class PreviewServerTests(unittest.TestCase):
    def test_default_bind_and_port_are_loopback_defaults(self):
        self.assertEqual(DEFAULT_BIND, "127.0.0.1")
        self.assertEqual(DEFAULT_PORT, 8794)


    def test_preview_serves_homepage_and_plaintext_routes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            site = make_site_fixture(Path(temp_dir))
            with running_preview(site) as address:
                status, headers, body = request(address, "/")
                self.assertEqual(status, 200)
                self.assertEqual(body, b"<h1>preview</h1>\n")
                self.assertTrue(headers["content-type"].startswith("text/html"))

                status, headers, body = request(address, "/iscooked.com")
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"], "text/plain; charset=utf-8")
                self.assertEqual(headers["x-content-type-options"], "nosniff")
                self.assertTrue(body.startswith(b"#!/usr/bin/env bash"))

                status, headers, body = request(address, "/llms.txt")
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"], "text/plain; charset=utf-8")
                self.assertEqual(headers["x-content-type-options"], "nosniff")
                self.assertEqual(body, b"# guide\n")

    def test_preview_preserves_legacy_redirect_and_custom_not_found_page(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            site = make_site_fixture(Path(temp_dir))
            with running_preview(site) as address:
                status, headers, body = request(address, "/i?legacy=1")
                self.assertEqual(status, 301)
                self.assertEqual(headers["location"], "/iscooked.com")
                self.assertEqual(body, b"")

                status, headers, body = request(address, "/missing-route")
                self.assertEqual(status, 404)
                self.assertTrue(headers["content-type"].startswith("text/html"))
                self.assertEqual(body, b"<h1>Page not found</h1>\n")

    def test_preview_disables_directory_listing_and_rejects_root_escape(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            site = make_site_fixture(base)
            with running_preview(site) as address:
                status, _, body = request(address, "/assets/")
                self.assertEqual(status, 404)
                self.assertNotIn(b"private.txt", body)
                self.assertNotIn(b"Directory listing", body)

                for path in ("/../outside.txt", "/%2e%2e/outside.txt"):
                    status, _, body = request(address, path)
                    self.assertEqual(status, 404)
                    self.assertNotIn(b"outside root", body)


if __name__ == "__main__":
    unittest.main()
