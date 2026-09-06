#!/usr/bin/env python3
"""Tests for WEB4 — Directory Bruteforcer.

The scanner is pointed at a localhost simulator that plants hidden paths
(/admin, /backup, /config, /robots.txt, /.env) and at a clean control server
that returns 404 for everything. Same HTTP code path as a live target.
"""

import sys
import os
import threading
import time
import unittest
import subprocess
import urllib.request
import urllib.error
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dirbrute import (
    DirBruteforcer, HiddenDirHandler, CleanDirHandler, DEFAULT_WORDLIST, HIDDEN_PATHS,
)


class _Server:
    def __init__(self, handler_cls):
        self.server = HTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)

    def url(self):
        return "http://127.0.0.1:{}".format(self.port)

    def shutdown(self):
        self.server.shutdown()


class TestDirbruteVulnDetection(unittest.TestCase):
    """Scanner must find planted hidden paths."""

    @classmethod
    def setUpClass(cls):
        cls.server = _Server(HiddenDirHandler)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_planted_paths_found(self):
        bf = DirBruteforcer(
            base_url=self.server.url(), wordlist=list(DEFAULT_WORDLIST),
            threads=4, timeout=3, verbose=False,
        )
        bf.scan()
        found_urls = [r.url for r in bf.results]
        for path in HIDDEN_PATHS:
            self.assertTrue(
                any(p == path for p in (u[len(self.server.url()):] for u in found_urls)),
                "Should find planted path {}".format(path),
            )

    def test_export_json(self):
        import tempfile
        bf = DirBruteforcer(
            base_url=self.server.url(), wordlist=["admin", "nonexistent_zz"],
            threads=2, timeout=3,
        )
        bf.scan()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name
        try:
            bf.export_json(tmp)
            with open(tmp) as fh:
                data = fh.read()
            self.assertIn("url", data)
        finally:
            os.unlink(tmp)


class TestDirbruteCleanNoFalsePositive(unittest.TestCase):
    """Scanner must find NOTHING on the clean control server."""

    @classmethod
    def setUpClass(cls):
        cls.server = _Server(CleanDirHandler)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_no_false_positive(self):
        bf = DirBruteforcer(
            base_url=self.server.url(), wordlist=list(DEFAULT_WORDLIST),
            threads=4, timeout=3,
        )
        bf.scan()
        self.assertEqual(len(bf.results), 0,
                         "Should NOT find anything on the clean control server")


class TestDirbruteSimulators(unittest.TestCase):
    def test_hidden_paths_planted(self):
        server = _Server(HiddenDirHandler)
        try:
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            opener = urllib.request.build_opener(NoRedir)
            for path in HIDDEN_PATHS:
                try:
                    r = opener.open(server.url() + path, timeout=3)
                    self.assertIn(r.getcode(), (200, 301, 403))
                    r.read()
                except urllib.error.HTTPError as e:
                    self.assertIn(e.code, (200, 301, 403))
        finally:
            server.shutdown()


class TestDirbruteDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "dirbrute.py", "--demo"],
            capture_output=True, text=True, timeout=30,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertEqual(result.returncode, 0,
                         "Demo should exit 0. stderr: " + result.stderr[:500])
        self.assertIn("vulnerable simulator", result.stdout)


if __name__ == "__main__":
    unittest.main()