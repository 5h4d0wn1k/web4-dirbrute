#!/usr/bin/env python3
"""
WEB4 — Directory Bruteforcer
HTTP directory brute-force scanner with recursive scanning and thread support.
"""

import json
import sys
import time
import argparse
import urllib.request
import urllib.error
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Set
from http.server import HTTPServer, BaseHTTPRequestHandler


DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "api", "backup", "config", "debug",
    "test", "dev", "staging", "old", "new", "temp", "tmp", "cache",
    "uploads", "images", "css", "js", "static", "assets", "media",
    "files", "docs", "download", "downloads", "export", "import",
    "robots.txt", "sitemap.xml", ".env", ".git", ".htaccess",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    ".well-known", "server-status", "server-info", "phpinfo.php",
    "xmlrpc.php", "readme.html", "license.txt", "changelog.txt",
    "install", "setup", "register", "signup", "signin",
    "profile", "account", "settings", "help", "support",
    "blog", "news", "forum", "community", "wiki",
    "search", "sort", "filter", "list", "index",
    "cgi-bin", "scripts", "bin", "conf", "etc", "var",
    "log", "logs", "error", "errors", "status", "health",
    "version", "info", "about", "contact", "legal", "privacy",
    "private", "secret", "internal", "hidden", "secure",
]


@dataclass
class ScanResult:
    url: str
    status_code: int
    content_length: int
    redirect_url: Optional[str] = None


@dataclass
class ScanStats:
    total_requests: int = 0
    found: int = 0
    errors: int = 0
    redirects: int = 0
    start_time: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def increment(self, attr: str) -> None:
        with self._lock:
            setattr(self, attr, getattr(self, attr) + 1)


class DirBruteforcer:
    def __init__(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        threads: int = 10,
        status_filter: Optional[List[int]] = None,
        extensions: Optional[List[str]] = None,
        timeout: int = 5,
        recursive: bool = False,
        follow_redirects: bool = False,
        verbose: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.threads = threads
        self.status_filter = status_filter or [200, 201, 301, 302, 307, 308, 403]
        self.extensions = extensions or [""]
        self.timeout = timeout
        self.recursive = recursive
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.results: List[ScanResult] = []
        self.stats = ScanStats()
        self._stop_event = threading.Event()
        self._results_lock = threading.Lock()
        self._dirs_found: Set[str] = set()

    def _build_urls(self, path: str) -> List[str]:
        urls = []
        for ext in self.extensions:
            url = f"{self.base_url}/{path}{ext}"
            urls.append(url)
        return urls

    def _request(self, url: str) -> Optional[urllib.request.Request]:
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                },
            )
            return req
        except Exception:
            return None

    def _check_url(self, url: str) -> Optional[ScanResult]:
        if self._stop_event.is_set():
            return None

        req = self._request(url)
        if req is None:
            return None

        try:
            if self.follow_redirects:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                status = resp.getcode()
                content_length = len(resp.read())
                redirect_url = resp.url if resp.url != url else None
            else:
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)
                resp = opener.open(req, timeout=self.timeout)
                status = resp.getcode()
                content_length = len(resp.read())
                redirect_url = resp.headers.get("Location")
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                content_length = len(e.read())
            except Exception:
                content_length = 0
            redirect_url = e.headers.get("Location") if e.code in (301, 302, 307, 308) else None
        except (urllib.error.URLError, OSError, TimeoutError):
            self.stats.increment("errors")
            return None
        except Exception:
            self.stats.increment("errors")
            return None

        self.stats.increment("total_requests")

        if status in self.status_filter:
            result = ScanResult(
                url=url,
                status_code=status,
                content_length=content_length,
                redirect_url=redirect_url,
            )
            with self._results_lock:
                self.results.append(result)
                self.stats.increment("found")
                if redirect_url:
                    self.stats.increment("redirects")
            return result
        return None

    def _scan_batch(self, urls: List[str]) -> List[ScanResult]:
        found = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_url, url): url for url in urls}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                result = future.result()
                if result:
                    found.append(result)
        return found

    def _is_directory(self, result: ScanResult) -> bool:
        if result.status_code in (301, 302, 307, 308):
            return True
        if result.url.endswith("/"):
            return True
        if result.status_code == 403:
            return True
        return False

    def scan(self) -> List[ScanResult]:
        print(f"\n{'='*60}")
        print(f"  WEB4 — Directory Bruteforcer")
        print(f"{'='*60}")
        print(f"  Target:    {self.base_url}")
        print(f"  Threads:   {self.threads}")
        print(f"  Wordlist:  {len(self.wordlist)} entries")
        print(f"  Extensions: {', '.join(self.extensions) if self.extensions else 'none'}")
        print(f"  Recursive: {self.recursive}")
        print(f"  Filter:    {self.status_filter}")
        print(f"{'='*60}\n")

        self.stats.start_time = time.time()
        queue = list(self.wordlist)
        scanned_dirs: Set[str] = set()
        depth = 0
        max_depth = 3

        while queue and depth <= max_depth:
            batch = queue[:500]
            queue = queue[500:]

            urls = []
            for path in batch:
                urls.extend(self._build_urls(path))

            if self.verbose:
                print(f"  [depth={depth}] Scanning {len(urls)} URLs...")
            found = self._scan_batch(urls)

            if self.recursive:
                for result in found:
                    if self._is_directory(result):
                        path = result.url.replace(self.base_url + "/", "").rstrip("/")
                        if path not in scanned_dirs:
                            scanned_dirs.add(path)
                            for word in self.wordlist:
                                new_path = f"{path}/{word}"
                                if new_path not in scanned_dirs:
                                    queue.append(new_path)

            depth += 1

        elapsed = time.time() - self.stats.start_time
        print(f"\n{'='*60}")
        print(f"  Scan Complete")
        print(f"{'='*60}")
        print(f"  Time:       {elapsed:.2f}s")
        print(f"  Requests:   {self.stats.total_requests}")
        print(f"  Found:      {self.stats.found}")
        print(f"  Redirects:  {self.stats.redirects}")
        print(f"  Errors:     {self.stats.errors}")
        print(f"{'='*60}\n")

        for r in sorted(self.results, key=lambda x: (x.status_code, x.url)):
            status_str = str(r.status_code)
            size_str = f"{r.content_length:>8}"
            redirect_str = f" -> {r.redirect_url}" if r.redirect_url else ""
            print(f"  [{status_str}] {size_str}  {r.url}{redirect_str}")

        print()
        return self.results

    def export_json(self, filename: str) -> None:
        data = []
        for r in self.results:
            data.append({
                "url": r.url, "status_code": r.status_code,
                "content_length": r.content_length, "redirect_url": r.redirect_url,
            })
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")

    def stop(self) -> None:
        self._stop_event.set()


def load_wordlist(filepath: str) -> List[str]:
    words = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


def parse_status_codes(status_str: str) -> List[int]:
    codes = []
    for part in status_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            codes.extend(range(int(start), int(end) + 1))
        else:
            codes.append(int(part))
    return codes


# ---------------------------------------------------------------------------
# Built-in simulators
# ---------------------------------------------------------------------------

HIDDEN_PATHS = {
    "/admin": (200, b"<html><body><h1>Admin panel</h1></body></html>"),
    "/backup": (200, b"<html><body><h1>Backup files</h1></body></html>"),
    "/config": (403, b"<html><body><h1>403 Forbidden</h1></body></html>"),
    "/robots.txt": (200, b"User-agent: *\nDisallow: /admin"),
    "/.env": (200, b"DB_PASSWORD=labsecret_dontleak"),
    "/private": (301, b""),
}


class HiddenDirHandler(BaseHTTPRequestHandler):
    """Simulates a server with discoverable hidden paths."""

    def do_GET(self):
        entry = HIDDEN_PATHS.get(self.path)
        if entry is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
            return
        status, body = entry
        loc = None
        if self.path == "/private":
            status, body, loc = 301, b"", "/login"
        self.send_response(status)
        if loc:
            self.send_header("Location", loc)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    log_message = lambda self, fmt, *args: None  # noqa: E731


class CleanDirHandler(BaseHTTPRequestHandler):
    """Control server: every path 404s, nothing discoverable."""

    def do_GET(self):
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")

    log_message = lambda self, fmt, *args: None  # noqa: E731


def _run_scan_against(server, wordlist, extinct=None):
    base = f"http://127.0.0.1:{server.server_port}"
    filter_codes = [200, 201, 301, 302, 307, 308, 403]
    bf = DirBruteforcer(
        base_url=base, wordlist=wordlist, threads=4, timeout=3,
        status_filter=filter_codes, verbose=False,
    )
    bf.scan()
    return bf


def demo():
    """Offline demo: bruteforce the built-in vulnerable simulator, then the clean one."""
    wordlist = [w for w in DEFAULT_WORDLIST]
    vuln = HTTPServer(("127.0.0.1", 0), HiddenDirHandler)
    thread_v = threading.Thread(target=vuln.serve_forever, daemon=True)
    thread_v.start()

    clean = HTTPServer(("127.0.0.1", 0), CleanDirHandler)
    thread_c = threading.Thread(target=clean.serve_forever, daemon=True)
    thread_c.start()

    print("  +------------------------------------------+")
    print("  |     WEB4 -- Directory Bruteforcer         |")
    print("  +------------------------------------------+\n")
    print(f"[*] DEMO MODE: vulnerable simulator on http://127.0.0.1:{vuln.server_port}")
    print(f"[*] DEMO MODE: clean control simulator on http://127.0.0.1:{clean.server_port}\n")

    print("=" * 40)
    print("  VULNERABLE TARGET (hidden paths planted)")
    print("=" * 40)
    bf_v = _run_scan_against(vuln, wordlist)
    print()

    print("=" * 40)
    print("  CLEAN CONTROL TARGET (nothing discoverable)")
    print("=" * 40)
    bf_c = _run_scan_against(clean, wordlist)
    print()

    vuln.shutdown()
    clean.shutdown()

    if bf_v.stats.found > 0 and bf_c.stats.found == 0:
        print("[+] Demo: hidden paths found on vulnerable simulator, none on clean control.")
        print(f"[+] Vulnerable simulator findings: {bf_v.stats.found}")
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    print("[-] Demo: unexpected result -- scanner may need tuning.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="WEB4 — Directory Bruteforcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s http://127.0.0.1:<port>
  %(prog)s http://127.0.0.1:<port> -w wordlist.txt -t 20 -e .php,.html -o out.json -v
  %(prog)s --demo
        """,
    )
    parser.add_argument("target", nargs="?", help="Target URL (e.g. http://127.0.0.1:<port>)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-s", "--status", default="200,201,301,302,403",
                        help="Status codes to report (default: 200,201,301,302,403)")
    parser.add_argument("-e", "--extensions", default="",
                        help="Extensions to append (comma-separated, e.g. .php,.html)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive scanning")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--demo", action="store_true", help="Run offline demo against built-in simulators")

    args = parser.parse_args()

    if args.demo:
        demo()
        return

    if not args.target:
        parser.error("target is required (or use --demo)")

    wordlist = DEFAULT_WORDLIST
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        print(f"[*] Loaded {len(wordlist)} words from {args.wordlist}")

    extensions = [""] if not args.extensions else args.extensions.split(",")
    status_filter = parse_status_codes(args.status)

    bruteforcer = DirBruteforcer(
        base_url=args.target,
        wordlist=wordlist,
        threads=args.threads,
        status_filter=status_filter,
        extensions=extensions,
        timeout=args.timeout,
        recursive=args.recursive,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose,
    )

    try:
        bruteforcer.scan()
        if args.output:
            bruteforcer.export_json(args.output)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        bruteforcer.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()