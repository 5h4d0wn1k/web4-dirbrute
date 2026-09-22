> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# WEB4 — HTTP Directory Bruteforcer

Recursive **directory brute-forcing** scanner with status-code filtering,
custom wordlists and extensions, and a configurable thread pool for **web
security** testing and hidden-endpoint discovery.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/web4-dirbrute)](https://github.com/5h4d0wn1k/web4-dirbrute)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/web4-dirbrute)](https://github.com/5h4d0wn1k/web4-dirbrute/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/web4-dirbrute)](https://github.com/5h4d0wn1k/web4-dirbrute)

## Why

Hidden paths — `/admin`, `/backup`, `/.env`, stray `.bak` files — are where web
applications leak configuration, credentials, and control panels that no link
ever advertises. Directory brute-forcing is the standard way defenders *and*
authorized testers map that surface, and doing it well means low noise:
filtering by status code, recursive descent into discovered directories, and
threaded requests that respect timeouts. WEB4 ships a stdlib-only engine plus
two built-in simulators — a deliberately vulnerable server and a clean control
server — so the exact HTTP code path used against a live lab target can be
verified offline with zero findings on the control. It is built for authorized
web penetration testing against targets you own or hold explicit permission to
scan.

## Features

- **HTTP brute-force** — discovers hidden paths on a target web server
- **Status-code filtering** — show only relevant codes (default `200,201,301,302,403`)
- **Recursive scanning** — automatically descends into discovered directories (`-r`)
- **Custom wordlists** — `-w wordlist.txt` or the built-in default list
- **Extension support** — append `.php`, `.html`, `.bak`, … (`-e`)
- **Thread pool** — configurable concurrency for fast scanning (`-t`)
- **Redirect detection** — reports `Location` and can follow redirects
- **Offline demo** — `--demo` against the bundled vulnerable + clean simulators (exit 0)

## Quickstart

Python 3.7+ standard library only — no dependencies.

```bash
# Offline demo against the built-in vulnerable + clean simulators (exit 0)
python3 dirbrute.py --demo

# Live scan of a lab target (loopback / RFC 5737 space only)
python3 dirbrute.py http://127.0.0.1:<port>

# Custom wordlist, extensions, and threads
python3 dirbrute.py http://127.0.0.1:<port> -w wordlist.txt -e .php,.html,.bak -t 20

# Recursive scan with status filter and JSON export
python3 dirbrute.py http://127.0.0.1:<port> -r -s 200,301,302,403 -o findings/dirs.json

# Unit tests (5 cases)
python3 -m unittest discover -s tests -v
```

## Project structure

- `dirbrute.py` — CLI entry point and HTTP scan engine
- `tests/` — unit tests

## Legal & authorized use

For **educational and authorized security testing purposes only**. Scan only
targets you own, e.g. a deliberately configured server on `127.0.0.1`, `192.0.2.x`
(RFC 5737), or other lab-only hosts in written scope. See [ETHICS.md](ETHICS.md),
[SCOPE.md](SCOPE.md), and [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).