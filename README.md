# WEB4 — Directory Bruteforcer

HTTP directory brute-force scanner with recursive scanning and thread support.

## Overview

This project implements a directory brute-force tool that:
- Scans for hidden directories and files on web servers
- Filters results by HTTP status codes
- Supports recursive scanning of discovered directories
- Uses custom wordlists and file extensions
- Multi-threaded for fast scanning

## Features

- **HTTP brute-force**: Discover hidden paths on web servers
- **Status filtering**: Show only relevant HTTP status codes
- **Recursive scanning**: Automatically scan discovered directories
- **Custom wordlists**: Load your own path lists from files
- **Extension support**: Append extensions like .php, .html, .bak
- **Thread pool**: Configurable concurrency for fast scanning
- **Redirect detection**: Identify and report HTTP redirects

## Installation

```bash
# No external dependencies required — uses Python stdlib only
python3 --version  # Requires Python 3.7+
```

## Usage

```bash
# Offline demo: brute-forces the built-in vulnerable + clean simulators (exit 0)
python3 dirbrute.py --demo

# Live scan of a lab target (127.0.0.1 / 192.0.2.x only)
python3 dirbrute.py http://127.0.0.1:<port>

# With custom wordlist
python3 dirbrute.py http://127.0.0.1:<port> -w wordlist.txt

# With extensions and threads
python3 dirbrute.py http://127.0.0.1:<port> -e .php,.html,.bak -t 20

# Recursive scan with specific status codes and JSON export
python3 dirbrute.py http://127.0.0.1:<port> -r -s 200,301,302,403 -o findings/dirs.json

# Follow redirects / verbose output
python3 dirbrute.py http://127.0.0.1:<port> --follow-redirects -v
```

## CLI Options

| Option | Description |
|--------|-------------|
| `target` | Target URL (e.g. http://127.0.0.1:<port>) |
| `-w, --wordlist` | Path to a wordlist file |
| `-t, --threads` | Number of concurrent threads (default: 10) |
| `-s, --status` | Status codes to report (default: 200,201,301,302,403) |
| `-e, --extensions` | Extensions to append (comma-separated) |
| `--timeout` | Per-request timeout in seconds |
| `-r, --recursive` | Recursively scan discovered directories |
| `--follow-redirects` | Follow HTTP redirects (default: report Location) |
| `-o, --output` | Export results to a JSON file |
| `-v, --verbose` | Verbose output |
| `--demo` | Offline demo against the two built-in simulators |

## Example Output

```
============================================================
  WEB4 — Directory Bruteforcer
============================================================
  Target:    http://example.com
  Threads:   10
  Wordlist:  91 entries
  Extensions: 
  Recursive: False
  Filter:    [200, 201, 301, 302, 403]
============================================================

  [depth=0] Scanning 91 URLs...

============================================================
  Scan Complete
============================================================
  Time:       3.45s
  Requests:   91
  Found:      5
  Redirects:  2
  Errors:     0
============================================================

  [301]       0  http://example.com/admin -> http://example.com/admin/
  [403]       0  http://example.com/.git
  [200]    1024  http://example.com/robots.txt
  [200]    2048  http://example.com/login
  [302]       0  http://example.com/dashboard -> http://example.com/login
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Running the Demo and Tests

The project ships two built-in simulators (stdlib `http.server`):

- **Vulnerable** — a server with planted hidden paths (`/admin`, `/backup`,
  `/config` (403), `/robots.txt`, `/.env`, `/private` (301 redirect)).
- **Clean** — a control server that returns 404 for every path.

`--demo` runs the full brute-force engine (same HTTP code path as a live target)
against both simulators and confirms the planted paths are found and the clean
control produces zero findings.

```bash
python3 -m unittest discover -s tests -v
```

## Live Lab Test Plan

Test only against targets in your own lab (e.g. a deliberately configured web
server on 127.0.0.1 or 192.0.2.x RFC-5737 space):

1. Deploy a local web server with a small set of known hidden files.
2. Baseline: `python3 dirbrute.py http://127.0.0.1:<port> -v`
3. Confirm the known hidden paths are reported with the expected status codes.
4. Point the scanner at a hardened server listing no hidden resources and confirm
   zero findings.
5. If recursive enabled, confirm discovered directories expand the scan.
6. Document the target, wordlist used, and the status-code evidence in your lab
   report.

## Metrics

- **Video metric**: 60-second screencast of `python3 dirbrute.py --demo` (vulnerable
  findings + clean control zero findings) and `python3 -m unittest discover -s tests -v`,
  recorded against the lab-only loopback target.
- **Pass rate**: all unit tests green; demo exit 0.

## License

MIT
