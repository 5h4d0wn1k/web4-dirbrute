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
# Basic scan
python3 dirbrute.py http://example.com

# With custom wordlist
python3 dirbrute.py http://example.com -w wordlist.txt

# With extensions and threads
python3 dirbrute.py http://example.com -e .php,.html,.bak -t 20

# Recursive scan with specific status codes
python3 dirbrute.py http://example.com -r -s 200,301,302,403

# Follow redirects
python3 dirbrute.py http://example.com --follow-redirects
```

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

## License

MIT
