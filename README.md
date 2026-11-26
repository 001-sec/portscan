# portscan

A fast, concurrent TCP port scanner with service identification and banner grabbing. Single-file, standard library only, no dependencies.

## Features
- Scans a curated set of common ports by default, or any range/list you give it (`22,80,443` or `1-65535`)
- Hundreds of ports per second via a thread pool
- Optional banner grabbing, with HTTP probing on web ports
- JSON output for pipelines and reports
- Clean exit codes (0 = open ports found, 1 = none)

## Usage
```
python3 portscan.py example.com
python3 portscan.py 192.168.1.10 -p 1-1024 --banners
python3 portscan.py example.com -p 20-25,80,443 -t 500 -o results.json
```

## Options
| Flag | Description |
|---|---|
| `-p, --ports` | Comma list and/or ranges, e.g. `22,80,1000-2000` |
| `-t, --threads` | Worker threads (default 200) |
| `--timeout` | Per-connect timeout in seconds (default 1.0) |
| `--banners` | Grab service banners on open ports |
| `-o, --output` | Write JSON results to a file |

## Legal
Only scan hosts you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

## License
MIT
