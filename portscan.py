#!/usr/bin/env python3
"""portscan - fast concurrent TCP port scanner with banner grabbing.
For authorized use on hosts you own or have permission to test."""
import argparse, json, socket, sys, concurrent.futures as cf
from datetime import datetime, timezone

COMMON = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,
          2049,3000,3306,3389,4444,5000,5432,5900,6379,8000,8080,8443,8888,9200,27017]
SERVICES = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
            111:"rpcbind",135:"msrpc",139:"netbios",143:"imap",443:"https",445:"smb",
            993:"imaps",995:"pop3s",1433:"mssql",1521:"oracle",2049:"nfs",3000:"dev-http",
            3306:"mysql",3389:"rdp",4444:"metasploit",5000:"dev-http",5432:"postgres",
            5900:"vnc",6379:"redis",8000:"http-alt",8080:"http-proxy",8443:"https-alt",
            8888:"http-alt",9200:"elasticsearch",27017:"mongodb"}

def grab_banner(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            if port in (80, 8080, 8000, 8888, 3000, 5000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            s.settimeout(timeout)
            data = s.recv(256)
            return data.decode("utf-8", "replace").strip().splitlines()[0][:120] if data else ""
    except Exception:
        return ""

def scan_port(host, port, timeout, banners):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            r = {"port": port, "state": "open", "service": SERVICES.get(port, "unknown")}
            if banners:
                b = grab_banner(host, port, timeout)
                if b: r["banner"] = b
            return r
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1); ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def main():
    ap = argparse.ArgumentParser(description="Concurrent TCP port scanner with banner grabbing.")
    ap.add_argument("host", help="Target hostname or IP (must be yours or authorized).")
    ap.add_argument("-p", "--ports", help="Ports: e.g. 22,80,443 or 1-1024. Default: common set.")
    ap.add_argument("-t", "--threads", type=int, default=200, help="Worker threads (default 200).")
    ap.add_argument("--timeout", type=float, default=1.0, help="Per-connect timeout seconds (default 1.0).")
    ap.add_argument("--banners", action="store_true", help="Grab service banners on open ports.")
    ap.add_argument("-o", "--output", help="Write JSON results to this file.")
    args = ap.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        sys.exit(f"error: cannot resolve {args.host}")
    ports = parse_ports(args.ports) if args.ports else COMMON
    print(f"[*] Scanning {args.host} ({ip}) - {len(ports)} ports, {args.threads} threads")

    open_ports, done = [], 0
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_port, ip, p, args.timeout, args.banners): p for p in ports}
        for fut in cf.as_completed(futs):
            done += 1
            r = fut.result()
            if r:
                open_ports.append(r)
                line = f"[+] {r['port']:>5}/tcp open  {r['service']}"
                if "banner" in r: line += f"  | {r['banner']}"
                print(line)
            if done % 500 == 0: print(f"    ... {done}/{len(ports)}", flush=True)

    open_ports.sort(key=lambda r: r["port"])
    result = {"host": args.host, "ip": ip, "scanned_ports": len(ports),
              "open_count": len(open_ports), "open_ports": open_ports,
              "scanned_at": datetime.now(timezone.utc).isoformat()}
    print(f"[*] Done: {len(open_ports)} open port(s) of {len(ports)} scanned.")
    if args.output:
        with open(args.output, "w") as f: json.dump(result, f, indent=2)
        print(f"[*] JSON written to {args.output}")
    sys.exit(0 if open_ports else 1)

if __name__ == "__main__":
    main()
