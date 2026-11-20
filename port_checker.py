#!/usr/bin/env python3
"""
Port Status Checker
Checks TCP ports on a target host and reports Open / Closed / Filtered,
plus the service name and how fast the port responded.

Use only on hosts you own or have permission to scan
(e.g. 127.0.0.1 or scanme.nmap.org).
"""

import errno
import socket
import time
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def check_port(host, port, timeout):
    """Try a TCP handshake. Returns (port, status, response_ms)."""
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        ms = round((time.time() - start) * 1000, 1)
        if result == 0:
            return port, "Open", ms          # handshake completed
        if result in (errno.ECONNREFUSED, 10061):
            return port, "Closed", ms        # connection refused (RST)
        # timeout / unreachable / no reply -> firewall is dropping packets
        return port, "Filtered", ms
    except socket.timeout:
        return port, "Filtered", round(timeout * 1000, 1)  # no reply (firewall)
    except OSError:
        return port, "Filtered", round(timeout * 1000, 1)
    finally:
        sock.close()


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def main():
    parser = argparse.ArgumentParser(description="TCP Port Status Checker")
    parser.add_argument("host", nargs="?", help="Target IP or hostname")
    parser.add_argument("-s", "--start", type=int, help="Start port")
    parser.add_argument("-e", "--end", type=int, help="End port")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Timeout in seconds (default 1.0)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Show every port in the table (Open, Closed, Filtered)")
    args = parser.parse_args()

    # Step 2: accept target IP and port range
    host = args.host or input("Enter target IP/hostname: ").strip()
    start_port = args.start or int(input("Enter start port: "))
    end_port = args.end or int(input("Enter end port: "))

    if not (1 <= start_port <= end_port <= 65535):
        print("Invalid port range (must be 1-65535, start <= end).")
        return

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Could not resolve host: {host}")
        return

    print(f"\nScan started : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"Target       : {host} ({ip})")
    print(f"Port range   : {start_port}-{end_port}   Timeout: {args.timeout}s\n")

    # Step 3: TCP handshake attempts with timeout (threaded for speed)
    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(lambda p: check_port(ip, p, args.timeout), ports))

    # Step 4: table of Open / Closed / Filtered
    print(f"{'PORT':<8}{'STATUS':<12}{'SERVICE':<16}{'RESPONSE (ms)':<14}")
    print("-" * 50)
    counts = {"Open": 0, "Closed": 0, "Filtered": 0}
    for port, status, ms in results:
        counts[status] += 1
        # Show all ports if --all is used or the range is small, else only Open
        if args.all or status == "Open" or len(results) <= 30:
            print(f"{port:<8}{status:<12}{service_name(port):<16}{ms:<14}")

    print("-" * 50)
    print(f"Summary: {counts['Open']} Open | {counts['Closed']} Closed | "
          f"{counts['Filtered']} Filtered  (total {len(results)})")
    print(f"Scan finished: {datetime.now():%Y-%m-%d %H:%M:%S}")


if __name__ == "__main__":
    main()
