# Port Status Checker

A simple TCP port scanner written in Python using the built-in `socket` library.
It attempts a TCP connection (handshake) to every port in a given range and
reports whether each port is **Open**, **Closed** or **Filtered**, along with
the service name and response time.

> **Ethical use:** Scan only systems you own or have explicit permission to test.
> The examples below use `127.0.0.1` (own machine) and `scanme.nmap.org`
> (a public server provided by Nmap for scan testing).

## How it works

| Status | Meaning |
|--------|---------|
| **Open** | TCP handshake completed, a service is listening |
| **Closed** | Host actively refused the connection (RST), nothing is listening |
| **Filtered** | No reply before the timeout, usually a firewall dropping packets |

Steps the script follows:
1. Import the `socket` library
2. Accept the target IP/hostname and port range
3. Attempt a TCP connection on each port with a timeout (multithreaded for speed)
4. Print a table of Open, Closed and Filtered ports with a summary

## Requirements

- Python 3.x (no external libraries needed)

## Usage

```
python port_checker.py <host> -s <start_port> -e <end_port> [-t timeout] [-a]
```

| Option | Description |
|--------|-------------|
| `host` | Target IP or hostname (asked interactively if omitted) |
| `-s`, `--start` | Start port |
| `-e`, `--end` | End port |
| `-t`, `--timeout` | Timeout in seconds (default 1.0) |
| `-a`, `--all` | Show every port in the table (otherwise large ranges show only Open ports) |

### Examples

Scan the local machine (start a test server first with `python -m http.server 8000`):
```
python port_checker.py 127.0.0.1 -s 8000 -e 8005 -t 3
```

Scan a public test host and show all ports:
```
python port_checker.py scanme.nmap.org -s 20 -e 100 -t 4 -a
```

## Sample output

```
Target       : 127.0.0.1 (127.0.0.1)
Port range   : 8000-8005   Timeout: 3.0s

PORT    STATUS      SERVICE         RESPONSE (ms)
--------------------------------------------------
8000    Open        unknown         2.5
8001    Closed      unknown         2019.2
8002    Closed      unknown         2018.9
8003    Closed      unknown         2018.4
8004    Closed      unknown         2018.0
8005    Closed      unknown         2018.1
--------------------------------------------------
Summary: 1 Open | 5 Closed | 0 Filtered  (total 6)
```

Full execution logs are in:
- `scan_log_localhost.txt`
- `scan_log_remote.txt`

Screenshots are in the `screenshots/` folder.

## Notes

- On Windows, a refused connection can take 1 to 4 seconds to be reported, so use
  a timeout of at least 3 to 4 seconds. With a very short timeout, closed ports
  may be wrongly reported as Filtered.
- Results against remote hosts can vary slightly between runs because of network
  conditions and firewall rate limiting.

## Author

Harsh Bhende
