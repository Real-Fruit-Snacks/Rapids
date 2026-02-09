<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/banner.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/banner.svg">
  <img alt="Rapids" src="assets/banner.svg" width="800">
</picture>

<br>

**Modular credential spraying tool for authorized security testing**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://python.org)
[![Services](https://img.shields.io/badge/Services-37%20modules-brightgreen.svg)](#supported-services)

<br>

Rapids sprays credentials across 28 protocols simultaneously using native Python libraries — no external tool dependencies for core functionality. Point it at a network, give it credentials, and it automatically scans ports, detects services, discovers domains, and tests authentication across everything it finds.

</div>

<br>

## Table of Contents

- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Architecture](#architecture)
- [Supported Services](#supported-services)
- [Features](#features)
- [Configuration](#configuration)
- [Contributing](#contributing)

---

## Highlights

<table>
<tr>
<td width="50%">

### Native Library Modules
Every protocol is implemented with a native Python library — impacket for SMB/MSSQL/Kerberos, paramiko for SSH, pywinrm for WinRM, pymysql/psycopg2/redis for databases. No shelling out to CLI tools means faster execution and richer error handling.

</td>
<td width="50%">

### Automatic Discovery
Point Rapids at IP addresses and it runs an nmap service scan automatically. Detected ports are mapped to the correct module, domains are discovered via SMB, and HTTP ports on different ports are kept separate (no deduplication across web apps).

</td>
</tr>
<tr>
<td width="50%">

### Adaptive Skipping
Rapids tracks timeouts per endpoint and per host. After 3 consecutive timeouts on a port, that endpoint is skipped. After 5 total timeouts across all ports on a host, the entire host is marked unreachable — no wasted time on dead targets.

</td>
<td width="50%">

### Dual Module System
Each supported protocol has a native library module and an optional NetExec wrapper. Use `--nxc` to swap to NetExec-backed modules for protocols where nxc provides better compatibility. Both module types share the same interface and run interchangeably.

</td>
</tr>
<tr>
<td width="50%">

### Proof of Access
Use `--verify` to execute proof-of-access commands after successful authentication — list SMB shares, run `whoami` over WinRM, query database versions, fetch Redis server info. Results appear in a dedicated Proof column alongside credentials.

</td>
<td width="50%">

### Per-Service Timeouts
RDP and WinRM connections are inherently slower than SSH or SMB. Rapids automatically applies timeout multipliers — 3x for RDP, 2x for WinRM/Kerberos — so slow protocols get enough time without penalizing fast ones.

</td>
</tr>
<tr>
<td width="50%">

### NT Hash Support
Pass-the-hash across SMB, RDP, WinRM, MSSQL, LDAP, and Kerberos. Credentials can be passwords or NT hashes (prefixed with `:`). Hash and password credentials can be mixed freely in credential files.

</td>
<td width="50%">

### Catppuccin Mocha Theme
All terminal output uses the Catppuccin Mocha color palette — gradient ASCII banner, color-coded status indicators, Rich tables with semantic styling. Because your terminal should look as good as your exploits.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | >= 3.10 |
| pip / pipx | Latest |
| nmap | Any (for auto-scan) |
| NetExec | Optional (for `--nxc` mode) |

### Install & Launch

```bash
git clone https://github.com/Real-Fruit-Snacks/Rapids.git
cd Rapids
pipx install -e .
```

```bash
# Basic spray — auto-scans ports, discovers domain, tests all detected services
rapids -t 192.168.1.0/24 -u admin -p 'Password123'

# Multiple credentials from file
rapids -t 10.10.10.50 -C creds.txt

# Spray with proof-of-access verification
rapids -t 192.168.1.100 -u admin -p 'Pass123' --verify

# Mask credentials for screenshots
rapids -t 10.0.0.0/24 -C creds.txt --mask-creds
```

### From Source (Development)

```bash
git clone https://github.com/Real-Fruit-Snacks/Rapids.git
cd Rapids
pip install -e .
python rapids.py -t 192.168.1.1 -u admin -p password
```

---

## Usage

```
Usage: rapids [OPTIONS]

Options:
  -t, --target TEXT        Target (IP, IP:port, IP:port:service)
  -T, --targets-file TEXT  File with targets (one per line)
  -n, --nmap TEXT          Nmap XML file for auto-discovery
  --no-scan                Disable automatic nmap port/service scan
  -u, --user TEXT          Single username
  -p, --pass TEXT          Single password (or NT hash prefixed with ':')
  -U, --userfile TEXT      Username wordlist file
  -P, --passfile TEXT      Password wordlist file (supports NT hashes)
  -C, --creds TEXT         Credentials file (user:pass or user:hash per line)
  -s, --services TEXT      Comma-separated services to test (default: all)
  -w, --threads INTEGER    Concurrent threads  [default: 10]
  --timeout INTEGER        Connection timeout in seconds  [default: 5]
  --delay FLOAT            Delay between attempts in seconds  [default: 0.0]
  -d, --domain TEXT        Domain for Kerberos/LDAP/WinRM/SMB
  --url-path TEXT          URL path for HTTP  [default: /]
  --http-form-data TEXT    POST form template (e.g. 'user=^USER^&pass=^PASS^')
  --success-string TEXT    String indicating successful HTTP form login
  --show-all               Show all results including failures
  --nxc                    Use NetExec (nxc) modules instead of library-based
  --no-auto-domain         Disable automatic domain discovery
  --dry-run                Show what would be tested without sending traffic
  --port TEXT              Override service port (e.g. --port ssh=2222)
  --verify                 Execute proof-of-access command after successful auth
  --mask-creds             Mask credentials in all output
  --debug                  Show raw debug output for every attempt
  -o, --output TEXT        Write results to JSON file
```

### Examples

```bash
# Spray a single target with one credential
rapids -t 10.10.10.50 -u administrator -p 'Winter2024!'

# Use an nmap XML file instead of auto-scanning
rapids -n scan.xml -u admin -p password --no-scan

# Spray only specific services
rapids -t 192.168.1.100 -C creds.txt -s smb,ssh,rdp

# Use NetExec modules instead of native libraries
rapids -t 10.0.0.5 -u admin -p pass --nxc

# Override default ports
rapids -t 10.0.0.5 -u root -p toor --port ssh=2222 --port mysql=3307

# Dry run — preview what would be tested
rapids -t 192.168.1.0/24 -C creds.txt --dry-run

# Pass-the-hash with NT hash
rapids -t 10.10.10.50 -u administrator -p ':aad3b435b51404eeaad3b435b51404ee'

# Write results to JSON for scripting
rapids -t 10.0.0.0/24 -C creds.txt -o results.json

# Credential file with mixed passwords and hashes
rapids -t 10.10.10.50 -C mixed_creds.txt --verify
```

### Credential File Formats

```bash
# -C / --creds (user:pass per line)
admin:Password123
administrator:aad3b435b51404eeaad3b435b51404ee
sa:SQLServer2024!

# -U / --userfile (one username per line)
admin
administrator
sa

# -P / --passfile (one password/hash per line)
Password123
Winter2024!
:aad3b435b51404eeaad3b435b51404ee
```

---

## Architecture

Rapids is a modular Python CLI application. Each protocol is an independent module that implements a two-method interface — `test_credential()` for authentication and `verify_access()` for proof-of-access. The spray engine handles concurrency, adaptive skipping, and result collection.

```
rapids/
├── rapids.py              # CLI entry point (Click)
├── core/
│   ├── engine.py          # SprayEngine — ThreadPoolExecutor, adaptive skip, timeout multipliers
│   ├── models.py          # Target, Credential, SprayResult dataclasses
│   ├── input_parser.py    # Target/credential parsing, nmap XML, port scanning
│   ├── output.py          # Rich tables, banner, summary, JSON export
│   └── theme.py           # Catppuccin Mocha color palette
├── modules/
│   ├── base.py            # ServiceModule abstract base class
│   ├── nxc_base.py        # NxcModule base (NetExec wrapper + domain discovery)
│   ├── smb.py             # Native: impacket SMBConnection
│   ├── ssh.py             # Native: paramiko
│   ├── rdp.py             # Native: xfreerdp + nxc fallback + impacket CredSSP
│   ├── winrm_mod.py       # Native: pywinrm (NTLM)
│   ├── evil_winrm.py      # Native: evil-winrm CLI wrapper
│   ├── mssql.py           # Native: impacket TDS
│   ├── mysql.py           # Native: pymysql
│   ├── postgres.py        # Native: psycopg2
│   ├── oracle.py          # Native: oracledb (thin mode)
│   ├── redis_mod.py       # Native: redis-py
│   ├── mongodb.py         # Native: pymongo
│   ├── ldap_mod.py        # Native: ldap3
│   ├── kerberos_mod.py    # Native: impacket getTGT
│   ├── ...                # + 13 more native modules
│   ├── nxc_smb.py         # NXC wrapper: smb
│   ├── nxc_winrm.py       # NXC wrapper: winrm
│   └── ...                # + 7 more NXC wrappers
└── pyproject.toml
```

### Module Interface

Every service module extends `ServiceModule` and implements two methods:

```python
class ServiceModule(ABC):
    name: str              # Module identifier (e.g. "smb", "ssh")
    default_port: int      # Default port (e.g. 445, 22)
    alternate_ports: list   # Additional ports to detect

    def test_credential(self, target, credential, timeout=5, **kwargs) -> bool:
        """Return True if authentication succeeds, False if it fails.
        Raise TimeoutError or ConnectionRefusedError for infrastructure errors."""

    def verify_access(self, target, credential, timeout=5, **kwargs) -> Optional[str]:
        """Run a proof-of-access command and return the output string."""
```

### Spray Flow

```
Targets + Credentials + Modules
        |
        v
+------------------+
|    Nmap Scan     |----> auto port/service scan + version detection
+--------+---------+
         |
         v
+------------------+
|  Domain Discov.  |----> nxc smb domain discovery per host
+--------+---------+
         |
         v
+----------------------------+
|       SprayEngine          |----> ThreadPoolExecutor (10 threads)
|                            |
|  Per attempt:              |
|   1. Check skip            |----> host/endpoint unreachable?
|   2. Apply timeout         |----> service multiplier (RDP=3x, WinRM=2x)
|   3. test_credential()     |
|   4. verify_access()       |----> if --verify and auth succeeded
|   5. Track timeouts        |----> adaptive skip counters
+-------------+--------------+
              |
              v
+----------------------------+
|  Rich Output               |----> live progress bar, hit announcements
|  Summary Table             |----> per-host breakdown, valid credentials
|  JSON Export               |----> machine-readable results
+----------------------------+
```

---

## Supported Services

### Native Library Modules (28)

| Protocol | Module | Library | Default Port | Hash Support |
|----------|--------|---------|:------------:|:------------:|
| SMB | `smb` | impacket | 445 | Yes |
| SSH | `ssh` | paramiko | 22 | — |
| RDP | `rdp` | xfreerdp / nxc / impacket | 3389 | Yes |
| WinRM | `winrm` | pywinrm | 5985 | — |
| Evil-WinRM | `evil-winrm` | evil-winrm CLI | 5985 | Yes |
| WMI | `wmi` | nxc wmi | 135 | Yes |
| MSSQL | `mssql` | impacket | 1433 | Yes |
| MySQL | `mysql` | pymysql | 3306 | — |
| PostgreSQL | `postgres` | psycopg2 | 5432 | — |
| Oracle | `oracle` | oracledb | 1521 | — |
| Redis | `redis` | redis-py | 6379 | — |
| MongoDB | `mongodb` | pymongo | 27017 | — |
| LDAP | `ldap` | ldap3 | 389 | — |
| Kerberos | `kerberos` | impacket | 88 | Yes |
| FTP | `ftp` | ftplib | 21 | — |
| HTTP Basic | `http` | requests | 80 | — |
| SMTP | `smtp` | smtplib | 587 | — |
| IMAP | `imap` | imaplib | 993 | — |
| POP3 | `pop3` | poplib | 995 | — |
| Telnet | `telnet` | telnetlib | 23 | — |
| VNC | `vnc` | socket | 5900 | — |
| SNMP | `snmp` | pysnmp | 161 | — |
| MQTT | `mqtt` | paho-mqtt | 1883 | — |
| CouchDB | `couchdb` | requests | 5984 | — |
| Cassandra | `cassandra` | cassandra-driver | 9042 | — |
| Elasticsearch | `elasticsearch` | requests | 9200 | — |
| Memcached | `memcached` | pymemcache | 11211 | — |
| IPMI | `ipmi` | ipmitool CLI | 623 | — |

### NetExec Wrapper Modules (9)

Use `--nxc` to swap native modules for NetExec-backed equivalents:

| Module | Protocol | Includes |
|--------|----------|----------|
| `nxc_smb` | SMB | Guest detection, Pwn3d! status |
| `nxc_winrm` | WinRM | SSL support |
| `nxc_ssh` | SSH | Platform detection |
| `nxc_rdp` | RDP | Guest detection |
| `nxc_mssql` | MSSQL | Domain auth |
| `nxc_ldap` | LDAP | Domain auth |
| `nxc_ftp` | FTP | — |
| `nxc_wmi` | WMI | Domain auth |
| `nxc_vnc` | VNC | — |

---

## Features

| Feature | Description |
|---------|-------------|
| **Auto nmap scan** | Automatic port/service/version scan on all targets before spraying |
| **Domain discovery** | Detects AD domain via SMB on hosts with port 445 open |
| **Adaptive skip** | Skips unreachable endpoints (3 timeouts) and hosts (5 timeouts) |
| **Per-service timeouts** | RDP gets 3x, WinRM/Kerberos get 2x the base timeout |
| **NT hash support** | Pass-the-hash on SMB, RDP, MSSQL, LDAP, Kerberos, WinRM |
| **Guest detection** | Rejects SMB/RDP/WMI guest logins as authentication failures |
| **Proof of access** | `--verify` runs post-auth commands (share listing, whoami, SELECT version) |
| **Credential masking** | `--mask-creds` hides passwords in all output for safe screen sharing |
| **HTTP dedup exemption** | Different HTTP ports are tested separately (each may be a different app) |
| **Dry run** | `--dry-run` previews targets, credentials, and attack plan without traffic |
| **JSON export** | `-o results.json` for scripting and integration |
| **NXC swap** | `--nxc` replaces native modules with NetExec wrappers |
| **Port overrides** | `--port ssh=2222` overrides default ports per service |
| **Debug mode** | `--debug` prints raw status for every attempt to stderr |
| **Catppuccin theme** | Full Mocha palette with semantic colors and Rich tables |
| **Hard timeout** | Safety net kills hung futures that exceed 3x the connection timeout |

---

## Configuration

Rapids uses sensible defaults with no config file required. All options are CLI flags:

| Option | Default | Description |
|--------|---------|-------------|
| `--threads` | `10` | Concurrent worker threads |
| `--timeout` | `5` | Base connection timeout (seconds) |
| `--delay` | `0.0` | Delay between attempts (seconds) |
| `--domain` | *(auto)* | Domain for AD protocols (auto-discovered if not set) |
| `--port` | *(default)* | Override any service port |
| `--nxc` | `false` | Swap to NetExec modules |
| `--no-scan` | `false` | Skip automatic nmap scan |
| `--no-auto-domain` | `false` | Skip SMB domain discovery |

### Timeout Multipliers

| Service | Multiplier | Effective (at default 5s) |
|---------|:----------:|:-------------------------:|
| SSH, SMB, FTP, etc. | 1x | 5s |
| WinRM, Kerberos | 2x | 10s |
| RDP | 3x | 15s |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Test with `rapids --dry-run` and against a lab environment
5. Commit with a descriptive message
6. Open a Pull Request

### Adding a New Module

1. Create `modules/myservice.py` extending `ServiceModule`
2. Implement `test_credential()` and optionally `verify_access()`
3. Set `name`, `default_port`, and `alternate_ports`
4. Add the port mapping to `PORT_SERVICE_MAP` in `core/input_parser.py`
5. The module auto-registers via `ModuleRegistry` — no manual wiring needed

---

<div align="center">

**Built for offense. Tested in labs.**

[GitHub](https://github.com/Real-Fruit-Snacks/Rapids) | [License (MIT)](LICENSE) | [Report Issue](https://github.com/Real-Fruit-Snacks/Rapids/issues)

*Rapids — modular credential spraying*

</div>
