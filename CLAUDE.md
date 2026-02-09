# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rapids is a modular credential spraying tool for authorized security testing (OSCP labs). It supports 37 service modules (28 native Python library + 9 NetExec CLI wrappers) with ThreadPoolExecutor-based concurrency, adaptive timeout skipping, and Rich terminal output using a Catppuccin Mocha theme.

## Build & Install

```bash
# Development install (editable)
pip install -e .

# User install via pipx
pipx install -e .

# Run directly without installing
python rapids.py [options]
```

No build step, linting, or test suite exists. The project is a single-package Python CLI tool.

## Running

```bash
# Basic usage
rapids -t 192.168.1.0/24 -u admin -p Password123

# With nmap auto-scan
rapids -t 10.10.10.0/24 -U users.txt -P passwords.txt

# Specific services, NXC mode, with verification
rapids -n scan.xml -C creds.txt -s smb,rdp,winrm --nxc --verify

# Dry run preview
rapids -t 10.10.10.5 -u admin -p pass --dry-run
```

Entry point: `rapids.py:main` (Click CLI) → `pyproject.toml` registers it as the `rapids` console script.

## Architecture

### Data Flow

```
CLI (rapids.py) → Input Parsing (core/input_parser.py) → Target/Credential models (core/models.py)
    → Optional nmap scan + domain discovery
    → Module selection from ModuleRegistry (modules/__init__.py)
    → SprayEngine (core/engine.py) runs ThreadPoolExecutor
    → Rich output tables + optional JSON export (core/output.py)
```

### Core Files

| File | Purpose |
|------|---------|
| `rapids.py` | CLI entry point, orchestrates entire workflow (24 Click options) |
| `core/engine.py` | SprayEngine - threading, adaptive skip, timeout multipliers, credential masking |
| `core/models.py` | Frozen dataclasses: Target, Credential, SprayResult, ResultStatus enum |
| `core/input_parser.py` | Target/credential parsing, nmap XML parsing, port→service mapping |
| `core/output.py` | All Rich output: banner, tables, JSON export, credential masking |
| `core/theme.py` | `RAPIDS_THEME` - Catppuccin Mocha color palette and semantic mappings |

### Module System

All service modules inherit from `ServiceModule` (in `modules/base.py`):

```python
class ServiceModule(ABC):
    name: str              # e.g. "ssh"
    default_port: int      # e.g. 22
    alternate_ports: list   # e.g. [2222]

    @abstractmethod
    def test_credential(self, target, credential, timeout=5, **kwargs) -> bool:
        """Return True for auth success, False for failure.
        Raise TimeoutError or ConnectionRefusedError for infrastructure errors."""

    def verify_access(self, target, credential, timeout=5, **kwargs) -> Optional[str]:
        """Optional: return proof-of-access string (e.g. output of 'id' command)."""
```

NetExec wrappers inherit from `NxcModule` (in `modules/nxc_base.py`), which shells out to `nxc <protocol>` and parses `[+]`/`[-]` output.

**Auto-discovery:** `ModuleRegistry` in `modules/__init__.py` uses `pkgutil.iter_modules()` to find all `ServiceModule` subclasses automatically. New modules are registered just by existing in the `modules/` directory.

### Adding a New Module

1. Create `modules/<service>.py`
2. Subclass `ServiceModule`, set `name`, `default_port`, implement `test_credential()`
3. Optionally implement `verify_access()` for `--verify` support
4. Add the port mapping in `core/input_parser.py` → `PORT_SERVICE_MAP`
5. Add nmap service name mapping in `core/input_parser.py` → `NMAP_SERVICE_MAP` if needed
6. Add any new dependency to `pyproject.toml` under `dependencies`

The module is auto-discovered - no manual registration required.

### Key Engine Behaviors

- **Adaptive endpoint skipping:** 3 consecutive timeouts → skip that (host, port); 5 total timeouts on a host → skip entire host
- **Per-service timeout multipliers:** RDP=3x, WinRM/Kerberos=2x the base `--timeout` value (in `SERVICE_TIMEOUT_MULTIPLIERS` dict)
- **Hard timeout safety net:** `future.result(timeout=self.timeout * 3)` prevents hung connections
- **Guest login rejection:** SMB/RDP/WMI check for guest sessions and return False
- **Dual module system:** `--nxc` flag swaps native modules for NetExec wrappers via `NXC_MAP` in `rapids.py`
- **HTTP dedup exemption:** Multiple HTTP ports on the same host are NOT deduplicated (different ports = different apps)

## Conventions

- **Error signaling in modules:** Return `False` for auth failure. Raise `TimeoutError` for timeouts, `ConnectionRefusedError` for unreachable hosts. Never catch these - the engine handles them for adaptive skipping.
- **Theme variable:** Always use `RAPIDS_THEME` from `core/theme.py` for Rich console output.
- **Frozen dataclasses:** `Target` and `Credential` are frozen (immutable). Create new instances instead of modifying.
- **Python 3.10+** required (uses `match/case` style patterns and modern type hints).
