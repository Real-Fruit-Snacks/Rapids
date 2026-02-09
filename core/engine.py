"""Spray engine with ThreadPoolExecutor and Rich progress."""

import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Type

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskID, TimeElapsedColumn
from rich.text import Text

from core.models import Credential, ResultStatus, SprayResult, Target
from core.theme import RAPIDS_THEME, MOCHA
from modules.base import ServiceModule

console = Console(theme=RAPIDS_THEME)

# Services that need longer timeouts (multiplier applied to base timeout)
SERVICE_TIMEOUT_MULTIPLIERS = {
    "rdp": 3,
    "nxc_rdp": 3,
    "evil-winrm": 2,
    "winrm": 2,
    "nxc_winrm": 2,
    "kerberos": 2,
}


def mask_password(password: str) -> str:
    """Mask a password for display (e.g. 'EricLikesRunning800' -> 'Er***00')."""
    if not password:
        return ""
    if len(password) <= 4:
        return password[0] + "***"
    return password[:2] + "***" + password[-2:]


class SprayEngine:
    """Concurrent credential spraying engine."""

    def __init__(
        self,
        threads: int = 10,
        timeout: int = 5,
        delay: float = 0,
        extra_kwargs: Optional[Dict] = None,
        port_overrides: Optional[Dict[str, int]] = None,
        host_domains: Optional[Dict[str, str]] = None,
        verify: bool = False,
        debug: bool = False,
        mask_creds: bool = False,
    ):
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.extra_kwargs = extra_kwargs or {}
        self.port_overrides = port_overrides or {}
        self.host_domains = host_domains or {}
        self.verify = verify
        self.debug = debug
        self.mask_creds = mask_creds
        self._results: List[SprayResult] = []
        self._lock = threading.Lock()
        self._endpoint_timeouts: Dict[tuple, int] = {}  # (host, port) -> consecutive timeout count
        self._endpoint_skipped: set = set()  # (host, port) endpoints marked as unreachable
        self._skip_threshold = 3  # skip after N consecutive timeouts
        self._host_timeouts: Dict[str, int] = {}  # host -> total timeout count across all ports
        self._host_skipped: set = set()  # hosts marked as fully unreachable
        self._host_skip_threshold = 5  # skip host after N total timeouts across different ports

    def _test_single(
        self,
        module: ServiceModule,
        target: Target,
        credential: Credential,
    ) -> SprayResult:
        """Test one credential against one target with one module."""
        result = SprayResult(
            target=target,
            credential=credential,
            service=module.name,
        )

        # Host-level skip - if the entire host is known unreachable, skip immediately
        if target.host in self._host_skipped:
            result.status = ResultStatus.TIMEOUT
            result.message = "Skipped (host unreachable)"
            return result

        # Adaptive endpoint skip - if host:port is known unreachable, skip immediately
        endpoint = (target.host, target.port)
        if endpoint in self._endpoint_skipped:
            result.status = ResultStatus.TIMEOUT
            result.message = "Skipped (endpoint unreachable)"
            return result

        if self.delay > 0:
            time.sleep(self.delay)

        # Per-service timeout multiplier (e.g. RDP gets 3x, WinRM gets 2x)
        effective_timeout = int(self.timeout * SERVICE_TIMEOUT_MULTIPLIERS.get(module.name, 1))

        # Merge per-host domain into kwargs (host-specific overrides global)
        kwargs = dict(self.extra_kwargs)
        if target.host in self.host_domains and "domain" not in kwargs:
            kwargs["domain"] = self.host_domains[target.host]

        try:
            success = module.test_credential(
                target, credential, timeout=effective_timeout, **kwargs
            )
            if success:
                result.status = ResultStatus.SUCCESS
                result.message = "Authentication successful"
                # Run proof-of-access command if --verify is on
                if self.verify:
                    try:
                        proof = module.verify_access(
                            target, credential, timeout=effective_timeout, **kwargs
                        )
                        if proof:
                            result.proof = proof.strip()
                    except Exception:
                        pass  # Verification is best-effort
            else:
                result.status = ResultStatus.FAILURE
                result.message = "Authentication failed"
        except TimeoutError as e:
            result.status = ResultStatus.TIMEOUT
            result.message = "Connection timed out"
            if self.debug:
                result._debug_detail = str(e)
        except ConnectionRefusedError:
            result.status = ResultStatus.FAILURE
            result.message = "Connection refused (service not running)"
        except OSError as e:
            err_str = str(e).lower()
            if e.errno == 111 or "connection refused" in err_str or "[errno 111]" in err_str:
                result.status = ResultStatus.FAILURE
                result.message = "Connection refused (service not running)"
            elif "timed out" in err_str or "timeout" in err_str:
                result.status = ResultStatus.TIMEOUT
                result.message = "Connection timed out"
                if self.debug:
                    result._debug_detail = str(e)
            else:
                result.status = ResultStatus.ERROR
                result.message = str(e)
                if self.debug:
                    result._debug_detail = traceback.format_exc()
        except Exception as e:
            err_str = str(e).lower()
            if "connection refused" in err_str or "[errno 111]" in err_str:
                result.status = ResultStatus.FAILURE
                result.message = "Connection refused (service not running)"
            else:
                result.status = ResultStatus.ERROR
                result.message = str(e)
                if self.debug:
                    result._debug_detail = traceback.format_exc()

        # Track endpoint-level timeouts for adaptive skipping
        with self._lock:
            if result.status == ResultStatus.TIMEOUT:
                self._endpoint_timeouts[endpoint] = self._endpoint_timeouts.get(endpoint, 0) + 1
                if self._endpoint_timeouts[endpoint] >= self._skip_threshold and endpoint not in self._endpoint_skipped:
                    self._endpoint_skipped.add(endpoint)
                # Track host-level timeouts
                self._host_timeouts[target.host] = self._host_timeouts.get(target.host, 0) + 1
                if self._host_timeouts[target.host] >= self._host_skip_threshold and target.host not in self._host_skipped:
                    self._host_skipped.add(target.host)
            elif result.status in (ResultStatus.SUCCESS, ResultStatus.FAILURE):
                # Endpoint responded - reset timeout counter
                self._endpoint_timeouts[endpoint] = 0
                self._host_timeouts[target.host] = 0

        if self.debug:
            self._print_debug(result)

        return result

    def _print_debug(self, result: SprayResult) -> None:
        """Print raw unformatted debug line to stderr."""
        pwd_display = mask_password(result.credential.password) if self.mask_creds else result.credential.password
        parts = [
            f"[DEBUG] {result.status.value}",
            f"svc={result.service}",
            f"target={result.target}",
            f"user={result.credential.username}",
            f"pass={pwd_display}",
        ]
        if result.message:
            parts.append(f"msg={result.message}")
        if result.proof:
            parts.append(f"proof={result.proof}")
        detail = getattr(result, "_debug_detail", None)
        if detail:
            parts.append(f"detail={detail.strip()}")
        line = " | ".join(parts)
        with self._lock:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()

    def spray(
        self,
        targets: List[Target],
        credentials: List[Credential],
        modules: Dict[str, Type[ServiceModule]],
    ) -> List[SprayResult]:
        """Run the spray across all targets/creds/modules."""
        # Build the work items
        work_items = []
        for target in targets:
            if target.service and target.service in modules:
                # Nmap-detected or auto-detected: only test the matching service
                mod_cls = modules[target.service]
                mod = mod_cls()
                # Apply port override if set, else keep target port
                port = self.port_overrides.get(mod.name, target.port or mod_cls.default_port)
                t = Target(host=target.host, port=port, service=mod.name)
                for cred in credentials:
                    work_items.append((mod, t, cred))
            elif not target.service:
                # No service detected: test all selected modules (manual target)
                for mod_cls in modules.values():
                    mod = mod_cls()
                    port = self.port_overrides.get(mod.name, target.port or mod_cls.default_port)
                    t = Target(host=target.host, port=port, service=mod.name)
                    for cred in credentials:
                        work_items.append((mod, t, cred))

        total = len(work_items)
        if total == 0:
            console.print(f"[{MOCHA['yellow']}]No work items to process.[/{MOCHA['yellow']}]")
            return []

        console.print(
            f"\n[heading]Spraying {len(credentials)} credential(s) "
            f"across {len(targets)} target(s) "
            f"with {len(modules)} service(s) "
            f"({total} total attempts, {self.threads} threads)[/heading]\n"
        )

        results: List[SprayResult] = []
        lock = threading.Lock()
        start_time = time.monotonic()

        with Progress(
            SpinnerColumn(style=MOCHA["mauve"]),
            TextColumn(f"[{MOCHA['blue']}]" + "{task.description}" + f"[/{MOCHA['blue']}]"),
            BarColumn(complete_style=MOCHA["green"], finished_style=MOCHA["green"], pulse_style=MOCHA["mauve"]),
            TextColumn(f"[{MOCHA['mauve']}]" + "{task.percentage:>3.0f}%" + f"[/{MOCHA['mauve']}]"),
            TextColumn(f"[{MOCHA['subtext0']}]" + "({task.completed}/{task.total})" + f"[/{MOCHA['subtext0']}]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Spraying...", total=total)

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._test_single, mod, tgt, cred): (mod, tgt, cred)
                    for mod, tgt, cred in work_items
                }

                try:
                    for future in as_completed(futures):
                        try:
                            result = future.result(timeout=self.timeout * 3)
                        except TimeoutError:
                            mod, tgt, cred = futures[future]
                            result = SprayResult(
                                target=tgt,
                                credential=cred,
                                service=mod.name,
                                status=ResultStatus.TIMEOUT,
                                message="Hard timeout exceeded",
                            )
                        with lock:
                            results.append(result)

                        if result.status == ResultStatus.SUCCESS:
                            hit_text = Text("  ")
                            hit_text.append("[+]", style="hit")
                            hit_text.append(f" {result.service}://{result.target} - ")
                            if self.mask_creds:
                                cred_display = f"{result.credential.username}:{mask_password(result.credential.password)}"
                            else:
                                cred_display = str(result.credential)
                            hit_text.append(cred_display, style="hit.cred")
                            if result.proof:
                                hit_text.append(f" | {result.proof}", style="dim")
                            progress.console.print(hit_text)

                        progress.advance(task_id)
                except KeyboardInterrupt:
                    progress.console.print(
                        f"\n[warn]Interrupted — cancelling remaining tasks...[/warn]"
                    )
                    executor.shutdown(wait=False, cancel_futures=True)

            # Report skipped hosts
            if self._host_skipped:
                for host in sorted(self._host_skipped):
                    progress.console.print(
                        f"  [warn][!] {host} appears fully unreachable — skipped remaining attempts[/warn]"
                    )

            # Report skipped endpoints
            if self._endpoint_skipped:
                for host, port in sorted(self._endpoint_skipped):
                    progress.console.print(
                        f"  [warn][!] {host}:{port} appears unreachable — skipped remaining attempts[/warn]"
                    )

        self.elapsed = time.monotonic() - start_time
        return results
