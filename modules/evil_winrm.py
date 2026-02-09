"""WinRM service module using evil-winrm (CLI wrapper)."""

import re
import shutil
import subprocess
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class EvilWinRMModule(ServiceModule):
    name = "evil-winrm"
    default_port = 5985
    alternate_ports = [5986]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        if not shutil.which("evil-winrm"):
            raise RuntimeError(
                "evil-winrm not found in PATH. "
                "Install with: gem install evil-winrm"
            )

        port = target.port or self.default_port
        domain = kwargs.get("domain", "")

        username = credential.username
        if domain and "\\" not in username and "@" not in username:
            username = f"{domain}\\{username}"

        cmd = [
            "evil-winrm",
            "-i", target.host,
            "-u", username,
            "-P", str(port),
            "-n",  # no colors
        ]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]
        if port == 5986:
            cmd.append("-S")  # SSL

        try:
            result = subprocess.run(
                cmd,
                input="whoami\nexit\n",
                capture_output=True,
                text=True,
                timeout=timeout + 15,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"evil-winrm connection to {target.host}:{port} timed out")

        stdout = result.stdout
        stderr = result.stderr

        # Check for auth failure
        combined = (stdout + stderr).lower()
        if "authorization" in combined or "authentication" in combined or "logon_failure" in combined:
            return False

        # Check for success — evil-winrm shows *Evil-WinRM* PS prompt
        if "*evil-winrm*" in combined or "ps " in combined:
            return True

        # Fallback: exit code 0 with output likely means success
        if result.returncode == 0 and stdout.strip():
            return True

        return False

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        if not shutil.which("evil-winrm"):
            return None

        port = target.port or self.default_port
        domain = kwargs.get("domain", "")

        username = credential.username
        if domain and "\\" not in username and "@" not in username:
            username = f"{domain}\\{username}"

        cmd = [
            "evil-winrm",
            "-i", target.host,
            "-u", username,
            "-P", str(port),
            "-n",
        ]
        if credential.is_hash:
            cmd += ["-H", credential.nthash]
        else:
            cmd += ["-p", credential.password]
        if port == 5986:
            cmd.append("-S")

        try:
            result = subprocess.run(
                cmd,
                input="whoami\nhostname\nexit\n",
                capture_output=True,
                text=True,
                timeout=timeout + 15,
            )
        except subprocess.TimeoutExpired:
            return None

        # Strip all ANSI escape codes (colors, cursor movement, etc.)
        raw = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', result.stdout)

        proof_lines = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip evil-winrm chrome
            lower = line.lower()
            if any(skip in lower for skip in (
                "evil-winrm", "info:", "warning:", "data:",
                "hackplayers", "github.com", "remote path completion",
                "ps ", "> whoami", "> hostname", "> exit",
            )):
                continue
            if line == "exit":
                continue
            proof_lines.append(line)

        if proof_lines:
            return " | ".join(proof_lines[:3])
        return "evil-winrm shell obtained"
