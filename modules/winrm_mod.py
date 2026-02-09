"""WinRM service module using pywinrm."""

from typing import Optional

import winrm

from core.models import Credential, Target
from modules.base import ServiceModule


class WinRMModule(ServiceModule):
    name = "winrm"
    default_port = 5985
    alternate_ports = [5986]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")

        username = credential.username
        if domain and "\\" not in username and "@" not in username:
            netbios = domain.split(".")[0].upper() if "." in domain else domain
            username = f"{netbios}\\{username}"

        scheme = "https" if port == 5986 else "http"
        endpoint = f"{scheme}://{target.host}:{port}/wsman"

        try:
            session = winrm.Session(
                endpoint,
                auth=(username, credential.password),
                transport="ntlm",
                server_cert_validation="ignore",
                operation_timeout_sec=timeout,
                read_timeout_sec=timeout + 5,
            )
            result = session.run_cmd("whoami")
            return result.status_code == 0
        except Exception as e:
            err = str(e).lower()
            if "401" in err or "unauthorized" in err or "logon_failure" in err or ("access" in err and "denied" in err):
                return False
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")
        username = credential.username
        if domain and "\\" not in username and "@" not in username:
            netbios = domain.split(".")[0].upper() if "." in domain else domain
            username = f"{netbios}\\{username}"
        scheme = "https" if port == 5986 else "http"
        endpoint = f"{scheme}://{target.host}:{port}/wsman"
        session = winrm.Session(
            endpoint, auth=(username, credential.password),
            transport="ntlm", server_cert_validation="ignore",
            operation_timeout_sec=timeout, read_timeout_sec=timeout + 5,
        )
        result = session.run_cmd("whoami /all")
        output = result.std_out.decode("utf-8", errors="ignore").strip()
        # Return first few lines (whoami /all can be long)
        lines = output.splitlines()[:5]
        return "\n".join(lines)
