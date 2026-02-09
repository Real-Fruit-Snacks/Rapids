"""SSH service module using paramiko."""

import logging
from typing import Optional

import paramiko

from core.models import Credential, Target
from modules.base import ServiceModule

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


class SSHModule(ServiceModule):
    name = "ssh"
    default_port = 22
    alternate_ports = [2222]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target.host,
                port=port,
                username=credential.username,
                password=credential.password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=timeout,
                auth_timeout=timeout,
            )
            return True
        except paramiko.AuthenticationException:
            return False
        except (TimeoutError, paramiko.SSHException) as e:
            if "timed out" in str(e).lower() or isinstance(e, TimeoutError):
                raise TimeoutError(str(e))
            raise
        finally:
            client.close()

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target.host, port=port,
                username=credential.username, password=credential.password,
                timeout=timeout, allow_agent=False, look_for_keys=False,
            )
            stdin, stdout, stderr = client.exec_command("id 2>/dev/null || whoami", timeout=timeout)
            return stdout.read().decode("utf-8", errors="ignore").strip()
        finally:
            client.close()
