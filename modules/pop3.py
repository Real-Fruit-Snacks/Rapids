"""POP3 service module using poplib (stdlib)."""

import poplib
import socket
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class POP3Module(ServiceModule):
    name = "pop3"
    default_port = 110
    alternate_ports = [995]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            if port == 995:
                server = poplib.POP3_SSL(target.host, port, timeout=timeout)
            else:
                server = poplib.POP3(target.host, port, timeout=timeout)

            server.user(credential.username)
            server.pass_(credential.password)
            server.quit()
            return True
        except poplib.error_proto as e:
            err = str(e).lower()
            if "authentication" in err or "login" in err or "denied" in err or "-err" in err:
                return False
            raise
        except socket.timeout:
            raise TimeoutError(f"POP3 connection to {target.host}:{port} timed out")
        except (ConnectionRefusedError, OSError) as e:
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            if port == 995:
                server = poplib.POP3_SSL(target.host, port, timeout=timeout)
            else:
                server = poplib.POP3(target.host, port, timeout=timeout)
            server.user(credential.username)
            server.pass_(credential.password)
            count, size = server.stat()
            server.quit()
            return f"{count} messages ({size} bytes)"
        except Exception:
            return None
