"""IMAP service module using imaplib (stdlib)."""

import imaplib
import socket
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class IMAPModule(ServiceModule):
    name = "imap"
    default_port = 143
    alternate_ports = [993]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            if port == 993:
                server = imaplib.IMAP4_SSL(target.host, port, timeout=timeout)
            else:
                server = imaplib.IMAP4(target.host, port, timeout=timeout)

            server.login(credential.username, credential.password)
            server.logout()
            return True
        except imaplib.IMAP4.error as e:
            err = str(e).lower()
            if "authentication" in err or "login" in err or "invalid" in err or "no" in err:
                return False
            raise
        except socket.timeout:
            raise TimeoutError(f"IMAP connection to {target.host}:{port} timed out")
        except (ConnectionRefusedError, OSError) as e:
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            if port == 993:
                server = imaplib.IMAP4_SSL(target.host, port, timeout=timeout)
            else:
                server = imaplib.IMAP4(target.host, port, timeout=timeout)
            server.login(credential.username, credential.password)
            status, folders = server.list()
            server.logout()
            if status == "OK" and folders:
                count = len(folders)
                names = []
                for f in folders[:5]:
                    parts = f.decode("utf-8", errors="ignore").split('" ')
                    names.append(parts[-1].strip('"') if parts else "?")
                return f"{count} folders: {', '.join(names)}"
            return "Authenticated"
        except Exception:
            return None
