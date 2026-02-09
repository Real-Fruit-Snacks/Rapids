"""SMTP service module using smtplib (stdlib)."""

import smtplib
import socket
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class SMTPModule(ServiceModule):
    name = "smtp"
    default_port = 587
    alternate_ports = [25, 465, 2525]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            if port == 465:
                server = smtplib.SMTP_SSL(target.host, port, timeout=timeout)
            else:
                server = smtplib.SMTP(target.host, port, timeout=timeout)
                # Try STARTTLS if available
                try:
                    server.starttls()
                except smtplib.SMTPNotSupportedError:
                    pass

            server.login(credential.username, credential.password)
            server.quit()
            return True
        except smtplib.SMTPAuthenticationError:
            return False
        except smtplib.SMTPNotSupportedError:
            # Server doesn't support AUTH
            raise RuntimeError(f"SMTP server {target.host}:{port} does not support authentication")
        except socket.timeout:
            raise TimeoutError(f"SMTP connection to {target.host}:{port} timed out")
        except (ConnectionRefusedError, OSError) as e:
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            if port == 465:
                server = smtplib.SMTP_SSL(target.host, port, timeout=timeout)
            else:
                server = smtplib.SMTP(target.host, port, timeout=timeout)
                try:
                    server.starttls()
                except smtplib.SMTPNotSupportedError:
                    pass
            server.login(credential.username, credential.password)
            # EHLO response contains server capabilities
            code, msg = server.ehlo()
            server.quit()
            banner = msg.decode("utf-8", errors="ignore").splitlines()[0] if msg else "?"
            return f"SMTP banner={banner}"
        except Exception:
            return None
