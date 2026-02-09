"""LDAP service module using ldap3."""

from typing import Optional

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from core.models import Credential, Target
from modules.base import ServiceModule


class LDAPModule(ServiceModule):
    name = "ldap"
    default_port = 389
    alternate_ports = [636, 3268, 3269]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")

        use_ssl = port in (636, 3269)

        # Build the bind DN
        username = credential.username
        if domain and "\\" not in username and "@" not in username:
            username = f"{domain}\\{username}"

        # Hash auth requires NTLM with domain prefix
        if credential.is_hash:
            if "\\" not in username:
                username = f".\\{username}"

        try:
            server = ldap3.Server(
                target.host,
                port=port,
                use_ssl=use_ssl,
                get_info=ldap3.NONE,
                connect_timeout=timeout,
            )
            if credential.is_hash:
                conn = ldap3.Connection(
                    server,
                    user=username,
                    password=f"aad3b435b51404eeaad3b435b51404ee:{credential.nthash}",
                    authentication=ldap3.NTLM,
                    receive_timeout=timeout,
                )
            else:
                conn = ldap3.Connection(
                    server,
                    user=username,
                    password=credential.password,
                    authentication=ldap3.NTLM if "\\" in username else ldap3.SIMPLE,
                    receive_timeout=timeout,
                )
            result = conn.bind()
            conn.unbind()
            return result
        except LDAPBindError:
            return False
        except LDAPSocketOpenError as e:
            if "timed out" in str(e).lower():
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        domain = kwargs.get("domain", "")
        use_ssl = port in (636, 3269)
        username = credential.username
        if domain and "\\" not in username and "@" not in username:
            username = f"{domain}\\{username}"
        if credential.is_hash and "\\" not in username:
            username = f".\\{username}"
        try:
            server = ldap3.Server(
                target.host, port=port, use_ssl=use_ssl,
                get_info=ldap3.ALL, connect_timeout=timeout,
            )
            if credential.is_hash:
                conn = ldap3.Connection(
                    server, user=username,
                    password=f"aad3b435b51404eeaad3b435b51404ee:{credential.nthash}",
                    authentication=ldap3.NTLM,
                    receive_timeout=timeout,
                )
            else:
                conn = ldap3.Connection(
                    server, user=username, password=credential.password,
                    authentication=ldap3.NTLM if "\\" in username else ldap3.SIMPLE,
                    receive_timeout=timeout,
                )
            conn.bind()
            info = server.info
            conn.unbind()
            if info:
                naming = str(getattr(info, "naming_contexts", "?"))
                return f"namingContexts={naming}"
            return "Bind successful"
        except Exception:
            return None
