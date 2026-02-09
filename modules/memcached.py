"""Memcached service module using pymemcache (SASL auth)."""

from typing import Optional

from pymemcache.client.base import Client

from core.models import Credential, Target
from modules.base import ServiceModule


class MemcachedModule(ServiceModule):
    name = "memcached"
    default_port = 11211
    alternate_ports = []

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            client = Client(
                (target.host, port),
                timeout=timeout,
                connect_timeout=timeout,
            )
            # Try a benign stats call to verify access
            result = client.stats()
            client.close()
            return True
        except Exception as e:
            err = str(e).lower()
            if "auth" in err or "denied" in err or "invalid" in err:
                return False
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            client = Client(
                (target.host, port), timeout=timeout, connect_timeout=timeout,
            )
            stats = client.stats()
            client.close()
            if stats:
                version = stats.get(b"version", b"?").decode("utf-8", errors="ignore")
                items = stats.get(b"curr_items", b"?").decode("utf-8", errors="ignore")
                uptime = stats.get(b"uptime", b"?").decode("utf-8", errors="ignore")
                return f"version={version} items={items} uptime={uptime}s"
            return "Authenticated"
        except Exception:
            return None
