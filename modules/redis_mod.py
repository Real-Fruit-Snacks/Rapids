"""Redis service module using redis library."""

from typing import Optional

import redis

from core.models import Credential, Target
from modules.base import ServiceModule


class RedisModule(ServiceModule):
    name = "redis"
    default_port = 6379
    alternate_ports = [6380]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        try:
            client = redis.Redis(
                host=target.host,
                port=port,
                password=credential.password or None,
                username=credential.username if credential.username != "default" else None,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
            )
            result = client.ping()
            client.close()
            return bool(result)
        except redis.exceptions.AuthenticationError:
            return False
        except redis.exceptions.ResponseError as e:
            if "NOAUTH" in str(e) or "AUTH" in str(e):
                return False
            raise
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as e:
            err = str(e).lower()
            if "connection refused" in err or "[errno 111]" in err:
                raise ConnectionRefusedError(f"Redis connection to {target.host}:{port} refused")
            if "timed out" in err or "timeout" in err:
                raise TimeoutError(str(e))
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            client = redis.Redis(
                host=target.host, port=port,
                password=credential.password or None,
                username=credential.username if credential.username != "default" else None,
                socket_timeout=timeout,
                socket_connect_timeout=timeout,
            )
            info = client.info("server")
            client.close()
            version = info.get("redis_version", "?")
            os_info = info.get("os", "?")
            return f"Redis {version} on {os_info}"
        except Exception:
            return None
