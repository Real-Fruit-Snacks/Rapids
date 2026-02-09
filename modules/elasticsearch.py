"""Elasticsearch service module using requests (REST API basic auth)."""

from typing import Optional

import requests
import urllib3

from core.models import Credential, Target
from modules.base import ServiceModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ElasticsearchModule(ServiceModule):
    name = "elasticsearch"
    default_port = 9200
    alternate_ports = [9201, 9243]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        last_error = None

        # Try HTTPS first, fallback to HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}:{port}/"
            try:
                resp = requests.get(
                    url,
                    auth=(credential.username, credential.password),
                    timeout=timeout,
                    verify=False,
                )
                if resp.status_code == 200:
                    return True
                if resp.status_code in (401, 403):
                    return False
            except requests.ConnectionError as e:
                last_error = e
                continue
            except requests.Timeout:
                raise TimeoutError(f"Elasticsearch connection to {target.host}:{port} timed out")

        # Both schemes failed to connect
        if last_error and "timed out" in str(last_error).lower():
            raise TimeoutError(f"Elasticsearch connection to {target.host}:{port} timed out")
        raise ConnectionRefusedError(f"Cannot connect to Elasticsearch at {target.host}:{port}")

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        for scheme in ("https", "http"):
            url = f"{scheme}://{target.host}:{port}/"
            try:
                resp = requests.get(
                    url,
                    auth=(credential.username, credential.password),
                    timeout=timeout,
                    verify=False,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name", "?")
                    cluster = data.get("cluster_name", "?")
                    version = data.get("version", {}).get("number", "?")
                    return f"node={name} cluster={cluster} version={version}"
            except Exception:
                continue
        return None
