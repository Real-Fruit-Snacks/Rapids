"""CouchDB service module using requests (REST API basic auth)."""

from typing import Optional

import requests
import urllib3

from core.models import Credential, Target
from modules.base import ServiceModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CouchDBModule(ServiceModule):
    name = "couchdb"
    default_port = 5984
    alternate_ports = [6984]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        url = f"http://{target.host}:{port}/_session"

        try:
            resp = requests.post(
                url,
                json={"name": credential.username, "password": credential.password},
                timeout=timeout,
                verify=False,
            )

            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    return True
                return False
            if resp.status_code == 401:
                return False
            return False
        except requests.Timeout:
            raise TimeoutError(f"CouchDB connection to {target.host}:{port} timed out")
        except requests.ConnectionError as e:
            err = str(e).lower()
            if "timed out" in err:
                raise TimeoutError(f"CouchDB connection to {target.host}:{port} timed out")
            if "connection refused" in err or "[errno 111]" in err:
                raise ConnectionRefusedError(f"CouchDB connection to {target.host}:{port} refused")
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        try:
            # Get server info
            info_resp = requests.get(
                f"http://{target.host}:{port}/",
                auth=(credential.username, credential.password),
                timeout=timeout, verify=False,
            )
            version = info_resp.json().get("version", "?") if info_resp.status_code == 200 else "?"
            # List databases
            dbs_resp = requests.get(
                f"http://{target.host}:{port}/_all_dbs",
                auth=(credential.username, credential.password),
                timeout=timeout, verify=False,
            )
            if dbs_resp.status_code == 200:
                dbs = dbs_resp.json()
                return f"version={version} dbs({len(dbs)})={','.join(dbs[:10])}"
            return f"version={version}"
        except Exception:
            return None
