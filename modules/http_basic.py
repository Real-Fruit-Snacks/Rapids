"""HTTP service module supporting Basic Auth and form-based login."""

from typing import Optional

import requests
import urllib3

from core.models import Credential, Target
from modules.base import ServiceModule

# Suppress InsecureRequestWarning for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPModule(ServiceModule):
    name = "http"
    default_port = 80
    alternate_ports = [443, 8080, 8443, 8000, 8888]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        url_path = kwargs.get("url_path", "/")
        form_data = kwargs.get("http_form_data")
        success_string = kwargs.get("success_string")

        scheme = "https" if port in (443, 8443) else "http"
        base_url = f"{scheme}://{target.host}:{port}{url_path}"

        if form_data:
            return self._try_form_login(
                base_url, credential, form_data, success_string, timeout
            )
        else:
            return self._try_basic_auth(base_url, credential, timeout)

    def _try_basic_auth(self, url: str, credential: Credential, timeout: int) -> bool:
        try:
            # First check if the endpoint requires auth at all
            noauth = requests.get(
                url, timeout=timeout, verify=False, allow_redirects=True,
            )
            if noauth.status_code == 200:
                # Server returns 200 without creds — no auth required, not a real hit
                return False

            # Server returned 401/403 — now try with credentials
            resp = requests.get(
                url,
                auth=(credential.username, credential.password),
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            if resp.status_code == 401 or resp.status_code == 403:
                return False
            if 200 <= resp.status_code < 400:
                return True
            return False
        except requests.Timeout:
            raise TimeoutError(f"HTTP request to {url} timed out")
        except requests.ConnectionError as e:
            err = str(e).lower()
            if "timed out" in err:
                raise TimeoutError(f"HTTP request to {url} timed out")
            if "connection refused" in err or "[errno 111]" in err:
                raise ConnectionRefusedError(f"HTTP connection to {url} refused")
            raise

    def _try_form_login(
        self,
        url: str,
        credential: Credential,
        form_data_template: str,
        success_string: str = None,
        timeout: int = 5,
    ) -> bool:
        # Replace ^USER^ and ^PASS^ placeholders (Hydra-style)
        post_data = form_data_template.replace("^USER^", credential.username)
        post_data = post_data.replace("^PASS^", credential.password)

        # Parse the form data string into a dict
        data = {}
        for pair in post_data.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                data[key] = value

        try:
            resp = requests.post(
                url,
                data=data,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )

            if success_string:
                return success_string in resp.text

            # Heuristic: 2xx after POST with no redirect back to login
            if resp.status_code == 200:
                return True
            if resp.status_code in (301, 302):
                return True

            return False
        except requests.Timeout:
            raise TimeoutError(f"HTTP form request to {url} timed out")
        except requests.ConnectionError as e:
            err = str(e).lower()
            if "timed out" in err:
                raise TimeoutError(f"HTTP form request to {url} timed out")
            if "connection refused" in err or "[errno 111]" in err:
                raise ConnectionRefusedError(f"HTTP connection to {url} refused")
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        url_path = kwargs.get("url_path", "/")
        scheme = "https" if port in (443, 8443) else "http"
        base_url = f"{scheme}://{target.host}:{port}{url_path}"
        try:
            resp = requests.get(
                base_url,
                auth=(credential.username, credential.password),
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            title = ""
            if "<title>" in resp.text.lower():
                start = resp.text.lower().index("<title>") + 7
                end = resp.text.lower().index("</title>", start)
                title = resp.text[start:end].strip()
            return f"HTTP {resp.status_code} title={title}" if title else f"HTTP {resp.status_code} ({len(resp.text)} bytes)"
        except Exception:
            return None
