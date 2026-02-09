"""Telnet service module using raw sockets.

Python 3.13 removed telnetlib from stdlib, so this module uses plain
sockets to perform the login handshake.  It handles basic Telnet IAC
negotiation (WILL/WONT/DO/DONT → refuse everything) which is enough
for credential testing against typical telnet daemons.
"""

import socket
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule

# Telnet protocol bytes
IAC = 0xFF
WILL = 0xFB
WONT = 0xFC
DO = 0xFD
DONT = 0xFE


def _strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC sequences from raw data and return clean text."""
    clean = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (WILL, WONT, DO, DONT) and i + 2 < len(data):
                i += 3  # skip IAC + cmd + option
                continue
            elif cmd == IAC:
                clean.append(IAC)  # escaped 0xFF
                i += 2
                continue
            else:
                i += 2  # skip unknown IAC sequence
                continue
        clean.append(data[i])
        i += 1
    return bytes(clean)


def _refuse_iac(data: bytes) -> bytes:
    """Build refusal responses for any IAC WILL/DO requests."""
    responses = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd = data[i + 1]
            opt = data[i + 2]
            if cmd == WILL:
                responses.extend([IAC, DONT, opt])
            elif cmd == DO:
                responses.extend([IAC, WONT, opt])
            if cmd in (WILL, WONT, DO, DONT):
                i += 3
                continue
        i += 1
    return bytes(responses)


def _recv_until(sock: socket.socket, marker: bytes, timeout: float) -> bytes:
    """Read from socket until marker is found or timeout expires."""
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        # Respond to any IAC negotiation immediately
        refusal = _refuse_iac(chunk)
        if refusal:
            try:
                sock.sendall(refusal)
            except OSError:
                pass
        buf.extend(_strip_iac(chunk))
        if marker in buf:
            break
    return bytes(buf)


class TelnetModule(ServiceModule):
    name = "telnet"
    default_port = 23
    alternate_ports = [2323]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target.host, port))

            # Wait for login prompt
            _recv_until(sock, b"ogin:", timeout)
            sock.sendall(credential.username.encode() + b"\n")

            # Wait for password prompt
            _recv_until(sock, b"assword:", timeout)
            sock.sendall(credential.password.encode() + b"\n")

            # Read response — look for shell prompt or failure indicators
            response = _recv_until(sock, b"$", timeout)
            resp_text = response.decode("utf-8", errors="ignore").lower()

            if "login incorrect" in resp_text or "login failed" in resp_text or "authentication failed" in resp_text:
                return False

            if "$" in resp_text or "#" in resp_text or ">" in resp_text or "welcome" in resp_text:
                return True

            return False
        except socket.timeout:
            raise TimeoutError(f"Telnet connection to {target.host}:{port} timed out")
        except (ConnectionRefusedError, OSError):
            raise
        finally:
            sock.close()

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target.host, port))
            _recv_until(sock, b"ogin:", timeout)
            sock.sendall(credential.username.encode() + b"\n")
            _recv_until(sock, b"assword:", timeout)
            sock.sendall(credential.password.encode() + b"\n")
            _recv_until(sock, b"$", timeout)
            sock.sendall(b"id 2>/dev/null || whoami\n")
            response = _recv_until(sock, b"$", timeout)
            text = response.decode("utf-8", errors="ignore").strip()
            # Remove the command echo if present
            lines = [l for l in text.splitlines() if l.strip() and "id 2>/dev/null" not in l]
            return lines[0].strip() if lines else text
        except Exception:
            return None
        finally:
            sock.close()
