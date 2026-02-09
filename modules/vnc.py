"""VNC service module using socket-level RFB handshake.

VNC auth is password-only (no username). The password field from the
credential is used; username is ignored.
"""

import hashlib
import socket
import struct
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule


class VNCModule(ServiceModule):
    name = "vnc"
    default_port = 5900
    alternate_ports = [5901, 5902]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((target.host, port))

            # Read server protocol version
            server_version = sock.recv(12)
            if not server_version.startswith(b"RFB"):
                raise RuntimeError(f"Not a VNC server: {server_version!r}")

            # Send client protocol version (match server or use 3.8)
            sock.sendall(b"RFB 003.008\n")

            # Read security types
            num_types = struct.unpack("!B", sock.recv(1))[0]
            if num_types == 0:
                # Server sent failure reason
                reason_len = struct.unpack("!I", sock.recv(4))[0]
                reason = sock.recv(reason_len).decode("utf-8", errors="ignore")
                raise RuntimeError(f"VNC connection refused: {reason}")

            sec_types = sock.recv(num_types)

            # Check for VNC Authentication (type 2)
            if 2 in sec_types:
                sock.sendall(bytes([2]))  # Select VNC auth
                return self._vnc_auth(sock, credential.password)
            elif 1 in sec_types:
                # No authentication required
                sock.sendall(bytes([1]))
                return True
            else:
                raise RuntimeError(f"Unsupported VNC security types: {list(sec_types)}")

        except socket.timeout:
            raise TimeoutError(f"VNC connection to {target.host}:{port} timed out")
        except (ConnectionRefusedError, OSError):
            raise
        finally:
            sock.close()

    def _vnc_auth(self, sock: socket.socket, password: str) -> bool:
        """Perform VNC DES challenge-response authentication."""
        # Read 16-byte challenge
        challenge = sock.recv(16)
        if len(challenge) != 16:
            raise RuntimeError("Invalid VNC challenge")

        # DES-encrypt the challenge with the password
        response = self._des_encrypt(password, challenge)
        sock.sendall(response)

        # Read security result (4 bytes, 0 = OK)
        result = struct.unpack("!I", sock.recv(4))[0]
        return result == 0

    @staticmethod
    def _des_encrypt(password: str, challenge: bytes) -> bytes:
        """VNC DES encryption — password is truncated/padded to 8 bytes,
        each byte is bit-reversed, then used as DES key."""
        try:
            from Crypto.Cipher import DES
        except ImportError:
            try:
                from Cryptodome.Cipher import DES
            except ImportError:
                raise RuntimeError(
                    "VNC auth requires pycryptodome: pip install pycryptodome"
                )

        # Pad/truncate password to 8 bytes
        key = password.encode("latin-1")[:8].ljust(8, b"\x00")

        # Bit-reverse each byte (VNC quirk)
        reversed_key = bytes(
            int(f"{b:08b}"[::-1], 2) for b in key
        )

        cipher = DES.new(reversed_key, DES.MODE_ECB)
        return cipher.encrypt(challenge[:8]) + cipher.encrypt(challenge[8:16])

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        """Report VNC server version from the RFB handshake."""
        port = target.port or self.default_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target.host, port))
            server_version = sock.recv(12).decode("utf-8", errors="ignore").strip()
            return f"RFB version={server_version}"
        except Exception:
            return None
        finally:
            sock.close()
