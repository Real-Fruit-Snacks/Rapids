"""Abstract base class for service modules."""

from abc import ABC, abstractmethod
from typing import List, Optional

from core.models import Credential, Target


class ServiceModule(ABC):
    """Base class all service modules must inherit from."""

    name: str = ""
    default_port: int = 0
    alternate_ports: List[int] = []

    @abstractmethod
    def test_credential(
        self,
        target: Target,
        credential: Credential,
        timeout: int = 5,
        **kwargs,
    ) -> bool:
        """Test a single credential against a target.

        Returns:
            True if authentication succeeded.
            False if authentication failed (wrong creds).

        Raises:
            TimeoutError: Connection timed out.
            Exception: Any other error (connection refused, etc.)
        """
        ...

    def verify_access(
        self,
        target: Target,
        credential: Credential,
        timeout: int = 5,
        **kwargs,
    ) -> Optional[str]:
        """Run a proof-of-access command after successful auth.

        Override in subclasses to execute a verification command
        (e.g. whoami, SELECT user(), list shares).

        Returns:
            String with proof output, or None if not supported.
        """
        return None
