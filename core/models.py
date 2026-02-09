"""Data models for Rapids."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ResultStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class Target:
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    nmap_service: Optional[str] = None   # raw nmap service name (e.g. "microsoft-ds")
    nmap_product: Optional[str] = None   # nmap product (e.g. "OpenSSH")
    nmap_version: Optional[str] = None   # nmap version (e.g. "8.9p1")

    def __str__(self) -> str:
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def version_string(self) -> str:
        """Human-readable product/version string from nmap detection."""
        parts = []
        if self.nmap_product:
            parts.append(self.nmap_product)
        if self.nmap_version:
            parts.append(self.nmap_version)
        return " ".join(parts)


@dataclass(frozen=True)
class Credential:
    username: str
    password: str
    nthash: str = ""

    def __str__(self) -> str:
        if self.nthash:
            return f"{self.username}::{self.nthash}"
        return f"{self.username}:{self.password}"

    @property
    def is_hash(self) -> bool:
        """True if this credential uses an NT hash instead of a password."""
        return bool(self.nthash)


@dataclass
class SprayResult:
    target: Target
    credential: Credential
    service: str
    status: ResultStatus = ResultStatus.FAILURE
    message: str = ""
    proof: str = ""
