"""SNMP service module using pysnmp.

Tests community strings (SNMPv1/v2c) and SNMPv3 credentials.
For SNMPv1/v2c: password is used as the community string, username is ignored.
For SNMPv3: username and password are both used (authNoPriv).

Supports pysnmp v7+ (fully async API with asyncio bridge).
"""

import asyncio
from typing import Optional

from core.models import Credential, Target
from modules.base import ServiceModule

from pysnmp.hlapi.v3arch import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

# OID for sysDescr — safe read-only query
SYS_DESCR = ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0"))


class SNMPModule(ServiceModule):
    name = "snmp"
    default_port = 161
    alternate_ports = []

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        snmpv3 = kwargs.get("snmpv3", False)

        if snmpv3:
            return asyncio.run(self._try_v3(target.host, port, credential, timeout))
        else:
            return asyncio.run(self._try_v2c(target.host, port, credential, timeout))

    async def _try_v2c(self, host: str, port: int, credential: Credential, timeout: int) -> bool:
        """Test SNMPv1/v2c community string (password = community string)."""
        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create((host, port), timeout, 0)
            error_indication, error_status, error_index, var_binds = await get_cmd(
                engine,
                CommunityData(credential.password),
                transport,
                ContextData(),
                SYS_DESCR,
            )

            if error_indication:
                err = str(error_indication).lower()
                if "timeout" in err:
                    raise TimeoutError(f"SNMP connection to {host}:{port} timed out")
                if "no snmp response" in err:
                    return False
                raise RuntimeError(str(error_indication))

            if error_status:
                return False

            return True
        finally:
            engine.close_dispatcher()

    async def _try_v3(self, host: str, port: int, credential: Credential, timeout: int) -> bool:
        """Test SNMPv3 authNoPriv (username + password)."""
        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create((host, port), timeout, 0)
            error_indication, error_status, error_index, var_binds = await get_cmd(
                engine,
                UsmUserData(credential.username, credential.password),
                transport,
                ContextData(),
                SYS_DESCR,
            )

            if error_indication:
                err = str(error_indication).lower()
                if "timeout" in err:
                    raise TimeoutError(f"SNMP connection to {host}:{port} timed out")
                if "wrong" in err or "unknown" in err or "auth" in err:
                    return False
                raise RuntimeError(str(error_indication))

            if error_status:
                return False

            return True
        finally:
            engine.close_dispatcher()

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        """Read sysDescr as proof of access."""
        try:
            return asyncio.run(self._verify_async(target, credential, timeout, **kwargs))
        except Exception:
            return None

    async def _verify_async(self, target: Target, credential: Credential, timeout: int, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        snmpv3 = kwargs.get("snmpv3", False)
        engine = SnmpEngine()
        try:
            auth_data = (
                UsmUserData(credential.username, credential.password)
                if snmpv3
                else CommunityData(credential.password)
            )
            transport = await UdpTransportTarget.create((target.host, port), timeout, 0)
            error_indication, error_status, error_index, var_binds = await get_cmd(
                engine, auth_data,
                transport,
                ContextData(), SYS_DESCR,
            )
            if not error_indication and not error_status and var_binds:
                return str(var_binds[0][1])
            return None
        finally:
            engine.close_dispatcher()
