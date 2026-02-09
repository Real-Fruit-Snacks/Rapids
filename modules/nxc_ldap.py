"""NXC-backed LDAP module."""

from modules.nxc_base import NxcModule


class NxcLDAPModule(NxcModule):
    name = "nxc_ldap"
    nxc_protocol = "ldap"
    default_port = 389
    alternate_ports = [636, 3268, 3269]
