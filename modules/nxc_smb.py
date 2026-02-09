"""NXC-backed SMB module."""

from modules.nxc_base import NxcModule


class NxcSMBModule(NxcModule):
    name = "nxc_smb"
    nxc_protocol = "smb"
    default_port = 445
    alternate_ports = [139]
