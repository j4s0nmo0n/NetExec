# SPDX-License-Identifier: MIT
#
# Portions of this file are adapted from SOAPy
# (https://github.com/logangoins/SOAPy)
#
# Original copyright:
#   Copyright (c) Logan Goins (@logangoins) and Jackson Leverett
#   Originally researched at IBM X-Force Red.
#
# SOAPy is licensed under the MIT License. See:
#   https://github.com/logangoins/SOAPy/blob/main/LICENSE
#
# Local modifications include:
#   - Integration into NetExec's nxc/protocols/adws/ layout
#   - Compatibility shim for impacket < 0.13 GSS_Wrap_LDAP
#   - Additional features: AD-integrated DNS, Shadow Credentials,
#     account add/delete/disable
from .constants import *
from .record import record
from .utils import Net7BitInteger, dump_records, print_records

__all__ = ["record", "Net7BitInteger", "dump_records", "print_records"]
