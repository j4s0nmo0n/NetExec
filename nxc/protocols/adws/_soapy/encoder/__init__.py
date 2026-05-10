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
from .xml_parser import XMLParser
from .encoder import Encoder

__all__ = ["XMLParser", "Encoder"]
