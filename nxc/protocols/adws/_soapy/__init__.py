"""
Vendored SOAPy for the NetExec ``adws`` protocol.

Source: https://github.com/logangoins/SOAPy (MIT)
Local modifications:
  - relative imports (``from .X`` instead of ``from src.X``)
  - ``GSS_Wrap_LDAP`` / ``GSS_Unwrap_LDAP`` fallback for impacket < 0.13
    (see ``_gss_wrap_ldap`` / ``_gss_unwrap_ldap`` in ``ms_nns``)
"""
from .ms_nmf import NMFConnection
from .ms_nns import NNS
from .encoder import Encoder
from .adws import ADWSConnect, ADWSAuthType, NTLMAuth, KerberosAuth, ADWSError
from .soap_templates import NAMESPACES

__all__ = [
    "NMFConnection",
    "NNS",
    "Encoder",
    "ADWSConnect",
    "ADWSAuthType",
    "NTLMAuth",
    "KerberosAuth",
    "ADWSError",
    "NAMESPACES",
]
