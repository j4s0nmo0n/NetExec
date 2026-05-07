"""
CLI arguments for the ``nxc adws`` protocol.

Wraps SOAPy's features (vendored under ``_soapy``):
  - AD enumeration via ADWS (NetTcpBinding, port 9389)
  - Attribute writes (RBCD, SPN, ASREP)
  - Machine account management
  - Shadow Credentials (msDS-KeyCredentialLink)
  - AD-integrated DNS management
  - NTLM authentication (password / NT hash) or Kerberos (ccache)
"""
from nxc.helpers.args import DisplayDefaultsNotNone


def proto_args(parser, parents):
    adws_parser = parser.add_parser(
        "adws",
        help="own stuff using ADWS (Active Directory Web Services, port 9389)",
        parents=parents,
        formatter_class=DisplayDefaultsNotNone,
    )
    adws_parser.add_argument("-H", "--hash", metavar="HASH", dest="hash", nargs="+", default=[], help="NTLM hash(es) or file(s) containing NTLM hashes")
    adws_parser.add_argument("--port", default=9389, type=int, help="ADWS port")
    adws_parser.add_argument("-d", metavar="DOMAIN", dest="domain", type=str, default=None, help="domain to authenticate to")
    adws_parser.add_argument(
        "--smb-info",
        action="store_true",
        help=(
            "Pre-flight SMB anonymous NEGOTIATE on port 445 to retrieve "
            "hostname/OS/domain (off by default for OPSEC; ADWS-only by default). "
            "Without this flag the hostname/domain are derived from the post-auth "
            "RootDSE on port 9389 only."
        ),
    )

    # ------------------------------------------------------------------
    # Enumeration (Pull queries)
    # ------------------------------------------------------------------
    enum = adws_parser.add_argument_group("Enumeration")
    enum.add_argument("--users", action="store_true", help="Enumerate user objects")
    enum.add_argument("--computers", action="store_true", help="Enumerate computer objects")
    enum.add_argument("--groups", action="store_true", help="Enumerate group objects")
    enum.add_argument("--admins", action="store_true", help="Enumerate accounts with adminCount=1")
    enum.add_argument("--spns", action="store_true", help="Enumerate accounts with servicePrincipalName")
    enum.add_argument("--asreproastable", action="store_true", help="Enumerate accounts with DONT_REQ_PREAUTH set")
    enum.add_argument("--constrained", action="store_true", help="Enumerate accounts with msDS-AllowedToDelegateTo set")
    enum.add_argument("--unconstrained", action="store_true", help="Enumerate accounts with TRUSTED_FOR_DELEGATION")
    enum.add_argument("--rbcds", action="store_true", help="Enumerate accounts with msDS-AllowedToActOnBehalfOfOtherIdentity set")
    enum.add_argument("--query", "-q", metavar="LDAP", help="Run a raw LDAP filter (e.g. '(samaccountname=Administrator)')")
    enum.add_argument("--filter", "-f", metavar="ATTR,...", help="Comma-separated list of attributes to retrieve")
    enum.add_argument("--basedn", "-dn", metavar="DN", dest="distinguishedname", help="Base DN for the search")
    enum.add_argument("--raw", action="store_true", help="Disable value parsing (raw base64 SIDs/GUIDs, raw int timestamps, raw UAC value)")
    enum.add_argument("--parse", action="store_true", help="(legacy) Parse SIDs/GUIDs/timestamps to human-readable. Now enabled by default; use --raw to disable.")

    # ------------------------------------------------------------------
    # Écriture d'attributs / actions offensives
    # ------------------------------------------------------------------
    writing = adws_parser.add_argument_group("Writing / Attacks")
    writing.add_argument("--rbcd", metavar="SOURCE", help="Write RBCD on --account using SOURCE machine (use --remove to delete)")
    writing.add_argument("--spn", metavar="VALUE", help="Add a servicePrincipalName on --account (use --remove to delete)")
    writing.add_argument("--asrep", action="store_true", help="Set DONT_REQ_PREAUTH (asrep-roastable) on --account (use --remove to clear)")
    writing.add_argument("--account", metavar="ACCOUNT", help="Target account for attribute writes (sAMAccountName)")
    writing.add_argument("--remove", action="store_true", help="Reverse the operation (remove attribute / disable flag)")

    # ------------------------------------------------------------------
    # Gestion de comptes machines
    # ------------------------------------------------------------------
    cm = adws_parser.add_argument_group("Computer management")
    cm.add_argument("--add-computer", dest="addcomputer", nargs="?", const="", metavar="MACHINE", help="Create a computer account (random name if omitted)")
    cm.add_argument("--computer-pass", dest="computer_pass", metavar="PASS", help="Password for the new computer account")
    cm.add_argument("--ou", metavar="OU_DN", help="DN of the OU to create the computer in")
    cm.add_argument("--delete-computer", dest="delete_computer", metavar="MACHINE", help="Delete a computer account (and its DN tree)")
    cm.add_argument("--disable-account", dest="disable_account", metavar="MACHINE", help="Disable a computer account (set ACCOUNTDISABLE)")

    # ------------------------------------------------------------------
    # Shadow Credentials (msDS-KeyCredentialLink)
    # ------------------------------------------------------------------
    sc = adws_parser.add_argument_group("Shadow Credentials")
    sc.add_argument("--shadow-creds", dest="shadow_creds", metavar="ACTION", choices=["list", "add", "remove", "clear", "info"], help="Shadow Credentials action")
    sc.add_argument("--shadow-target", dest="shadow_target", metavar="TARGET", help="Target account for Shadow Credentials")
    sc.add_argument("--device-id", dest="device_id", metavar="ID", help="Device ID (for remove/info)")
    sc.add_argument("--cert-filename", dest="cert_filename", metavar="NAME", help="Filename for certificate export (add)")
    sc.add_argument("--cert-export", dest="cert_export", metavar="TYPE", choices=["PEM", "PFX"], default="PFX", help="Export type (default PFX)")
    sc.add_argument("--cert-password", dest="cert_password", metavar="PASS", help="Password for the PFX file")

    # ------------------------------------------------------------------
    # Gestion DNS (AD-integrated DNS)
    # ------------------------------------------------------------------
    dns = adws_parser.add_argument_group("DNS management")
    dns.add_argument("--dns-add", dest="dns_add", metavar="FQDN", help="Add an A record (requires --dns-ip)")
    dns.add_argument("--dns-modify", dest="dns_modify", metavar="FQDN", help="Replace the A record (requires --dns-ip)")
    dns.add_argument("--dns-remove", dest="dns_remove", metavar="FQDN", help="Remove an A record (requires --dns-ip unless --ldapdelete)")
    dns.add_argument("--dns-tombstone", dest="dns_tombstone", metavar="FQDN", help="Tombstone a dnsNode")
    dns.add_argument("--dns-resurrect", dest="dns_resurrect", metavar="FQDN", help="Resurrect a tombstoned dnsNode")
    dns.add_argument("--dns-ip", dest="dns_ip", metavar="IP", help="IP for dns add/modify/remove")
    dns.add_argument("--ldapdelete", action="store_true", help="Use LDAP delete on the dnsNode")
    dns.add_argument("--allow-multiple", dest="allow_multiple", action="store_true", help="Allow multiple A records when adding")
    dns.add_argument("--ttl", type=int, default=180, help="TTL for new A records")
    dns.add_argument("--dns-soa-tcp", dest="dns_tcp_soa", action="store_true", help="Use DNS over TCP when fetching SOA serial for dns-add/modify/remove")

    return parser
