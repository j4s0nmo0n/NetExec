"""
NetExec ``adws`` protocol - Active Directory Web Services (port 9389).

This protocol exposes the offensive and reconnaissance features of SOAPy
(https://github.com/jlevere/SOAPy) as a first-class NetExec protocol. SOAPy
is vendored under ``_soapy`` inside this package, with a ``GSS_Wrap_LDAP``
fallback for impacket < 0.13.

Supported authentication:
  - NTLM (password or NT hash)
  - Kerberos via ccache (KRB5CCNAME environment variable)

The NetExec ``call_cmd_args`` dispatch mechanism automatically invokes the
method on this class whose name matches the argparse ``dest`` defined in
``proto_args.py``. Each public method below therefore maps to one CLI flag.
"""
import os
import logging
from datetime import datetime

from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_target  # noqa: F401  (legitimate import, may be used by future helpers)

from nxc.config import process_secret, host_info_colors  # noqa: F401
from nxc.connection import connection
from nxc.helpers.bloodhound import add_user_bh
from nxc.logger import NXCAdapter

# Vendored SOAPy
from nxc.protocols.adws._soapy import (
    ADWSConnect,
    NTLMAuth,
    KerberosAuth,
    ADWSError,
    NAMESPACES,
)
from nxc.protocols.adws._soapy.soa import (
    set_rbcd,
    set_spn,
    set_asrep,
    add_computer as soapy_add_computer,
    delete_computer as soapy_delete_computer,
    disable_machine_account as soapy_disable_machine_account,
)
from nxc.protocols.adws._soapy.ad_dns_manager_adws import (
    add_dns_record_adws,
    modify_dns_record_adws,
    remove_dns_record_adws,
    tombstone_dns_record_adws,
    resurrect_dns_record_adws,
)

# Formatters de sortie nxc-style
from nxc.protocols.adws import formatters

# LDAP "family" queries mapped to the enumeration flags
ENUM_QUERIES = {
    "users":         "(&(objectClass=user)(objectCategory=person))",
    "computers":     "(objectClass=computer)",
    "groups":        "(objectCategory=group)",
    "admins":        "(&(objectClass=user)(adminCount=1))",
    "spns":          "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
    "asreproastable":"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
    "constrained":   "(msds-allowedtodelegateto=*)",
    "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
    "rbcds":         "(msds-allowedtoactonbehalfofotheridentity=*)",
}


class adws(connection):
    """ADWS protocol for NetExec - orchestrates SOAPy features."""

    def __init__(self, args, db, host):
        # Fields required by the parent ``connection`` class
        self.domain = ""
        self.targetDomain = ""
        self.server_os = None
        # NOTE: do NOT set self.hostname here. connection.__init__ will populate
        # it with the original target supplied by the user (which can be either
        # an IP or an FQDN, see nxc/connection.py line 160). It is crucial that
        # ``self.hostname`` remain the original string so
        # ``_resolve_domain_via_dns()`` can detect an FQDN target.
        self.lmhash = ""
        self.nthash = ""
        self.no_ntlm = False
        self.admin_privs = False  # ADWS has no notion of "local admin" the way SMB does

        # ADWS-specific
        self._auth = None             # NTLMAuth | KerberosAuth
        self._enum_client = None      # ADWSConnect "Enumeration" (lazy)
        self.baseDN = ""              # default, populated on first query

        connection.__init__(self, args, db, host)

    # ------------------------------------------------------------------
    # NetExec plumbing
    # ------------------------------------------------------------------
    def proto_logger(self):
        # Silence verbose logging from vendored libs
        logging.getLogger("nxc.protocols.adws._soapy").setLevel(logging.WARNING)
        self.logger = NXCAdapter(
            extra={
                "protocol": "ADWS",
                "host": self.host,
                "port": str(self.args.port),
                "hostname": self.hostname,
            }
        )

    def enum_host_info(self):
        """
        OPSEC-first: by default, no network traffic before authentication.

        Behavior:
          - Without ``--smb-info`` (default): port 445 is NOT contacted.
            If the user did not pass ``-d``, the domain is inferred via a
            DNS reverse lookup (PTR record) followed by a split on the first
            dot. Hostname and OS are enriched after ADWS authentication via
            the RootDSE.
          - With ``--smb-info``: anonymous SMB pre-flight (NEGOTIATE) to
            retrieve hostname/OS/domain, just like ``nxc winrm`` /
            ``nxc ldap``. Useful for mass scans where OPSEC does not matter
            and the OS info is wanted in the output.
        """
        # Default hostname = the target (enriched after ADWS auth).
        self.hostname = self.hostname or self.host
        self.server_os = "Active Directory Web Services"

        if getattr(self.args, "smb_info", False):
            try:
                smb_conn = SMBConnection(self.host, self.host, sess_port=445, timeout=5)
                try:
                    smb_conn.login("", "")
                except Exception:
                    pass  # anonymous auth rejected; banner already retrieved
                self.hostname = smb_conn.getServerName() or self.hostname
                self.targetDomain = self.domain = smb_conn.getServerDNSDomainName() or ""
                self.server_os = smb_conn.getServerOS() or self.server_os
                try:
                    smb_conn.logoff()
                except Exception:
                    pass
            except Exception as e:
                self.logger.debug(f"--smb-info pre-flight failed (non fatal): {e}")
        else:
            # OPSEC-first: no SMB. Try a DNS reverse lookup to get an FQDN
            # from which the domain can be extracted.
            self._resolve_domain_via_dns()

        # User-supplied domain (-d) wins over everything else
        if getattr(self.args, "domain", None):
            self.domain = self.args.domain

        self.logger.extra["hostname"] = self.hostname
        try:
            self.db.add_host(
                self.host, self.args.port, self.hostname, self.domain, self.server_os
            )
        except Exception as e:
            self.logger.debug(f"db.add_host failed (non fatal): {e}")

    def _resolve_domain_via_dns(self):
        """
        Try to extract the domain in this order:
          1. If the original target (``self.hostname``, supplied by the user
             on the CLI) is already an FQDN, split short host + domain
             directly **without any network traffic**.
          2. Otherwise, DNS reverse lookup (PTR) on ``self.host`` (the IP).

        Best-effort, silent on failure.

        If the user passed ``-d``, the result will be overwritten by
        ``self.args.domain`` further down anyway.
        """
        # 1. Original user target = FQDN?
        target = getattr(self, "hostname", None) or self.host
        if target and not self._looks_like_ip(target) and "." in target:
            parts = target.split(".")
            if len(parts) >= 2:
                self.hostname = parts[0]
                self.domain = ".".join(parts[1:])
                self.logger.debug(
                    f"FQDN target ({target!r}) -> hostname={self.hostname} domain={self.domain}"
                )
                return

        # 2. Otherwise, DNS reverse on the resolved IP
        try:
            import socket as _socket
            fqdn, _, _ = _socket.gethostbyaddr(self.host)
            if fqdn and "." in fqdn:
                parts = fqdn.split(".")
                self.hostname = parts[0]
                self.domain = ".".join(parts[1:])
                self.logger.debug(
                    f"DNS reverse -> fqdn={fqdn} hostname={self.hostname} domain={self.domain}"
                )
        except Exception as e:
            self.logger.debug(f"DNS reverse failed for {self.host}: {e}")

    @staticmethod
    def _looks_like_ip(s):
        """Heuristic: does the string look like an IPv4/IPv6 address?"""
        if not s:
            return False
        # IPv6 typically has ':'
        if ":" in s:
            return True
        # IPv4: 4 numbers separated by '.'
        parts = s.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return True
        return False

    # msDS-Behavior-Version (domainFunctionality) -> minimum required OS
    # cf. https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9a06a14b-4946-4b9e-9f99-5a4ed8ae35e2
    _DOMAIN_FUNCTIONALITY_OS = {
        0: "Windows 2000",
        1: "Windows Server 2003 Interim",
        2: "Windows Server 2003",
        3: "Windows Server 2008",
        4: "Windows Server 2008 R2",
        5: "Windows Server 2012",
        6: "Windows Server 2012 R2",
        7: "Windows Server 2016",
        10: "Windows Server 2025",
    }

    def _post_auth_enrich_host_info(self):
        """
        After successful ADWS authentication, enrich hostname/domain/OS from
        the RootDSE (port 9389 only, no SMB). Best-effort, silent on failure.

        - ``defaultNamingContext`` (e.g. "DC=example,DC=com") -> ``domain`` = "example.com"
        - ``dnsHostName`` of the current server (RootDSE) -> ``hostname``
        - ``domainFunctionality`` -> minimum OS (e.g. "Windows Server 2025")

        Opens a dedicated ``Resource`` client (the RootDSE is fetched via
        WS-Transfer Get, not via Pull/Enumerate; ``_enum_client`` is in
        Enumeration mode and cannot be used here).

        Returns True if something actually changed (useful to decide whether
        the host info line should be reprinted), False otherwise.
        """
        try:
            res_client = ADWSConnect.put_client(
                ip=self.host,
                domain=self.domain,
                username=self.username,
                auth=self._auth,
            )
            ctxs = res_client.get_rootdse_contexts()
        except Exception as e:
            self.logger.debug(f"RootDSE post-auth enrichment failed: {e}")
            return False

        self.logger.debug(f"RootDSE fetched: {ctxs}")
        changed = False

        # Domain from defaultNamingContext if not already known
        default_dn = ctxs.get("defaultNamingContext")
        if default_dn and not self.domain:
            parts = [p[3:] for p in default_dn.split(",") if p.upper().startswith("DC=")]
            if parts:
                self.domain = ".".join(parts)
                changed = True

        # Hostname from dnsHostName: take the short form if we currently
        # have an FQDN or an IP as hostname
        dns_host = ctxs.get("dnsHostName")
        if dns_host:
            short = dns_host.split(".")[0]
            if short and (self.hostname == self.host
                          or "." in (self.hostname or "")
                          or self.hostname.lower() != short.lower()):
                if self.hostname != short:
                    self.hostname = short
                    self.logger.extra["hostname"] = self.hostname
                    changed = True

        # Approximate OS from the domain functional level.
        # ``domainFunctionality`` is returned as list[str] by the RootDSE
        # template (naming contexts are multi-valued), take the first item.
        domain_func_raw = ctxs.get("domainFunctionality")
        domain_func = None
        if isinstance(domain_func_raw, list) and domain_func_raw:
            domain_func = domain_func_raw[0]
        elif isinstance(domain_func_raw, str):
            domain_func = domain_func_raw

        if domain_func:
            try:
                level = int(domain_func)
                os_label = self._DOMAIN_FUNCTIONALITY_OS.get(level)
                if os_label:
                    new_os = f"{os_label} (or higher) - Active Directory Web Services"
                    if new_os != self.server_os:
                        self.server_os = new_os
                        changed = True
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Could not parse domainFunctionality={domain_func!r}: {e}")

        if default_dn:
            self.baseDN = default_dn

        return changed

    def print_host_info(self):
        self.logger.display(f"{self.server_os or 'Windows'} (name:{self.hostname}) (domain:{self.domain or '?'})")

    def create_conn_obj(self):
        """
        We do not create an ADWS connection here (it requires authentication).
        Just verify that port 9389 is reachable.
        """
        import socket
        try:
            with socket.create_connection((self.host, self.args.port), timeout=5):
                return True
        except Exception as e:
            self.logger.info(f"ADWS port {self.args.port} unreachable: {e}")
            return False

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def _try_adws_bind(self, label_secret):
        """
        Actually attempt to establish an ADWS Enumeration connection using
        ``self._auth``. Returns True on success, False otherwise.

        ``label_secret`` is the string (password / hash / 'ccache') that
        will be displayed in success/fail logs.
        """
        try:
            self._enum_client = ADWSConnect.pull_client(
                ip=self.host,
                domain=self.domain,
                username=self.username,
                auth=self._auth,
            )
            # Once authenticated, enrich hostname/domain/OS from the ADWS
            # RootDSE - port 9389 only, no SMB.
            enriched = self._post_auth_enrich_host_info()
            # Reprint the host info line if we discovered something new
            # (OS, short hostname, domain).
            if enriched:
                self.logger.display(
                    f"{self.server_os} (name:{self.hostname}) (domain:{self.domain})"
                )
            self.logger.success(f"{self.domain}\\{self.username}:{process_secret(label_secret)} {self.mark_pwned()}")
            return True
        except SystemExit as e:
            # SOAPy raises SystemExit on auth failure (see NNS._raise_auth_error)
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(label_secret)} ({e})")
            return False
        except Exception as e:
            self.logger.fail(f"{self.domain}\\{self.username}:{process_secret(label_secret)} ({e})")
            return False

    def _normalize_domain(self, incoming):
        """
        If NetExec passes ``domain=None`` (case where neither ``-d`` nor an
        SMB pre-flight populated the domain), fall back on ``self.domain``
        (populated by DNS reverse). If even that is empty, raise an explicit
        error rather than letting impacket crash on ``None.encode``.
        """
        if incoming:
            return incoming
        if self.domain:
            return self.domain
        self.logger.fail(
            "Could not determine target domain. Pass it explicitly via -d, "
            "or enable --smb-info, or ensure a PTR record exists for the target."
        )
        return None

    def plaintext_login(self, domain, username, password):
        domain = self._normalize_domain(domain)
        if domain is None:
            return False
        self.domain = domain
        self.username = username
        self.password = password
        self._auth = NTLMAuth(password=password)
        if not self._try_adws_bind(password):
            return False
        try:
            self.db.add_credential("plaintext", domain, username, password)
            user_id = self.db.get_credential("plaintext", domain, username, password)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)
        except Exception as e:
            self.logger.debug(f"db credential update failed (non fatal): {e}")
        if username:
            add_user_bh(username, domain, self.logger, self.config)
        return True

    def hash_login(self, domain, username, ntlm_hash):
        domain = self._normalize_domain(domain)
        if domain is None:
            return False
        self.domain = domain
        self.username = username
        nthash = ntlm_hash.split(":")[1] if ":" in ntlm_hash else ntlm_hash
        self.nthash = nthash
        self._auth = NTLMAuth(hashes=nthash)
        if not self._try_adws_bind(nthash):
            return False
        try:
            self.db.add_credential("hash", domain, username, ntlm_hash)
            user_id = self.db.get_credential("hash", domain, username, ntlm_hash)
            host_id = self.db.get_hosts(self.host)[0].id
            self.db.add_loggedin_relation(user_id, host_id)
        except Exception as e:
            self.logger.debug(f"db credential update failed (non fatal): {e}")
        if username:
            add_user_bh(username, domain, self.logger, self.config)
        return True

    def kerberos_login(self, domain, username, password="", ntlm_hash="", aesKey="", kdcHost="", useCache=False):
        # SOAPy s'appuie sur KRB5CCNAME, donc useCache vaut effectivement toujours True ici
        if not os.getenv("KRB5CCNAME"):
            self.logger.fail("Kerberos auth requires KRB5CCNAME pointing to a valid ccache")
            return False

        # If username/domain are missing, derive them from the ccache
        if not username or not domain:
            try:
                from impacket.krb5.ccache import CCache
                ccache_domain, ccache_user, _, _ = CCache.parseFile(
                    domain=domain or "",
                    username=username or "",
                    target=f"LDAP/{self.host}",
                )
                username = username or ccache_user
                domain = domain or ccache_domain
            except Exception as e:
                self.logger.fail(f"Could not parse ccache: {e}")
                return False

        self.domain = domain
        self.username = username
        self._auth = KerberosAuth(kdc_host=kdcHost or self.host)
        if not self._try_adws_bind("ccache"):
            return False
        try:
            self.db.add_credential("kerberos", domain, username, "ccache")
        except Exception as e:
            self.logger.debug(f"db credential update failed (non fatal): {e}")
        if username:
            add_user_bh(username, domain, self.logger, self.config)
        return True

    # ------------------------------------------------------------------
    # Common helpers
    # ------------------------------------------------------------------
    def _ensure_basedn(self):
        """
        Returns the defaultNamingContext (populated by
        _post_auth_enrich_host_info after the bind). If for some reason it is
        empty, fall back to a SOAP RootDSE fetch via a dedicated Resource
        client.
        """
        if self.baseDN:
            return self.baseDN
        if self._auth is None:
            return None
        try:
            res_client = ADWSConnect.put_client(
                ip=self.host,
                domain=self.domain,
                username=self.username,
                auth=self._auth,
            )
            ctxs = res_client.get_rootdse_contexts()
            self.baseDN = ctxs.get("defaultNamingContext", "") or ""
        except Exception as e:
            self.logger.debug(f"Could not retrieve defaultNamingContext: {e}")
        return self.baseDN

    # ------------------------------------------------------------------
    # Pull + dispatch to dedicated formatters
    # ------------------------------------------------------------------
    # Minimum attributes required by each formatter to produce a useful
    # display. If the user passes ``--filter ATTR,...``, those attributes
    # are used instead.
    _ATTRS_USERS = [
        "sAMAccountName", "pwdLastSet", "badPwdCount", "description",
        "userAccountControl", "memberOf",
    ]
    _ATTRS_COMPUTERS = [
        "sAMAccountName", "operatingSystem", "operatingSystemVersion",
        "lastLogonTimestamp", "description", "dNSHostName",
    ]
    _ATTRS_GROUPS = ["sAMAccountName", "description", "member", "groupType"]
    _ATTRS_ADMINS = [
        "sAMAccountName", "pwdLastSet", "badPwdCount", "memberOf",
        "userAccountControl",
    ]
    _ATTRS_SPNS = [
        "sAMAccountName", "servicePrincipalName", "userAccountControl",
        "pwdLastSet",
    ]
    _ATTRS_ASREP = [
        "sAMAccountName", "pwdLastSet", "badPwdCount", "description",
        "userAccountControl",
    ]
    _ATTRS_DELEGATION = [
        "sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    ]

    def _pull_records(self, ldap_filter, default_attrs=None, base_dn=None):
        """Run a Pull query and return parsed records.

        Honors ``--filter`` (attribute override), ``--basedn`` (base DN
        override), and ``--raw`` (disables SID/timestamp parsing).
        """
        if self._enum_client is None:
            self.logger.fail("Not authenticated to ADWS")
            return None

        attrs = default_attrs
        if getattr(self.args, "filter", None):
            attrs = [x.strip() for x in self.args.filter.split(",")]
        base = (
            base_dn
            or getattr(self.args, "distinguishedname", None)
            or self._ensure_basedn()
            or None
        )
        # --raw disables parsing, otherwise default is to parse.
        # --parse is still accepted for backward compatibility but has no
        # effect (parsing is already the default).
        parse_values = not getattr(self.args, "raw", False)

        try:
            return self._enum_client.pull_records(
                query=ldap_filter,
                basedn=base,
                attributes=attrs,
                parse_values=parse_values,
            )
        except Exception as e:
            self.logger.fail(f"Query failed: {e}")
            self.logger.debug("", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Methods invoked automatically by call_cmd_args (one per flag)
    # ------------------------------------------------------------------

    # --- Enumeration with dedicated formatters
    def users(self):
        records = self._pull_records(ENUM_QUERIES["users"], self._ATTRS_USERS)
        if records is not None:
            formatters.format_users(records, self.logger)

    def computers(self):
        records = self._pull_records(ENUM_QUERIES["computers"], self._ATTRS_COMPUTERS)
        if records is not None:
            formatters.format_computers(records, self.logger)

    def groups(self):
        records = self._pull_records(ENUM_QUERIES["groups"], self._ATTRS_GROUPS)
        if records is not None:
            formatters.format_groups(records, self.logger)

    def admins(self):
        records = self._pull_records(ENUM_QUERIES["admins"], self._ATTRS_ADMINS)
        if records is not None:
            formatters.format_admins(records, self.logger)

    def spns(self):
        records = self._pull_records(ENUM_QUERIES["spns"], self._ATTRS_SPNS)
        if records is not None:
            formatters.format_spns(records, self.logger)

    def asreproastable(self):
        records = self._pull_records(ENUM_QUERIES["asreproastable"], self._ATTRS_ASREP)
        if records is not None:
            formatters.format_asreproastable(records, self.logger)

    def constrained(self):
        records = self._pull_records(ENUM_QUERIES["constrained"], self._ATTRS_DELEGATION)
        if records is not None:
            formatters.format_delegation(records, self.logger, kind="constrained delegation")

    def unconstrained(self):
        records = self._pull_records(ENUM_QUERIES["unconstrained"], self._ATTRS_DELEGATION)
        if records is not None:
            formatters.format_delegation(records, self.logger, kind="unconstrained delegation")

    def rbcds(self):
        records = self._pull_records(ENUM_QUERIES["rbcds"], self._ATTRS_DELEGATION)
        if records is not None:
            formatters.format_delegation(records, self.logger, kind="resource-based constrained delegation")

    def query(self):
        """Free-form LDAP query via ``--query/-q``: key:value output."""
        # No default attributes - the user picks them via --filter,
        # otherwise we retrieve all attributes (None on the SOAPy side).
        records = self._pull_records(self.args.query, default_attrs=None)
        if records is not None:
            formatters.format_keyvalue(records, self.logger)

    # ------------------------------------------------------------------
    # Helper to reroute SOAPy print() to self.logger
    # ------------------------------------------------------------------
    def _emit_to_logger(self):
        """Returns a ``(level, message) -> None`` callback that routes SOAPy
        messages to the standard NXC logger chain.
        """
        log = self.logger
        def _emit(level, message):
            if level == "ok":
                log.success(message)
            elif level == "fail":
                log.fail(message)
            elif level == "info":
                log.display(message)
            else:
                log.info(message)
        return _emit

    # --- Write / offensive actions
    def rbcd(self):
        if not self.args.account:
            self.logger.fail("--rbcd requires --account")
            return
        try:
            set_rbcd(
                ip=self.host, domain=self.domain, target=self.args.account,
                account=self.args.rbcd, username=self.username, auth=self._auth,
                remove=self.args.remove,
                emit=self._emit_to_logger(),
            )
        except Exception as e:
            self.logger.fail(f"RBCD operation failed: {e}")

    def spn(self):
        if not self.args.account:
            self.logger.fail("--spn requires --account")
            return
        try:
            set_spn(
                ip=self.host, domain=self.domain, target=self.args.account,
                value=self.args.spn, username=self.username, auth=self._auth,
                remove=self.args.remove,
                emit=self._emit_to_logger(),
            )
        except Exception as e:
            self.logger.fail(f"SPN operation failed: {e}")

    def asrep(self):
        if not self.args.account:
            self.logger.fail("--asrep requires --account")
            return
        try:
            set_asrep(
                ip=self.host, domain=self.domain, target=self.args.account,
                username=self.username, auth=self._auth, remove=self.args.remove,
                emit=self._emit_to_logger(),
            )
        except Exception as e:
            self.logger.fail(f"ASREP operation failed: {e}")

    # --- Computer management
    def addcomputer(self):
        machine = self.args.addcomputer or None  # "" -> None to generate randomly
        try:
            soapy_add_computer(
                target=self.args.account if self.args.account else None,
                machine_name=machine,
                ou_dn=self.args.ou,
                username=self.username,
                ip=self.host,
                domain=self.domain,
                auth=self._auth,
                remove=False,
                computer_pass=self.args.computer_pass,
                emit=self._emit_to_logger(),
            )
        except Exception as e:
            self.logger.fail(f"Add computer failed: {e}")

    def delete_computer(self):
        try:
            soapy_delete_computer(
                machine_name=self.args.delete_computer,
                username=self.username,
                ip=self.host,
                domain=self.domain,
                auth=self._auth,
                emit=self._emit_to_logger(),
            )
        except Exception as e:
            self.logger.fail(f"Delete computer failed: {e}")

    def disable_account(self):
        try:
            soapy_disable_machine_account(
                machine_name=self.args.disable_account,
                username=self.username,
                ip=self.host,
                domain=self.domain,
                auth=self._auth,
                emit=self._emit_to_logger(),
            )
        except Exception as e:
            self.logger.fail(f"Disable account failed: {e}")

    # --- Shadow Credentials
    def shadow_creds(self):
        try:
            from nxc.protocols.adws._soapy.shadow_credentials import (
                shadow_credentials_list,
                shadow_credentials_add,
                shadow_credentials_remove,
                shadow_credentials_clear,
                shadow_credentials_info,
                DSINTERNALS_AVAILABLE,
            )
        except ImportError as e:
            self.logger.fail(f"Shadow Credentials module unavailable: {e}")
            return
        if not DSINTERNALS_AVAILABLE:
            self.logger.fail("Install dsinternals: pip install dsinternals")
            return
        if not self.args.shadow_target:
            self.logger.fail("--shadow-creds requires --shadow-target")
            return

        action = self.args.shadow_creds
        common = {
            "target": self.args.shadow_target,
            "username": self.username,
            "ip": self.host,
            "domain": self.domain,
            "auth": self._auth,
        }
        try:
            if action == "list":
                shadow_credentials_list(**common)
            elif action == "add":
                shadow_credentials_add(
                    filename=self.args.cert_filename,
                    export_type=self.args.cert_export,
                    pfx_password=self.args.cert_password,
                    **common,
                )
            elif action == "remove":
                if not self.args.device_id:
                    self.logger.fail("--shadow-creds remove requires --device-id")
                    return
                shadow_credentials_remove(device_id=self.args.device_id, **common)
            elif action == "clear":
                shadow_credentials_clear(**common)
            elif action == "info":
                if not self.args.device_id:
                    self.logger.fail("--shadow-creds info requires --device-id")
                    return
                shadow_credentials_info(device_id=self.args.device_id, **common)
        except Exception as e:
            self.logger.fail(f"Shadow Credentials {action} failed: {e}")

    # --- DNS management
    def dns_add(self):
        if not self.args.dns_ip:
            self.logger.fail("--dns-add requires --dns-ip")
            return
        try:
            add_dns_record_adws(
                fqdn_record=self.args.dns_add, ip_addr=self.args.dns_ip,
                username=self.username, ip=self.host, domain=self.domain,
                auth=self._auth, allow_multiple=self.args.allow_multiple,
                ttl=self.args.ttl, tcp=self.args.dns_tcp_soa,
            )
        except Exception as e:
            self.logger.fail(f"DNS add failed: {e}")

    def dns_modify(self):
        if not self.args.dns_ip:
            self.logger.fail("--dns-modify requires --dns-ip")
            return
        try:
            modify_dns_record_adws(
                fqdn_record=self.args.dns_modify, new_ip=self.args.dns_ip,
                username=self.username, ip=self.host, domain=self.domain,
                auth=self._auth, ttl=self.args.ttl, tcp=self.args.dns_tcp_soa,
            )
        except Exception as e:
            self.logger.fail(f"DNS modify failed: {e}")

    def dns_remove(self):
        if not self.args.ldapdelete and not self.args.dns_ip:
            self.logger.fail("--dns-remove requires --dns-ip unless --ldapdelete")
            return
        try:
            remove_dns_record_adws(
                fqdn_record=self.args.dns_remove,
                ip_to_remove=self.args.dns_ip or "",
                username=self.username, ip=self.host, domain=self.domain,
                auth=self._auth, tcp=self.args.dns_tcp_soa,
                ldapdelete=self.args.ldapdelete,
            )
        except Exception as e:
            self.logger.fail(f"DNS remove failed: {e}")

    def dns_tombstone(self):
        try:
            tombstone_dns_record_adws(
                fqdn_record=self.args.dns_tombstone,
                username=self.username, ip=self.host, domain=self.domain,
                auth=self._auth, tcp=self.args.dns_tcp_soa,
            )
        except Exception as e:
            self.logger.fail(f"DNS tombstone failed: {e}")

    def dns_resurrect(self):
        try:
            resurrect_dns_record_adws(
                fqdn_record=self.args.dns_resurrect,
                username=self.username, ip=self.host, domain=self.domain,
                auth=self._auth, tcp=self.args.dns_tcp_soa,
            )
        except Exception as e:
            self.logger.fail(f"DNS resurrect failed: {e}")
