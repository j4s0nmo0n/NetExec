from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from ...ad.cache_gen import pull_all_ad_objects, _parse_aces, filetime_to_unix, dedupe_aces, BH_TYPE_LABEL_MAP
from ...lib.utils import ADUtils, DNSCache
from ...ad.adws import WELL_KNOWN_SIDS
from .bh_rpc_computer import ADComputer
import logging
import queue
import threading
import json
from ...lib.computers import ComputerEnumerator
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import tsts as TSTS
import os
import sys

from ...lib.authentication import ADAuthentication
from ...ad.acls import normalize_name


def get_cache_file_path(output_dir, domain_name):
    """
    Get the cache file path with domain name.
    
    Args:
        output_dir: Output directory
        domain_name: Domain name
        
    Returns:
        str: Path to cache file
    """
    cache_filename = f"cache_{domain_name}.json"
    return os.path.join(output_dir, cache_filename)

def get_output_dir_and_domain_from_argv():
    """
    Extract output directory and domain from command line arguments.
    
    Returns:
        tuple: (output_dir, domain_name)
    """
    output_dir = "output"
    domain_name = None
    
    if "--output-dir" in sys.argv:
        idx = sys.argv.index("--output-dir")
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]
    
    if "-d" in sys.argv:
        idx = sys.argv.index("-d")
        if idx + 1 < len(sys.argv):
            domain_name = sys.argv[idx + 1]
    elif "--domain" in sys.argv:
        idx = sys.argv.index("--domain")
        if idx + 1 < len(sys.argv):
            domain_name = sys.argv[idx + 1]
    
    return output_dir, domain_name

output_dir, domain_name = get_output_dir_and_domain_from_argv()
if domain_name:
    cache_file_path = get_cache_file_path(output_dir, domain_name)
else:
    cache_file_path = os.path.join(output_dir, "Cache.json")


def collect_computers(
    ip=None,
    domain=None,
    username=None,
    auth=None,
    base_dn_override=None,
    cache_file=None,
    adws_object_classes=None, has_laps=False,
    has_lapsv2=False,
    objecttype_guid_map=None
):
    """
        Collect all AD computers with ACLs, LAPS, without sessions or RPC.
    """
    import json
    from uuid import UUID
    from ...lib.utils import ADUtils

    # In case we have a cache file ready
    if cache_file:
        with open(cache_file, "r", encoding="utf-8") as f:
            cache_data = json.load(f)
        if isinstance(cache_data, dict):
            if "objects" in cache_data:
                objs = cache_data["objects"]
            elif "data" in cache_data:
                objs = cache_data["data"]
            else:
                objs = list(cache_data.values())
        else:
            objs = cache_data
        computers = [
            o for o in objs
            if o.get("distinguishedName") and isinstance(o.get("distinguishedName"), str)
        ]
        print(f"[INFO] Computers collected: {len(computers)}")
        return computers

    # --- Attributes to collect ---
    attributes = [
        "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
        "nTSecurityDescriptor", "whenCreated", "description", "sAMAccountName", "dNSHostName", "userAccountControl",
        "operatingSystem", "operatingSystemVersion", "servicePrincipalName", "msDS-AllowedToDelegateTo",
        "lastLogon", "lastLogonTimestamp", "adminCount", "primaryGroupID"
    ]
    
    objecttype_guid_map_normalized = {k.lower(): v for k, v in (objecttype_guid_map or {}).items()}

    # Add msDS-AllowedToActOnBehalfOfOtherIdentity if available in schema
    if "msds-allowedtoactonbehalfofotheridentity".lower() in objecttype_guid_map_normalized:
        attributes.append("msDS-AllowedToActOnBehalfOfOtherIdentity")
    # Add LAPS v1 attributes if available
    if has_laps:
        if "ms-mcs-admpwdexpirationtime".lower() in objecttype_guid_map_normalized:
            attributes.append("ms-Mcs-AdmPwdExpirationTime")
        if "ms-mcs-admpwd".lower() in objecttype_guid_map_normalized:
            attributes.append("ms-Mcs-AdmPwd")
    # Add LAPS v2 attributes if available
    if has_lapsv2:
        if "mslaps-passwordexpirationtime".lower() in objecttype_guid_map_normalized:
            attributes.append("msLAPS-PasswordExpirationTime")
        if "mslaps-encryptedpassword".lower() in objecttype_guid_map_normalized:
            attributes.append("msLAPS-EncryptedPassword")

    # Exclude GMSA/SMSA objects if present in schema
    gmsa_filter = '(!(objectClass=msDS-GroupManagedServiceAccount))' if adws_object_classes and 'msDS-GroupManagedServiceAccount' in adws_object_classes else ''
    smsa_filter = '(!(objectClass=msDS-ManagedServiceAccount))' if adws_object_classes and 'msDS-ManagedServiceAccount' in adws_object_classes else ''
    query = f"(&(sAMAccountType=805306369){gmsa_filter}{smsa_filter})"

    # --- Pull via ADWS ---
    raw_objects = pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query=query,
        attributes=attributes,
        base_dn_override=base_dn_override
    ).get("objects", [])

    # --- BloodHound-style normalization ---
    for obj in raw_objects:
        # objectClass
        oc = ADUtils.get_entry_property(obj, "objectClass", default=[])
        if isinstance(oc, str):
            obj["objectClass"] = [oc]
        elif oc is None:
            obj["objectClass"] = []
        # DN as string
        dn = ADUtils.get_entry_property(obj, "distinguishedName", default="")
        if isinstance(dn, list):
            obj["distinguishedName"] = dn[0] if dn else ""
        # GUID as upper string
        guid = ADUtils.get_entry_property(obj, "objectGUID")
        if isinstance(guid, bytes):
            try:
                obj["objectGUID"] = str(UUID(bytes_le=guid)).upper()
            except Exception:
                pass

    print(f"[INFO] Computers collected: {len(raw_objects)}")
    return raw_objects


def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

import queue


def format_computers(
    computers,
    domain,
    domain_sid,
    adws_conn,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map,
    bh_rpc_context,
    num_workers=100
):
    computers_by_sid = {}
    formatted_computers = []
    domain_upper = domain.upper()
    all_sessions_users = {}

    if not hasattr(bh_rpc_context, "domain_object"):
        class DomainObject:
            def __init__(self, sid):
                self.sid = sid
        bh_rpc_context.domain_object = DomainObject(domain_sid)

    for cache_name in ["sidcache", "samcache", "computersidcache", "dnscache"]:
        if not hasattr(bh_rpc_context, cache_name):
            setattr(bh_rpc_context, cache_name, {})

    enumerator = ComputerEnumerator(
        addomain=bh_rpc_context,
        addc=None,
        collect=["session", "localadmin", "rdp", "dcom", "psremote", "loggedon"],
        do_gc_lookup=True,
        exclude_dcs=False
    )

    jobs = []
    obj_by_hostname = {}

    process_queue = queue.Queue()
    results_q = queue.Queue()

    for obj in computers:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        comp_guid = obj.get("objectGUID")
        if isinstance(comp_guid, bytes):
            comp_guid = str(UUID(bytes_le=comp_guid)).upper()
        elif isinstance(comp_guid, str):
            comp_guid = comp_guid.upper()
        value_to_id_cache[dn.upper()] = comp_guid

        sid_bytes = obj.get("objectSid")
        comp_sid = None
        if isinstance(sid_bytes, bytes):
            comp_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            comp_sid = sid_bytes.upper()
        if not comp_sid:
            continue

        sAM = obj.get("sAMAccountName", "")
        hostname = obj.get("dNSHostName", "") or sAM[:-1].upper()
        entry = {"attributes": obj}
        jobs.append((hostname, sAM, comp_sid, entry, results_q, all_sessions_users))
        obj_by_hostname[hostname.lower()] = obj

    threads = []
    for _ in range(num_workers):
        t = threading.Thread(target=enumerator.work, args=(process_queue, results_q))
        t.daemon = True
        t.start()
        threads.append(t)

    process_queue.join()

    total_jobs = len(jobs)
    for job in jobs:
        process_queue.put(job)

    # Sentinels to allow threads to terminate cleanly
    for _ in range(len(computers)):
        try:
            _, bh_result = results_q.get(timeout=3)
            formatted_computers.append(bh_result)
        except queue.Empty:
            continue

    # Retrieving thread results
    computer_results = {}
    received = 0
    while received < total_jobs:
        try:
            hostname, bh_result = results_q.get(timeout=3)
            computer_results[hostname.lower()] = bh_result
            received += 1
        except queue.Empty:
            print("[!] Timeout or workers stuck.")
            break

    # SID cache resolution (loading from disk cache)
    try:
        with open(cache_file_path, "r", encoding="utf-8") as f:
            _cache_json_loaded = json.load(f)
    except Exception as e:
        _cache_json_loaded = {}

    cache_disk = _cache_json_loaded.get("ValueToIdCache", {})

    def resolve_sid_from_cache(username, value_to_id_cache):
        if not value_to_id_cache:
            return None
        username_variants = set([
            username,
            username.upper(),
            username.lower(),
            username.capitalize(),
        ])
        # Brute search on DN where CN matches the username
        for key in value_to_id_cache:
            if key.upper().startswith(f"CN={username.upper()},"):
                candidate = value_to_id_cache[key]
                if isinstance(candidate, str) and candidate.startswith("S-1-5-"):
                    return candidate
        # Direct search (short mapping)
        for v in username_variants:
            candidate = value_to_id_cache.get(v)
            if isinstance(candidate, str) and candidate.startswith("S-1-5-"):
                return candidate
        return None

    # Building the BloodHound format
    for hostname_lower, obj in obj_by_hostname.items():
        bh_result = computer_results.get(hostname_lower, {})

        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        comp_guid = obj.get("objectGUID")
        if isinstance(comp_guid, bytes):
            comp_guid = str(UUID(bytes_le=comp_guid)).upper()
        elif isinstance(comp_guid, str):
            comp_guid = comp_guid.upper()

        sid_bytes = obj.get("objectSid")
        comp_sid = None
        if isinstance(sid_bytes, bytes):
            comp_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            comp_sid = sid_bytes.upper()

        sAM = obj.get("sAMAccountName", "")
        hostname = obj.get("dNSHostName", "") or sAM[:-1].upper()
        dns_host = obj.get("dNSHostName", "")
        os_name = obj.get("operatingSystem", "")
        admin_count = int(obj.get("adminCount", 0) or 0)
       
        uac = obj.get("userAccountControl", 0)
        try:
            uac = int(uac)
        except Exception:
            uac = 0
        description = obj.get("description", "")
        serviceprincipalnames = obj.get("servicePrincipalName", [])
        delegatehosts_raw = obj.get("msDS-AllowedToDelegateTo", [])
        if not isinstance(delegatehosts_raw, list):
            if delegatehosts_raw:
                delegatehosts_raw = [delegatehosts_raw]
            else:
                delegatehosts_raw = []

        lastlogon = filetime_to_unix(obj.get("lastLogon"))
        lastlogontimestamp = filetime_to_unix(obj.get("lastLogonTimestamp"))
        if lastlogontimestamp == 0 or lastlogontimestamp == -11644473600:
            lastlogontimestamp = -1
        pwdlastset = filetime_to_unix(obj.get("pwdLastSet"))
        whencreated = filetime_to_unix(obj.get("whenCreated"))

        if dns_host:
            value_to_id_cache[dn.upper()] = comp_sid
        if sAM:
            value_to_id_cache[sAM.upper()] = comp_sid
            if not sAM.endswith('$'):
                value_to_id_cache[(sAM + '$').upper()] = comp_sid
            value_to_id_cache[sAM.rstrip('$').upper()] = comp_sid
        if dns_host:
            value_to_id_cache[dns_host.upper()] = comp_sid
            value_to_id_cache[dns_host.split('.')[0].upper()] = comp_sid

        allowed_to_delegate_list = []
        for host_spn in delegatehosts_raw:
            if not host_spn or '/' not in host_spn:
                logging.debug("Invalid delegation SPN ignored: %s", host_spn)
                continue
            target_hostname = host_spn.split('/')[1].split(':')[0].upper()
            target_short = target_hostname.split('.')[0]
            possible_keys = [
                target_hostname,
                target_short,
                target_short + '$'
            ]
            target_sid = None
            for key in possible_keys:
                target_sid = value_to_id_cache.get(key)
                if target_sid:
                    break
            if target_sid:
                target_type = id_to_type_cache.get(target_sid)
                target_type_label = BH_TYPE_LABEL_MAP.get(target_type, "Computer")
                allowed_to_delegate_list.append({
                    "ObjectIdentifier": target_sid,
                    "ObjectType": target_type_label
                })
            else:
                logging.warning("Unable to resolve SID for delegation target '%s' via cache.", target_hostname)

        # --- LAPS v1 and/or v2 detection ---
        laps_signals = [
            "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
            "msLAPS-Password", "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory"
        ]
        has_laps = any(obj.get(attr) not in (None, "", b"") for attr in laps_signals)

        aces_computer, isaclprotected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            comp_sid,
            "Computer",
            object_type_guid_map=objecttype_guid_map
        )
        aces_computer = dedupe_aces(aces_computer)
        for ace in aces_computer:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, domain_sid)

        allowed_to_act_list = []
        act_raw = obj.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if act_raw:
            try:
                act_aces, _ = _parse_aces(
                    act_raw,
                    id_to_type_cache,
                    comp_sid,
                    "Computer",
                    object_type_guid_map=objecttype_guid_map
                )
                act_aces = dedupe_aces(act_aces)
                for a in act_aces:
                    a["PrincipalSID"] = prefix_well_known_sid(a["PrincipalSID"], domain, domain_sid)
                    right = a.get("RightName", "")
                    # Follow BloodHound behavior: ignore Owner; only include meaningful rights (GenericAll is a clear signal)
                    if right == "Owner":
                        continue
                    if right in ("GenericAll", "WriteDacl", "WriteOwner", "AddKeyCredentialLink", "ReadLAPSPassword"):
                        allowed_to_act_list.append({
                            "ObjectIdentifier": a["PrincipalSID"],
                            "ObjectType": a.get("PrincipalType", "User")
                        })
            except Exception as e:
                logging.debug("Failed to parse msDS-AllowedToActOnBehalfOfOtherIdentity for %s: %s", hostname, e)

        props = {
            "name": hostname.upper() if hostname.upper().endswith(domain_upper) else f"{hostname.upper()}.{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "highvalue": False,
            "distinguishedname": dn.upper() if dn else None,
            "enabled": (uac & 2) == 0,
            "unconstraineddelegation": (uac & 0x00080000) == 0x00080000,
            "trustedtoauth": (uac & 0x01000000) == 0x01000000,
            "operatingsystem": os_name if os_name else None,
            "operatingsystemversion": obj.get("operatingSystemVersion"),
            "description": description if description else None,
            "samaccountname": sAM,
            "dnshostname": dns_host,
            "admincount": admin_count == 1,
            "serviceprincipalnames": serviceprincipalnames,
            "hasspn": bool(serviceprincipalnames),
            "whencreated": whencreated,
            "lastlogon": lastlogon,
            "lastlogontimestamp": lastlogontimestamp,
            "pwdlastset": pwdlastset,
            "isaclprotected": isaclprotected,
            "haslaps": has_laps,
            "sidhistory": [LDAP_SID(x).formatCanonical() for x in obj.get("sIDHistory", [])],
            "allowedtodelegate": delegatehosts_raw
        }

        #  LAPS attributes if present
        laps_attrs_to_export = [
            "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime",
            "msLAPS-Password", "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory"
        ]
        for attr in laps_attrs_to_export:
            if obj.get(attr) is not None:
                val = obj[attr]
                if isinstance(val, bytes):
                    import base64
                    val = base64.b64encode(val).decode('ascii')
                props[attr] = val

        key = f"{hostname.lower()}_session_users"
        user_sessions = all_sessions_users.get(key, [])
        sessions_results = []
        for user in user_sessions:
            sessions_results.append({
                "UserSID": user['usersid'],
                "ComputerSID": user['computersid'],
                "SessionType": user['session_type']
            })

        computer_bh_entry = {
            "ObjectIdentifier": comp_sid,
            "AllowedToAct": allowed_to_act_list,
            "PrimaryGroupSID": f"{domain_sid}-{obj.get('primaryGroupID', 515)}",
            "Properties": props,
            "Aces": aces_computer,
            "Sessions": {
                "Collected": bool(sessions_results),
                "FailureReason": None if sessions_results else "No sessions found or collection failed",
                "Results": sessions_results
            },
            "PrivilegedSessions": bh_result.get("PrivilegedSessions", {"Collected": False, "FailureReason": "Not collected", "Results": []}),
            "RegistrySessions": bh_result.get("RegistrySessions", {"Collected": False, "FailureReason": "Not collected", "Results": []}),
            "LocalGroups": bh_result.get("LocalGroups", []),
            "UserRights": [],
            "AllowedToDelegate": allowed_to_delegate_list,
            "HasSIDHistory": [],
            "IsDeleted": False,
            "Status": None,
            "IsACLProtected": isaclprotected,
            "ContainedBy": None,
            "DumpSMSAPassword": []
        }
        computers_by_sid[comp_sid] = computer_bh_entry
        formatted_computers = list(computers_by_sid.values())

    print("\n========== Summary of session users connected on machines ==========")
    for k in sorted(all_sessions_users.keys()):
        print(f"{k} = {all_sessions_users[k]}")
    print("====================================================")

    return {
        "data": formatted_computers,
        "meta": {
            "methods": 0,
            "type": "computers",
            "count": len(formatted_computers),
            "version": 6
        }
    }
