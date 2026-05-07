from uuid import UUID
import logging
from impacket.ldap.ldaptypes import LDAP_SID
from ...ad.cache_gen import pull_all_ad_objects, _parse_aces, dedupe_aces, filetime_to_unix, adws_objecttype_guid_map
from ...ad.adws import WELL_KNOWN_SIDS
from ...lib.utils import ADUtils



def collect_users(
    ip=None,
    domain=None,
    username=None,
    auth=None,
    base_dn_override=None,
    adws_object_classes=None,
    adws_objecttype_guid_map=None,
    include_properties=True,
    acl=True
):
    """
    Collect all user objects (regular, GMSA, SMSA) in a granular way, like BloodHound.py.
    `adws_object_classes` must be the list of objectClass from the schema.
    `adws_objecttype_guid_map` must be the mapping of attributes in the schema (lDAPDisplayName: GUID).
    """
    # BH base properties
    properties = [
        "sAMAccountName", "distinguishedName", "sAMAccountType",
        "objectSid", "primaryGroupID", "isDeleted", "objectClass"
    ]
    # msDS-GroupMSAMembership if attribute is present (mapping of attributes, not classes)
    if adws_objecttype_guid_map and "msds-groupmsamembership".lower() in adws_objecttype_guid_map:
        properties.append("msDS-GroupMSAMembership")
    # Additional properties if requested
    if include_properties:
        properties += [
            "servicePrincipalName", "userAccountControl", "displayName",
            "lastLogon", "lastLogonTimestamp", "pwdLastSet", "mail", "title", "homeDirectory",
            "description", "userPassword", "adminCount", "msDS-AllowedToDelegateTo", "sIDHistory",
            "whencreated", "unicodepwd", "scriptpath"
        ]
        if adws_objecttype_guid_map and "unixuserpassword" in adws_objecttype_guid_map:
            properties.append("unixuserpassword")
    if acl:
        properties.append("nTSecurityDescriptor")

    # Build objectClass filters exactly like BH
    # GMSA
    if adws_object_classes and "msDS-GroupManagedServiceAccount" in adws_object_classes:
        gmsa_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
    else:
        logging.debug("No support for GMSA, skipping in query")
        gmsa_filter = ""
    # SMSA
    if adws_object_classes and "msDS-ManagedServiceAccount" in adws_object_classes:
        smsa_filter = "(objectClass=msDS-ManagedServiceAccount)"
    else:
        logging.debug("No support for SMSA, skipping in query")
        smsa_filter = ""

    # Combine all user object types in a single query (exactly like BloodHound.py)
    if gmsa_filter or smsa_filter:
        query = f"(|(&(objectCategory=person)(objectClass=user)){gmsa_filter}{smsa_filter})"
    else:
        query = "(&(objectCategory=person)(objectClass=user))"

    # Retrieve the objects
    users = pull_all_ad_objects(
        ip=ip,
        domain=domain,
        username=username,
        auth=auth,
        query=query,
        attributes=properties,
        base_dn_override=base_dn_override
    ).get("objects", [])

    # Normalization as in BloodHound.py
    for obj in users:
        # objectClass always a list
        oc = ADUtils.get_entry_property(obj, "objectClass", default=[])
        if isinstance(oc, str):
            obj["objectClass"] = [oc]
        elif oc is None:
            obj["objectClass"] = []
        # DN always a string
        dn = ADUtils.get_entry_property(obj, "distinguishedName", default="")
        if isinstance(dn, list):
            obj["distinguishedName"] = dn[0] if dn else ""
        # GUID as string
        guid = ADUtils.get_entry_property(obj, "objectGUID")
        if isinstance(guid, bytes):
            try:
                obj["objectGUID"] = str(UUID(bytes_le=guid)).upper()
            except Exception:
                pass

    print(f"[INFO] Users collected : {len(users)}")
    return users


def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def append_bh_default_users(formatted_users, domain_name, domain_sid):
   
    
    formatted_users.append({
        "AllowedToDelegate": [],
        "ObjectIdentifier": f"{domain_name.upper()}-S-1-5-20",
        "PrimaryGroupSID": None,
        "ContainedBy": None,
        "Properties": {
            "domain": domain_name.upper(),
            "domainsid": domain_sid,
            "name": f"NT AUTHORITY@{domain_name.upper()}",
        },
        "Aces": [],
        "SPNTargets": [],
        "HasSIDHistory": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    })
    return formatted_users

def ensure_string(val):
    if val is None:
        return None
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8')
        except Exception:
            return None
    return str(val)

def format_users(
    users,
    domain,
    domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    formatted_users = []
    domain_upper = domain.upper()

    for obj in users:
        # Prepare the IDs
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        user_guid = obj.get("objectGUID")
        if isinstance(user_guid, bytes):
            user_guid = str(UUID(bytes_le=user_guid)).upper()
        elif isinstance(user_guid, str):
            user_guid = user_guid.upper()
        value_to_id_cache[dn.upper()] = user_guid

        sid_bytes = obj.get("objectSid")
        user_sid = None
        if isinstance(sid_bytes, bytes):
            user_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            user_sid = sid_bytes.upper()

        # Numeric properties and conversions
        def _get(obj, key):
            v = obj.get(key)
            if isinstance(v, list):
                v = v[0] if v else None
            return v

        user_account_control = int(_get(obj, "userAccountControl") or 0)
        admin_count = int(_get(obj, "adminCount") or 0)
        sAM = _get(obj, "sAMAccountName") or ""
        description = _get(obj, "description")
        displayname = _get(obj, "displayName")
        email = _get(obj, "mail")
        title = _get(obj, "title")
        homedirectory = _get(obj, "homeDirectory")
        logonscript = _get(obj, "logonScript")
        userpassword = _get(obj, "userPassword")
        unicodepassword = _get(obj, "unicodePwd")
        unixpassword = _get(obj, "unixUserPassword")
        sfupassword = _get(obj, "sFUPassword")
        sidhistory = obj.get("sIDHistory", [])
        if not isinstance(sidhistory, list): sidhistory = []
        serviceprincipalnames = obj.get("servicePrincipalName", [])
        if not isinstance(serviceprincipalnames, list): serviceprincipalnames = []
        isaclprotected = False  # Default value, updated if ACL is processed

        # ACEs on the user
        aces_user, isaclprotected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            user_sid,
            "User", object_type_guid_map=objecttype_guid_map
        )

        # gMSA: parse the msDS-GroupMSAMembership SD to expose ReadGMSAPassword
        # edges in BloodHound. This attribute holds a security descriptor whose
        # DACL controls who is allowed to retrieve the gMSA's managed password.
        # bloodhound.py does the equivalent in parse_gmsa() (memberships.py:720).
        # Without this, every gMSA in the graph is missing its ReadGMSAPassword
        # edges, breaking gMSA compromise paths.
        gmsa_sd = obj.get("msDS-GroupMSAMembership")
        if gmsa_sd:
            gmsa_aces, _ = _parse_aces(
                gmsa_sd,
                id_to_type_cache,
                user_sid,
                "User", object_type_guid_map=objecttype_guid_map,
            )
            for ace in gmsa_aces:
                # Owner relations on the gMSA SD are not meaningful here
                if ace.get("RightName") == "Owner":
                    continue
                ace["RightName"] = "ReadGMSAPassword"
                aces_user.append(ace)

        aces_user = dedupe_aces(aces_user)
        for ace in aces_user:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, domain_sid)

        # FILETIME -> Unix
        lastlogon = filetime_to_unix(obj.get("lastLogon"))
        lastlogontimestamp = filetime_to_unix(obj.get("lastLogonTimestamp"))
        if lastlogontimestamp == 0:
            lastlogontimestamp = -11644473600
        pwdlastset = filetime_to_unix(obj.get("pwdLastSet"))
        whencreated = filetime_to_unix(obj.get("whenCreated"))

        # Order and property names **exactly like BH**
        props = {
            "name": f"{sAM.upper()}@{domain_upper}",
            "domain": domain_upper,
            "domainsid": domain_sid,
            "highvalue": admin_count == 1,  
            "distinguishedname": dn.upper() if dn else None,
            "unconstraineddelegation": (user_account_control & 0x00080000) == 0x00080000,
            "trustedtoauth": (user_account_control & 0x01000000) == 0x01000000,
            "passwordnotreqd": (user_account_control & 0x00000020) == 0x00000020,
            "enabled": (user_account_control & 2) == 0,
            "lastlogon": lastlogon,
            "lastlogontimestamp": lastlogontimestamp,
            "pwdlastset": pwdlastset,
            "dontreqpreauth": (user_account_control & 0x00400000) == 0x00400000,
            "pwdneverexpires": (user_account_control & 0x00010000) == 0x00010000,
            "sensitive": (user_account_control & 0x00100000) == 0x00100000,
            "serviceprincipalnames": serviceprincipalnames,
            "hasspn": bool(serviceprincipalnames),
            "displayname": displayname if displayname else None,
            "email": email if email else None,
            "title": title if title else None,
            "homedirectory": homedirectory if homedirectory else None,
            "description": description if description else None,
            "userpassword": userpassword if userpassword else None,
            "admincount": admin_count == 1,
            "sidhistory": sidhistory,
            "whencreated": whencreated,
            "unixpassword": unixpassword if unixpassword else None,
            "unicodepassword": unicodepassword if unicodepassword else None,
            "logonscript": logonscript if logonscript else None,
            "samaccountname": sAM,
            "sfupassword": sfupassword if sfupassword else None,
            "isaclprotected": isaclprotected,
        }

        # PRIMARY GROUP
        primary_group = obj.get("primaryGroupID")
        if isinstance(primary_group, list):
            primary_group = primary_group[0] if primary_group else None
        if primary_group:
            primary_sid = f"{domain_sid}-{primary_group}"
        else:
            primary_sid = None

        user_bh_entry = {
            "AllowedToDelegate": [],        # Can be completed like in BH if needed
            "ObjectIdentifier": user_sid,
            "PrimaryGroupSID": primary_sid,
            "ContainedBy": None,
            "Properties": props,
            "Aces": aces_user,
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": False,
            "IsACLProtected": isaclprotected,
        }
        formatted_users.append(user_bh_entry)

    formatted_users = append_bh_default_users(formatted_users, domain, domain_sid)

    return {
        "data": formatted_users,
        "meta": {
            "type": "users",
            "count": len(formatted_users),
            "version": 6
        }
    }



