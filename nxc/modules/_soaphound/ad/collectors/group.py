from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from ...ad.cache_gen import pull_all_ad_objects, filetime_to_unix, _parse_aces, dedupe_aces,BH_TYPE_LABEL_MAP, adws_objecttype_guid_map
from ...ad.adws import WELL_KNOWN_SIDS
import json
import unicodedata

def collect_groups(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
    """
    Collect all AD groups from the directory or from a cache.
    No filtering on objectClass or other attributes.
    """
    import json
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
        # No filtering: take all objects with a DN (to avoid None)
        groups = [
            o for o in objs
            if o.get("distinguishedName") and isinstance(o.get("distinguishedName"), str)
        ]
        return groups
    else:
        attributes = [
            "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
            "nTSecurityDescriptor", "whenCreated", "description", "sAMAccountName", "adminCount", "member"
        ]
        query = "(objectCategory=group)"
        raw_objects = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        # No filtering: take all objects with a DN (to avoid None)
        groups = [
            o for o in raw_objects
            if o.get("distinguishedName") and isinstance(o.get("distinguishedName"), str)
        ]
        print(f"[INFO] Groups collected : {len(groups)}")
        return groups

def is_real_group(obj):
    # Simple basic check, just like BloodHound
    object_class = obj.get("objectClass", [])
    if isinstance(object_class, list):
        return "group" in [x.lower() for x in object_class]
    return "group" in object_class.lower()

def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def is_highvalue(sid):
    # Like BloodHound: Domain Admins, Enterprise Admins, Schema Admins, and a few well-known groups
    if sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519"):
        return True
    return sid in [
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-551",  # Backup Operators
        "S-1-5-32-548",  # Account Operators
    ]




def format_wellknown_groups(domain, domain_sid, domain_controllers=None):
    """Build the four well-known security principal groups that BloodHound
    expects as nodes in _groups.json.

    These SIDs are not real AD objects, but BloodHound needs them as nodes
    so that ACEs referencing them as a principal can be resolved in the
    graph. Without these, edges pointing to S-1-5-9 (Enterprise DCs),
    S-1-5-11 (Authenticated Users), S-1-1-0 (Everyone), or S-1-5-4
    (Interactive) become orphan and break compromise paths - notably the
    DCSync path (Enterprise DCs has GetChanges/GetChangesAll on the domain
    object).

    Aligned on bloodhound.py memberships.py:799-841.

    Args:
        domain: the domain name (e.g. "corp.lab"), case-insensitive.
        domain_sid: the domain SID (e.g. "S-1-5-21-...").
        domain_controllers: optional list of DC entries to populate the
            Enterprise DCs Members list. Each entry should be a dict with
            "ObjectIdentifier" and "ObjectType" keys. If None or empty,
            Enterprise DCs is created with empty Members.

    Returns:
        list[dict]: the four BloodHound-formatted group nodes.
    """
    domain_upper = domain.upper()
    groups = []

    # Enterprise Domain Controllers (S-1-5-9)
    # In bloodhound.py this is keyed on the root domain. For ADWS-only
    # collection we use the current domain as a best-effort proxy.
    edc_members = []
    if domain_controllers:
        for dc in domain_controllers:
            edc_members.append({
                "ObjectIdentifier": dc.get("ObjectIdentifier"),
                "ObjectType": dc.get("ObjectType", "Computer"),
            })
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": "%s-S-1-5-9" % domain_upper,
        "Properties": {
            "domain": domain_upper,
            "domainsid": domain_sid,
            "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % domain_upper,
        },
        "Members": edc_members,
        "Aces": [],
    })

    # Everyone (S-1-1-0)
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": "%s-S-1-1-0" % domain_upper,
        "Properties": {
            "domain": domain_upper,
            "domainsid": domain_sid,
            "name": "EVERYONE@%s" % domain_upper,
        },
        "Members": [],
        "Aces": [],
    })

    # Authenticated Users (S-1-5-11)
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": "%s-S-1-5-11" % domain_upper,
        "Properties": {
            "domain": domain_upper,
            "domainsid": domain_sid,
            "name": "AUTHENTICATED USERS@%s" % domain_upper,
        },
        "Members": [],
        "Aces": [],
    })

    # Interactive (S-1-5-4)
    groups.append({
        "IsDeleted": False,
        "IsACLProtected": False,
        "ObjectIdentifier": "%s-S-1-5-4" % domain_upper,
        "Properties": {
            "domain": domain_upper,
            "domainsid": domain_sid,
            "name": "INTERACTIVE@%s" % domain_upper,
        },
        "Members": [],
        "Aces": [],
    })

    return groups

def normalize_dn(dn):
    """Uniformise la casse, les espaces et les variantes unicode pour les DN."""
    if not isinstance(dn, str):
        dn = str(dn)
    return unicodedata.normalize('NFKC', dn).strip().upper()


def load_cache(cache_path):
    with open(cache_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    keys = set([normalize_dn(str(k)) for k in data.keys()])
    values = set([normalize_dn(str(v)) for v in data.values() if isinstance(v, str)])
    return data, keys, values


def format_groups(
    raw_groups, domain, main_domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map,
    debug=False  # Parameter no longer used, kept for backward compatibility
):
    formatted_groups = []
    domain_upper = domain.upper()
    value_to_id_cache = {normalize_dn(k): v for k, v in value_to_id_cache.items()}
    #cache_data, cache_keys, cache_values = load_cache("output/Cache.json")

    for obj in raw_groups:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        group_dn_norm = normalize_dn(dn)

        guid_bytes = obj.get("objectGUID")
        group_guid = str(UUID(bytes_le=guid_bytes)).upper() if isinstance(guid_bytes, bytes) else str(guid_bytes).upper()
        value_to_id_cache[group_dn_norm] = group_guid

        sid_bytes = obj.get("objectSid")
        if isinstance(sid_bytes, bytes):
            group_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            group_sid = sid_bytes.upper()
        else:
            group_sid = ""
        group_sid = prefix_well_known_sid(group_sid, domain, main_domain_sid)

        aces, is_acl_protected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            group_sid,
            "Group",
            object_type_guid_map=objecttype_guid_map,
        )
        aces = dedupe_aces(aces)
        for ace in aces:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, main_domain_sid)

        members = []
        raw_members = obj.get("member", [])
        if isinstance(raw_members, str):
            raw_members = [raw_members]

        for m_dn in raw_members:
            if not m_dn:
                continue

            m_dn_norm = normalize_dn(m_dn)
            m_id = None
            m_type = None

            sid = None
            if m_dn_norm.startswith("CN=S-1-5-") and "FOREIGNSECURITYPRINCIPALS" in m_dn_norm:
                sid = m_dn_norm.split(',')[0][3:]

            if m_dn.upper().startswith("S-1-5-"):
                m_id = value_to_id_cache.get(m_dn.upper())
                m_type = id_to_type_cache.get(m_id)
            if not m_id and sid:
                m_id = value_to_id_cache.get(sid)
                m_type = id_to_type_cache.get(m_id)
            if not m_id:
                m_id = value_to_id_cache.get(m_dn_norm)
                m_type = id_to_type_cache.get(m_id)

            if m_id and m_type is not None:
                if m_type == 0:
                    m_type_label = "User"
                else:
                    m_type_label = BH_TYPE_LABEL_MAP.get(m_type, "Unknown")
                members.append({
                    "ObjectIdentifier": m_id,
                    "ObjectType": m_type_label
                })

                
        name = obj.get("name", "")
        if isinstance(name, list):
            name = name[0] if name else ""
        description = obj.get("description", "")
        if isinstance(description, list):
            description = description[0] if description else ""
        samaccountname = obj.get("sAMAccountName", "")
        if isinstance(samaccountname, list):
            samaccountname = samaccountname[0] if samaccountname else ""

        props = {
            "domain": domain_upper,
            "domainsid": main_domain_sid,
            "highvalue": is_highvalue(group_sid),
            "name": f"{name.upper()}@{domain_upper}",
            "distinguishedname": group_dn_norm,
            "samaccountname": samaccountname,
            "admincount": obj.get("adminCount", 0) == 1,
            "description": description,
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
        }

        group_bh_entry = {
            "ObjectIdentifier": group_sid,
            "Properties": props,
            "ContainedBy": None,
            "Members": members,
            "Aces": aces,
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected,
        }
        formatted_groups.append(group_bh_entry)

    # Inject the four well-known security principal groups so that ACEs
    # referencing them as a principal can be resolved as graph nodes in
    # BloodHound. Without these the DCSync path (Enterprise DCs has
    # GetChanges/GetChangesAll on the domain object) is broken, and many
    # default ACEs become orphan edges.
    # Aligned on bloodhound.py memberships.py:799-841.
    formatted_groups.extend(format_wellknown_groups(domain, main_domain_sid))

    return {
        "data": formatted_groups,
        "meta": {
            "type": "groups",
            "count": len(formatted_groups),
            "version": 6
        }
    }
