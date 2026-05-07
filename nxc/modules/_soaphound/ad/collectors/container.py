from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from ...lib.utils import ADUtils
from ...ad.cache_gen import filetime_to_unix, _parse_aces, pull_all_ad_objects, BH_TYPE_LABEL_MAP, dedupe_aces, adws_objecttype_guid_map
import re
import unicodedata
import json
import os

def is_bloodhound_filtered_container(dn):
    """BloodHound filter: exclude technical and GPO User/Machine containers."""
    dn_upper = dn.upper()
    if "CN=DOMAINUPDATES,CN=SYSTEM," in dn_upper:
        return True
    if "CN=POLICIES,CN=SYSTEM," in dn_upper and (dn_upper.startswith('CN=USER') or dn_upper.startswith('CN=MACHINE')):
        return True
    return False

def is_bloodhound_filtered_container_child(dn):
    """BloodHound child filter: exclude objects under Program Data or System."""
    dn_upper = dn.upper()
    if "CN=PROGRAM DATA," in dn_upper:
        return True
    if "CN=SYSTEM," in dn_upper:
        return True
    return False

def is_bloodhound_exported_container(obj):
    """
    Strict BloodHound-style: keep only containers that pass the exclusion filter.
    """
    name = obj.get("name", "")
    if isinstance(name, list):
        name = name[0] if name else ""
    dn = obj.get("distinguishedName", "")
    dn_upper = dn.upper()

    # Exclude containers per BloodHound.py logic
    if is_bloodhound_filtered_container(dn):
        return False

    # Exclude pure GUID containers (typical for technical subcontainers)
    if isinstance(name, str) and re.fullmatch(r"[A-F0-9\-]{36}", name):
        return False

    # Otherwise, keep all
    return True

def filter_bloodhound_container_aces(aces):
    """
    Filter ACEs to keep only those exported by BloodHound.py for containers.
    Default excludes AddKeyCredentialLink, AllExtendedRights, GenericWrite.
    Keeps: Owns, WriteDacl, WriteOwner, GenericAll, basic inherited rights.
    """
    excluded_rights = {
        "addkeycredentiallink", "allextendedrights", "genericwrite"
    }
    filtered = []
    for ace in aces:
        right = ace.get("RightName", "").lower()
        if right in excluded_rights:
            continue
        filtered.append(ace)
    return filtered

def _is_guid_str(s):
    return isinstance(s, str) and re.fullmatch(r"[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}", s, re.I)

def get_child_objects(container_dn_upper, value_to_id_cache, id_to_type_cache, BH_TYPE_LABEL_MAP):
    """
    Find direct children of a container/OU/domain per cache_gen logic.
    Does NOT include objects filtered by BloodHound.
    """
    if isinstance(value_to_id_cache, str) and os.path.isfile(value_to_id_cache):
        with open(value_to_id_cache, "r", encoding="utf-8") as f:
            value_to_id_cache = json.load(f)
    children = []
    for item_dn_child_upper, item_child_id in value_to_id_cache.items():
        # Direct child criterion
        if item_dn_child_upper != container_dn_upper and item_dn_child_upper.endswith("," + container_dn_upper):
            if item_dn_child_upper.count(',') == container_dn_upper.count(',') + 1:
                # BloodHound child filter (avoid technical subcontainers)
                if is_bloodhound_filtered_container_child(item_dn_child_upper):
                    continue
                child_type_numeric = id_to_type_cache.get(item_child_id)
                child_type_label = BH_TYPE_LABEL_MAP.get(child_type_numeric, "Container").capitalize()
                children.append({
                    "ObjectIdentifier": item_child_id,
                    "ObjectType": child_type_label,
                })
    return children

def collect_containers(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
    """
    If cache_file is provided, load containers from this cache without live ADWS collection.
    Otherwise, collect live via ADWS.
    """
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
        containers = [
            c for c in objs
            if c.get("distinguishedName") and isinstance(c.get("distinguishedName"), str)
            and is_bloodhound_exported_container(c)
        ]
        print(f"[INFO] Containers collected : {len(containers)}")
        return containers
    else:
        attributes = [
            "distinguishedName",
            "name",
            "objectGUID",
            "isCriticalSystemObject",
            "objectClass",
            "objectCategory",
            "description",
            "whenCreated",
            "nTSecurityDescriptor",
        ]
        # BloodHound.py uses this wide query!
        query = "(&(objectCategory=container)(objectClass=container))"

        containers = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        containers = [
            c for c in containers
            if c.get("distinguishedName") and isinstance(c.get("distinguishedName"), str)
            and is_bloodhound_exported_container(c)
        ]
        print(f"[INFO] Containers collected : {len(containers)}")
        return containers

def format_containers(
    raw_containers,
    domain,
    main_domain_root_dn,
    id_to_type_cache,
    value_to_id_cache,
    all_collected_items,
    objecttype_guid_map
):
    from uuid import UUID
    import unicodedata
    from impacket.ldap.ldaptypes import LDAP_SID

    main_domain_sid = ADUtils.find_main_domain_sid(all_collected_items, main_domain_root_dn)

    formatted_containers = []
    for obj in raw_containers:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        container_dn_upper = unicodedata.normalize('NFKC', dn).upper()

        guid_bytes = obj.get("objectGUID")
        # Normalize the GUID: bytes -> canonical UUID string, otherwise string -> uppercase canonical
        if isinstance(guid_bytes, bytes):
            object_guid_str = str(UUID(bytes_le=guid_bytes)).upper()
        else:
            object_guid_str = str(guid_bytes).upper() if guid_bytes else None

        aces, is_acl_protected = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            object_guid_str,
            "Container",
            object_type_guid_map=objecttype_guid_map
        )

        # Normalize PrincipalSIDs:
        def _normalize_principal_sid(sid):
            if not sid:
                return sid
            s_val = str(sid)
            # If already prefixed like "DOMAIN-S-1-..." keep as uppercase
            if re.match(r'^[A-Z0-9\.\-_]+-S-1-', s_val, re.I):
                return s_val.upper()
            su = s_val.upper()
            # If it's a well-known SID, prefix with domain (to match BloodHound output)
            if su in ADUtils.WELLKNOWN_SIDS:
                return f"{domain.upper()}-{su}"
            # Otherwise return uppercase canonical SID
            return su

        for a in aces:
            if "PrincipalSID" in a and a["PrincipalSID"]:
                a["PrincipalSID"] = _normalize_principal_sid(a["PrincipalSID"])

        # Uncomment to filter ACEs like BloodHound
        # aces = filter_bloodhound_container_aces(aces)
        # aces = dedupe_aces(aces)
        
        name = obj.get("name", "")
        if isinstance(name, list):
            name = name[0] if name else ""
        description = obj.get("description", "")
        if isinstance(description, list):
            description = description[0] if description else ""

        # domainsid: use object, else main domain SID (always filled!)
        domainsid = obj.get("domainsid") or obj.get("domainSid") or main_domain_sid or ""

        highvalue = obj.get("highvalue", False)

        props = {
            "domain": domain.upper(),
            "name": f"{name.upper()}@{domain.upper()}",
            "distinguishedname": container_dn_upper,
            "domainsid": domainsid,
            "highvalue": highvalue,
            "description": description,
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
            "isaclprotected": is_acl_protected,
        }

        container_bh_entry = {
            "ObjectIdentifier": object_guid_str,
            "Properties": props,
            "Aces": aces,
            "ChildObjects": get_child_objects(container_dn_upper, value_to_id_cache, id_to_type_cache, BH_TYPE_LABEL_MAP),
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected,
        }
        formatted_containers.append(container_bh_entry)

    # Final deduplication: merge entries having the same canonical ObjectIdentifier (upper)
    seen = set()
    final_list = []
    for c in formatted_containers:
        oid = c.get("ObjectIdentifier")
        key = oid.upper() if isinstance(oid, str) else None
        if key:
            if key in seen:
                # simple merge possible here (if needed), but avoid adding duplicate entries
                continue
            seen.add(key)
        final_list.append(c)

    return {
        "data": final_list,
        "meta": {
            "type": "containers",
            "count": len(final_list),
            "version": 6
        }
    }
