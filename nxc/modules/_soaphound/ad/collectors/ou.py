from uuid import UUID
import unicodedata
from impacket.ldap.ldaptypes import LDAP_SID
from ...ad.cache_gen import pull_all_ad_objects, filetime_to_unix, _parse_aces, dedupe_aces,adws_objecttype_guid_map
from .container import get_child_objects, BH_TYPE_LABEL_MAP
from ...ad.adws import WELL_KNOWN_SIDS
import json
import os

def collect_ous(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
    """
    Collect Organizational Units (OUs) from AD (live or via cache).
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
        result = [o for o in objs if o.get("distinguishedName")]
        print(f"[INFO] OUs collected : {len(result)}") 
        return result           
        #return [o for o in objs if o.get("distinguishedName")]
    else:
        attributes = [
            "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
            "nTSecurityDescriptor", "whenCreated", "description", "gPLink"
        ]
        query = "(objectCategory=organizationalUnit)"
        ous = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        result = [o for o in ous if o.get("distinguishedName")]
        print(f"[INFO] OUs collected : {len(result)}")
        return result
        #print(f"[DEBUG] OUs collected : {len(ous)}")
        
        #if ous:
        #    print("[DEBUG] Premier DN:", ous[0].get("distinguishedName"))
        #return [o for o in ous if o.get("distinguishedName")]

def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def format_ous(
    raw_ous,
    domain,
    main_domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    formatted_ous = []
    domain_upper = domain.upper()
    for obj in raw_ous:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        ou_dn_upper = unicodedata.normalize('NFKC', dn).upper()
        guid_bytes = obj.get("objectGUID")
        ou_guid = str(UUID(bytes_le=guid_bytes)).upper() if isinstance(guid_bytes, bytes) else str(guid_bytes).upper()
        value_to_id_cache[ou_dn_upper] = ou_guid

        # ACEs sur l'OU
        aces_ou, is_acl_protected_ou = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            ou_guid,
            object_type_label_for_ace="organizational-unit", object_type_guid_map=objecttype_guid_map
        )
        aces_ou = dedupe_aces(aces_ou)
        for ace in aces_ou:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, main_domain_sid)

        # GPO Links (gPLink)
        raw_gplinks = obj.get("gPLink", [])
        gplink_values = raw_gplinks if isinstance(raw_gplinks, list) else ([raw_gplinks] if raw_gplinks else [])
        ou_gplinks = []
        for gplink_str in gplink_values:
            if not gplink_str or not isinstance(gplink_str, str):
                continue
            try:
                link_part, options_part = gplink_str.split(';', 1)
                if not link_part.lower().startswith("[ldap://"):
                    continue
                link_dn = link_part[len("[ldap://"):].strip("]")
                link_options = int(options_part.strip('[]'))
                gpo_id = value_to_id_cache.get(link_dn.upper())
                if gpo_id:
                    ou_gplinks.append({"IsEnforced": bool(link_options & 0x1), "GUID": gpo_id.upper()})
            except Exception as e:
                pass

        name = obj.get("name", "")
        if isinstance(name, list):
            name = name[0] if name else ""
        description = obj.get("description", "")
        if isinstance(description, list):
            description = description[0] if description else ""

        props = {
            "domain": domain_upper,
            "name": f"{name.upper()}@{domain_upper}",
            "distinguishedname": ou_dn_upper,
            "domainsid": main_domain_sid,
            "highvalue": False,
            "description": description,
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
            "isaclprotected": is_acl_protected_ou,
        }

        ou_bh_entry = {
            "ObjectIdentifier": ou_guid,
            "Properties": props,
            "Aces": aces_ou,
            "Links": ou_gplinks,
            "ChildObjects": get_child_objects(ou_dn_upper, value_to_id_cache, id_to_type_cache, BH_TYPE_LABEL_MAP),
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected_ou,
        }
        formatted_ous.append(ou_bh_entry)
    return {
        "data": formatted_ous,
        "meta": {
            "type": "ous",
            "count": len(formatted_ous),
            "version": 6
        }
    }
