from uuid import UUID
import unicodedata
from impacket.ldap.ldaptypes import LDAP_SID
from ...ad.cache_gen import pull_all_ad_objects, filetime_to_unix, _parse_aces, adws_objecttype_guid_map
from ...ad.adws import WELL_KNOWN_SIDS
from ...lib.utils import ADUtils
import json
import os

BH_VALID_RIGHTS = {"Owns", "GenericWrite", "WriteOwner", "WriteDacl", "AllExtendedRights"}

def collect_gpos(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None):
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
        gpos = [g for g in objs if g.get("distinguishedName") and isinstance(g.get("distinguishedName"), str)]
        return gpos
    else:
        attributes = [
            "name", "displayName", "objectGUID", "nTSecurityDescriptor",
            "distinguishedName", "gPCFileSysPath", "versionNumber", "flags",
            "gPCFunctionalityVersion", "whenCreated", "description"
        ]
        query = "(objectClass=groupPolicyContainer)"
        gpos = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        result = [g for g in gpos if g.get("distinguishedName") and isinstance(g.get("distinguishedName"), str)]
        print(f"[INFO] GPOs collected : {len(result)}")
        return result
        #return [g for g in gpos if g.get("distinguishedName") and isinstance(g.get("distinguishedName"), str)]

def prefix_well_known_sid(sid: str, domain_name: str, domain_sid: str, well_known_sids=WELL_KNOWN_SIDS):
    sid = sid.upper()
    domain_sid = domain_sid.upper()
    if sid.startswith(domain_sid + "-") or sid == domain_sid:
        return sid
    if sid in well_known_sids or sid.startswith("S-1-5-32-"):
        return f"{domain_name.upper()}-{sid}"
    return sid

def filter_bloodhound_gpo_aces(aces):
    return [
            {
        "RightName": ace["RightName"],
        "IsInherited": ace["IsInherited"],
        "PrincipalSID": ace["PrincipalSID"],
        "PrincipalType": ace["PrincipalType"]
    }
        for ace in aces
        if not ace.get("IsInherited", False) and ace.get("RightName") in BH_VALID_RIGHTS
    ]

def format_gpos(
    raw_gpos,
    domain,
    main_domain_sid,
    id_to_type_cache,
    value_to_id_cache,
    objecttype_guid_map
):
    formatted_gpos = []
    domain_upper = domain.upper()
    for obj in raw_gpos:
        dn = obj.get("distinguishedName", "")
        if isinstance(dn, list):
            dn = dn[0] if dn else ""
        gpo_dn_upper = unicodedata.normalize('NFKC', dn).upper()
        guid_bytes = obj.get("objectGUID")
        gpo_guid = str(UUID(bytes_le=guid_bytes)).upper() if isinstance(guid_bytes, bytes) else str(guid_bytes).upper()
        value_to_id_cache[gpo_dn_upper] = gpo_guid

        # ACEs on GPO
        aces_gpo, is_acl_protected_gpo = _parse_aces(
            obj.get("nTSecurityDescriptor"),
            id_to_type_cache,
            gpo_guid,
            "GPO", object_type_guid_map=objecttype_guid_map
        )
        # Prefix SIDs

        for ace in aces_gpo:
            ace["PrincipalSID"] = prefix_well_known_sid(ace["PrincipalSID"], domain, main_domain_sid)
        # Filtrer comme BloodHound.py
        #aces_gpo = filter_bloodhound_gpo_aces(aces_gpo)

        # Name: displayName ou name, format BloodHound
        name = obj.get("displayName") or obj.get("name") or ""
        if isinstance(name, list):
            name = name[0] if name else ""
        name = f"{name.upper()}@{domain_upper}"

        # gpcpath (UNC, casing)
        gpcfilesyspath = obj.get("gPCFileSysPath", "") or ""
        gpcpath = gpcfilesyspath
        if gpcpath:
            gpcpath = gpcpath.replace("sysvol", "SYSVOL").replace("policies", "POLICIES")
            if gpcpath.startswith("\\\\"):
                left, right = gpcpath[2:].split("\\", 1)
                left = domain_upper
                gpcpath = f"\\\\{left}\\{right}"

        description = obj.get("description", None)
        
        gplink = obj.get("gPLink", "")
        gpo_links = []
        if gplink:
            for dn, option in ADUtils.parse_gplink_string(gplink):
                # option == 2 => enforced ; == 0 => non-enforced
                gpo_links.append({
                    "dn": dn,
                    "option": option,
                    "is_enforced": option == 2
                })        
                
     #   print("[DEBUG GPO LOOP] domain (avant upper) =", repr(domain))
      #  print("[DEBUG GPO LOOP] domain_upper =", repr(domain.upper()))
        props = {
            "domain": domain.upper(),
            "name": name,
            "distinguishedname": gpo_dn_upper,
            "domainsid": main_domain_sid,
            "highvalue": False,
            "gpcpath": gpcpath or None,
            "description": description,
            "whencreated": filetime_to_unix(obj.get("whenCreated")),
            "isaclprotected": is_acl_protected_gpo,
        }

       
        
        gpo_bh_entry = {
            "ObjectIdentifier": gpo_guid,
            "Properties": props,
            "Aces": aces_gpo,
            "IsDeleted": False,
            "IsACLProtected": is_acl_protected_gpo
        }
        formatted_gpos.append(gpo_bh_entry)
    return {
        "data": formatted_gpos,
        "meta": {
            "methods": 0,
            "type": "gpos",
            "count": len(formatted_gpos),
            "version": 6
        }
    }
