import base64, os, json
import re
from datetime import datetime, timezone
import logging
import unicodedata
from uuid import UUID
from ..ad.adws import ADWSConnect, NTLMAuth, KerberosAuth, ADWSAuthType
from ..ad.soap_templates import NAMESPACES
from base64 import b64decode, b64encode
from impacket.ldap.ldaptypes import LDAP_SID

from ..ad.acls import parse_binary_acl

SOAPHOUND_LDAP_PROPERTIES = sorted(list(set([
    "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID",
    "primaryGroupID", "distinguishedName", "lastLogonTimestamp", "pwdLastSet",
    "servicePrincipalName", "description", "operatingSystem", "sIDHistory",
    "nTSecurityDescriptor", "userAccountControl", "whenCreated", "lastLogon",
    "displayName", "title", "homeDirectory",
    "scriptPath", "adminCount", "member", "memberOf", "msDS-Behavior-Version",
    "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "gPCFileSysPath", "gPLink", "gPOptions", "objectClass",
    "trustAttributes", "trustDirection", "trustPartner", "flatName", "securityIdentifier",
    "instanceType", "whenChanged", "uSNChanged", "mail",
])))

SOAPHOUND_CACHE_PROPERTIES = ["distinguishedName", "objectSid", "ObjectGuid", "ObjectClass"]

SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT = {
    "user": 0, "computer": 1, "group": 2, "grouppolicycontainer": 3,
    "domaindns": 4, "domain": 4, "organizationalunit": 5,
    "container": 6, "rpccontainer": 6,
    "builtindomain": 7, "foreignsecurityprincipal": 2, "trusteddomain": 4,
    "certificationauthority": 8, "pkienrollmentservice": 8,
    "pkicertificatetemplate": 9,
}
SOAPHOUND_OBJECT_CLASS_PRIORITY = [
    "computer", "user", "group", "foreignsecurityprincipal", "grouppolicycontainer",
    "pkicertificatetemplate", "certificationauthority", "pkienrollmentservice",
    "organizationalunit", "domaindns", "domain", "trusteddomain",
    "container", "rpccontainer", "builtindomain"
]

KNOWN_BINARY_ADWS_ATTRIBUTES = [
    "objectsid", "objectguid", "ntsecuritydescriptor", "sidhistory",
    "cacertificate", "pkiexpirationperiod", "pkioverlapperiod", "msds-allowedtoactonbehalfofotheridentity"
]

BH_TYPE_LABEL_MAP = {
    0: "User", 1: "Computer", 2: "Group", 3: "Gpo",
    4: "Domain", 5: "OU", 6: "Container", 7: "Domain",
    8: "CA", 9: "CertTemplate",
}

def generate_caches(all_objects):
    value_to_id_cache = {}
    id_to_type_cache = {}
    for obj in all_objects:
        dn = obj.get("distinguishedName")
        sid = None
        if obj.get("objectSid"):
            sid = LDAP_SID(obj["objectSid"]).formatCanonical()
        elif obj.get("objectGUID"):
            sid = str(UUID(bytes_le=obj["objectGUID"])).upper()
        else:
            continue

        # Find the BH type (integer) from mapping
        typ = None
        object_class = obj.get("objectClass", [])
        if isinstance(object_class, str):
            object_class = [object_class]
        object_class = [oc.lower() for oc in object_class]

        # Get the strongest type found in the objectClass list
        for oc in object_class:
            if oc in BH_TYPE_LABEL_MAP:
                typ = BH_TYPE_LABEL_MAP[oc]
                break

        if dn and sid and typ is not None:
            value_to_id_cache[normalize_dn(dn)] = sid
            id_to_type_cache[sid] = typ

    return value_to_id_cache, id_to_type_cache

def pull_all_ad_objects(ip: str, domain: str, username: str, auth: ADWSAuthType, query: str, attributes: list, base_dn_override: str = None):
    """
    Pulls all AD objects using ADWS for the given query and attributes.
    Always provide defaultNamingContext (real base DN) via base_dn_override.
    """
    effective_base_dn = base_dn_override if base_dn_override else "DC=" + ",DC=".join(domain.split('.'))
    logging.debug(f"Collecting AD objects. Domain: {domain}, Query: '{query}', Base DN: {effective_base_dn}, Attributes: {len(attributes)}")
    pull_client = ADWSConnect.pull_client(ip, domain, username, auth)
    all_pulled_items = []
    pull_et_root_items = pull_client.pull(query=query, attributes=attributes, base_object_dn_for_soap=effective_base_dn)
    if pull_et_root_items is None:
        logging.error(f"ADWSConnect.pull returned None for query '{query}' and base '{effective_base_dn}'.")
        return {"objects": [], "domain_root_dn": effective_base_dn, "effective_base_dn_used": effective_base_dn}
    for item_elem in pull_et_root_items:
        obj_data = {}
        for attr_name_original_case in attributes:
            attr_name_lower = attr_name_original_case.lower()
            attr_elems = item_elem.findall(f".//addata:{attr_name_original_case}/ad:value", namespaces=NAMESPACES)
            if not attr_elems and attr_name_original_case != attr_name_lower:
                 attr_elems = item_elem.findall(f".//addata:{attr_name_lower}/ad:value", namespaces=NAMESPACES)
            if attr_elems:
                values = []
                for val_elem in attr_elems:
                    if val_elem.text is None: continue
                    is_b64_by_type = val_elem.attrib.get('{http://www.w3.org/2001/XMLSchema-instance}type') == 'ad:base64Binary'
                    if is_b64_by_type or attr_name_lower in KNOWN_BINARY_ADWS_ATTRIBUTES:
                        if isinstance(val_elem.text, str):
                            try: values.append(b64decode(val_elem.text))
                            except Exception as e:
                                logging.debug(f"Failed b64decode for '{attr_name_original_case}' (value: '{val_elem.text[:30]}...'), storing as string. Error: {e}")
                                values.append(val_elem.text)
                        else: values.append(val_elem.text)
                    else: values.append(val_elem.text)
                if values:
                    obj_data[attr_name_original_case] = values[0] if len(values) == 1 and not isinstance(values[0], list) else values
        if 'distinguishedName' not in obj_data:
            dn_elem = item_elem.find(".//addata:distinguishedName/ad:value", namespaces=NAMESPACES)
            if dn_elem is not None and dn_elem.text is not None:
                obj_data['distinguishedName'] = dn_elem.text
        if 'objectClass' not in obj_data:
            oc_val = [oc.text for oc in item_elem.findall(".//addata:objectClass/ad:value", namespaces=NAMESPACES) if oc.text]
            if oc_val:
                obj_data['objectClass'] = oc_val
        if obj_data.get('distinguishedName'):
            all_pulled_items.append(obj_data)
    logging.debug(f"Parsed {len(all_pulled_items)} objects from ADWS response for query '{query}' (Base DN target: {effective_base_dn}).")
    return {"objects": all_pulled_items, "domain_root_dn": effective_base_dn, "effective_base_dn_used": effective_base_dn}

def adws_objecttype_guid_map(adws, schema_dn, follow_referrals=True) -> dict:
    """
    Retrieves the lDAPDisplayName → schemaIDGUID map (as string) via ADWS for classSchema and attributeSchema.
    schema_dn MUST be passed from the main script (do not fetch it here).
    
    Args:
        adws: ADWS connection object
        schema_dn: Schema DN from RootDSE (required)
        follow_referrals: Whether to follow AD referrals (default: True)
    """
    if schema_dn is None:
        raise ValueError("schema_dn must be provided from RootDSE")
    
    query = "(objectClass=*)"
    attributes = ["name", "schemaIDGUID", "lDAPDisplayName"]
    mapping = {}
    
    NAMESPACES = {
        "ns1": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
        "ns2": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    }
    
    # Pass follow_referrals to pull()
    et_classes = adws.pull(
        query, 
        attributes, 
        use_schema=True, 
        base_object_dn_for_soap=schema_dn,
        follow_referrals=follow_referrals
    )
    
    if et_classes is not None:
        for item in et_classes.findall(".//ns1:classSchema", NAMESPACES):
            ldn = item.find(".//ns1:lDAPDisplayName/ns2:value", NAMESPACES)
            guid = item.find(".//ns1:schemaIDGUID/ns2:value", NAMESPACES)
            if ldn is not None and ldn.text and guid is not None and guid.text:
                try:
                    guid_bytes = base64.b64decode(guid.text)
                    guid_str = str(UUID(bytes_le=guid_bytes)).lower()
                    mapping[ldn.text.lower()] = guid_str
                except Exception:
                    pass
    
    # attributeSchema - also pass follow_referrals
    et_attrs = adws.pull(
        query, 
        attributes, 
        use_schema=True, 
        base_object_dn_for_soap=schema_dn,
        follow_referrals=follow_referrals
    )
    
    if et_attrs is not None:
        for item in et_attrs.findall(".//ns1:attributeSchema", NAMESPACES):
            ldn = item.find(".//ns1:lDAPDisplayName/ns2:value", NAMESPACES)
            guid = item.find(".//ns1:schemaIDGUID/ns2:value", NAMESPACES)
            if ldn is not None and ldn.text and guid is not None and guid.text:
                try:
                    guid_bytes = base64.b64decode(guid.text)
                    guid_str = str(UUID(bytes_le=guid_bytes)).lower()
                    mapping[ldn.text.lower()] = guid_str
                except Exception:
                    pass
    
    return mapping

def _generate_individual_caches(all_pulled_items, domain_root_dn):
    logging.debug("Generating individual cache dictionaries in memory for SOAPHound...")
    id_to_type_cache = {}
    value_to_id_cache = {}
    for idx, obj in enumerate(all_pulled_items):
        dn = obj.get('distinguishedName')
        raw_sid_bytes = obj.get('objectSid')
        raw_guid_bytes = obj.get('objectGUID')
        object_classes = obj.get('objectClass', [])

        sid_str = None
        if isinstance(raw_sid_bytes, bytes):
            try: sid_str = LDAP_SID(raw_sid_bytes).formatCanonical()
            except Exception as e: sid_str = f"<SID decode error: {e}>"
        elif isinstance(raw_sid_bytes, str):
            if raw_sid_bytes.upper().startswith("S-1-"):
                sid_str = raw_sid_bytes.upper()
        guid_str = None
        if isinstance(raw_guid_bytes, bytes):
            try: guid_str = str(UUID(bytes_le=raw_guid_bytes))
            except Exception as e: guid_str = f"<GUID decode error: {e}>"
        elif isinstance(raw_guid_bytes, str) and len(raw_guid_bytes) == 36:
            guid_str = raw_guid_bytes.lower()

        primary_id = sid_str if sid_str else guid_str
        oc_lower_list_for_check = [str(oc).lower() for oc in object_classes] if isinstance(object_classes, list) else ([str(object_classes).lower()] if object_classes else [])

        if "cn=configuration,".lower() in (dn or "").lower() or \
           "pkicertificatetemplate" in oc_lower_list_for_check or \
           "certificationauthority" in oc_lower_list_for_check or \
           "pkienrollmentservice" in oc_lower_list_for_check or \
           not sid_str:
            primary_id = guid_str

        if not primary_id:
            primary_id = sid_str or guid_str

        if not primary_id:
            logging.debug(f"Cache: Skipping object {dn} due to missing primary identifier (SID/GUID).")
            continue

        id_to_type_cache[primary_id] = get_soaphound_type_id(dn, object_classes, sid_str, domain_root_dn)
        value_to_id_cache[unicodedata.normalize('NFKC', dn).upper()] = primary_id
    logging.debug(f"Generated {len(id_to_type_cache)} IdToType mappings and {len(value_to_id_cache)} ValueToId mappings.")
    return id_to_type_cache, value_to_id_cache

def get_soaphound_type_id(dn, object_classes, object_sid_str, domain_root_dn):
    if not isinstance(object_classes, list): object_classes = [object_classes]
    object_classes_lower = [str(oc).lower() for oc in object_classes]
    if "pkicertificatetemplate" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("pkicertificatetemplate")
    if "certificationauthority" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("certificationauthority")
    if "pkienrollmentservice" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("pkienrollmentservice")
    if object_sid_str == "S-1-5-32": return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("builtindomain", 7)
    if object_sid_str == "S-1-5-17": return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("group", 2)
    if dn and domain_root_dn and dn.lower() == domain_root_dn.lower(): return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("domaindns", 4)
    for oc_priority in SOAPHOUND_OBJECT_CLASS_PRIORITY:
        if oc_priority in object_classes_lower:
            type_id = SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get(oc_priority)
            if type_id is not None: return type_id
    if "container" in object_classes_lower: return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("container", 6)
    return SOAPHOUND_OBJECT_CLASS_MAPPING_TO_INT.get("container", 6)

def _parse_aces(ntsd_bytes, id_to_type_cache, current_object_id, object_type_label_for_ace="Base",
               has_laps_prop=False, object_type_guid_map=None, extrights_guid_mapping=None):
    if not ntsd_bytes or not isinstance(ntsd_bytes, bytes):
        return [], False
    if object_type_guid_map is None:
        object_type_guid_map = {}
    entry = {"Properties": {"haslaps": bool(has_laps_prop)}}
    et = object_type_label_for_ace.lower()
    if et == "ou":
        et = "organizational-unit"
    entry, relations = parse_binary_acl(entry, et, ntsd_bytes, object_type_guid_map)
    is_acl_protected = entry.get('IsACLProtected', False)
    aces_list = []
    for rel in relations:
        sid = rel['sid']
        rightname = rel['rightname']
        inherited = rel['inherited']
        principal_type = _resolve_principal_type_from_cache(sid, id_to_type_cache, "Unknown").capitalize()
        aces_list.append(_build_relation(sid, principal_type, rightname, inherited))
    return aces_list, is_acl_protected

def dedupe_aces(aces):
    seen = set()
    result = []
    for ace in aces:
        key = (ace['PrincipalSID'], ace['PrincipalType'], ace['RightName'], ace['IsInherited'])
        if key not in seen:
            seen.add(key)
            result.append(ace)
    return result

def _resolve_principal_type_from_cache(principal_id, id_to_type_cache, default_bh_type="Base"):
    if not principal_id: return default_bh_type.capitalize()
    numeric_type = id_to_type_cache.get(principal_id)
    if numeric_type is not None: return BH_TYPE_LABEL_MAP.get(numeric_type, default_bh_type).capitalize()
    if isinstance(principal_id, str):
        if principal_id.upper().startswith("S-1-5-21-"): return "User"
        if principal_id.upper().startswith("S-1-5-32-"): return "Group"
        if principal_id.upper() == "S-1-1-0": return "Group"
        if principal_id.upper() == "S-1-5-18": return "System"
        if principal_id.upper() == "S-1-5-9": return "Group"
    return default_bh_type.capitalize()

def _build_relation(sid, principal_type, rightname, inherited):
    return {
        "PrincipalSID": sid,
        "PrincipalType": principal_type,
        "RightName": rightname,
        "IsInherited": inherited
    }

def adws_object_classes(adws) -> set:
    """
    Retrieves all objectClass names from the schema via ADWS.
    """
    query = "(lDAPDisplayName=*)"
    attributes = ["lDAPDisplayName"]
    et = adws.pull(query, attributes, use_schema=True)
    if et is None:
        logging.error("[adws_object_classes] Unable to collect object classes from the schema (use_schema)")
        return set()

    NAMESPACES = {
        "ns1": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
        "ns2": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
    }

    classes = set()
    for item in et.findall(".//ns1:classSchema", NAMESPACES):
        ldn = item.find(".//ns1:lDAPDisplayName/ns2:value", NAMESPACES)
        if ldn is not None and ldn.text:
            classes.add(ldn.text)
    return classes

def filetime_to_unix(val):
    """
    Converts an AD date field (FILETIME or LDAP time string) to UNIX timestamp.
    If the value cannot be converted, returns 0.
    """
    if val is None:
        return 0
    if isinstance(val, list):
        val = val[0] if val else 0
    # Handle integer/filetime
    try:
        if isinstance(val, int):
            if val == 0:
                return 0
            return int((val - 116444736000000000) / 10000000)
        if isinstance(val, str) and val.isdigit():
            val = int(val)
            if val == 0:
                return 0
            return int((val - 116444736000000000) / 10000000)
    except Exception:
        pass
    # Handle LDAP generalized time: "YYYYMMDDHHMMSS.0Z" or "YYYYMMDDHHMMSS.123456Z"
    if isinstance(val, str) and "." in val and val.endswith("Z"):
        try:
            # .0Z case
            if val.endswith(".0Z"):
                return int(datetime.strptime(val, "%Y%m%d%H%M%S.0Z").replace(tzinfo=timezone.utc).timestamp())
            # .xxxZ or .xxxxxxZ case
            match = re.match(r"^(\d{14})\.(\d+)Z$", val)
            if match:
                main_dt, fraction = match.groups()
                fraction = (fraction + "000000")[:6]  # pad to 6 digits
                dt_str = f"{main_dt}.{fraction}Z"
                dt_format = "%Y%m%d%H%M%S.%fZ"
                return int(datetime.strptime(dt_str, dt_format).replace(tzinfo=timezone.utc).timestamp())
        except Exception as e:
            print(f"filetime_to_unix: failed to parse {val} - {e}")
            return 0
    return 0

def create_and_combine_soaphound_cache(all_pulled_items, domain_root_dn, output_dir=".", domain_name=None):
    """
    Generate and save the SOAPHound cache (IdToTypeCache + ValueToIdCache).
    
    Args:
        all_pulled_items: List of AD objects
        domain_root_dn: DN of the domain root
        output_dir: Output directory (default: current directory)
        domain_name: Domain name to include in filename (optional)
    """
    # Build the cache filename with domain name
    if domain_name:
        safe_domain = domain_name.lower().replace(' ', '_')
        cache_filename = f"cache_{safe_domain}.json"
    else:
        cache_filename = "Cache.json"
    
    combined_output_path = os.path.join(output_dir, cache_filename)
    
    # Ensure directory exists before writing
    output_dir = output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    
    logging.info(f"Initiating SOAPHound cache generation to {combined_output_path}...")
    id_to_type_dict, value_to_id_dict = _generate_individual_caches(all_pulled_items, domain_root_dn)
    
    if not id_to_type_dict or not value_to_id_dict:
        logging.error("Failed to generate individual cache dictionaries. Combined cache not created.")
        return
    
    try:
        combined_data = {"IdToTypeCache": id_to_type_dict, "ValueToIdCache": value_to_id_dict}
        with open(combined_output_path, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Cache.json saved to {combined_output_path}")
    except IOError as e:
        logging.error(f"Error writing cache files: {e}")
