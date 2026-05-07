from uuid import UUID
from impacket.ldap.ldaptypes import LDAP_SID
from ...ad.cache_gen import pull_all_ad_objects
import json
import base64

def collect_trusts(ip=None, domain=None, username=None, auth=None, base_dn_override=None, cache_file=None, domain_sid=None):
    """
    Collect all trustedDomain objects from the directory or a cache.
    Automatically add the 'domainsid' field to each trust if domain_sid is provided.
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
        trusts = [
            o for o in objs
            if o.get("distinguishedName") and isinstance(o.get("distinguishedName"), str)
        ]
    else:
        attributes = [
            "name", "objectGUID", "objectSid", "objectClass", "distinguishedName",
            "trustDirection", "trustType", "trustAttributes", "flatName", "trustPartner",
            "whenCreated", "securityIdentifier"
        ]
        query = "(objectClass=trustedDomain)"
        trusts = pull_all_ad_objects(
            ip=ip,
            domain=domain,
            username=username,
            auth=auth,
            query=query,
            attributes=attributes,
            base_dn_override=base_dn_override
        ).get("objects", [])
        trusts = [t for t in trusts if t.get("distinguishedName") and isinstance(t.get("distinguishedName"), str)]

    # Automatically add domainsid if provided
    if domain_sid is not None:
        for t in trusts:
            t["domainsid"] = domain_sid

    print(f"[INFO] Trusts collected: {len(trusts)}")
    return trusts

# Mapping for trust direction and type to string values expected by BloodHound CE
TRUST_DIRECTION_MAP = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional"
}

TRUST_TYPE_MAP = {
    0: "ParentChild",  # BloodHound.py sometimes uses 0 for ParentChild
    1: "ParentChild",
    2: "TreeRoot",
    3: "External",
    4: "Forest",
    5: "Realm",
    6: "MIT"
}

def trust_to_bh_output(trust_obj):
    """
    Transform an LDAP trust object to BloodHound 'Trusts' format for domains.json.
    Converts TrustDirection and TrustType to string values expected by BloodHound CE.
    """
    # All known trust flags
    TRUST_FLAGS = {
        'NON_TRANSITIVE': 0x00000001,
        'UPLEVEL_ONLY': 0x00000002,
        'QUARANTINED_DOMAIN': 0x00000004,
        'FOREST_TRANSITIVE': 0x00000008,
        'CROSS_ORGANIZATION': 0x00000010,
        'WITHIN_FOREST': 0x00000020,
        'TREAT_AS_EXTERNAL': 0x00000040,
        'USES_RC4_ENCRYPTION': 0x00000080,
        'PIM_TRUST': 0x00000400,
        'CROSS_ORGANIZATION_NO_TGT_DELEGATION': 0x00000200,
        'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION': 0x00000800,
    }

    def has_flag(flags, flagname):
        """Return True if the specific flag is set in flags."""
        return (flags & TRUST_FLAGS[flagname]) == TRUST_FLAGS[flagname]

    trusttype = 'Unknown'
    is_transitive = False
    sid_filtering = True

    flags = int(trust_obj.get("trustAttributes", 0) or 0)
    # Logic for determining trust type and its properties
    if has_flag(flags, 'WITHIN_FOREST'):
        trusttype = 'ParentChild'
        is_transitive = True
        sid_filtering = has_flag(flags, 'QUARANTINED_DOMAIN')
    elif has_flag(flags, 'FOREST_TRANSITIVE'):
        trusttype = 'Forest'
        is_transitive = True
        sid_filtering = not has_flag(flags, 'TREAT_AS_EXTERNAL')
    elif has_flag(flags, 'TREAT_AS_EXTERNAL') or has_flag(flags, 'CROSS_ORGANIZATION'):
        trusttype = 'External'
        is_transitive = False
        sid_filtering = True
    else:
        is_transitive = not has_flag(flags, 'NON_TRANSITIVE')

    # Get string representation for TrustType
    trusttype_out = TRUST_TYPE_MAP.get(trust_obj.get("trustType", 0), "ParentChild")

    secid_raw = trust_obj.get('securityIdentifier')
    try:
        if secid_raw:
            if isinstance(secid_raw, bytes):
                sid_full = LDAP_SID(secid_raw).formatCanonical()
            elif isinstance(secid_raw, str):
                sid_full = LDAP_SID(base64.b64decode(secid_raw)).formatCanonical()
            else:
                sid_full = str(secid_raw)
        else:
            sid_full = ""
    except Exception:
        sid_full = ""
    
    # Get string representation for TrustDirection
    trust_direction_raw = int(trust_obj.get("trustDirection", 0) or 0)
    trust_direction_out = TRUST_DIRECTION_MAP.get(trust_direction_raw, "Disabled")

    return {
        "TargetDomainName": (trust_obj.get("trustPartner") or trust_obj.get("flatName") or trust_obj.get("name", "")).upper(),
        "TargetDomainSid": sid_full,
        "IsTransitive": is_transitive,
        "TrustDirection": trust_direction_out,
        "TrustType": trusttype_out,
        "SidFilteringEnabled": sid_filtering
    }
