import logging, sys, os, getpass, json, dns.resolver, datetime, time, zipfile, base64
from .lib.cli import gen_cli_args
from impacket.ldap.ldaptypes import LDAP_SID
from .ad.adws import ADWSConnect, NTLMAuth, KerberosAuth
from .ad.cache_gen import (
    pull_all_ad_objects, adws_objecttype_guid_map, generate_caches,
    _generate_individual_caches, adws_object_classes, create_and_combine_soaphound_cache,
    SOAPHOUND_LDAP_PROPERTIES, SOAPHOUND_CACHE_PROPERTIES
)
from .ad.acls import normalize_name
from .ad.collectors.cert_find import run_cert_find
from .ad.collectors.domain import collect_domains, format_domains
from .ad.collectors.container import collect_containers, format_containers
from .ad.collectors.gpo import collect_gpos, format_gpos
from .ad.collectors.ou import collect_ous, format_ous
from .ad.collectors.group import collect_groups, format_groups
from .ad.collectors.user import collect_users, format_users
from .ad.collectors.trust import collect_trusts, trust_to_bh_output

from .lib.utils import ObjectCache, DNSCache
from .lib.authentication import ADAuthentication
from .ad.collectors.computer import collect_computers, format_computers
from .ad.collectors.computer_adws import collect_computers_adws, format_computers_adws
from .lib.domain import ADDomain

def export_bloodhound_json(data, output_path):
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(clean_bytes(data), f, indent=2)

def safe_export_bloodhound_json(data, output_path):
    if "meta" in data and data["meta"].get("count", 0) > 0:
        export_bloodhound_json(data, output_path)

def clean_bytes(obj):
    """Recursively traverse an object and encode all bytes to base64 for JSON."""
    if isinstance(obj, dict):
        return {k: clean_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_bytes(x) for x in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('ascii')
    else:
        return obj

def zip_bloodhound_jsons(output_dir, timestamp,  archive_name="BloodHound.zip"):
    """
    Archive all .json files from output_dir into BloodHound.zip,
    except cache.json (case-insensitive).
    """
    archive_path = archive_name
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for fname in os.listdir(output_dir):
            if fname.lower().endswith(".json") and fname.lower().startswith(timestamp):
                fpath = os.path.join(output_dir, fname)
                archive.write(fpath, arcname=fname)
    print(f"Zip file created at : {archive_path}")

def main():
    options = gen_cli_args()
    banner = """
 .oooooo..o                                oooo                                                .o8                             
d8P'    `Y8                                `888                                               "888                             
Y88bo.       .ooooo.   .oooo.   oo.ooooo.   888 .oo.    .ooooo.  oooo  oooo  ooo. .oo.    .oooo888      oo.ooooo.  oooo    ooo 
 `"Y8888o.  d88' `88b `P  )88b   888' `88b  888P"Y88b  d88' `88b `888  `888  `888P"Y88b  d88' `888       888' `88b  `88.  .8'  
     `"Y88b 888   888  .oP"888   888   888  888   888  888   888  888   888   888   888  888   888       888   888   `88..8'   
oo     .d8P 888   888 d8(  888   888   888  888   888  888   888  888   888   888   888  888   888  .o.  888   888    `888'    
8""88888P'  `Y8bod8P' `Y888""8o  888bod8P' o888o o888o `Y8bod8P'  `V88V"V8P' o888o o888o `Y8bod88P" Y8P  888bod8P'     .8'     
                                 888                                                                     888       .o..P'      
                                o888o                                                                   o888o      `Y8P'       
                                                                                                    (made by @belettet1m0ree)
"""
    log_format = '%(asctime)s %(levelname)s: %(name)s: %(message)s' if options.ts else '[%(levelname)s] %(message)s'

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter(log_format)
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if options.v is True:
        logger.setLevel(logging.DEBUG)

    logging.debug(options)
    print(options)

    lm = ''
    nt = ''
    aeskey = getattr(options, 'aes_key', None) or ''
    kdc_host = getattr(options, 'kdc_ip', None) or options.domain_controller

    # ------------------------------------------------------------------
    # Selection du mode d'authentification (NTLM ou Kerberos)
    # ------------------------------------------------------------------
    if options.kerberos:
        # Kerberos mode: rely on the KRB5CCNAME credential cache.
        # If the username is missing, extract it from the ccache.
        logging.debug('Authentication: Kerberos (KRB5CCNAME)')

        krb5cc = os.getenv('KRB5CCNAME')
        if not krb5cc:
            logging.warning("KRB5CCNAME is not set. "
                            "Make sure a ticket is loaded (e.g. export KRB5CCNAME=/tmp/ticket.ccache).")
        elif not os.path.isfile(krb5cc):
            logging.warning("The ccache file referenced by KRB5CCNAME does not exist: %s", krb5cc)

        # If the user does not pass -u/-d, derive them from the ccache.
        if (not options.username) or (not options.domain):
            try:
                from impacket.krb5.ccache import CCache
                ccache_domain, ccache_user, _, _ = CCache.parseFile(
                    domain=options.domain or "",
                    username=options.username or "",
                    target=f"LDAP/{options.domain_controller}",
                )
                if not options.username and ccache_user:
                    options.username = ccache_user
                    logging.debug('Username extracted from ccache: %s', options.username)
                if not options.domain and ccache_domain:
                    options.domain = ccache_domain
                    logging.debug('Domain extracted from ccache: %s', options.domain)
            except Exception as e:
                logging.debug("Could not parse ccache: %s", e)

        if not options.username:
            logging.critical("Username not found: pass -u or use a ccache containing a valid principal.")
            sys.exit(1)
        if not options.domain:
            logging.critical("Domain not found: pass -d or use a ccache containing a valid principal.")
            sys.exit(1)

        auth = KerberosAuth(kdc_host=kdc_host)

    elif options.username is not None and options.password is not None:
        logging.debug('Authentication: username/password')
        auth = NTLMAuth(password=options.password)
    elif options.username is not None and options.password is None and options.hashes is None:
        options.password = getpass.getpass("Password:")
        logging.debug('Authentication: username/password')
        auth = NTLMAuth(password=options.password)
    elif options.hashes is not None and options.username is not None:
        logging.debug('Authentication: NT hash')
        if ':' in options.hashes:
            lm, nt = options.hashes.split(":")
        else:
            lm, nt = '', options.hashes
        auth = NTLMAuth(password=None, hashes=nt)
    else:
        logging.debug('Failed to parse options')
        logging.critical("No valid authentication method. Use -u/-p, --hashes, or -k.")
        sys.exit(1)

    print(banner)

    # 1. RootDSE query (Resource)
    adws_resource = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Resource")
    contexts = adws_resource.get_rootdse_contexts(adws_resource._fqdn, adws_resource._nmf)
    schema_dn = contexts["schemaNamingContext"]
    default_dn = contexts["defaultNamingContext"]   # Use this DN for all pulls!
    root_domain_dn = contexts["rootDomainNamingContext"]
    config_dn = contexts["configurationNamingContext"]
    naming_contexts = contexts["namingContexts"]
    vals = contexts["domainFunctionality"]
    #Here we save domainFunctionality and ForestFunctionality value that we got from RootDSE request 
    domainFunctionality = int(vals[0]) if vals else None
    vals_forest = contexts["forestFunctionality"]
    forestFunctionality = int(vals[0]) if vals_forest else None

    # 2. One Enumeration connection for all pulls
    adws_enum = ADWSConnect(options.domain_controller, options.domain, options.username, auth, "Enumeration")

    if options.cert_find:
        force_epa = {"auto": None, "enabled": True, "disabled": False}.get(
            getattr(options, "cert_find_force_epa", "auto"), None
        )
        run_cert_find(
            adws_enum=adws_enum,
            resource_client=adws_resource,
            config_dn=config_dn,
            schema_dn=schema_dn,
            default_dn=default_dn,
            domain=options.domain,
            username=options.username,
            auth=auth,
            output_dir=options.output_dir,
            web_probe_force_epa=force_epa,
            web_probe_enabled=not getattr(options, "cert_find_skip_web_probe", False),
            ca_rpc_enabled=getattr(options, "cert_find_ca_rpc", False),
        )
        return

    # 3. ObjectType GUID Mapping (pass schema_dn)
    objecttype_guid_map = adws_objecttype_guid_map(adws_enum, schema_dn=schema_dn)
    objecttype_guid_map_normalized = {normalize_name(k): v for k, v in objecttype_guid_map.items()}
    laps_guid = objecttype_guid_map_normalized.get(normalize_name("ms-Mcs-AdmPwd"))
    laps2_guid = objecttype_guid_map_normalized.get(normalize_name("msLAPS-EncryptedPassword"))
    has_laps = laps_guid is not None
    has_laps2 = laps2_guid is not None

    main_query = "(|(objectCategory=person)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount)(objectCategory=computer)(objectCategory=group)(objectClass=organizationalUnit)(objectClass=domain)(objectClass=container)(objectClass=groupPolicyContainer))"

    child_objects_query = "(|(objectClass=container)(objectClass=organizationalUnit)(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
    attributes_child = [ "objectSid", "objectClass", "objectGUID", "distinguishedName", "sAMAccountName", "sAMAccountType"]
    
    data_child_main = pull_all_ad_objects(
        ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
        query=main_query, attributes=attributes_child, base_dn_override=default_dn
    )
    all_child_items = data_child_main.get("objects", [])
    
    # 4. Collecte principale (utilise default_dn pour le base_dn)
    data_container_main = pull_all_ad_objects(
        ip=options.domain_controller, domain=options.domain, username=options.username, auth=auth,
        query=main_query, attributes=SOAPHOUND_CACHE_PROPERTIES, base_dn_override=default_dn
    )
    all_collected_items = data_container_main.get("objects", [])

    if not all_collected_items:
        logging.error("No objects collected (objs is empty or None)")
        sys.exit(1)

    objs = all_collected_items
    # Normalisation des objets si besoin
    if (isinstance(objs, list) and len(objs) == 1 and isinstance(objs[0], dict) and all(isinstance(v, list) for v in objs[0].values())):
        objs = fix_superdict_to_list(objs[0])
    elif isinstance(objs, dict) and all(isinstance(v, list) for v in objs.values()):
        objs = fix_superdict_to_list(objs)
    else:
        if not objs or not isinstance(objs, list) or not isinstance(objs[0], dict):
            logging.error("Something went wrong with object collected")
            sys.exit(1)

    for obj in objs:
        dn = obj.get('distinguishedName')
        if isinstance(dn, list):
            obj['distinguishedName'] = dn[0] if dn else ""
        oc = obj.get('objectClass')
        if isinstance(oc, str):
            obj['objectClass'] = [oc]
        elif oc is None:
            obj['objectClass'] = []

    # We Generate Soaphound Cache data
    create_and_combine_soaphound_cache(objs, default_dn, output_dir=options.output_dir)
    id_to_type_cache, value_to_id_cache = _generate_individual_caches(objs, default_dn)

    logging.info(f"Start collecting ...")

    
    
    # --- (1) Collect raw domains ---   
    raw_domains = collect_domains(options.domain_controller, options.domain, options.username, auth)
    
    # Collect and format containers
    raw_containers = collect_containers(options.domain_controller, options.domain, options.username, auth)
    containers_bh = format_containers(raw_containers, options.domain, default_dn, id_to_type_cache, value_to_id_cache, objs, objecttype_guid_map)

    # --- (2) Get main domain SID for formatting trusts etc. ---
    domain_obj = raw_domains[0]  # If only one domain, otherwise adapt according to the context.
    sid_bytes = domain_obj.get("objectSid")
        
    if isinstance(sid_bytes, bytes):
        domain_sid = LDAP_SID(sid_bytes).formatCanonical()
    elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
        domain_sid = sid_bytes.upper()
    else:
        raise RuntimeError("Unable to find the SID of the primary domain.")

    collect_domain_args = {
    "username": options.username,
    "auth": auth
    }

    # Collect and format GPOs
    gpos = collect_gpos(options.domain_controller, options.domain, options.username, auth)
    gpos_bh = format_gpos(gpos, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)
        

    # Collect and format Trusts
    trusts = collect_trusts(options.domain_controller, options.domain, options.username, auth, domain_sid=domain_sid)
    

    
    print("Number of trusts collected:", len(trusts))
    # --- (4) Format domains, inject trusts ---
    domains_bh = format_domains(
    raw_domains, options.domain, default_dn,
    id_to_type_cache, value_to_id_cache,
    all_child_items,   
    objecttype_guid_map, trusts,
    domain_functionality=domainFunctionality
)


 
    # Collect and format OUs
    ous = collect_ous(options.domain_controller, options.domain, options.username, auth)
    ous_bh = format_ous(ous, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

    # Collect and format Groups
    groups = collect_groups(options.domain_controller, options.domain, options.username, auth)
    groups_bh = format_groups(groups, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

    # Collect and format Users
    object_classes = adws_object_classes(adws_enum)
    users = collect_users(options.domain_controller, options.domain, options.username, auth, adws_object_classes=object_classes,adws_objecttype_guid_map=objecttype_guid_map)
    users_bh = format_users(users, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)


    # Collect and format Computers
    if (options.collectionmethod == "ADWSOnly"):
        computers = collect_computers_adws(
            options.domain_controller, options.domain, options.username, auth,
            base_dn_override=default_dn, adws_object_classes=object_classes,
            has_laps=has_laps, has_lapsv2=has_laps2,objecttype_guid_map=objecttype_guid_map )
        
        computers_bh = format_computers_adws(computers, options.domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map=objecttype_guid_map)
    else:
        # ------------------------------------------------------------------
        # Configuration de l'authentification SMB/RPC (collecte de sessions)
        # ------------------------------------------------------------------
        if options.kerberos:
            # En mode Kerberos, on charge le ticket depuis le ccache (KRB5CCNAME)
            # afin que les connexions SMB/RPC utilisent ce TGT.
            smb_auth = ADAuthentication(
                username=options.username,
                password='',
                domain=options.domain,
                lm_hash='',
                nt_hash='',
                aeskey=aeskey,
                kdc=kdc_host,
                auth_method='kerberos',
            )
            try:
                if not smb_auth.load_ccache():
                    logging.warning("Could not load a TGT from the ccache. "
                                    "SMB session collection is likely to fail. "
                                    "Check KRB5CCNAME and the validity of the ticket.")
            except Exception as e:
                logging.warning("Error while loading the ccache: %s", e)
        else:
            smb_auth = ADAuthentication(username=options.username, password=options.password, domain=options.domain, lm_hash=lm, nt_hash=nt, aeskey=aeskey, kdc=options.domain_controller)

        addomain = ADDomain(
            name=options.domain,
            netbios_name=None,
            sid=domain_sid,
            distinguishedname=default_dn
        )
        addomain.domain = addomain.name
        addomain.auth = smb_auth
        addomain.dnscache = DNSCache()
        addomain.dnsresolver = dns.resolver.Resolver()
        addomain.dns_tcp = dns.resolver.Resolver(); addomain.dns_tcp.use_tcp = True
        addomain.sidcache = ObjectCache()
        addomain.samcache = ObjectCache()
        addomain.computersidcache = ObjectCache()
        addomain.num_domains = 1

        def get_domain_by_name(name):
            if name.lower() == addomain.name.lower():
                return addomain
            return None
        addomain.get_domain_by_name = get_domain_by_name

        computers = collect_computers(
            options.domain_controller, options.domain, options.username, auth,
            base_dn_override=default_dn, adws_object_classes=object_classes,
            has_laps=has_laps, has_lapsv2=has_laps2, objecttype_guid_map=objecttype_guid_map
        )
        computers_bh = format_computers(
            computers, options.domain, domain_sid, adws_enum,
            id_to_type_cache, value_to_id_cache, objecttype_guid_map,
            bh_rpc_context=addomain, num_workers=options.worker_num
        )

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S') + "_"
    output_dir = options.output_dir
    safe_export_bloodhound_json(domains_bh, os.path.join(output_dir, timestamp + "domains.json"))
    safe_export_bloodhound_json(containers_bh, os.path.join(output_dir, timestamp + "containers.json"))
    safe_export_bloodhound_json(gpos_bh, os.path.join(output_dir, timestamp + "gpos.json"))
    safe_export_bloodhound_json(ous_bh, os.path.join(output_dir, timestamp + "ous.json"))
    safe_export_bloodhound_json(groups_bh, os.path.join(output_dir, timestamp + "groups.json"))
    safe_export_bloodhound_json(users_bh, os.path.join(output_dir, timestamp + "users.json"))
    safe_export_bloodhound_json(computers_bh, os.path.join(output_dir, timestamp + "computers.json"))

    if options.zip:
        zip_bloodhound_jsons(output_dir, timestamp, timestamp + "bloodhound.zip")

if __name__ == "__main__":
    main()
