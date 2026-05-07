"""
``soaphound`` module for ``nxc adws``.

Runs the full BloodHound collection over ADWS by reusing the connection
established by the ``adws`` protocol. Soaphound (vendored under
``nxc/modules/_soaphound``) generates the BloodHound JSON files (users,
groups, computers, ous, gpos, containers, domains) compatible with
BloodHound CE and BloodHound Legacy.

Usage:
    nxc adws dc01 -d corp.lab -u alice -p Pwd -M soaphound
    nxc adws dc01 -d corp.lab -u alice -k       -M soaphound -o COLLECTION=ADWSOnly
    nxc adws dc01 -d corp.lab -u alice -p Pwd -M soaphound -o OUTPUT_DIR=/tmp/bh ZIP=true

Options:
    COLLECTION    "Default" (with SMB sessions) or "ADWSOnly" (default: Default)
    OUTPUT_DIR    Output directory for the .json files (default: ./bloodhound-<host>)
    ZIP           Compress the .json files into bloodhound.zip (default: false)
    CERT_FIND     Also run the AD CS / certipy-find collection (default: false)
"""
import os
import sys
import time
import datetime
import logging
import json
import zipfile
from types import SimpleNamespace

import dns.resolver
from impacket.ldap.ldaptypes import LDAP_SID

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Soaphound BloodHound ingestor over ADWS."""

    name = "soaphound"
    description = "Collect AD objects over ADWS and produce BloodHound JSON files (Soaphound)"
    supported_protocols = ["adws"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.collection = "Default"
        self.output_dir = None
        self.zip_output = False
        self.cert_find = False

    def options(self, context, module_options):
        """
        COLLECTION    "Default" or "ADWSOnly" (no SMB session collection). Default: Default.
        OUTPUT_DIR    Output folder for .json files. Default: ./bloodhound-<host>
        ZIP           Compress .json files into bloodhound.zip. Default: false
        CERT_FIND     Also run AD CS / certipy-find collection. Default: false
        """
        self.collection = (module_options.get("COLLECTION") or "Default").strip()
        if self.collection not in ("Default", "ADWSOnly"):
            context.log.fail(f"Invalid COLLECTION '{self.collection}', must be 'Default' or 'ADWSOnly'")
            self.collection = "Default"
        self.output_dir = module_options.get("OUTPUT_DIR")
        self.zip_output = str(module_options.get("ZIP", "false")).lower() in ("true", "1", "yes")
        self.cert_find = str(module_options.get("CERT_FIND", "false")).lower() in ("true", "1", "yes")

    def on_login(self, context, connection):
        """
        Reuses the ADWS connection (`connection._auth`, `connection._enum_client`)
        established by the ``adws`` protocol to drive the Soaphound collection.
        """
        self.context = context

        if connection._auth is None:
            context.log.fail("No active ADWS authentication context found")
            return

        # Prepare the output directory
        out_dir = self.output_dir or f"bloodhound-{connection.host}"
        os.makedirs(out_dir, exist_ok=True)
        context.log.display(f"Output directory: {out_dir}")
        context.log.display(f"Collection mode:  {self.collection}")

        try:
            self._run_collection(context, connection, out_dir)
        except Exception as e:
            context.log.fail(f"Soaphound collection failed: {e}")
            context.log.debug("", exc_info=True)
            return

        if self.zip_output:
            self._zip_output(context, out_dir, connection.host)

    # ------------------------------------------------------------------
    def _run_collection(self, context, connection, out_dir):
        """Drive the collection via the modules vendored under _soaphound/."""
        # Lazy imports: these are heavy, and only useful when the module runs
        from nxc.modules._soaphound.ad.adws import (
            ADWSConnect,
            KerberosAuth as SH_KerberosAuth,
            NTLMAuth as SH_NTLMAuth,
        )
        from nxc.modules._soaphound.ad.cache_gen import (
            pull_all_ad_objects,
            adws_objecttype_guid_map,
            generate_caches,
            _generate_individual_caches,
            adws_object_classes,
            create_and_combine_soaphound_cache,
            SOAPHOUND_LDAP_PROPERTIES,
            SOAPHOUND_CACHE_PROPERTIES,
        )
        from nxc.modules._soaphound.ad.acls import normalize_name
        from nxc.modules._soaphound.ad.collectors.domain import collect_domains, format_domains
        from nxc.modules._soaphound.ad.collectors.container import collect_containers, format_containers
        from nxc.modules._soaphound.ad.collectors.gpo import collect_gpos, format_gpos
        from nxc.modules._soaphound.ad.collectors.ou import collect_ous, format_ous
        from nxc.modules._soaphound.ad.collectors.group import collect_groups, format_groups
        from nxc.modules._soaphound.ad.collectors.user import collect_users, format_users
        from nxc.modules._soaphound.ad.collectors.trust import collect_trusts
        from nxc.modules._soaphound.ad.collectors.computer import collect_computers, format_computers
        from nxc.modules._soaphound.ad.collectors.computer_adws import collect_computers_adws, format_computers_adws
        from nxc.modules._soaphound.ad.collectors.cert_find import run_cert_find
        from nxc.modules._soaphound.lib.utils import ObjectCache, DNSCache
        from nxc.modules._soaphound.lib.authentication import ADAuthentication
        from nxc.modules._soaphound.lib.domain import ADDomain

        host = connection.host
        domain = connection.domain
        username = connection.username

        # ------------------------------------------------------------------
        # Convert the auth object from the _soapy namespace (used by the
        # nxc adws protocol) to the _soaphound namespace. The classes share
        # the same name but live in two different modules, so the
        # ``isinstance`` check inside _soaphound.ADWSConnect was silently
        # failing and triggering ``NotImplementedError: Authentication type
        # not supported``.
        # ------------------------------------------------------------------
        soapy_auth = connection._auth
        soapy_auth_type = type(soapy_auth).__name__
        kerberos_mode = False

        if soapy_auth_type == "KerberosAuth":
            auth = SH_KerberosAuth(kdc_host=getattr(soapy_auth, "kdc_host", None))
            kerberos_mode = True
        elif soapy_auth_type == "NTLMAuth":
            if getattr(soapy_auth, "password", None) is not None:
                auth = SH_NTLMAuth(password=soapy_auth.password)
            else:
                auth = SH_NTLMAuth(hashes=soapy_auth.nt)
        else:
            context.log.fail(f"Unsupported auth type for Soaphound: {soapy_auth_type}")
            return

        context.log.debug(f"Auth converted to _soaphound namespace: {type(auth).__name__}")

        # 1) RootDSE
        adws_resource = ADWSConnect(host, domain, username, auth, "Resource")
        ctxs = adws_resource.get_rootdse_contexts(adws_resource._fqdn, adws_resource._nmf)
        schema_dn = ctxs["schemaNamingContext"]
        default_dn = ctxs["defaultNamingContext"]
        config_dn = ctxs["configurationNamingContext"]
        domain_functionality = int(ctxs["domainFunctionality"][0]) if ctxs.get("domainFunctionality") else None

        # 2) Shared Enumeration connection used by the rest of the steps
        adws_enum = ADWSConnect(host, domain, username, auth, "Enumeration")

        # 3) Optional: AD CS collection via certipy-find
        if self.cert_find:
            context.log.display("Running cert-find (AD CS) ...")
            try:
                run_cert_find(
                    adws_enum=adws_enum,
                    resource_client=adws_resource,
                    config_dn=config_dn,
                    schema_dn=schema_dn,
                    default_dn=default_dn,
                    domain=domain,
                    username=username,
                    auth=auth,
                    output_dir=out_dir,
                    web_probe_force_epa=None,
                    web_probe_enabled=True,
                    ca_rpc_enabled=False,
                )
            except Exception as e:
                context.log.fail(f"cert-find failed: {e}")

        # 4) Mapping objectType GUID
        objecttype_guid_map = adws_objecttype_guid_map(adws_enum, schema_dn=schema_dn)
        objecttype_guid_map_normalized = {normalize_name(k): v for k, v in objecttype_guid_map.items()}
        laps_guid = objecttype_guid_map_normalized.get(normalize_name("ms-Mcs-AdmPwd"))
        laps2_guid = objecttype_guid_map_normalized.get(normalize_name("msLAPS-EncryptedPassword"))
        has_laps = laps_guid is not None
        has_laps2 = laps2_guid is not None

        # 5) Pull principal
        main_query = (
            "(|(objectCategory=person)"
            "(objectClass=msDS-GroupManagedServiceAccount)"
            "(objectClass=msDS-ManagedServiceAccount)"
            "(objectCategory=computer)(objectCategory=group)"
            "(objectClass=organizationalUnit)(objectClass=domain)"
            "(objectClass=container)(objectClass=groupPolicyContainer))"
        )
        attrs_child = ["objectSid", "objectClass", "objectGUID", "distinguishedName", "sAMAccountName", "sAMAccountType"]

        context.log.display("Pulling AD object cache (this can take a while)...")
        data_child = pull_all_ad_objects(
            ip=host, domain=domain, username=username, auth=auth,
            query=main_query, attributes=attrs_child, base_dn_override=default_dn,
        )
        all_child_items = data_child.get("objects", [])

        data_main = pull_all_ad_objects(
            ip=host, domain=domain, username=username, auth=auth,
            query=main_query, attributes=SOAPHOUND_CACHE_PROPERTIES, base_dn_override=default_dn,
        )
        objs = data_main.get("objects", [])
        if not objs:
            context.log.fail("No objects collected from ADWS")
            return

        # Normalisation
        for obj in objs:
            dn = obj.get("distinguishedName")
            if isinstance(dn, list):
                obj["distinguishedName"] = dn[0] if dn else ""
            oc = obj.get("objectClass")
            if isinstance(oc, str):
                obj["objectClass"] = [oc]
            elif oc is None:
                obj["objectClass"] = []

        create_and_combine_soaphound_cache(objs, default_dn, output_dir=out_dir)
        id_to_type_cache, value_to_id_cache = _generate_individual_caches(objs, default_dn)

        context.log.success(f"Collected {len(objs)} objects from ADWS")

        # 6) Per-type collection
        raw_domains = collect_domains(host, domain, username, auth)
        raw_containers = collect_containers(host, domain, username, auth)
        containers_bh = format_containers(raw_containers, domain, default_dn, id_to_type_cache, value_to_id_cache, objs, objecttype_guid_map)

        domain_obj = raw_domains[0]
        sid_bytes = domain_obj.get("objectSid")
        if isinstance(sid_bytes, bytes):
            domain_sid = LDAP_SID(sid_bytes).formatCanonical()
        elif isinstance(sid_bytes, str) and sid_bytes.upper().startswith("S-1-"):
            domain_sid = sid_bytes.upper()
        else:
            context.log.fail("Could not determine primary domain SID")
            return

        gpos = collect_gpos(host, domain, username, auth)
        gpos_bh = format_gpos(gpos, domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

        trusts = collect_trusts(host, domain, username, auth, domain_sid=domain_sid)
        context.log.display(f"Trusts collected: {len(trusts)}")

        domains_bh = format_domains(
            raw_domains, domain, default_dn, id_to_type_cache, value_to_id_cache,
            all_child_items, objecttype_guid_map, trusts,
            domain_functionality=domain_functionality,
        )
        ous = collect_ous(host, domain, username, auth)
        ous_bh = format_ous(ous, domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

        groups = collect_groups(host, domain, username, auth)
        groups_bh = format_groups(groups, domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

        object_classes = adws_object_classes(adws_enum)
        users = collect_users(host, domain, username, auth, adws_object_classes=object_classes, adws_objecttype_guid_map=objecttype_guid_map)
        users_bh = format_users(users, domain, domain_sid, id_to_type_cache, value_to_id_cache, objecttype_guid_map)

        # 7) Computers: ADWSOnly skips SMB/RPC sessions
        if self.collection == "ADWSOnly":
            computers = collect_computers_adws(
                host, domain, username, auth, base_dn_override=default_dn,
                adws_object_classes=object_classes, has_laps=has_laps,
                has_lapsv2=has_laps2, objecttype_guid_map=objecttype_guid_map,
            )
            computers_bh = format_computers_adws(
                computers, domain, domain_sid, id_to_type_cache,
                value_to_id_cache, objecttype_guid_map=objecttype_guid_map,
            )
        else:
            # Mode Default : on prepare un ADAuthentication adapte au mode courant
            password_for_smb = getattr(connection, "password", "") or ""
            nthash_for_smb = getattr(connection, "nthash", "") or ""

            smb_auth = ADAuthentication(
                username=username,
                password=password_for_smb,
                domain=domain,
                lm_hash="",
                nt_hash=nthash_for_smb,
                aeskey="",
                kdc=host,
                auth_method="kerberos" if kerberos_mode else "auto",
            )
            if kerberos_mode:
                try:
                    smb_auth.load_ccache()
                except Exception as e:
                    context.log.fail(f"Could not load ccache for SMB session collection: {e}")

            ad_dom = ADDomain(name=domain, netbios_name=None, sid=domain_sid, distinguishedname=default_dn)
            ad_dom.domain = ad_dom.name
            ad_dom.auth = smb_auth
            ad_dom.dnscache = DNSCache()
            ad_dom.dnsresolver = dns.resolver.Resolver()
            ad_dom.dns_tcp = dns.resolver.Resolver()
            ad_dom.dns_tcp.use_tcp = True
            ad_dom.sidcache = ObjectCache()
            ad_dom.samcache = ObjectCache()
            ad_dom.computersidcache = ObjectCache()
            ad_dom.num_domains = 1
            ad_dom.get_domain_by_name = lambda name: ad_dom if name.lower() == ad_dom.name.lower() else None

            computers = collect_computers(
                host, domain, username, auth, base_dn_override=default_dn,
                adws_object_classes=object_classes, has_laps=has_laps,
                has_lapsv2=has_laps2, objecttype_guid_map=objecttype_guid_map,
            )
            computers_bh = format_computers(
                computers, domain, domain_sid, adws_enum,
                id_to_type_cache, value_to_id_cache, objecttype_guid_map,
                bh_rpc_context=ad_dom, num_workers=50,
            )

        # 8) Export
        ts = datetime.datetime.fromtimestamp(time.time()).strftime("%Y%m%d%H%M%S") + "_"
        for label, payload in [
            ("domains", domains_bh), ("containers", containers_bh),
            ("gpos", gpos_bh), ("ous", ous_bh),
            ("groups", groups_bh), ("users", users_bh),
            ("computers", computers_bh),
        ]:
            if payload and payload.get("meta", {}).get("count", 0) > 0:
                path = os.path.join(out_dir, f"{ts}{label}.json")
                self._dump_json(payload, path)
                context.log.success(f"Wrote {label}: {path} ({payload['meta']['count']} entries)")

    # ------------------------------------------------------------------
    def _dump_json(self, data, path):
        import base64

        def _encode(obj):
            if isinstance(obj, dict):
                return {k: _encode(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_encode(x) for x in obj]
            if isinstance(obj, bytes):
                return base64.b64encode(obj).decode("ascii")
            return obj

        with open(path, "w", encoding="utf-8") as f:
            json.dump(_encode(data), f, indent=2)

    def _zip_output(self, context, out_dir, host):
        zip_path = os.path.join(out_dir, f"bloodhound-{host}.zip")
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for fn in os.listdir(out_dir):
                    if fn.lower().endswith(".json"):
                        zf.write(os.path.join(out_dir, fn), arcname=fn)
            context.log.success(f"BloodHound archive: {zip_path}")
        except Exception as e:
            context.log.fail(f"Could not create zip: {e}")
