"""
Module ``certfind`` pour ``nxc adws``.

Lance uniquement la collecte AD CS (equivalent ``certipy find``) via ADWS,
sans la collecte BloodHound complete. Plus rapide et plus cible que
``-M soaphound -o CERT_FIND=true`` quand on veut juste l'enumeration des
templates et CAs.

Usage :
    nxc adws dc01 -d corp.lab -u alice -p Pwd  -M certfind
    nxc adws dc01 -d corp.lab -u alice -k        -M certfind
    nxc adws dc01 -d corp.lab -u alice -p Pwd  -M certfind -o OUTPUT_DIR=/tmp/cf

Options :
    OUTPUT_DIR            Repertoire de sortie pour les .json/.txt (defaut: ./certfind-<host>)
    SKIP_WEB_PROBE        Desactiver la sonde HTTP/HTTPS pour ESC8 (defaut: false)
    FORCE_EPA             Forcer le test EPA (auto/disabled/required, defaut: auto)
    CA_RPC                Activer l'enrichissement CA via Remote Registry (defaut: false)
"""
import os

from nxc.helpers.misc import CATEGORY


class NXCModule:
    """Cert-find AD CS enumeration via ADWS (Soaphound)."""

    name = "certfind"
    description = "Enumerate AD CS templates, CAs and ESC vulnerabilities over ADWS (certipy-find equivalent)"
    supported_protocols = ["adws"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.output_dir = None
        self.skip_web_probe = False
        self.force_epa = None
        self.ca_rpc = False

    def options(self, context, module_options):
        """
        OUTPUT_DIR     Output directory for cert-find files. Default: ./certfind-<host>
        SKIP_WEB_PROBE Disable HTTP/HTTPS probe for ESC8 detection. Default: false
        FORCE_EPA      Force EPA mode: auto/disabled/required. Default: auto
        CA_RPC         Enable CA enrichment via Remote Registry. Default: false
        """
        self.output_dir = module_options.get("OUTPUT_DIR")
        self.skip_web_probe = str(module_options.get("SKIP_WEB_PROBE", "false")).lower() in ("true", "1", "yes")
        self.ca_rpc = str(module_options.get("CA_RPC", "false")).lower() in ("true", "1", "yes")

        force_epa_raw = (module_options.get("FORCE_EPA") or "auto").strip().lower()
        if force_epa_raw in ("auto", "", "none"):
            self.force_epa = None
        elif force_epa_raw in ("disabled", "false", "off", "0", "no"):
            self.force_epa = False
        elif force_epa_raw in ("required", "true", "on", "1", "yes"):
            self.force_epa = True
        else:
            context.log.fail(f"Invalid FORCE_EPA '{force_epa_raw}', must be auto/disabled/required")
            self.force_epa = None

    def on_login(self, context, connection):
        """
        Reutilise la connexion ADWS etablie par le protocole ``adws``.
        """
        self.context = context

        if connection._auth is None:
            context.log.fail("No active ADWS authentication context found")
            return

        out_dir = self.output_dir or f"certfind-{connection.host}"
        os.makedirs(out_dir, exist_ok=True)
        context.log.display(f"Cert-find output directory: {out_dir}")

        try:
            self._run(context, connection, out_dir)
        except Exception as e:
            context.log.fail(f"Cert-find failed: {e}")
            context.log.debug("", exc_info=True)

    # ------------------------------------------------------------------
    def _run(self, context, connection, out_dir):
        """Convertit l'auth puis appelle run_cert_find."""
        # Imports tardifs (lourds, only quand le module tourne)
        from nxc.modules._soaphound.ad.adws import (
            ADWSConnect,
            KerberosAuth as SH_KerberosAuth,
            NTLMAuth as SH_NTLMAuth,
        )
        from nxc.modules._soaphound.ad.collectors.cert_find import run_cert_find

        host = connection.host
        domain = connection.domain
        username = connection.username

        # Conversion auth depuis le namespace _soapy vers _soaphound
        # (les classes ont le meme nom mais sont dans deux modules differents,
        #  l'isinstance interne de _soaphound.ADWSConnect echoue sans cette
        #  conversion -- voir module soaphound.py pour l'historique).
        soapy_auth = connection._auth
        soapy_auth_type = type(soapy_auth).__name__

        if soapy_auth_type == "KerberosAuth":
            auth = SH_KerberosAuth(kdc_host=getattr(soapy_auth, "kdc_host", None))
        elif soapy_auth_type == "NTLMAuth":
            if getattr(soapy_auth, "password", None) is not None:
                auth = SH_NTLMAuth(password=soapy_auth.password)
            else:
                auth = SH_NTLMAuth(hashes=soapy_auth.nt)
        else:
            context.log.fail(f"Unsupported auth type for cert-find: {soapy_auth_type}")
            return

        context.log.debug(f"Auth converted to _soaphound namespace: {type(auth).__name__}")

        # Recuperation RootDSE pour les naming contexts
        adws_resource = ADWSConnect(host, domain, username, auth, "Resource")
        ctxs = adws_resource.get_rootdse_contexts(adws_resource._fqdn, adws_resource._nmf)

        schema_dn = ctxs.get("schemaNamingContext")
        default_dn = ctxs.get("defaultNamingContext")
        config_dn = ctxs.get("configurationNamingContext")

        if not (schema_dn and default_dn and config_dn):
            context.log.fail("Could not retrieve naming contexts from RootDSE")
            return

        context.log.display(f"Domain naming contexts:")
        context.log.display(f"  default       = {default_dn}")
        context.log.display(f"  configuration = {config_dn}")

        # Connexion Enumeration (run_cert_find l'attend en parametre,
        # meme s'il ne s'en sert plus directement -- gardee pour compat).
        adws_enum = ADWSConnect(host, domain, username, auth, "Enumeration")

        if self.skip_web_probe:
            context.log.display("ESC8 web probe: DISABLED (SKIP_WEB_PROBE=true)")
        else:
            context.log.display("ESC8 web probe: enabled (set SKIP_WEB_PROBE=true to disable)")

        if self.ca_rpc:
            context.log.display("CA-RPC enrichment: enabled")

        context.log.display("Running cert-find collection ...")

        result = run_cert_find(
            adws_enum=adws_enum,
            resource_client=adws_resource,
            config_dn=config_dn,
            default_dn=default_dn,
            schema_dn=schema_dn,
            domain=domain,
            username=username,
            auth=auth,
            output_dir=out_dir,
            web_probe_force_epa=self.force_epa,
            web_probe_enabled=not self.skip_web_probe,
            ca_rpc_enabled=self.ca_rpc,
        )

        # Resume final
        if isinstance(result, dict):
            templates = result.get("Certificate Templates", {}) or {}
            cas = result.get("Certificate Authorities", {}) or {}
            n_templates = len(templates) if isinstance(templates, dict) else 0
            n_cas = len(cas) if isinstance(cas, dict) else 0
            context.log.success(f"Cert-find completed: {n_cas} CA(s), {n_templates} template(s)")
        else:
            context.log.success("Cert-find completed")

        context.log.display(f"Output saved to: {out_dir}")
