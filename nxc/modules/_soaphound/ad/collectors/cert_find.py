import json
import logging
import os
import re
import socket
import ssl
import time
import unicodedata
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from uuid import UUID

from impacket.ldap.ldaptypes import LDAP_SID

from ...ad.acls import (
    ACCESS_ALLOWED_OBJECT_ACE,
    SecurityDescriptor,
)
from ...ad.cache_gen import filetime_to_unix, pull_all_ad_objects
from ...lib.utils import ADUtils

try:
    import requests
except Exception:
    requests = None

try:
    from requests_ntlm import HttpNtlmAuth
except Exception:
    HttpNtlmAuth = None

try:
    from cryptography import x509
except Exception:
    x509 = None

ENROLL_GUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
ALL_EXTENDED_RIGHTS_GUID = "00000000-0000-0000-0000-000000000000"

# CA management extended right GUIDs (used in _parse_ca_acl)
MANAGE_CA_GUID = "6e9c1a4e-fd75-4e42-a5f5-3d0cc87a6fc7"
MANAGE_CERTS_GUID = "4607af17-85dc-4660-b0b0-3e5bcf578b2c"

GENERIC_ALL_BIT = 0x10000000
GENERIC_WRITE_BIT = 0x40000000

GENERIC_ALL_MASK = 0xF01FF
GENERIC_WRITE_MASK = 0x20028
WRITE_OWNER_MASK = 0x80000
WRITE_DACL_MASK = 0x40000
WRITE_PROPERTY_MASK = 0x20
EXTENDED_RIGHT_MASK = 0x100

WEB_PROBE_TIMEOUT = 5
WEB_PROBE_READ_BYTES = 8192  # [PATCH 3] read more bytes to detect SSL-required pages
CERTSRV_PATH = "/certsrv/"

ANY_PURPOSE_OID = "2.5.29.37.0"
CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4",
}
ENROLLMENT_AGENT_EKUS = {
    "1.3.6.1.4.1.311.20.2.1",
}

OID_FRIENDLY_NAMES = {
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "2.5.29.37.0": "Any Purpose",
}

CERT_NAME_FLAG_MAP = OrderedDict([
    (0x00000001, "EnrolleeSuppliesSubject"),
    (0x00000002, "AddEmail"),
    (0x00000004, "AddObjGuid"),
    (0x00000100, "AddDirectoryPath"),
    (0x00010000, "EnrolleeSuppliesSubjectAltName"),
    (0x00400000, "SubjectAltRequireDomainDns"),
    (0x00800000, "SubjectAltRequireSpn"),
    (0x01000000, "SubjectAltRequireDirectoryGuid"),
    (0x02000000, "SubjectAltRequireUpn"),
    (0x04000000, "SubjectAltRequireEmail"),
    (0x08000000, "SubjectAltRequireDns"),
    (0x10000000, "SubjectRequireDnsAsCn"),
    (0x20000000, "SubjectRequireEmail"),
    (0x40000000, "SubjectRequireCommonName"),
    (0x80000000, "SubjectRequireDirectoryPath"),
])

ENROLLMENT_FLAG_MAP = OrderedDict([
    (0x00000001, "IncludeSymmetricAlgorithms"),
    (0x00000002, "PendAllRequests"),
    (0x00000004, "PublishToKraContainer"),
    (0x00000008, "PublishToDs"),
    (0x00000010, "AutoEnrollmentCheckUserDsCertificate"),
    (0x00000020, "AutoEnrollment"),
    (0x00000040, "PreviousApprovalValidateReenrollment"),
    (0x00000080, "DomainAuthenticationNotRequired"),
    (0x00000100, "UserInteractionRequired"),
    (0x00000200, "AddTemplateName"),
    (0x00000400, "RemoveInvalidCertificateFromPersonalStore"),
    (0x00000800, "AllowEnrollOnBehalfOf"),
    (0x00001000, "AddOcspNocheck"),
    (0x00002000, "EnableKeyReuseOnNtTokenKeysetStorageFull"),
    (0x00004000, "Norevocationinfoinissuedcerts"),
    (0x00008000, "IncludeBasicConstraintsForEeCerts"),
    (0x00010000, "AllowPreviousApprovalKeybasedrenewalValidateReenrollment"),
    (0x00020000, "IssuancePoliciesFromRequest"),
    (0x00040000, "SkipAutoRenewal"),
    (0x00080000, "NoSecurityExtension"),
])

PRIVATE_KEY_FLAG_MAP = OrderedDict([
    (0x00000001, "RequirePrivateKeyArchival"),
    (0x00000010, "ExportableKey"),
    (0x00000020, "StrongKeyProtectionRequired"),
    (0x00000040, "RequireAlternateSignatureAlgorithm"),
    (0x00000080, "RequireSameKeyRenewal"),
    (0x00000100, "UseLegacyProvider"),
    (0x00000200, "EkTrustOnUse"),
    (0x00000400, "EkValidateCert"),
    (0x00000800, "EkValidateKey"),
    (0x00001000, "AttestPreferred"),
    (0x00002000, "AttestRequired"),
    (0x00004000, "AttestationWithoutPolicy"),
    (0x00200000, "HelloLogonKey"),
])

LOWPRIV_WELLKNOWN_SIDS = {
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-545",
}

# editFlags bits for CA-level vulnerability detection
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # ESC6: user can specify arbitrary SAN
CA_EDITFLAG_PEND_ALL = 0x00000002            # legacy/fallback only
CA_REQUEST_DISPOSITION_PENDING = 0x00000100  # RequestDisposition policy module value
IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200   # InterfaceFlags: require encrypted ICertRequest RPC

OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
CA_SD_FLAGS = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

DISPLAY_KEY_WIDTH = 36


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_value(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _hostname_resolves(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except Exception:
        return False


def _parse_ca_certificate_info(ca: dict) -> dict:
    info = {"serial_number": None, "validity_start": None, "validity_end": None}
    cert_blob = _first_value(ca.get("cACertificate"))
    if not cert_blob or not isinstance(cert_blob, (bytes, bytearray)):
        return info
    if x509 is None:
        return info
    try:
        cert = x509.load_der_x509_certificate(bytes(cert_blob))
        info["serial_number"] = format(cert.serial_number, "X").upper()
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=timezone.utc)
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
        info["validity_start"] = str(not_before)
        info["validity_end"] = str(not_after)
    except Exception as e:
        logging.debug("Failed to parse CA certificate info: %s", e)
    return info


def _decode_flags(value: int, mapping: OrderedDict) -> list[str]:
    return [name for bit, name in mapping.items() if value & bit]


def _friendly_name(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="ignore")
        except Exception:
            value = repr(value)
    value = str(value)
    return OID_FRIENDLY_NAMES.get(value, value)


def _friendly_oids(values: list[Any]) -> list[str]:
    return [_friendly_name(v) for v in values]


def _format_period_from_bytes(raw: Any) -> str | None:
    if not isinstance(raw, bytes) or len(raw) != 8:
        return None
    try:
        ticks = abs(int.from_bytes(raw, byteorder="little", signed=True))
        days = int((ticks / 10_000_000) // 86400)
        if days % 365 == 0 and days >= 365:
            years = days // 365
            return f"{years} year" if years == 1 else f"{years} years"
        if days % 7 == 0 and days >= 7:
            weeks = days // 7
            return f"{weeks} week" if weeks == 1 else f"{weeks} weeks"
        if days == 1:
            return "1 day"
        return f"{days} days"
    except Exception:
        return None


def _format_when(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, str) and value.endswith("Z") and "." in value:
        try:
            if value.endswith(".0Z"):
                dt = datetime.strptime(value, "%Y%m%d%H%M%S.0Z").replace(tzinfo=timezone.utc)
                return dt.isoformat()
        except Exception:
            pass
    try:
        ts = filetime_to_unix(value)
        if ts:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return str(value)


def _resolve_names(sids: set[str], sid_to_name: dict[str, str]) -> list[str]:
    return [sid_to_name.get(sid, sid) for sid in sorted(sids)]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _norm_dn(dn) -> str:
    if not dn:
        return ""
    if isinstance(dn, (list, tuple)):
        dn = dn[0] if dn else ""
    if not dn:
        return ""
    normalized = unicodedata.normalize("NFKC", str(dn)).upper()
    return re.sub(r'\s*,\s*', ',', normalized)


def _domain_from_dn(dn: str | None) -> str:
    if not dn:
        return ""
    try:
        return ADUtils.ldap2domain(dn)
    except Exception:
        return ""


def _ldap_escape(value: str) -> str:
    if value is None:
        return ""
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def _sid_bytes_to_str(value: Any) -> str | None:
    try:
        if isinstance(value, bytes):
            return LDAP_SID(value).formatCanonical()
        if isinstance(value, str) and value.upper().startswith("S-1-"):
            return value.upper()
    except Exception:
        return None
    return None


def _guid_to_str(value: Any) -> str | None:
    try:
        if isinstance(value, bytes):
            return str(UUID(bytes_le=value)).upper()
        if isinstance(value, str):
            v = value.strip("{}")
            if len(v) == 36:
                return v.upper()
    except Exception:
        return None
    return None


def _principal_display_name(entry: dict, fallback_domain: str) -> str:
    sid = _sid_bytes_to_str(entry.get("objectSid"))
    if sid in ADUtils.WELLKNOWN_SIDS:
        return f"{ADUtils.WELLKNOWN_SIDS[sid][0].upper()}@{fallback_domain.upper()}"
    sam = entry.get("sAMAccountName")
    classes = [str(x).lower() for x in _as_list(entry.get("objectClass"))]
    domain = _domain_from_dn(entry.get("distinguishedName")) or fallback_domain
    if sam:
        sam = str(sam)
        if "computer" in classes or sam.endswith("$"):
            return f"{sam.rstrip('$').upper()}.{domain.upper()}"
        return f"{sam.upper()}@{domain.upper()}"
    name = entry.get("name") or entry.get("cn")
    if name:
        return f"{str(name).upper()}@{domain.upper()}"
    dn = entry.get("distinguishedName")
    if dn:
        return str(dn)
    return sid or "UNKNOWN"


def _pretty_name_token(token: str) -> str:
    acronym_words = {"RAS", "IAS", "DNS", "KDC", "EFS", "OCSP", "IPSEC", "CA", "PKI", "LDAP", "LDAPS"}
    lower_words = {"AND", "OF", "THE", "FOR", "TO", "IN"}
    up = token.upper()
    if up in acronym_words:
        return up
    if up == "READ-ONLY":
        return "Read-only"
    if up in lower_words:
        return up.lower()
    return up.capitalize()


def _pretty_account_name(name: str) -> str:
    parts = str(name).split(" ")
    return " ".join(_pretty_name_token(part) for part in parts)


def _certipy_principal(value: Any) -> str:
    if value is None:
        return "None"
    value = str(value)
    if value.startswith("S-1-"):
        return value
    if "\\" in value:
        return value
    if "@" in value:
        left, right = value.split("@", 1)
        return f"{right.upper()}\\{_pretty_account_name(left)}"
    return value


def _certipy_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if value is None:
        return "None"
    if isinstance(value, str):
        return _certipy_principal(value)
    return str(value)


def _normalize_headers(headers: Any) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    if headers is None:
        return normalized
    try:
        items = list(headers.items())
    except Exception:
        return normalized
    for key, value in items:
        lk = str(key).lower()
        normalized.setdefault(lk, []).append(str(value))
    return normalized


def _get_header_values(resp: dict, header_name: str) -> list[str]:
    return resp.get("headers", {}).get(header_name.lower(), [])


def _join_header_values(resp: dict, header_name: str) -> str:
    return ", ".join(_get_header_values(resp, header_name))


def _extract_cleartext_password(auth: Any) -> str | None:
    if auth is None:
        return None
    if isinstance(auth, str):
        return auth
    if isinstance(auth, dict):
        for key in ("password", "secret", "passwd", "passphrase"):
            value = auth.get(key)
            if isinstance(value, str) and value:
                return value
        return None
    for attr in ("password", "secret", "passwd", "passphrase", "_password", "_secret"):
        try:
            value = getattr(auth, attr)
            if isinstance(value, str) and value:
                return value
        except Exception:
            pass
    return None


def _build_ntlm_username(domain: str, username: str) -> str:
    if "\\" in username or "@" in username:
        return username
    return f"{domain}\\{username}"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_301(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_303(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_307(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    def http_error_308(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def _fetch_url(url: str, verify_ssl: bool = True, follow_redirects: bool = False) -> dict:
    result = {
        "url": url, "reachable": False, "status": None,
        "final_url": url, "body": "", "headers": {}, "error": None,
    }
    req = urllib.request.Request(url, headers={"User-Agent": "Soaphound/1.0"})
    context = None
    if url.lower().startswith("https://") and not verify_ssl:
        context = ssl._create_unverified_context()

    if follow_redirects:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context)) if context else urllib.request.build_opener()
    else:
        if context:
            opener = urllib.request.build_opener(_NoRedirectHandler(), urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener(_NoRedirectHandler())

    try:
        response = opener.open(req, timeout=WEB_PROBE_TIMEOUT)
        # [PATCH 3] Read more bytes to detect SSL-required pages reliably
        body = response.read(WEB_PROBE_READ_BYTES)
        result["reachable"] = True
        result["status"] = getattr(response, "status", response.getcode())
        result["final_url"] = response.geturl()
        result["headers"] = _normalize_headers(response.headers)
        result["body"] = body.decode("utf-8", errors="ignore")
        return result
    except urllib.error.HTTPError as e:
        try:
            body = e.read(WEB_PROBE_READ_BYTES)
            body = body.decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        location = ""
        try:
            location = e.headers.get("Location") or ""
        except Exception:
            pass
        result["reachable"] = True
        result["status"] = e.code
        result["final_url"] = location if (e.code in (301, 302, 303, 307, 308) and location) else e.geturl()
        result["headers"] = _normalize_headers(e.headers)
        result["body"] = body
        result["error"] = f"HTTP {e.code}"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def _body_contains_certsrv_markers(body: str) -> bool:
    if not body:
        return False
    body_l = body.lower()
    markers = ["/certsrv/", "certsrv", "active directory certificate services",
               "certificate services", "certfnsh.asp", "certrqxt.asp", "certnew.cer"]
    return any(marker in body_l for marker in markers)


def _body_indicates_ssl_required(body: str) -> bool:
    if not body:
        return False
    body_l = body.lower()
    markers = [
        "secure sockets layer", "ssl is required", "requires ssl",
        "the page you are trying to access is secured with secure sockets layer",
        "http error 403.4", 'use the "https:" prefix', "request from a secure channel",
    ]
    return any(marker in body_l for marker in markers)


def _looks_like_ssl_required(resp: dict) -> bool:
    return resp.get("status") == 403 and _body_indicates_ssl_required(resp.get("body") or "")


def _looks_like_certsrv(resp: dict) -> bool:
    """Return True when a response is likely the AD CS Web Enrollment endpoint.

    This helper is intentionally permissive for HTTPS detection: a `/certsrv/` URL
    protected by NTLM/Negotiate usually returns a 401 with an empty body before
    authentication, but still means the endpoint exists. Do not use it directly to
    mark HTTP ESC8 as vulnerable; `_http_web_enrollment_enabled()` is stricter.
    """
    body = resp.get("body") or ""
    final_url = (resp.get("final_url") or "").lower()
    auth_headers = _join_header_values(resp, "www-authenticate").lower()
    source_url = (resp.get("url") or "").lower()
    if _body_contains_certsrv_markers(body):
        return True
    if "/certsrv" in final_url or "/certsrv" in source_url:
        return True
    if any(x in auth_headers for x in ("ntlm", "negotiate")) and "/certsrv/" in source_url:
        return True
    return False


def _http_web_enrollment_enabled(resp: dict) -> bool:
    """Return True only when Web Enrollment is confirmed over cleartext HTTP.

    Certipy is conservative here: a bare HTTP 401/403 on `/certsrv/`, especially
    with an empty body, is not enough to claim ESC8 over HTTP. IIS may challenge
    before returning an SSL-required page, or the request may be routed through
    a hardened binding. To avoid false positives, HTTP is considered enabled only
    when the cleartext response body actually contains AD CS Web Enrollment
    markers and the response is not an SSL-required page or redirect to HTTPS.
    """
    if not resp.get("reachable"):
        return False

    status = resp.get("status")
    final_url = (resp.get("final_url") or "").lower()
    body = resp.get("body") or ""

    if final_url.startswith("https://"):
        return False
    if status in (301, 302, 303, 307, 308):
        return False
    if _looks_like_ssl_required(resp):
        return False

    # Strict confirmation: do not rely on the requested /certsrv/ URL alone.
    if status in (200, 401, 403) and _body_contains_certsrv_markers(body):
        return True

    return False


def _https_web_enrollment_enabled(resp: dict) -> bool:
    if not resp.get("reachable"):
        return False
    status = resp.get("status")
    if status in (200, 401, 403) and _looks_like_certsrv(resp):
        return True
    if status in (301, 302, 307, 308) and "/certsrv" in (resp.get("final_url") or "").lower():
        return True
    return False


def _try_detect_https_epa(https_url: str, username: str, domain: str, auth: Any) -> tuple[str | bool, str | None]:
    if requests is None or HttpNtlmAuth is None:
        return "Unknown", "requests / requests_ntlm not available for HTTPS NTLM auth test"
    password = _extract_cleartext_password(auth)
    if not password:
        return "Unknown", "cleartext password not available for EPA test"
    ntlm_username = _build_ntlm_username(domain, username)
    try:
        session = requests.Session()
        response = session.get(
            https_url, auth=HttpNtlmAuth(ntlm_username, password),
            verify=False, allow_redirects=True, timeout=WEB_PROBE_TIMEOUT,
            headers={"User-Agent": "Soaphound/1.0"},
        )
        history_codes = [r.status_code for r in response.history]
        final_code = response.status_code
        if final_code in (200, 403):
            return False, None
        if 401 in history_codes and final_code not in (401, 407):
            return False, None
        if final_code == 401:
            return "Unknown", "HTTPS NTLM auth incomplete; EPA may be required or auth failed"
        return "Unknown", f"Unexpected HTTPS response after NTLM attempt: {final_code}"
    except Exception as e:
        return "Unknown", str(e)


def probe_ca_web_enrollment(ca: dict, username: str, auth: Any, domain: str, force_epa: bool | None = None) -> None:
    dns_host = ca.get("dNSHostName")
    dns_host = str(dns_host).strip() if dns_host else None

    vulnerabilities = ca.setdefault("vulnerabilities", OrderedDict())
    remarks = ca.setdefault("remarks", OrderedDict())

    if not dns_host:
        ca["web_enrollment"] = {
            "http_enabled": False, "https_enabled": False, "channel_binding": "Unknown",
            "http_url": None, "https_url": None,
            "http_probe_error": "CA has no dNSHostName",
            "https_probe_error": "CA has no dNSHostName",
            "channel_binding_error": None, "selected_host": None, "tested_hosts": [],
        }
        return

    if not _hostname_resolves(dns_host):
        ca["web_enrollment"] = {
            "http_enabled": False, "https_enabled": False, "channel_binding": "Unknown",
            "http_url": f"http://{dns_host}{CERTSRV_PATH}",
            "https_url": f"https://{dns_host}{CERTSRV_PATH}",
            "http_probe_error": f"Name resolution failed for {dns_host}",
            "https_probe_error": f"Name resolution failed for {dns_host}",
            "channel_binding_error": None, "selected_host": dns_host, "tested_hosts": [dns_host],
        }
        return

    http_url = f"http://{dns_host}{CERTSRV_PATH}"
    https_url = f"https://{dns_host}{CERTSRV_PATH}"

    http_resp = _fetch_url(http_url, verify_ssl=False)
    https_resp = _fetch_url(https_url, verify_ssl=False)

    http_enabled = _http_web_enrollment_enabled(http_resp)
    https_enabled = _https_web_enrollment_enabled(https_resp)

    channel_binding: str | bool = "Unknown"
    channel_binding_error: str | None = None

    if force_epa is True:
        channel_binding = True
    elif force_epa is False:
        channel_binding = False
    elif https_enabled:
        channel_binding, channel_binding_error = _try_detect_https_epa(
            https_url=https_url, username=username, domain=domain, auth=auth,
        )

    if http_enabled:
        vulnerabilities["ESC8"] = "Web Enrollment is enabled over HTTP."
    elif https_enabled and channel_binding is False:
        vulnerabilities["ESC8"] = "Web Enrollment is enabled over HTTPS and Channel Binding (EPA) is disabled."
    elif https_enabled and channel_binding == "Unknown":
        # [PATCH 3] Match exact Certipy remarks message
        remarks["ESC8"] = (
            "Channel Binding couldn't be verified for HTTPS Web Enrollment. "
            "For manual verification, request a certificate via HTTPS with Channel Binding disabled "
            "and observe if the request succeeds or is rejected."
        )

    ca["web_enrollment"] = {
        "http_enabled": http_enabled,
        "https_enabled": https_enabled,
        "channel_binding": channel_binding,
        "http_url": http_url,
        "https_url": https_url,
        "http_probe_error": http_resp.get("error"),
        "https_probe_error": https_resp.get("error"),
        "channel_binding_error": channel_binding_error,
        "selected_host": dns_host,
        "tested_hosts": [dns_host],
    }


def process_ca_flags(ca: dict) -> None:
    raw = ca.get("editFlags")
    if raw is None:
        ca.setdefault("user_specified_san", "Unknown")
    else:
        try:
            flags = int(_first_value(raw) if isinstance(raw, list) else raw)
            ca["user_specified_san"] = bool(flags & EDITF_ATTRIBUTESUBJECTALTNAME2)
        except (ValueError, TypeError):
            ca.setdefault("user_specified_san", "Unknown")

    # Certipy reads RequestDisposition from the CA policy module registry key.
    # It is not the same value as editFlags. Keep Unknown in ADWS/LDAP-only mode.
    if ca.get("RequestDisposition") is not None:
        try:
            request_disposition = int(_first_value(ca.get("RequestDisposition")))
            ca["request_disposition"] = (
                "Pending" if (request_disposition & CA_REQUEST_DISPOSITION_PENDING) else "Issue"
            )
        except (ValueError, TypeError):
            ca.setdefault("request_disposition", "Unknown")
    elif ca.get("request_disposition") is None:
        ca["request_disposition"] = "Unknown"

    if ca.get("InterfaceFlags") is not None:
        try:
            interface_flags = int(_first_value(ca.get("InterfaceFlags")))
            ca["enforce_encrypt_icertrequest"] = bool(interface_flags & IF_ENFORCEENCRYPTICERTREQUEST)
        except (ValueError, TypeError):
            ca.setdefault("enforce_encrypt_icertrequest", "Unknown")


def evaluate_ca(ca: dict, sid_to_name: dict[str, str], user_sids: set[str]) -> None:
    process_ca_flags(ca)
    vulnerabilities = ca.setdefault("vulnerabilities", OrderedDict())

    if ca.get("user_specified_san") is True:
        vulnerabilities["ESC6"] = (
            "The CA allows enrollees to specify a Subject Alternative Name (SAN), "
            "which can be abused for privilege escalation if any template allows client authentication."
        )

    ntsd_bytes = ca.get("nTSecurityDescriptor")
    if isinstance(ntsd_bytes, bytes):
        ca_acl = _parse_ca_acl(ntsd_bytes)
        ca["ca_acl"] = ca_acl
        dangerous_sids = (
            ca_acl.get("manage_ca_sids", set())
            | ca_acl.get("manage_certificates_sids", set())
            | ca_acl.get("genericall_sids", set())
            | ca_acl.get("write_owner_sids", set())
            | ca_acl.get("write_dacl_sids", set())
        )
        user_dangerous = dangerous_sids & user_sids
        if user_dangerous:
            principals = _resolve_names(user_dangerous, sid_to_name)
            vulnerabilities["ESC7"] = (
                f"Current user has dangerous rights on the CA object "
                f"({', '.join(principals)})."
            )



def _parse_sd_owner_sid(ntsd_bytes: bytes) -> str | None:
    """Parse and return only the owner SID from a security descriptor."""
    try:
        sd = SecurityDescriptor(BytesIO(ntsd_bytes))
        return str(sd.owner_sid)
    except Exception as exc:
        logging.debug("Failed to parse security descriptor owner: %s", exc)
        return None

def _parse_ca_acl(ntsd_bytes: bytes) -> dict:
    """
    [PATCH 1] Parse CA object nTSecurityDescriptor.
    Now extracts enroll_sids in addition to manage_ca, manage_certificates,
    genericall, write_owner, write_dacl — matching Certipy's Permissions output.
    """
    result = {
        "owner_sid": None,
        "manage_ca_sids": set(),
        "manage_certificates_sids": set(),
        "enroll_sids": set(),           # [PATCH 1] NEW
        "genericall_sids": set(),
        "write_owner_sids": set(),
        "write_dacl_sids": set(),
    }

    try:
        sd = SecurityDescriptor(BytesIO(ntsd_bytes))
    except Exception as e:
        logging.debug("Failed to parse CA security descriptor: %s", e)
        return result

    try:
        result["owner_sid"] = str(sd.owner_sid)
    except Exception:
        pass

    if not getattr(sd, "dacl", None):
        return result

    for ace in sd.dacl.aces:
        try:
            if ace.ace.AceType not in (0x00, 0x05):
                continue

            sid = str(ace.acedata.sid)

            try:
                mask = ace.acedata.mask["Mask"]
            except Exception:
                try:
                    mask = ace.acedata.mask.mask
                except Exception:
                    mask = int(ace.acedata.mask)

            if (mask & GENERIC_ALL_BIT) == GENERIC_ALL_BIT or (mask & GENERIC_ALL_MASK) == GENERIC_ALL_MASK:
                result["genericall_sids"].add(sid)

            if mask & WRITE_OWNER_MASK:
                result["write_owner_sids"].add(sid)

            if mask & WRITE_DACL_MASK:
                result["write_dacl_sids"].add(sid)

            if ace.ace.AceType == 0x05 and (mask & EXTENDED_RIGHT_MASK):
                object_guid = None
                if ace.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                    object_guid = ace.acedata.get_object_type()
                    if object_guid:
                        object_guid = object_guid.lower()

                if not object_guid or object_guid == ALL_EXTENDED_RIGHTS_GUID:
                    # All Extended Rights → has all CA rights
                    result["manage_ca_sids"].add(sid)
                    result["manage_certificates_sids"].add(sid)
                    result["enroll_sids"].add(sid)          # [PATCH 1]
                elif object_guid == MANAGE_CA_GUID:
                    result["manage_ca_sids"].add(sid)
                elif object_guid == MANAGE_CERTS_GUID:
                    result["manage_certificates_sids"].add(sid)
                elif object_guid == ENROLL_GUID:
                    result["enroll_sids"].add(sid)          # [PATCH 1]

            # Standard ACE with control access (type 0x00 + EXTENDED_RIGHT)
            if ace.ace.AceType == 0x00 and (mask & EXTENDED_RIGHT_MASK):
                # Without an object GUID we can't distinguish — add to all for safety
                result["manage_ca_sids"].add(sid)
                result["manage_certificates_sids"].add(sid)
                result["enroll_sids"].add(sid)              # [PATCH 1]

        except Exception as e:
            logging.debug("Failed to parse ACE on CA: %s", e)

    return result


# ---------------------------------------------------------------------------
# Directory map builders
# ---------------------------------------------------------------------------

def build_directory_maps(ip: str, domain: str, username: str, auth, default_dn: str) -> tuple[dict, dict]:
    query = (
        "(|"
        "(&(objectCategory=person)(objectClass=user))"
        "(objectCategory=group)"
        "(objectCategory=computer)"
        ")"
    )
    attributes = ["objectSid", "distinguishedName", "sAMAccountName", "name", "objectClass"]
    objs = pull_all_ad_objects(
        ip=ip, domain=domain, username=username, auth=auth,
        query=query, attributes=attributes, base_dn_override=default_dn,
    ).get("objects", [])

    sid_to_name: dict[str, str] = {}
    dn_to_name: dict[str, str] = {}
    for obj in objs:
        sid = _sid_bytes_to_str(obj.get("objectSid"))
        dn = _norm_dn(obj.get("distinguishedName"))
        name = _principal_display_name(obj, domain)
        if sid:
            sid_to_name[sid] = name
        if dn:
            dn_to_name[dn] = name
    for sid, (name, _) in ADUtils.WELLKNOWN_SIDS.items():
        sid_to_name.setdefault(sid, f"{name.upper()}@{domain.upper()}")
    return sid_to_name, dn_to_name


def collect_current_user_sids(ip: str, domain: str, username: str, auth, default_dn: str) -> tuple[set[str], str | None]:
    sam = username.split("\\")[-1].split("@")[0]
    user_query = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={_ldap_escape(sam)}))"
    user_attributes = ["objectSid", "distinguishedName", "sAMAccountName", "userPrincipalName", "primaryGroupID"]
    users = pull_all_ad_objects(
        ip=ip, domain=domain, username=username, auth=auth,
        query=user_query, attributes=user_attributes, base_dn_override=default_dn,
    ).get("objects", [])

    if not users:
        logging.warning("Unable to resolve current user in ADWS for cert-find. Falling back to well-known low-privilege groups only.")
        return set(LOWPRIV_WELLKNOWN_SIDS) | {"S-1-5-11"}, None

    user = users[0]
    user_dn = user.get("distinguishedName")
    user_sid = _sid_bytes_to_str(user.get("objectSid"))
    user_sids: set[str] = set()
    domain_sid: str | None = None

    if user_sid:
        user_sids.add(user_sid)
        if user_sid.startswith("S-1-5-21-") and user_sid.count("-") >= 4:
            domain_sid = "-".join(user_sid.split("-")[:-1])

    primary_group_id = user.get("primaryGroupID")
    try:
        if domain_sid and primary_group_id is not None:
            if isinstance(primary_group_id, list):
                primary_group_id = primary_group_id[0]
            user_sids.add(f"{domain_sid}-{int(primary_group_id)}")
    except Exception:
        pass

    if user_dn:
        group_query = f"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:={_ldap_escape(user_dn)}))"
        group_attributes = ["objectSid", "distinguishedName", "sAMAccountName", "name", "objectClass"]
        groups = pull_all_ad_objects(
            ip=ip, domain=domain, username=username, auth=auth,
            query=group_query, attributes=group_attributes, base_dn_override=default_dn,
        ).get("objects", [])
        for group in groups:
            sid = _sid_bytes_to_str(group.get("objectSid"))
            if sid:
                user_sids.add(sid)

    user_sids |= LOWPRIV_WELLKNOWN_SIDS
    user_sids.add("S-1-5-11")
    if domain_sid:
        user_sids.add(f"{domain_sid}-513")
    return user_sids, domain_sid


def collect_certificate_templates(ip: str, domain: str, username: str, auth, config_dn: str) -> list[dict]:
    # [PATCH 4] base_dn covers all standard templates; pull_all_ad_objects uses SUBTREE scope
    base_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}"
    attributes = [
        "cn", "name", "displayName",
        "pKIExpirationPeriod", "pKIOverlapPeriod",
        "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag",
        "msPKI-Certificate-Name-Flag", "msPKI-Certificate-Policy",
        "msPKI-Minimal-Key-Size", "msPKI-RA-Signature",
        "msPKI-Template-Schema-Version", "msPKI-RA-Application-Policies",
        "pKIExtendedKeyUsage", "nTSecurityDescriptor",
        "objectGUID", "whenCreated", "whenChanged",
        "distinguishedName", "objectClass",
    ]
    return pull_all_ad_objects(
        ip=ip, domain=domain, username=username, auth=auth,
        query="(objectClass=pKICertificateTemplate)",
        attributes=attributes, base_dn_override=base_dn,
    ).get("objects", [])


def collect_certificate_authorities(ip: str, domain: str, username: str, auth, config_dn: str) -> list[dict]:
    base_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}"
    attributes = [
        "cn", "name", "dNSHostName", "cACertificateDN", "cACertificate",
        "certificateTemplates", "objectGUID", "distinguishedName", "objectClass",
        # NOTE: editFlags are NOT requested here — they are CA registry/policy
        # values and are fetched only when --cert-find-ca-rpc is enabled.
        # nTSecurityDescriptor is fetched through ADWS below to
        # keep cert-find ADWS-only by default.
    ]
    return pull_all_ad_objects(
        ip=ip, domain=domain, username=username, auth=auth,
        query="(&(objectClass=pKIEnrollmentService))",
        attributes=attributes, base_dn_override=base_dn,
    ).get("objects", [])


def fetch_ca_security_descriptors_adws(ip: str, domain: str, username: str, auth, config_dn: str, cas: list[dict]) -> None:
    """
    Best-effort fallback for CA object nTSecurityDescriptor via ADWS.

    Some environments allow reading pKIEnrollmentService security descriptors through
    ADWS while others reject them. This function is intentionally isolated and only
    fills missing CA SDs, so a rejection does not break cert-find. CA registry values
    such as editFlags are still not expected to be available through ADWS.
    """
    if not cas:
        return

    base_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}"
    try:
        objects = pull_all_ad_objects(
            ip=ip, domain=domain, username=username, auth=auth,
            query="(objectClass=pKIEnrollmentService)",
            attributes=["cn", "name", "distinguishedName", "nTSecurityDescriptor"],
            base_dn_override=base_dn,
        ).get("objects", [])
    except Exception as exc:
        logging.debug("ADWS CA nTSecurityDescriptor fallback failed: %s", exc)
        return

    by_dn: dict[str, dict] = {}
    by_cn: dict[str, dict] = {}
    for obj in objects:
        dn = _norm_dn(obj.get("distinguishedName"))
        if dn:
            by_dn[dn] = obj
        for attr in ("cn", "name"):
            val = _first_value(obj.get(attr))
            if val:
                by_cn[unicodedata.normalize("NFKC", str(val)).upper()] = obj

    enriched = 0
    for ca in cas:
        if ca.get("nTSecurityDescriptor"):
            continue
        entry = by_dn.get(_norm_dn(ca.get("distinguishedName")))
        if entry is None:
            name = _first_value(ca.get("cn")) or _first_value(ca.get("name")) or ca.get("CA Name")
            if name:
                entry = by_cn.get(unicodedata.normalize("NFKC", str(name)).upper())
        if not entry:
            continue
        sd = entry.get("nTSecurityDescriptor")
        if isinstance(sd, list):
            sd = sd[0] if sd else None
        if isinstance(sd, bytes):
            ca["nTSecurityDescriptor"] = sd
            enriched += 1

    if enriched:
        logging.info("CA ADWS nTSecurityDescriptor fallback: enriched=%d/%d", enriched, len(cas))

def _rrp_query_value(dce, key_handle, value_name: str) -> Any:
    from impacket.dcerpc.v5 import rrp
    _reg_type, value = rrp.hBaseRegQueryValue(dce, key_handle, value_name)
    if isinstance(value, str):
        return value.rstrip("\x00")
    return value


def _normalise_registry_multistring(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).rstrip("\x00") for v in value if str(v).rstrip("\x00")]
    if isinstance(value, str):
        return [item for item in value.rstrip("\x00").split("\x00") if item]
    return []


def _rpc_lm_nt_hashes(auth: Any) -> tuple[str, str]:
    raw = getattr(auth, "nt", None) or getattr(auth, "hashes", None) or getattr(auth, "nt_hash", None) or ""
    lm_hash = getattr(auth, "lm_hash", None) or ""
    nt_hash = getattr(auth, "nt_hash", None) or ""
    if raw:
        raw = str(raw)
        if ":" in raw:
            lm_hash, nt_hash = raw.split(":", 1)
        else:
            nt_hash = raw
    if nt_hash and not lm_hash:
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
    return lm_hash or "", nt_hash or ""


def _rpc_username_domain(username: str, domain: str) -> tuple[str, str]:
    if not username:
        return "", domain
    username = str(username)
    if "\\" in username:
        user_domain, user = username.split("\\", 1)
        return user, user_domain
    if "@" in username:
        user, user_domain = username.rsplit("@", 1)
        return user, user_domain
    return username, domain


def _rrp_to_int(value: Any, default: int | None = None) -> int | None:
    """Normalize Impacket RRP REG_DWORD representations."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        if len(value) >= 4:
            return int.from_bytes(value[:4], "little", signed=False)
        if len(value) > 0:
            return int.from_bytes(value, "little", signed=False)
        return default
    if isinstance(value, (list, tuple)):
        if all(isinstance(x, int) for x in value):
            data = bytes(value)
            if len(data) >= 4:
                return int.from_bytes(data[:4], "little", signed=False)
            if data:
                return int.from_bytes(data, "little", signed=False)
            return default
        if len(value) == 1:
            return _rrp_to_int(value[0], default)
    try:
        return int(value)
    except Exception:
        return default


def _rrp_to_str(value: Any, default: str | None = None) -> str | None:
    """Normalize Impacket RRP REG_SZ / REG_MULTI_SZ representations."""
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip("\x00")
    if isinstance(value, bytes):
        for enc in ("utf-16le", "utf-8", "latin-1"):
            try:
                out = value.decode(enc).strip("\x00")
                if out:
                    return out
            except Exception:
                pass
        return default
    if isinstance(value, (list, tuple)):
        if all(isinstance(x, int) for x in value):
            return _rrp_to_str(bytes(value), default)
        if len(value) == 1:
            return _rrp_to_str(value[0], default)
        return "\x00".join(str(x).strip("\x00") for x in value if str(x).strip("\x00"))
    return str(value).strip("\x00")


def _rrp_to_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        if all(isinstance(x, int) for x in value):
            return bytes(value)
        if len(value) == 1:
            return _rrp_to_bytes(value[0])
    return None


def _make_rrp_transport(host: str, remote_name: str, domain: str, username: str, auth: Any, timeout: float):
    """Create an Impacket RRP transport in the same style Certipy uses."""
    from impacket.dcerpc.v5 import transport

    rpc = transport.DCERPCTransportFactory(r"ncacn_np:445[\pipe\winreg]")
    try:
        rpc.set_connect_timeout(timeout)
    except Exception:
        pass
    if hasattr(rpc, "setRemoteHost"):
        rpc.setRemoteHost(host)
    if hasattr(rpc, "setRemoteName"):
        rpc.setRemoteName(remote_name)

    user, user_domain = _rpc_username_domain(username, domain)
    lm_hash, nt_hash = _rpc_lm_nt_hashes(auth)
    password = getattr(auth, "password", None) or ""
    if hasattr(rpc, "set_credentials"):
        rpc.set_credentials(user, password, user_domain, lm_hash, nt_hash)
    return rpc


def fetch_ca_config_rrp(ip: str, domain: str, username: str, auth, cas: list[dict], timeout: float = 5.0) -> None:
    """
    Optional Remote Registry/RPC enrichment for CA runtime configuration.

    Mirrors Certipy's RRP flow: bind to ncacn_np:445[\\pipe\\winreg], use the
    CA DNS name as SMB remote_name, use the collection target/IP as transport
    host, retry while RemoteRegistry starts, and read the same CertSvc keys.
    """
    if not cas:
        return

    try:
        from impacket.dcerpc.v5 import rrp
    except Exception as exc:
        logging.warning("Impacket RRP is not available; CA-RPC enrichment skipped: %s", exc)
        return

    enriched = 0
    for ca in cas:
        ca_name = _first_value(ca.get("name")) or _first_value(ca.get("cn")) or ca.get("CA Name")
        dns_host = _first_value(ca.get("dNSHostName")) or ip
        if not ca_name or not dns_host:
            logging.debug("Skipping CA-RPC enrichment for CA without name or host: %r", ca)
            continue

        host_candidates = []
        for candidate in (ip, dns_host):
            if candidate and str(candidate) not in host_candidates:
                host_candidates.append(str(candidate))

        last_error = None
        for host in host_candidates:
            dce = None
            h_root_key = None
            handles_to_close = []
            try:
                logging.debug(
                    "Trying CA-RPC/RRP enrichment for %s through host=%r remote_name=%r",
                    ca_name, host, dns_host,
                )
                rpc = _make_rrp_transport(host, str(dns_host), domain, username, auth, timeout)
                dce = rpc.get_dce_rpc()

                for attempt in range(3):
                    try:
                        dce.connect()
                        dce.bind(rrp.MSRPC_UUID_RRP)
                        break
                    except Exception as exc:
                        last_error = exc
                        if "STATUS_PIPE_NOT_AVAILABLE" in str(exc) and attempt < 2:
                            logging.warning(
                                "Failed to connect to remote registry. Service should be starting now. Trying again..."
                            )
                            time.sleep(2)
                            continue
                        raise

                hklm = rrp.hOpenLocalMachine(dce)
                h_root_key = hklm["phKey"]

                base_path = f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca_name}"
                policy_modules_path = base_path + "\\PolicyModules"

                policy_modules_key = rrp.hBaseRegOpenKey(dce, h_root_key, policy_modules_path)
                handles_to_close.append(policy_modules_key["phkResult"])
                _, active_policy_raw = rrp.hBaseRegQueryValue(dce, policy_modules_key["phkResult"], "Active")
                active_policy = _rrp_to_str(active_policy_raw, "CertificateAuthority_MicrosoftDefault.Policy")
                if not active_policy:
                    active_policy = "CertificateAuthority_MicrosoftDefault.Policy"
                ca["active_policy"] = active_policy

                policy_path = policy_modules_path + "\\" + active_policy
                policy_key = rrp.hBaseRegOpenKey(dce, h_root_key, policy_path)
                handles_to_close.append(policy_key["phkResult"])

                _, edit_flags_raw = rrp.hBaseRegQueryValue(dce, policy_key["phkResult"], "EditFlags")
                edit_flags = _rrp_to_int(edit_flags_raw, 0)
                if edit_flags is not None:
                    ca["editFlags"] = edit_flags

                _, request_disposition_raw = rrp.hBaseRegQueryValue(dce, policy_key["phkResult"], "RequestDisposition")
                request_disposition = _rrp_to_int(request_disposition_raw, 0)
                if request_disposition is not None:
                    ca["RequestDisposition"] = request_disposition

                try:
                    _, disable_extension_raw = rrp.hBaseRegQueryValue(dce, policy_key["phkResult"], "DisableExtensionList")
                    ca["DisableExtensionList"] = _normalise_registry_multistring(_rrp_to_str(disable_extension_raw, "") or "")
                except Exception as exc:
                    logging.debug("Could not read DisableExtensionList for %s: %s", ca_name, exc)

                config_key = rrp.hBaseRegOpenKey(dce, h_root_key, base_path)
                handles_to_close.append(config_key["phkResult"])

                _, interface_flags_raw = rrp.hBaseRegQueryValue(dce, config_key["phkResult"], "InterfaceFlags")
                interface_flags = _rrp_to_int(interface_flags_raw, 0)
                if interface_flags is not None:
                    ca["InterfaceFlags"] = interface_flags

                _, security_raw = rrp.hBaseRegQueryValue(dce, config_key["phkResult"], "Security")
                security = _rrp_to_bytes(security_raw)
                if security:
                    # Keep the AD pKIEnrollmentService nTSecurityDescriptor intact.
                    # It contains the CA Access Rights (ManageCa, ManageCertificates, Enroll).
                    # The registry/RRP Security value is still useful, but only for the
                    # runtime CA owner displayed by Certipy.
                    ca["ca_runtime_security"] = security
                    runtime_owner_sid = _parse_sd_owner_sid(security)
                    if runtime_owner_sid:
                        ca["ca_runtime_owner_sid"] = runtime_owner_sid

                process_ca_flags(ca)
                enriched += 1
                logging.info(
                    "Successfully retrieved CA configuration for %r via RRP: Active Policy=%r EditFlags=%r RequestDisposition=%r InterfaceFlags=%r",
                    ca_name, ca.get("active_policy"), ca.get("editFlags"),
                    ca.get("RequestDisposition"), ca.get("InterfaceFlags"),
                )
                last_error = None
                break
            except Exception as exc:
                last_error = exc
                logging.warning("CA-RPC/RRP enrichment failed for %r via host %r: %s", ca_name, host, exc)
            finally:
                if dce is not None:
                    for handle in reversed(handles_to_close):
                        try:
                            rrp.hBaseRegCloseKey(dce, handle)
                        except Exception:
                            pass
                    try:
                        if h_root_key is not None:
                            rrp.hBaseRegCloseKey(dce, h_root_key)
                    except Exception:
                        pass
                    try:
                        dce.disconnect()
                    except Exception:
                        pass

        if last_error is not None:
            logging.warning("Could not retrieve CA configuration for %r via RRP: %s", ca_name, last_error)

    logging.info("CA-RPC configuration enrichment: enriched=%d/%d", enriched, len(cas))

def collect_issuance_policies(ip: str, domain: str, username: str, auth, config_dn: str) -> list[dict]:
    base_dn = f"CN=OID,CN=Public Key Services,CN=Services,{config_dn}"
    attributes = [
        "cn", "name", "displayName", "msDS-OIDToGroupLink",
        "msPKI-Cert-Template-OID", "nTSecurityDescriptor",
        "objectGUID", "distinguishedName", "objectClass",
    ]
    return pull_all_ad_objects(
        ip=ip, domain=domain, username=username, auth=auth,
        query="(objectClass=msPKI-Enterprise-Oid)",
        attributes=attributes, base_dn_override=base_dn,
    ).get("objects", [])


def link_cas_and_templates(cas: list[dict], templates: list[dict]) -> int:
    for tpl in templates:
        tpl["enabled"] = False
        tpl["cas"] = []
        tpl["cas_ids"] = []
    template_by_name = {}
    for tpl in templates:
        name = tpl.get("name")
        if name:
            template_by_name[str(name).lower()] = tpl
    enabled_count = 0
    for ca in cas:
        ca_guid = _guid_to_str(ca.get("objectGUID"))
        for tpl_name in _as_list(ca.get("certificateTemplates")):
            tpl = template_by_name.get(str(tpl_name).lower())
            if tpl is None:
                continue
            tpl["enabled"] = True
            tpl["cas"].append(ca.get("name"))
            if ca_guid:
                tpl["cas_ids"].append(ca_guid)
            enabled_count += 1
    return enabled_count


def link_templates_and_policies(templates: list[dict], oids: list[dict], dn_to_name: dict[str, str]) -> int:
    enabled_links = 0
    oid_by_value = {}
    for oid in oids:
        tpl_oid = oid.get("msPKI-Cert-Template-OID")
        if tpl_oid:
            oid_by_value[str(tpl_oid)] = oid
    for tpl in templates:
        tpl["issuance_policies_linked_groups"] = []
        for policy in _as_list(tpl.get("msPKI-Certificate-Policy")):
            oid = oid_by_value.get(str(policy))
            if oid is None:
                continue
            enabled_links += 1
            linked_group_dn = oid.get("msDS-OIDToGroupLink")
            if linked_group_dn:
                tpl["issuance_policies_linked_groups"].append(
                    dn_to_name.get(_norm_dn(linked_group_dn), str(linked_group_dn))
                )
    return enabled_links


def process_template_flags(template: dict) -> None:
    name_flag = int(template.get("msPKI-Certificate-Name-Flag") or 0)
    enrollment_flag = int(template.get("msPKI-Enrollment-Flag") or 0)
    private_key_flag = int(template.get("msPKI-Private-Key-Flag") or 0)
    schema_version = int(template.get("msPKI-Template-Schema-Version") or 1)
    authorized_signatures_required = int(template.get("msPKI-RA-Signature") or 0)

    ekus = [str(x) for x in _as_list(template.get("pKIExtendedKeyUsage"))]
    app_policies = [str(x) for x in _as_list(template.get("msPKI-RA-Application-Policies"))]

    template["certificate_name_flag"] = name_flag
    template["enrollment_flag"] = enrollment_flag
    template["private_key_flag"] = private_key_flag
    template["schema_version"] = schema_version
    template["authorized_signatures_required"] = authorized_signatures_required
    template["extended_key_usage"] = ekus
    template["application_policies"] = app_policies

    template["any_purpose"] = (not ekus) or (ANY_PURPOSE_OID in ekus)
    template["client_authentication"] = template["any_purpose"] or any(eku in CLIENT_AUTH_EKUS for eku in ekus)
    template["enrollment_agent"] = template["any_purpose"] or any(eku in ENROLLMENT_AGENT_EKUS for eku in ekus)
    template["enrollee_supplies_subject"] = bool(name_flag & 0x00000001)
    template["requires_manager_approval"] = bool(enrollment_flag & 0x00000002)
    template["no_security_extension"] = bool(enrollment_flag & 0x00080000)
    template["requires_key_archival"] = bool(private_key_flag & 0x00000001)


def parse_certificate_template_acl(ntsd_bytes: Any) -> dict:
    result = {
        "owner_sid": None,
        "enroll_sids": set(),
        "autoenroll_sids": set(),
        "all_extended_rights_sids": set(),
        "standard_control_access_sids": set(),
        "genericall_sids": set(),
        "genericwrite_sids": set(),
        "write_owner_sids": set(),
        "write_dacl_sids": set(),
        "write_property_all_sids": set(),
        "write_property_enroll_sids": set(),
        "write_property_autoenroll_sids": set(),
    }

    if not isinstance(ntsd_bytes, bytes):
        return result
    try:
        sd = SecurityDescriptor(BytesIO(ntsd_bytes))
    except Exception as e:
        logging.debug("Failed to parse template security descriptor: %s", e)
        return result

    try:
        result["owner_sid"] = str(sd.owner_sid)
    except Exception:
        pass

    if not getattr(sd, "dacl", None):
        return result

    for ace in sd.dacl.aces:
        try:
            if ace.ace.AceType not in (0x00, 0x05):
                continue
            sid = str(ace.acedata.sid)
            try:
                mask = ace.acedata.mask["Mask"]
            except Exception:
                try:
                    mask = ace.acedata.mask.mask
                except Exception:
                    mask = int(ace.acedata.mask)

            if (mask & GENERIC_ALL_BIT) == GENERIC_ALL_BIT or (mask & GENERIC_ALL_MASK) == GENERIC_ALL_MASK:
                result["genericall_sids"].add(sid)
            if (mask & GENERIC_WRITE_BIT) == GENERIC_WRITE_BIT or (mask & GENERIC_WRITE_MASK) == GENERIC_WRITE_MASK:
                result["genericwrite_sids"].add(sid)
            if mask & WRITE_OWNER_MASK:
                result["write_owner_sids"].add(sid)
            if mask & WRITE_DACL_MASK:
                result["write_dacl_sids"].add(sid)

            if ace.ace.AceType == 0x00:
                if mask & EXTENDED_RIGHT_MASK:
                    result["standard_control_access_sids"].add(sid)
                if mask & WRITE_PROPERTY_MASK:
                    result["write_property_all_sids"].add(sid)
                continue

            object_guid = None
            if ace.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                object_guid = ace.acedata.get_object_type()
                if object_guid:
                    object_guid = object_guid.lower()

            if mask & EXTENDED_RIGHT_MASK:
                if not object_guid or object_guid == ALL_EXTENDED_RIGHTS_GUID:
                    result["all_extended_rights_sids"].add(sid)
                elif object_guid == ENROLL_GUID:
                    result["enroll_sids"].add(sid)
                elif object_guid == AUTOENROLL_GUID:
                    result["autoenroll_sids"].add(sid)

            if mask & WRITE_PROPERTY_MASK:
                if not object_guid:
                    result["write_property_all_sids"].add(sid)
                elif object_guid == ENROLL_GUID:
                    result["write_property_enroll_sids"].add(sid)
                elif object_guid == AUTOENROLL_GUID:
                    result["write_property_autoenroll_sids"].add(sid)

        except Exception as e:
            logging.debug("Failed to parse ACE on template: %s", e)

    return result


def build_template_permissions(template: dict, sid_to_name: dict[str, str]) -> dict:
    acl = template["acl_info"]
    permissions = OrderedDict()

    enrollment_rights = (
        acl["enroll_sids"]
        | acl["all_extended_rights_sids"]
        | acl["standard_control_access_sids"]
        | acl.get("full_control_sids", set())
    )
    enrollment_permissions = OrderedDict()
    if enrollment_rights:
        enrollment_permissions["Enrollment Rights"] = [
            _certipy_principal(x) for x in _resolve_names(enrollment_rights, sid_to_name)
        ]
    if acl["all_extended_rights_sids"]:
        enrollment_permissions["All Extended Rights"] = [
            _certipy_principal(x) for x in _resolve_names(acl["all_extended_rights_sids"], sid_to_name)
        ]
    if acl["autoenroll_sids"]:
        enrollment_permissions["AutoEnrollment Rights"] = [
            _certipy_principal(x) for x in _resolve_names(acl["autoenroll_sids"], sid_to_name)
        ]
    if enrollment_permissions:
        permissions["Enrollment Permissions"] = enrollment_permissions

    object_control = OrderedDict()
    if template.get("owner_name"):
        object_control["Owner"] = _certipy_principal(template["owner_name"])

    full_control_sids = acl.get("full_control_sids", set())
    if full_control_sids:
        object_control["Full Control Principals"] = [
            _certipy_principal(x) for x in _resolve_names(full_control_sids, sid_to_name)
        ]

    display_write_owner_sids = acl.get("display_write_owner_sids", acl["write_owner_sids"])
    if display_write_owner_sids:
        object_control["Write Owner Principals"] = [
            _certipy_principal(x) for x in _resolve_names(display_write_owner_sids, sid_to_name)
        ]

    display_write_dacl_sids = acl.get("display_write_dacl_sids", acl["write_dacl_sids"])
    if display_write_dacl_sids:
        object_control["Write Dacl Principals"] = [
            _certipy_principal(x) for x in _resolve_names(display_write_dacl_sids, sid_to_name)
        ]

    if acl["write_property_enroll_sids"]:
        object_control["Write Property Enroll"] = [
            _certipy_principal(x) for x in _resolve_names(acl["write_property_enroll_sids"], sid_to_name)
        ]

    # Write Property AutoEnroll — already implemented, explicitly shown
    if acl["write_property_autoenroll_sids"]:
        object_control["Write Property AutoEnroll"] = [
            _certipy_principal(x) for x in _resolve_names(acl["write_property_autoenroll_sids"], sid_to_name)
        ]

    if object_control:
        permissions["Object Control Permissions"] = object_control

    return permissions


def get_user_enrollable_principals(template: dict, sid_to_name: dict[str, str], user_sids: set[str]) -> list[str]:
    acl = template["acl_info"]
    enrollment_rights = (
        acl["enroll_sids"]
        | acl["all_extended_rights_sids"]
        | acl["standard_control_access_sids"]
        | acl.get("full_control_sids", set())
    )
    matched = enrollment_rights & user_sids
    return [_certipy_principal(x) for x in _resolve_names(matched, sid_to_name)]


def get_user_acl_principals(template: dict, sid_to_name: dict[str, str], user_sids: set[str]) -> list[str]:
    acl = template["acl_info"]
    matched = set()
    owner_sid = acl.get("owner_sid")
    if owner_sid and owner_sid in user_sids:
        matched.add(owner_sid)
    dangerous = (
        acl.get("full_control_sids", set())
        | acl["genericwrite_sids"]
        | acl.get("display_write_owner_sids", acl["write_owner_sids"])
        | acl.get("display_write_dacl_sids", acl["write_dacl_sids"])
        | acl["write_property_all_sids"]
    )
    matched |= (dangerous & user_sids)
    return [_certipy_principal(x) for x in _resolve_names(matched, sid_to_name)]


def evaluate_template(template: dict, sid_to_name: dict[str, str], user_sids: set[str], domain_sid: str | None) -> None:
    del domain_sid

    process_template_flags(template)
    acl = parse_certificate_template_acl(template.get("nTSecurityDescriptor"))
    template["acl_info"] = acl

    owner_sid = acl["owner_sid"]

    full_control_sids = set(acl["genericall_sids"])
    if not full_control_sids:
        full_control_sids = set(acl["write_owner_sids"]) & set(acl["write_dacl_sids"])

    if owner_sid:
        full_control_sids.discard(owner_sid)

    display_write_owner_sids = set(acl["write_owner_sids"])
    display_write_dacl_sids = set(acl["write_dacl_sids"])
    if owner_sid:
        display_write_owner_sids.discard(owner_sid)
        display_write_dacl_sids.discard(owner_sid)

    acl["full_control_sids"] = full_control_sids
    acl["display_write_owner_sids"] = display_write_owner_sids
    acl["display_write_dacl_sids"] = display_write_dacl_sids

    enrollable_sids = (
        acl["enroll_sids"]
        | acl["all_extended_rights_sids"]
        | acl["standard_control_access_sids"]
        | acl["full_control_sids"]
    )
    dangerous_acl_sids = (
        acl["full_control_sids"]
        | acl["genericwrite_sids"]
        | acl["display_write_owner_sids"]
        | acl["display_write_dacl_sids"]
        | acl["write_property_all_sids"]
    )

    template["owner_sid"] = owner_sid
    template["owner_name"] = sid_to_name.get(owner_sid, owner_sid) if owner_sid else None
    template["permissions"] = build_template_permissions(template, sid_to_name)
    template["user_enrollable_principals"] = get_user_enrollable_principals(template, sid_to_name, user_sids)
    template["user_acl_principals"] = get_user_acl_principals(template, sid_to_name, user_sids)

    user_is_owner = bool(owner_sid and owner_sid in user_sids)
    user_has_dangerous_acl = bool(dangerous_acl_sids & user_sids)

    template["user_can_enroll"] = bool(enrollable_sids & user_sids)
    template["user_has_dangerous_acl"] = user_is_owner or user_has_dangerous_acl

    blocked = template["requires_manager_approval"] or template["authorized_signatures_required"] > 0
    enrollment_reachable = template.get("enabled", False) and template["user_can_enroll"]

    vulnerabilities = OrderedDict()
    remarks = OrderedDict()

    if enrollment_reachable and not blocked:
        if template["enrollee_supplies_subject"] and template["client_authentication"]:
            vulnerabilities["ESC1"] = "Enrollee supplies subject and template allows client authentication."
        if template["any_purpose"]:
            vulnerabilities["ESC2"] = "Template can be used for any purpose."
        if template["enrollment_agent"]:
            vulnerabilities["ESC3"] = "Template has Certificate Request Agent EKU set."
        if template["no_security_extension"] and template["client_authentication"]:
            vulnerabilities["ESC9"] = "Template has no security extension."
            remarks["ESC9"] = "Other prerequisites may be required for this to be exploitable. See the wiki for more details."
        if template["client_authentication"] and template.get("issuance_policies_linked_groups"):
            group = template["issuance_policies_linked_groups"][0]
            vulnerabilities["ESC13"] = f"Template allows client authentication and issuance policy is linked to group '{group}'."
        if template["enrollee_supplies_subject"] and template["schema_version"] == 1:
            vulnerabilities["ESC15"] = "Enrollee supplies subject and schema version is 1."
            remarks["ESC15"] = "Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details."

    if user_is_owner:
        vulnerabilities["ESC4"] = "Template is owned by user."
    elif user_has_dangerous_acl:
        vulnerabilities["ESC4"] = "User has dangerous permissions."

    # Certipy-like output: do not emit noisy ESC2/ESC3 target-template
    # remarks by default. These remarks are informational only and are not
    # vulnerabilities; emitting them for every schema v1 client-auth template
    # makes the output much noisier than Certipy.

    template["vulnerabilities"] = vulnerabilities
    template["remarks"] = remarks


# ---------------------------------------------------------------------------
# Output builder
# ---------------------------------------------------------------------------

def build_output(templates: list[dict], cas: list[dict], oids: list[dict], domain: str, sid_to_name: dict | None = None) -> dict:
    del domain
    if sid_to_name is None:
        sid_to_name = {}

    ca_entries = OrderedDict()
    for idx, ca in enumerate(cas):
        entry = OrderedDict()
        entry["CA Name"] = ca.get("name")
        entry["DNS Name"] = ca.get("dNSHostName")
        entry["Certificate Subject"] = ca.get("cACertificateDN")

        cert_info = _parse_ca_certificate_info(ca)
        if cert_info.get("serial_number"):
            entry["Certificate Serial Number"] = cert_info["serial_number"]
        if cert_info.get("validity_start"):
            entry["Certificate Validity Start"] = cert_info["validity_start"]
        if cert_info.get("validity_end"):
            entry["Certificate Validity End"] = cert_info["validity_end"]

        web_enrollment = ca.get("web_enrollment")
        if web_enrollment:
            web_node = OrderedDict()
            http_node = OrderedDict()
            http_node["Enabled"] = bool(web_enrollment.get("http_enabled", False))
            web_node["HTTP"] = http_node
            https_node = OrderedDict()
            https_node["Enabled"] = bool(web_enrollment.get("https_enabled", False))
            if web_enrollment.get("https_enabled", False):
                https_node["Channel Binding (EPA)"] = web_enrollment.get("channel_binding", "Unknown")
            web_node["HTTPS"] = https_node
            entry["Web Enrollment"] = web_node
        else:
            entry["Web Enrollment"] = OrderedDict([
                ("HTTP", OrderedDict([("Enabled", False)])),
                ("HTTPS", OrderedDict([("Enabled", False)])),
            ])

        user_specified_san = ca.get("user_specified_san", "Unknown")
        entry["User Specified SAN"] = "Enabled" if user_specified_san is True else ("Disabled" if user_specified_san is False else user_specified_san)

        entry["Request Disposition"] = ca.get("request_disposition", "Unknown")

        enforce_encrypt = ca.get("enforce_encrypt_icertrequest", "Unknown")
        if enforce_encrypt is not None:
            entry["Enforce Encryption for Requests"] = (
                "Enabled" if enforce_encrypt is True else ("Disabled" if enforce_encrypt is False else enforce_encrypt)
            )

        if ca.get("active_policy") is not None:
            entry["Active Policy"] = ca.get("active_policy")

        # [PATCH 1+2] CA Permissions — Owner + ManageCa + ManageCertificates + Enroll
        ca_acl = ca.get("ca_acl")
        if ca_acl:
            ca_perms = OrderedDict()
            owner_sid = ca.get("ca_runtime_owner_sid") or ca_acl.get("owner_sid")
            if owner_sid:
                ca_perms["Owner"] = _certipy_principal(sid_to_name.get(owner_sid, owner_sid))

            access_rights = OrderedDict()

            # [PATCH 2] Use human-readable keys matching Certipy output
            manage_ca = ca_acl.get("manage_ca_sids", set()) | ca_acl.get("genericall_sids", set())
            if manage_ca:
                access_rights["ManageCa"] = [
                    _certipy_principal(sid_to_name.get(s, s)) for s in sorted(manage_ca)
                ]

            manage_certs = ca_acl.get("manage_certificates_sids", set()) | ca_acl.get("genericall_sids", set())
            if manage_certs:
                access_rights["ManageCertificates"] = [
                    _certipy_principal(sid_to_name.get(s, s)) for s in sorted(manage_certs)
                ]

            # [PATCH 1+2] Enroll rights (was missing entirely before)
            enroll_sids = ca_acl.get("enroll_sids", set())
            if enroll_sids:
                access_rights["Enroll"] = [
                    _certipy_principal(sid_to_name.get(s, s)) for s in sorted(enroll_sids)
                ]

            if access_rights:
                ca_perms["Access Rights"] = access_rights

            if ca_perms:
                entry["Permissions"] = ca_perms

        entry["Published Templates"] = _as_list(ca.get("certificateTemplates"))
        entry["Object ID"] = _guid_to_str(ca.get("objectGUID"))

        if ca.get("vulnerabilities"):
            entry["[!] Vulnerabilities"] = ca["vulnerabilities"]
        if ca.get("remarks"):
            entry["[*] Remarks"] = ca["remarks"]

        ca_entries[idx] = entry

    template_entries = OrderedDict()
    for idx, tpl in enumerate(templates):
        entry = OrderedDict()
        entry["Template Name"] = tpl.get("name") or tpl.get("cn")
        entry["Display Name"] = tpl.get("displayName")
        if tpl.get("cas"):
            entry["Certificate Authorities"] = tpl.get("cas", [])
        entry["Enabled"] = bool(tpl.get("enabled", False))
        entry["Client Authentication"] = tpl.get("client_authentication", False)
        entry["Enrollment Agent"] = tpl.get("enrollment_agent", False)
        entry["Any Purpose"] = tpl.get("any_purpose", False)
        entry["Enrollee Supplies Subject"] = tpl.get("enrollee_supplies_subject", False)

        cert_name_flags = _decode_flags(int(tpl.get("certificate_name_flag", 0)), CERT_NAME_FLAG_MAP)
        if cert_name_flags:
            entry["Certificate Name Flag"] = cert_name_flags

        enrollment_flags = _decode_flags(int(tpl.get("enrollment_flag", 0)), ENROLLMENT_FLAG_MAP)
        if enrollment_flags:
            entry["Enrollment Flag"] = enrollment_flags

        private_key_flags = _decode_flags(int(tpl.get("private_key_flag", 0)), PRIVATE_KEY_FLAG_MAP)
        if private_key_flags:
            entry["Private Key Flag"] = private_key_flags

        ekus = _friendly_oids(tpl.get("extended_key_usage", []))
        if ekus:
            entry["Extended Key Usage"] = ekus

        entry["Requires Manager Approval"] = tpl.get("requires_manager_approval", False)
        entry["Requires Key Archival"] = tpl.get("requires_key_archival", False)

        ra_policies = _friendly_oids(tpl.get("application_policies", []))
        if ra_policies:
            entry["RA Application Policies"] = ra_policies

        entry["Authorized Signatures Required"] = tpl.get("authorized_signatures_required")
        entry["Schema Version"] = tpl.get("schema_version")
        entry["Validity Period"] = _format_period_from_bytes(tpl.get("pKIExpirationPeriod"))
        entry["Renewal Period"] = _format_period_from_bytes(tpl.get("pKIOverlapPeriod"))
        entry["Minimum RSA Key Length"] = tpl.get("msPKI-Minimal-Key-Size")
        entry["Template Created"] = _format_when(tpl.get("whenCreated"))
        entry["Template Last Modified"] = _format_when(tpl.get("whenChanged"))

        if tpl.get("permissions"):
            entry["Permissions"] = tpl["permissions"]
        if tpl.get("user_enrollable_principals"):
            entry["[+] User Enrollable Principals"] = tpl["user_enrollable_principals"]
        if tpl.get("user_acl_principals"):
            entry["[+] User ACL Principals"] = tpl["user_acl_principals"]
        if tpl.get("vulnerabilities"):
            entry["[!] Vulnerabilities"] = tpl["vulnerabilities"]
        if tpl.get("remarks"):
            entry["[*] Remarks"] = tpl["remarks"]

        template_entries[idx] = entry

    oid_entries = OrderedDict()
    for idx, oid in enumerate(oids):
        entry = OrderedDict()
        entry["Issuance Policy Name"] = oid.get("displayName") or oid.get("name") or oid.get("cn")
        entry["Template OID"] = oid.get("msPKI-Cert-Template-OID")
        entry["Linked Group DN"] = oid.get("msDS-OIDToGroupLink")
        entry["Object ID"] = _guid_to_str(oid.get("objectGUID"))
        oid_entries[idx] = entry

    return {
        "Certificate Authorities": ca_entries,
        "Certificate Templates": template_entries,
        "Issuance Policies": oid_entries,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_cert_find(
    adws_enum,
    resource_client,
    config_dn: str,
    default_dn: str,
    schema_dn: str,
    domain: str,
    username: str,
    auth,
    output_dir: str = "",
    web_probe_force_epa: bool | None = None,
    web_probe_enabled: bool = True,
    ca_rpc_enabled: bool = False,
) -> dict:
    del adws_enum
    del schema_dn

    target_domain = getattr(resource_client, "_domain", None) or domain
    target_fqdn = getattr(resource_client, "_fqdn", None)
    target_ip = (
        getattr(resource_client, "_ip", None)
        or getattr(resource_client, "_target", None)
        or getattr(resource_client, "_host", None)
    )
    adws_target = target_fqdn or target_ip or target_domain

    logging.info("Building directory maps for SID/DN resolution")
    sid_to_name, dn_to_name = build_directory_maps(
        ip=adws_target, domain=target_domain, username=username, auth=auth, default_dn=default_dn,
    )

    logging.info("Resolving current user SIDs")
    user_sids, domain_sid = collect_current_user_sids(
        ip=adws_target, domain=target_domain, username=username, auth=auth, default_dn=default_dn,
    )

    logging.info("Finding certificate templates")
    templates = collect_certificate_templates(
        ip=adws_target, domain=target_domain, username=username, auth=auth, config_dn=config_dn,
    )

    logging.info("Finding certificate authorities")
    cas = collect_certificate_authorities(
        ip=adws_target, domain=target_domain, username=username, auth=auth, config_dn=config_dn,
    )

    # CA object permissions are stored in the pKIEnrollmentService security descriptor.
    # Keep this path ADWS-only: do not perform LDAP queries here. Registry/runtime CA
    # values such as EditFlags, RequestDisposition, InterfaceFlags and Active Policy
    # are fetched only through optional RRP when --cert-find-ca-rpc is enabled.
    logging.info("Fetching CA nTSecurityDescriptor via ADWS")
    fetch_ca_security_descriptors_adws(
        ip=adws_target, domain=target_domain, username=username, auth=auth,
        config_dn=config_dn, cas=cas,
    )

    if ca_rpc_enabled:
        logging.info("Enriching CA configuration through Remote Registry/RPC")
        fetch_ca_config_rrp(
            ip=adws_target, domain=target_domain, username=username, auth=auth, cas=cas,
        )
    else:
        logging.info("Skipping CA-RPC configuration enrichment. Use --cert-find-ca-rpc to enable it.")

    logging.info("Finding issuance policies")
    oids = collect_issuance_policies(
        ip=adws_target, domain=target_domain, username=username, auth=auth, config_dn=config_dn,
    )

    enabled_templates_count = link_cas_and_templates(cas, templates)
    enabled_oids_count = link_templates_and_policies(templates, oids, dn_to_name)

    logging.info("Found %d certificate templates", len(templates))
    logging.info("Found %d certificate authorities", len(cas))
    logging.info("Found %d enabled template links", enabled_templates_count)
    logging.info("Found %d issuance policy links", enabled_oids_count)

    if web_probe_enabled:
        logging.info("Probing Web Enrollment / ESC8 on certificate authorities")
        for ca in cas:
            probe_ca_web_enrollment(ca=ca, username=username, auth=auth, domain=target_domain, force_epa=web_probe_force_epa)
    else:
        logging.info("Skipping Web Enrollment / ESC8 probe (--cert-find-skip-web-probe)")
        for ca in cas:
            ca["web_enrollment"] = {
                "http_enabled": False,
                "https_enabled": False,
                "channel_binding": "Unknown",
                "http_url": None,
                "https_url": None,
                "http_probe_error": "Skipped by user",
                "https_probe_error": "Skipped by user",
                "channel_binding_error": None,
                "selected_host": ca.get("dNSHostName"),
                "tested_hosts": [],
            }

    logging.info("Evaluating certificate authority vulnerabilities (ESC6, ESC7)")
    for ca in cas:
        evaluate_ca(ca, sid_to_name, user_sids)

    for tpl in templates:
        evaluate_template(tpl, sid_to_name, user_sids, domain_sid)

    output = build_output(templates, cas, oids, target_domain, sid_to_name=sid_to_name)
    json_path, text_path = save_output(output, output_dir)

    logging.info("Cert-find JSON output written to %s", json_path)
    logging.info("Cert-find text output written to %s", text_path)

    return output


# ---------------------------------------------------------------------------
# Text renderer (aligned on certipy find output)
# ---------------------------------------------------------------------------

# Champs filtres au rendu texte (gardes dans le JSON).
# Certipy n'affiche pas Object ID par template ni la section Issuance Policies.
_TEXT_HIDDEN_KEYS_PER_TEMPLATE = {"Object ID"}
_TEXT_HIDDEN_KEYS_PER_CA = {"Object ID"}


def _render_certipy_node(node: Any, indent: int = 0, hidden_keys: set | None = None) -> list[str]:
    lines: list[str] = []
    # Certipy uses 2 spaces per indent level (vs 4 previously).
    prefix = "  " * indent

    if isinstance(node, dict):
        for key, value in node.items():
            is_index = isinstance(key, int) or (isinstance(key, str) and key.isdigit())

            if is_index:
                lines.append(f"{prefix}{key}")
                lines.extend(_render_certipy_node(value, indent + 1, hidden_keys=hidden_keys))
                continue

            # Skip filtered keys at any level
            if hidden_keys and str(key) in hidden_keys:
                continue

            if isinstance(value, dict):
                lines.append(f"{prefix}{key}")
                lines.extend(_render_certipy_node(value, indent + 1, hidden_keys=hidden_keys))
                continue

            if isinstance(value, list):
                if not value:
                    continue
                first = _certipy_scalar(value[0])
                lines.append(f"{prefix}{str(key):<{DISPLAY_KEY_WIDTH}} : {first}")
                continuation_prefix = f"{prefix}{' ' * DISPLAY_KEY_WIDTH}   "
                for item in value[1:]:
                    lines.append(f"{continuation_prefix}{_certipy_scalar(item)}")
                continue

            lines.append(f"{prefix}{str(key):<{DISPLAY_KEY_WIDTH}} : {_certipy_scalar(value)}")

    elif isinstance(node, list):
        for item in node:
            lines.append(f"{prefix}- {_certipy_scalar(item)}")
    else:
        lines.append(f"{prefix}{_certipy_scalar(node)}")

    return lines


def render_certipy_text(output: dict) -> str:
    """Render output as text aligned on certipy find format.

    Differences with the JSON output:
      - 2-space indentation per level (vs 4 in legacy renderer)
      - "Object ID" lines are hidden per CA and per template
      - "Issuance Policies" section is omitted from the text render
        (kept in JSON for downstream tooling)
    """
    lines: list[str] = []

    # Certificate Authorities
    if "Certificate Authorities" in output:
        lines.append("Certificate Authorities")
        lines.extend(_render_certipy_node(
            output["Certificate Authorities"],
            indent=1,
            hidden_keys=_TEXT_HIDDEN_KEYS_PER_CA,
        ))

    # Certificate Templates
    if "Certificate Templates" in output:
        lines.append("Certificate Templates")
        lines.extend(_render_certipy_node(
            output["Certificate Templates"],
            indent=1,
            hidden_keys=_TEXT_HIDDEN_KEYS_PER_TEMPLATE,
        ))

    # Note: "Issuance Policies" is intentionally omitted from the text output
    # to match certipy. The data is still present in the JSON file.

    return "\n".join(lines) + "\n"


def save_output(output: dict, output_dir: str) -> tuple[str, str]:
    ts = datetime.fromtimestamp(time.time()).strftime("%Y%m%d%H%M%S")
    output_dir = output_dir or "."
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{ts}_Soaphound_CertFind.json")
    text_path = os.path.join(output_dir, f"{ts}_Soaphound_CertFind.txt")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    with open(text_path, "w", encoding="utf-8") as f:
        f.write(render_certipy_text(output))
    return json_path, text_path
