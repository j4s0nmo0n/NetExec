"""
Formatters for the NetExec ``adws`` protocol.

Converts ADWS records (list[dict] returned by ``ADWSConnect.pull_records()``)
into column-formatted output, in the same style as ``nxc smb --users`` /
``nxc smb --computers``.

Each formatter takes:
  - records: list[dict] with already-parsed ADWS attributes (objectSid as
    S-1-..., timestamps as ISO, userAccountControl as text flags, etc.)
  - logger: NXCAdapter, used for highlight()/display()/info()

And prints line by line in columns.
"""
from datetime import datetime


def _trunc(value, width):
    """Truncate ``value`` to ``width`` characters, append '..' if truncated."""
    s = str(value) if value is not None else ""
    if len(s) <= width:
        return s
    if width <= 2:
        return s[:width]
    return s[: width - 2] + ".."


def _first(record, key, default="<not set>"):
    """Get the first value of a multi-valued attribute (', '-separated)."""
    v = record.get(key)
    if v is None or v == "":
        return default
    if isinstance(v, str) and ", " in v:
        return v.split(", ")[0]
    return v


def _format_iso_short(iso_str):
    """ISO timestamp -> 'YYYY-MM-DD HH:MM:SS' (compact)."""
    if not iso_str or iso_str == "none/never":
        return "<never>"
    try:
        # handles "2025-06-10T14:51:38+00:00" and variants
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return _trunc(iso_str, 19)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
USERS_HEADER = "{:<25} {:<22} {:<7} {}".format(
    "-Username-", "-Last PW Set-", "-BadPW-", "-Description-"
)


def format_users(records, logger):
    if not records:
        logger.fail("No users returned")
        return
    logger.highlight(USERS_HEADER)
    for r in records:
        username = _trunc(_first(r, "sAMAccountName", default="?"), 25)
        pwd_last_set = _format_iso_short(_first(r, "pwdLastSet", default=""))
        bad_pwd = _first(r, "badPwdCount", default="0")
        try:
            bad_pwd_int = int(bad_pwd)
        except (ValueError, TypeError):
            bad_pwd_int = 0
        description = _trunc(_first(r, "description", default=""), 80)
        logger.highlight(
            "{:<25} {:<22} {:<7} {}".format(
                username, pwd_last_set, bad_pwd_int, description
            )
        )
    logger.success(f"Enumerated {len(records)} domain users")


# ---------------------------------------------------------------------------
# Computers
# ---------------------------------------------------------------------------
COMPUTERS_HEADER = "{:<28} {:<40} {:<22} {}".format(
    "-Hostname-", "-Operating System-", "-Last Logon-", "-Description-"
)


def format_computers(records, logger):
    if not records:
        logger.fail("No computers returned")
        return
    logger.highlight(COMPUTERS_HEADER)
    for r in records:
        # Strip the trailing $ and truncate
        sam = _first(r, "sAMAccountName", default="?").rstrip("$")
        hostname = _trunc(sam, 28)
        os_str = _trunc(_first(r, "operatingSystem", default="?"), 40)
        last_logon = _format_iso_short(_first(r, "lastLogonTimestamp", default=""))
        description = _trunc(_first(r, "description", default=""), 80)
        logger.highlight(
            "{:<28} {:<40} {:<22} {}".format(hostname, os_str, last_logon, description)
        )
    logger.success(f"Enumerated {len(records)} domain computers")


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------
GROUPS_HEADER = "{:<40} {:<10} {}".format("-Group Name-", "-Members-", "-Description-")


def format_groups(records, logger):
    if not records:
        logger.fail("No groups returned")
        return
    logger.highlight(GROUPS_HEADER)
    for r in records:
        name = _trunc(_first(r, "sAMAccountName", default="?"), 40)
        # ``member`` is multi-valued (', '-separated)
        members_raw = r.get("member", "")
        if members_raw:
            count = len(members_raw.split(", ")) if isinstance(members_raw, str) else 0
        else:
            count = 0
        description = _trunc(_first(r, "description", default=""), 80)
        logger.highlight("{:<40} {:<10} {}".format(name, count, description))
    logger.success(f"Enumerated {len(records)} domain groups")


# ---------------------------------------------------------------------------
# Admins (adminCount=1)
# ---------------------------------------------------------------------------
ADMINS_HEADER = "{:<25} {:<22} {:<7} {}".format(
    "-Username-", "-Last PW Set-", "-BadPW-", "-MemberOf-"
)


def format_admins(records, logger):
    if not records:
        logger.fail("No privileged accounts returned")
        return
    logger.highlight(ADMINS_HEADER)
    for r in records:
        username = _trunc(_first(r, "sAMAccountName", default="?"), 25)
        pwd_last_set = _format_iso_short(_first(r, "pwdLastSet", default=""))
        bad_pwd = _first(r, "badPwdCount", default="0")
        try:
            bad_pwd_int = int(bad_pwd)
        except (ValueError, TypeError):
            bad_pwd_int = 0
        # Extract just the CN= entries from memberOf, '; '-separated
        member_of_raw = r.get("memberOf", "")
        groups = []
        if isinstance(member_of_raw, str) and member_of_raw:
            for dn in member_of_raw.split(", CN="):
                # The first element always carries the "CN=" prefix
                cn = dn.split(",")[0].lstrip("CN=").lstrip("=")
                groups.append(cn)
        member_of = _trunc("; ".join(groups), 80)
        logger.highlight(
            "{:<25} {:<22} {:<7} {}".format(
                username, pwd_last_set, bad_pwd_int, member_of
            )
        )
    logger.success(f"Enumerated {len(records)} privileged accounts (adminCount=1)")


# ---------------------------------------------------------------------------
# SPNs
# ---------------------------------------------------------------------------
SPNS_HEADER = "{:<25} {}".format("-Username-", "-SPN(s)-")


def format_spns(records, logger):
    if not records:
        logger.fail("No SPN-bearing accounts returned")
        return
    logger.highlight(SPNS_HEADER)
    total_spns = 0
    for r in records:
        username = _trunc(_first(r, "sAMAccountName", default="?"), 25)
        spns_raw = r.get("servicePrincipalName", "")
        if not spns_raw:
            continue
        spns = spns_raw.split(", ") if isinstance(spns_raw, str) else [spns_raw]
        total_spns += len(spns)
        # First SPN on the first line with username, the rest indented
        first = True
        for spn in spns:
            if first:
                logger.highlight("{:<25} {}".format(username, spn))
                first = False
            else:
                logger.highlight("{:<25} {}".format("", spn))
    logger.success(
        f"Enumerated {len(records)} kerberoastable accounts ({total_spns} SPNs)"
    )


# ---------------------------------------------------------------------------
# AS-REP roastable
# ---------------------------------------------------------------------------
ASREP_HEADER = "{:<25} {:<22} {:<7} {}".format(
    "-Username-", "-Last PW Set-", "-BadPW-", "-Description-"
)


def format_asreproastable(records, logger):
    """Same format as --users but with a different final summary line."""
    if not records:
        logger.fail("No AS-REP roastable accounts returned")
        return
    logger.highlight(ASREP_HEADER)
    for r in records:
        username = _trunc(_first(r, "sAMAccountName", default="?"), 25)
        pwd_last_set = _format_iso_short(_first(r, "pwdLastSet", default=""))
        bad_pwd = _first(r, "badPwdCount", default="0")
        try:
            bad_pwd_int = int(bad_pwd)
        except (ValueError, TypeError):
            bad_pwd_int = 0
        description = _trunc(_first(r, "description", default=""), 80)
        logger.highlight(
            "{:<25} {:<22} {:<7} {}".format(
                username, pwd_last_set, bad_pwd_int, description
            )
        )
    logger.success(f"Enumerated {len(records)} AS-REP roastable accounts")


# ---------------------------------------------------------------------------
# Generic key:value (--query / -q libre)
# ---------------------------------------------------------------------------
def format_keyvalue(records, logger, separator="-" * 20):
    """Key:value display with separators for free-form queries.

    One separator between each record, ``attribute: value`` per line.
    Compatible with the ``nxc ldap -q`` output style.
    """
    if not records:
        logger.fail("No objects returned")
        return
    for r in records:
        logger.highlight(separator)
        for k, v in r.items():
            # Avoid dumping huge binary blobs in the standard output
            if k == "nTSecurityDescriptor" and len(str(v)) > 200:
                logger.highlight(f"{k}: <SDDL not parsed; use --raw to see base64>")
                continue
            logger.highlight(f"{k}: {v}")
    logger.success(f"Enumerated {len(records)} object(s)")


# ---------------------------------------------------------------------------
# Constrained / Unconstrained / RBCDs: reuse format_users/computers
# but adjust the final summary line
# ---------------------------------------------------------------------------
def format_delegation(records, logger, kind="delegation"):
    """Display for accounts with Kerberos delegation."""
    if not records:
        logger.fail(f"No accounts with {kind} returned")
        return
    header = "{:<25} {:<7} {}".format("-Account-", "-Type-", "-Delegation-")
    logger.highlight(header)
    for r in records:
        sam = _first(r, "sAMAccountName", default="?")
        # Distinguish user / computer via sAMAccountType if available, else via $
        is_computer = sam.endswith("$")
        acc_type = "comp" if is_computer else "user"
        # AllowedToDelegateTo (constrained) or AllowedToActOn... (RBCD)
        delegation = (
            r.get("msDS-AllowedToDelegateTo", "")
            or r.get("msDS-AllowedToActOnBehalfOfOtherIdentity", "")
            or "Unconstrained (TRUSTED_FOR_DELEGATION)"
        )
        logger.highlight(
            "{:<25} {:<7} {}".format(_trunc(sam, 25), acc_type, _trunc(delegation, 80))
        )
    logger.success(f"Enumerated {len(records)} accounts with {kind}")
