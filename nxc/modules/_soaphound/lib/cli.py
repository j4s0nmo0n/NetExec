import argparse
import sys


def gen_cli_args():
    parser = argparse.ArgumentParser(add_help=True, description="Python based ingestor for BloodHound using ADWS")
    #parser.add_argument("connection", action="store", help="domain/user[:pass]@host", nargs='?')
    #parser.add_argument("--debug", action="store_true", help="Enable DEBUG output")
    #parser.add_argument("--ts", action="store_true", help="Add timestamp to logs")
    #parser.add_argument("--hash", action="store", metavar="NTHASH", help="NT hash for auth")
    #parser.add_argument("--output-dir", type=str, default="output", help="Output directory for exported files (default: ./output)")
    #parser.add_argument("--adws-only", action="store_true", help="Collect computers only via ADWS (no session/RPC/SMB data)")

    #bh_group = parser.add_argument_group('BloodHound, Cache & PKI Collection')
    #bh_group.add_argument("--bloodhound", action="store_true", help="Collect fresh data and generate BloodHound JSON files.")
    #bh_group.add_argument("--bloodhound-cache-file", metavar="CACHE_FILE_PATH", help="Path to cache.json to assist BloodHound processing if fresh data is also collected.")
    #bh_group.add_argument("--cache", action="store_true", help="Create/regenerate SOAPHound compatible cache files from fresh ADWS data.")



    parser.add_argument('-c',
                        '--collectionmethod',
                        action='store',
                        default='Default',
                        help='Which information to collect : Default or ADWSOnly (no computer connections).')
    parser.add_argument('-d',
                        '--domain',
                        action='store',
                        required=False,
                        help='Domain to query (extracted from the ccache in -k mode if not supplied).')
    parser.add_argument('-v',
                        action='store_true',
                        help='Enable verbose output.')

    parser.add_argument("--ts", action="store_true", help="Add timestamp to logs.")


    helptext = 'NTLM (username/password or NT hash) or Kerberos (-k via KRB5CCNAME).'

    auopts = parser.add_argument_group('authentication options', description=helptext)
    auopts.add_argument('-u',
                        '--username',
                        action='store',
                        required=False,
                        help='Username. Format: username[@domain]; If the domain is unspecified, the current domain is used.')
    auopts.add_argument('-p',
                        '--password',
                        action='store',
                        help='Password')
    auopts.add_argument('--hashes',
                        action='store',
                        help='LM:NLTM hashes')
    auopts.add_argument('-k',
                        '--kerberos',
                        action='store_true',
                        help='Kerberos authentication using the ticket present in the ccache pointed to by KRB5CCNAME.')
    auopts.add_argument('-aesKey',
                        '--aes-key',
                        action='store',
                        metavar='HEXKEY',
                        help='AES key (128/256 bits) for Kerberos authentication (used for SMB collection in Default mode).')
    auopts.add_argument('-dc-ip',
                        '--kdc-ip',
                        action='store',
                        metavar='HOST',
                        help='KDC IP/host. Useful when the ADWS DC and the KDC differ (default: value of -dc).')

    coopts = parser.add_argument_group('collection options')

    coopts.add_argument('-dc',
                        '--domain-controller',
                        metavar='HOST',
                        action='store',
                        required=True,
                        help='DC to query (hostname)')

    coopts.add_argument('--zip',
                        action='store_true',
                        help='Compress the JSON output files into a zip archive.')

    coopts.add_argument('-op',
                        '--outputprefix',
                        metavar='PREFIX_NAME',
                        action='store',
                        help='String to prepend to output file names.')

    coopts.add_argument('-wk',
                        '--worker_num',
                        metavar='NUM_WORKERS',
                        action='store',
                        default=100,
                        help='Number of workers, default 100')

    coopts.add_argument("--output-dir", type=str, default=".", help="Output folder (default .).")

    coopts.add_argument(
        "--cert-find",
        action="store_true",
        help="Enumerate AD CS certificate templates and CAs like certipy find."
    )

    coopts.add_argument(
        "--cert-find-force-epa",
        choices=("auto", "enabled", "disabled"),
        default="auto",
        help="Override HTTPS EPA detection for AD CS Web Enrollment: auto, enabled, or disabled."
    )

    coopts.add_argument(
        "--cert-find-skip-web-probe",
        action="store_true",
        help="Do not probe HTTP/HTTPS /certsrv/ endpoints. AD CS Web Enrollment and ESC8 will not be evaluated."
    )

    coopts.add_argument(
        "--cert-find-ca-rpc",
        action="store_true",
        help="Enrich CA configuration through Remote Registry/RPC (User Specified SAN, Request Disposition, Enforce Encryption, Active Policy)."
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    return args
