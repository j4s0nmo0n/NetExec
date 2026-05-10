####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
import queue
import threading
import logging
import traceback
import codecs
from impacket.dcerpc.v5.rpcrt import DCERPCException
from ..lib.outputworker import OutputWorker
from ..lib.memberships import MembershipEnumerator
from ..ad.collectors.bh_rpc_computer import ADComputer
from ..lib.utils import ADUtils

class ComputerEnumerator(MembershipEnumerator):
    """
    Class to enumerate computers in the domain.
    Contains the threading logic and workers which will call the collection
    methods from the bloodhound.ad module.

    This class extends the MembershipEnumerator class just to inherit the
    membership lookup functions which are also needed for computers.
    """
    def __init__(self, addomain, addc, collect, do_gc_lookup=True, computerfile="", exclude_dcs=False):
        """
        Computer enumeration. Enumerates all computers in the given domain.
        Every domain enumerated will get its own instance of this class.
        """
        self.addomain = addomain
        self.addc = addc
        # blocklist and allowlist are only used for debugging purposes
        self.blocklist = []
        self.allowlist = []
        self.do_gc_lookup = do_gc_lookup
        # Store collection methods specified
        self.collect = collect
        self.exclude_dcs = exclude_dcs
        if computerfile:
            logging.info('Limiting enumeration to FQDNs in %s', computerfile)
            with codecs.open(computerfile, 'r', 'utf-8') as cfile:
                for line in cfile:
                    self.allowlist.append(line.strip().lower())

    def enumerate_computers(self, computers, num_workers=10, timestamp="", fileNamePrefix=""):
        """
            Enumerates the computers in the domain. Is threaded, you can specify the number of workers.
            Will spawn threads to resolve computers and enumerate the information.
        """
        process_queue = queue.Queue()

        result_q = queue.Queue()
        if (fileNamePrefix != None):
            results_worker = threading.Thread(target=OutputWorker.write_worker, args=(result_q, fileNamePrefix + '_' + timestamp + 'computers.json'))
        else:
            results_worker = threading.Thread(target=OutputWorker.write_worker, args=(result_q, timestamp + 'computers.json'))
        results_worker.daemon = True
        results_worker.start()
        logging.info('Starting computer enumeration with %d workers', num_workers)
        if len(computers) / num_workers > 500:
            logging.info('The workload seems to be rather large. Consider increasing the number of workers.')
        for _ in range(0, num_workers):
            thread = threading.Thread(target=self.work, args=(process_queue, result_q))
            thread.daemon = True
            thread.start()

        for _, computer in computers.items():
            if not 'attributes' in computer:
                continue

            # if 'dNSHostName' not in computer['attributes']:
            #     continue

            hostname = ADUtils.get_entry_property(computer, 'dNSHostName')
            samname = computer['attributes']['sAMAccountName']
            if not hostname:
                logging.debug('Invalid computer object without hostname: %s', samname)
                hostname = ''

            # Check if filtering
            if hostname in self.blocklist:
                logging.info('Skipping computer: %s (blocklisted)', hostname)
                continue
            if len(self.allowlist) > 0 and hostname.lower() not in self.allowlist:
                logging.debug('Skipping computer: %s (not allowlisted)', hostname)
                continue

            process_queue.put((hostname, samname, computer))
        process_queue.join()
        result_q.put(None)
        result_q.join()

    def process_computer(self, hostname, samname, objectsid, entry, results_q, all_sessions_users=None):
        """
            Processes a single computer, pushes the results of the computer to the given queue.
        """

        logging.debug('Querying computer: %s', hostname)

        if 'session_users_by_machine' not in globals():
            global session_users_by_machine
            session_users_by_machine = {}


        c = ADComputer(hostname=hostname, samname=samname, ad=self.addomain, addc=self.addc, objectsid=objectsid)
        
        c.primarygroup = MembershipEnumerator.get_primary_membership(entry)
        
        if hostname and (not self.exclude_dcs or not ADUtils.is_dc(entry)) and c.try_connect():
            try:

                # Affichage temporaire pour debug
                sessions = []
                if 'session' in self.collect and False: #TODO Fix TS collect
                    # Sessions SMB (NetSessionEnum)
                    sessions = c.rpc_get_sessions() or []
                   # print(f"[DEBUG] Sessions (NetSessionEnum) sur {hostname}: {sessions}")
                    # Sessions RDP/Terminal Services (TSHandler)
                    ts_sessions = c.tsts_get_sessions() or []
                    print(ts_sessions)
                    #print(f"[DEBUG] Sessions RDP sur {hostname}: {ts_sessions}")
                    if ts_sessions:
                        sessions.extend(ts_sessions)
                # Si on ne collecte pas, sessions reste une liste vide

                # Immediate debug output
                #if sessions:
                #    #print(f"[+] Sessions collected on {hostname}:")
                #    for sess in sessions:
                #        print("    ", sess)
                #else:
                #    print(f"[DEBUG] No connected users on {hostname}.")


                # Temporary debug output
                #if sessions:
                #    print(f"[+] Sessions collected on {hostname}:")
                #    for sess in sessions:
                #        print("    ", sess)
                #else:
                #    print(f"[DEBUG] No connected users on {hostname}.")

                

                if 'localadmin' in self.collect:
                    unresolved = c.rpc_get_group_members(544, c.admins)
                    c.rpc_resolve_sids(unresolved, c.admins)
                if 'rdp' in self.collect:
                    unresolved = c.rpc_get_group_members(555, c.rdp)
                    c.rpc_resolve_sids(unresolved, c.rdp)
                if 'dcom' in self.collect:
                    unresolved = c.rpc_get_group_members(562, c.dcom)
                    c.rpc_resolve_sids(unresolved, c.dcom)
                if 'psremote' in self.collect:
                    unresolved = c.rpc_get_group_members(580, c.psremote)
                    c.rpc_resolve_sids(unresolved, c.psremote)
                if 'loggedon' in self.collect:
                    loggedon = c.rpc_get_loggedon()
                    if loggedon is None:
                        loggedon = []
                    registry_sessions = c.rpc_get_registry_sessions()
                    if registry_sessions is None:
                        registry_sessions = []
                    sessions += registry_sessions
                else:
                    loggedon = []
                    registry_sessions = []
                if 'experimental' in self.collect:
                    services = c.rpc_get_services()
                    if services is None:
                        services = []
                    tasks = c.rpc_get_schtasks()
                    if tasks is None:
                        tasks = []
                else:
                    services = []
                    tasks = []

                c.rpc_close()
                # c.rpc_get_domain_trusts()

                # Should we use the GC?
                use_gc = self.addomain.num_domains > 1 and self.do_gc_lookup

                # Process found sessions
                #print(f"[DEBUG] Combined sessions to process on {hostname}: {sessions}")
                #print(">>>>>>>>>>>>>>>>>>>>>> looking for username "+str(sessions[1]))
                for ses in sessions:
                   # print("[>>>>>>>>>>>>>>>>>>>>>>DEBUG] Raw session:", ses)
                    key = f"{hostname.lower()}_session_users"
                    if key not in session_users_by_machine:
                        session_users_by_machine[key] = []
                    user_sid = ses.get('user')
                    session_type = "RDP" if ses.get('session_name') == "Console" else "SMB"
                    if user_sid and user_sid not in session_users_by_machine[key]:
                        session_users_by_machine[key].append({
                            "session_type": session_type,
                            "usersid": user_sid,           # Resolved in the loop
                            "computersid": objectsid       # SID of the current machine
                        })

                    #if isinstance(ses, dict):
                    #    for k, v in ses.items():
                    #        print(f"    {k}: {v}")
                    #else:
                    #    print(f"    [non-dict]: {ses!r}")


                    use_gc = self.addomain.num_domains > 1 and self.do_gc_lookup
                    
                    try:
                        users = self.addomain.samcache.get(user_sid)
                    except KeyError:
                        entries = self.addomain.objectresolver.resolve_samname(user_sid, use_gc=use_gc)
                        if entries and len(entries) > 0:
                            users = [user['attributes']['objectSid'] for user in entries]
                            self.addomain.samcache.put(uname, users)
                        else:
                            #print(f"[WARNING] Could not resolve SID for {uname}")
                            users = None

                    if users:
                        user_sid = users[0]  # take the first SID if multiple
                    else:
                        #print(f"[WARNING] No SID entry found for user '{uname}' on {hostname}")
                        
                        continue

                    for user_sid in users:
                        session_users_by_machine[key].append({
                            "username": uname,
                            "session_type": session_type,
                            "usersid": user_sid,
                            "computersid": objectsid
                        })
                         #print(f"[DEBUG] Ajout de session SID={user_sid} User={uname} sur {hostname}")

                    
                    try:
                        users = self.addomain.samcache.get(ses['username'])
                    except KeyError:
                        entries = self.addomain.objectresolver.resolve_samname(ses['username'], use_gc=use_gc)
                        if entries is not None and len(entries) > 0:
                            users = [user['attributes']['objectSid'] for user in entries]
                            self.addomain.samcache.put(ses['username'], users)
                        else:
                            logging.warning('Failed to resolve SAM name %s in current forest', ses['user'])
                            continue  # On ne traite pas cette session si l'utilisateur est inconnu

                    # users must now exist and be non-empty
                    if not users:
                        logging.warning('No users found for session user %s', ses['username'])
                        continue

                        # Resolve the IP to obtain the host the session is from (reste du code…)

                        self.addomain.samcache.put(ses['username'], users)
                        if users is None:
                            users = []

                    # Resolve the IP to obtain the host the session is from
                    try:
                        target = self.addomain.dnscache.get(ses['source'])
                    except KeyError:
                        target = ADUtils.ip2host(ses['source'], self.addomain.dnsresolver, self.addomain.dns_tcp)

                        # not resolved using dns - resolve using SMB/RPC NTLM
                        if target == ses['source']:
                            target = ADUtils.get_ntlm_hostname(ses['source'])

                        self.addomain.dnscache.put_single(ses['source'], target)
                    if ':' in target:
                        continue
                    if '.' not in target:
                        logging.debug('Resolved target does not look like an IP or domain. Assuming hostname: %s', target)
                        target = '%s.%s' % (target, domain)
                    # Resolve target hostname
                    try:
                        hostsid = self.addomain.computersidcache.get(target.lower())
                    except KeyError:
                        logging.warning('Could not resolve hostname to SID: %s', target)
                        continue

                    for user in (users or []):
                        c.sessions.append({
                            "UserSID": user,
                            "ComputerSID": hostsid,
                            "SessionFrom": ses.get('client') or ses.get('remote_ip') or "",   # selon ce que tu as dispo
                            "SessionType": "RDP" if ses.get('session_name') == "Console" else "SMB"
                        })
                        #print(f"[DEBUG] c.sessions after processing: {c.sessions}")
                # Loggons
                for user, userdomain in loggedon:
                    fupn = '%s@%s' % (user.upper(), userdomain.upper())
                    try:
                        users = self.addomain.samcache.get(fupn)
                    except KeyError:
                        entries = self.addomain.objectresolver.resolve_samname(user, use_gc=use_gc)
                        if entries is not None:
                            if len(entries) > 1:
                                for resolved_user in entries:
                                    edn = ADUtils.get_entry_property(resolved_user, 'distinguishedName')
                                    edom = ADUtils.ldap2domain(edn).lower()
                                    if edom == userdomain.lower():
                                        users = [resolved_user['attributes']['objectSid']]
                                        break
                                    logging.debug('Skipping resolved user %s since domain does not match (%s != %s)', edn, edom, userdomain.lower())
                            else:
                                users = [resolved_user['attributes']['objectSid'] for resolved_user in entries]
                        if entries is None or users == []:
                            logging.warning('Failed to resolve SAM name %s in current forest', samname)
                            continue
                        self.addomain.samcache.put(fupn, users)
                        if users is None:
                            users = []
                    for resultuser in users or []:
                        c.loggedon.append({'ComputerSID':objectsid, 'UserSID':resultuser})

                for ses in registry_sessions:
                    c.registry_sessions.append({'ComputerSID':objectsid, 'UserSID':ses['user']})

                for taskuser in tasks:
                    c.loggedon.append({'ComputerSID':objectsid, 'UserSID':taskuser})

                for serviceuser in services:
                    try:
                        user = self.addomain.sidcache.get(serviceuser)
                    except KeyError:
                        userentry = self.addomain.objectresolver.resolve_upn(serviceuser)
                        self.addomain.sidcache.put(serviceuser, userentry['attributes']['objectSid'])
                        user = userentry['attributes']['objectSid']
                    logging.debug('Resolved Service UPN to SID: %s', user)
                    c.loggedon.append({'ComputerSID':objectsid, 'UserSID':user})

                results_q.put(('computer', c.get_bloodhound_data(entry, self.collect)))

            except DCERPCException:
                logging.debug(traceback.format_exc())
                logging.warning('Querying computer failed: %s', hostname)
            except Exception as e:
                logging.error('Unhandled exception in computer %s processing: %s', hostname, str(e))
                logging.info(traceback.format_exc())
           
            #print("[DEBUG SESSIONS AVANT EXPORT]", c.sessions)

            # AJOUT POUR FORMAT_COMPUTERS
            if all_sessions_users is not None:
                host_key = f"{hostname.lower()}_session_users"
                all_sessions_users[host_key] = list(session_users_by_machine.get(host_key, []))

            results_q.put(('computer', c.get_bloodhound_data(entry, self.collect)))
            
            #print("[DEBUG] Connected users per machine:")
            #for machinename, users in session_users_by_machine.items():
            #    print(f"{machinename}: {users}")

    def work(self, process_queue, results_q):
        logging.debug('Start working')
        while True:
            args = process_queue.get()
            # Adapte ici :
            hostname, samname, comp_sid, entry, results_q, all_sessions_users = args
            logging.info('Querying computer: %s', hostname)
            self.process_computer(
                hostname, samname, comp_sid, entry, results_q, all_sessions_users
            )
            process_queue.task_done()

