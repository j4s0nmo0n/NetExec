import logging

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aeskey='', kdc=None, auth_method='auto'):#, ldap_channel_binding=False):
        self.username = username
        # Assume user domain and enum domain are same
        self.domain = domain.lower()
        self.userdomain = domain.lower()
        # If not, override userdomain
        if '@' in self.username:
            self.username, self.userdomain = self.username.lower().rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aeskey = aeskey
        # KDC for domain we query
        self.kdc = kdc
        # KDC for domain of the user - fill with domain first, will be resolved later
        self.userdomain_kdc = self.domain
        self.auth_method = auth_method
        #self.ldap_channel_binding = ldap_channel_binding

        # Kerberos
        self.tgt = None

