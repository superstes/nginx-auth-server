DEBUG = False
TESTING = False  # direct non-proxy access to flask server

ENCRYPTION_KEY = ''  # NEEDS TO BE REPLACED!

AUTH_USER_TYPE = 'system'  # system,ldap,totp; totp only valid if 'TOKEN_TYPE' is None
AUTH_TOKEN_TYPE = None  # if 2FA should be used; totp or None

PORT = 8080
LOCATION = '/auth'
ORIGIN_HEADER = 'HTTP_X_AUTH_REQUEST_REDIRECT'

FORM_PARAM_USER = 'u'
FORM_PARAM_PWD = 'p'
FORM_PARAM_TOKEN = 't'

SESSION_LIFETIME = 8 * 3600  # 8 hours
COOKIE_SESSION = 'NGINX-AUTH-SESSION'
COOKIE_USER = 'NGINX-AUTH-USER'

PAM_FILE_SYSTEM = 'nginx-auth-system'
PAM_FILE_TOTP = 'nginx-auth-totp'
PAM_FILE_CUSTOM = 'nginx-auth-custom'

LDAP_CONFIG = dict(
    tls=True,
    server='',
    port=636,
    ca='/etc/auth/ldap/ca.crt',  # to validate server-cert
    use_client_cert=False,
    client_cert='/etc/auth/ldap/client.crt',
    client_key='/etc/auth/ldap/client.key',
    client_key_pwd='',
    base_dn='',
    bind=dict(
        user='',
        pwd='',
    ),
    filter='',
    # '(&(mail=%s)(objectClass=person)(memberOf:=CN=nginx,OU=Groups,DC=YOUR,DC=ORG))'
    #   login with mail; must be in group 'nginx'
    ignore_attrs=[],  # some LDAP (cloud-)providers may not support all attributes
    ip_version=46,  # 4, 46, 6, 64 or auto
    tls_version=1.2,  # 1.0, 1.1, 1.2, auto
)
