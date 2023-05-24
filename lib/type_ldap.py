import ssl
from pathlib import Path

import ldap3
from ldap3.utils.conv import escape_filter_chars as ldap_escape_filter_chars

from config import LDAP_CONFIG
from util import debug

# see: https://www.python-ldap.org/_/downloads/en/python-ldap-3.3.0/pdf/

# some providers like google don't support all attributes
LDAP_ATTRIBUTE_IGNORE = [
    'createTimestamp',
    'modifyTimestamp',
]
LDAP_IP_MODE_MAPPING = {
    4: ldap3.IP_V4_ONLY,
    6: ldap3.IP_V6_ONLY,
    46: ldap3.IP_V4_PREFERRED,
    64: ldap3.IP_V6_PREFERRED,
}
LDAP_TLS_VERSION_MAPPING = {
    1.0: ssl.PROTOCOL_TLSv1,
    1.1: ssl.PROTOCOL_TLSv1_1,
    1.2: ssl.PROTOCOL_TLSv1_2,
}


def _server() -> ldap3.Server:
    mode = ldap3.IP_SYSTEM_DEFAULT

    if LDAP_CONFIG['ip_version'] in LDAP_IP_MODE_MAPPING:
        mode = LDAP_IP_MODE_MAPPING[LDAP_CONFIG['ip_version']]

    if LDAP_CONFIG['tls']:
        return ldap3.Server(
            host=LDAP_CONFIG['server'],
            tls=_tls(),
            mode=mode,
            port=LDAP_CONFIG['port'],
            use_ssl=True,
        )

    return ldap3.Server(
        host=LDAP_CONFIG['server'],
        mode=mode,
        port=LDAP_CONFIG['port'],
        use_ssl=False,
    )


def _tls_set_cert(ssl_context: dict, ctx_key: str, config_key: str):
    try:
        if Path(LDAP_CONFIG[config_key]).exists():
            ssl_context[ctx_key] = LDAP_CONFIG[config_key + '_file']

        else:
            ssl_context[ctx_key] = LDAP_CONFIG[config_key + '_data']

    except OSError:
        ssl_context[ctx_key] = LDAP_CONFIG[config_key + '_data']


def _tls() -> ldap3.Tls:
    tls_version = ssl.PROTOCOL_TLS

    if LDAP_CONFIG['tls_version'] in LDAP_TLS_VERSION_MAPPING:
        tls_version = LDAP_TLS_VERSION_MAPPING[LDAP_CONFIG['tls_version']]

    ssl_context = {
        'validate': ssl.CERT_REQUIRED,
        'version': tls_version,
    }

    _tls_set_cert(ssl_context=ssl_context, ctx_key='ca_certs', config_key='ca')

    ldap3.set_config_parameter(
        'ATTRIBUTES_EXCLUDED_FROM_CHECK',
        ldap3.get_config_parameter('ATTRIBUTES_EXCLUDED_FROM_CHECK') +
        LDAP_ATTRIBUTE_IGNORE +
        LDAP_CONFIG['ignore_attrs']
    )

    if LDAP_CONFIG['use_client_cert']:
        _tls_set_cert(ssl_context=ssl_context, ctx_key='local_certificate', config_key='client_cert')
        _tls_set_cert(ssl_context=ssl_context, ctx_key='local_private_key', config_key='client_key')
        if LDAP_CONFIG['client_key_pwd'] not in ['', ' ', None]:
            ssl_context['local_private_key_password'] = LDAP_CONFIG['client_key_pwd']

    return ldap3.Tls(**ssl_context)


def auth_ldap(user: str, secret: str) -> bool:
    user = ldap_escape_filter_chars(user)
    server = _server()
    ldap = ldap3.Connection(
        server=server,
        user=LDAP_CONFIG['bind']['user'],
        password=LDAP_CONFIG['bind']['pwd'],
    )

    # bind with service user to check if user is authorized
    ldap.open()
    if ldap.bind():
        debug('AUTH LDAP | Bind user | Authentication successful')
        ldap.search(
            search_base=LDAP_CONFIG['base_dn'],
            search_filter=LDAP_CONFIG['filter'],
        )
        if len(ldap.entries) == 1:
            print(f"AUTH LDAP | User '{user}' | Authorized")
            ldap_user = ldap.entries[0]
            debug(f"AUTH LDAP | User '{user}' | Matched filter: '{LDAP_CONFIG['filter']}'")

            # validate actual user credentials
            login_test = ldap3.Connection(
                server=server,
                user=ldap_user.entry_dn,
                password=secret,
            )
            login_test.open()

            if login_test.bind():
                login_test.unbind()
                print(f"AUTH LDAP | User '{user}' | Authentication successful")
                return True

            print(f"AUTH LDAP | User '{user}' | Authentication failed")

        else:
            print(f"AUTH LDAP | User '{user}' | Unauthorized")

    else:
        print('AUTH LDAP | Bind User | Authentication failed')

    return False
