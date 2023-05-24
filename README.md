# Nginx 'auth_request' Server

A minimal [Python3-Flask](https://flask.palletsprojects.com/en/2.3.x/quickstart/) web-server that can be used as 'auth_request' target by Nginx.

What authentication methods are supported?

* LDAP using [ldap3](https://pypi.org/project/ldap3/)
* [PAM](https://github.com/linux-pam/linux-pam) using [python-pam](https://pypi.org/project/python-pam/)
  * System-User authentication (_local linux users_)
  * Time-based Tokens (_TOTP_) using [libpam-google-authenticator](https://github.com/google/google-authenticator-libpam)
  * any custom PAM module
* 2-Factor Authentication

If you want to use OAuth2 => you should look at [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy/blob/master/contrib/local-environment/nginx.conf) instead.

## Install

```bash
# edit and replace placeholders in:
#   lib/config.py
#   lib/templates/login.html
#   systemd/auth-server.service
#   pam/*

PATH_LIB='/var/local/lib/nginx_auth'
PATH_TOTP='/etc/auth/totp'
PATH_LDAP='/etc/auth/ldap'
SERVICE='nginx-auth-server'
AUTH_USER='nginx-auth'

useradd "$AUTH_USER"
mkdir -p "$PATH_LIB"
cp -r lib/* "$PATH_LIB"
chown -R "$AUTH_USER":"$AUTH_USER" "$PATH_LIB" 
chmod -R 750 "$PATH_LIB" 
apt install python3-pip sqlite3

# to use TOTP-authentication
apt install libpam-google-authenticator qrencode

mkdir -p "$PATH_TOTP"
chown -R "$AUTH_USER":"$AUTH_USER" "$PATH_TOTP" 
chmod 750 "$PATH_TOTP" 

# to use LDAP-authentication
mkdir -p "$PATH_LDAP"
chown -R "$AUTH_USER":"$AUTH_USER" "$PATH_LDAP" 
chmod 750 "$PATH_LDAP" 
#   add certificates (at least CA-Cert) to PATH_LDAP

# to use system-user authentication
usermod -a -G shadow "$AUTH_USER"

# create virtual environment
python3 -m pip install virtualenv
python3 -m virtualenv "${PATH_LIB}/venv"
source "${PATH_LIB}/venv/bin/activate"

python3 -m pip install flask waitress db-sqlite3

# you could remove unneeded modules
python3 -m pip install python-pam ldap3

# add systemd service
cp systemd/nginx-auth-server.service "/etc/systemd/system/${SERVICE}.service"
systemctl daemon-reload
systemctl enable "${SERVICE}.service"
systemctl start "${SERVICE}.service"
```

## Example

### Authentication config

Edit: lib/config.py

```python3
ENCRYPTION_KEY='YOUR-SECRET-RANDOM-SECRET'

AUTH_USER_TYPE = 'system'  # system,ldap,totp; totp only valid if 'TOKEN_TYPE' is None
AUTH_TOKEN_TYPE = None  # if 2FA should be used; 'totp' or None

LDAP_CONFIG=dict(
    tls=True,
    server='ldap.your.org',
    port=636,
    ca='/etc/auth/ldap/ca.crt',  # to validate server-cert
    use_client_cert=False,
    # client_cert='/etc/auth/ldap/client.crt',
    # client_key='/etc/auth/ldap/client.key',
    # client_key_pwd='',
    base_dn='OU=Base,DC=YOUR,DC=ORG',
    bind=dict(
        user='YOUR-BIND-USER',
        pwd='YOUR-BIND-PWD',
    ),
    filter='(&(mail=%s)(objectClass=person)(memberOf:=CN=nginx,OU=Groups,DC=YOUR,DC=ORG))',
)
```

### Nginx config

```
# you should limit the request-rate on the login location
limit_req_zone $binary_remote_addr zone=login_sec:20m rate=1r/s;
limit_req_zone $binary_remote_addr zone=login_min:40m rate=10r/m;
limit_req_status 429;

server {
  ...

  location {
    ...
    auth_request /auth;
    error_page 401 = /auth/login;
    auth_request_set $user $upstream_http_x_auth_request_user;
    proxy_set_header X-User $user;
  }

  # authentication
  location /auth {
    # access_log syslog:server=unix:/dev/log,tag=nginx_auth,nohostname,severity=info combined;
    # error_log  syslog:server=unix:/dev/log,tag=nginx_auth,nohostname,severity=error;
    internal;
    proxy_pass http://127.0.0.1:8080;
    proxy_pass_request_body off;
    proxy_pass_request_headers on;
    proxy_set_header Content-Length "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Scheme $scheme;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
  }
  location /auth/login {
    # access_log syslog:server=unix:/dev/log,tag=nginx_auth_login,nohostname,severity=info combined;
    # error_log  syslog:server=unix:/dev/log,tag=nginx_auth_login,nohostname,severity=error;
    limit_req zone=login_sec;
    limit_req zone=login_min;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Scheme $scheme;
    proxy_set_header X-Auth-Request-Redirect $request_uri;
  }
}
```

## Known issues

### libpam-google-authenticator 'user id/group id'

This error only occurs if the totp-validation is done by a non-root user.

Errors:
```
Failed to change group id for user ...
Failed to change user id to ... (should not appear if 'user=serviceuser' is used inside the pam-file)
```

Solution:
```bash
# make sure the python-binary inside your virtual-environment is no link
ls -l "${PATH_LIB}/venv/python"
# else you might need to copy the currently linked binary inside your venv
cp /usr/bin/python3 "${PATH_LIB}/venv/python/bin/python"
# make sure to limit the execution privileges on the binary

# after that you can add system capabilities to the binary
## if you encounter the 'Failed to change group id for user' error:
sudo setcap cap_setgid=+eip /usr/bin/python3.9
## if you encounter the 'Failed to change user id to' error:
sudo setcap cap_setuid=+eip /usr/bin/python3.9
```

**WARNING:**
Especially the 'cap_setuid' can lead to major security issues if not handled with care!

## System-user password-check fails

This error only occurs if the system-user validation is done by a non-root user.

Error:
```
unix_chkpwd: password check failed for user
```

Solution:
```
usermod -a -G shadow "$AUTH_USER"
```
