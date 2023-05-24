#!/usr/bin/env python3

# flask application that acts as authentication service

from flask import Flask, request, render_template, redirect, Response
from waitress import serve

from config import PORT, AUTH_USER_TYPE, AUTH_TOKEN_TYPE, LOCATION, ORIGIN_HEADER, TESTING, \
    FORM_PARAM_USER, FORM_PARAM_PWD, FORM_PARAM_TOKEN, \
    SESSION_LIFETIME, COOKIE_SESSION, COOKIE_USER
from session import has_valid_session, create_session_token
from util import debug
from type_ldap import auth_ldap
from type_pam import auth_system, auth_totp
from type_multi import auth_multi

app = Flask('Nginx-Auth')

AUTH_MAPPING = {
    'ldap': auth_ldap,
    'system': auth_system,
    'totp': auth_totp,
}

SCHEME = 'http' if TESTING else 'https'


def _authenticate(user: str, secret_user: str, secret_token: (str, None)) -> bool:
    if AUTH_TOKEN_TYPE is None or secret_token is None:
        auth = AUTH_MAPPING[AUTH_USER_TYPE](user=user, secret=secret_user)

    else:
        auth = auth_multi(
            user=user, secret_user=secret_user, secret_token=secret_token,
            user_auth=AUTH_USER_TYPE, token_auth=AUTH_TOKEN_TYPE,
        )

    if auth:
        print(f"INFO: User '{user}' authentication successful.")

    else:
        print(f"WARNING: User '{user}' authentication failed.")

    return auth


def _redirect_origin() -> Response:
    origin = '/' if ORIGIN_HEADER not in request.headers else request.headers[ORIGIN_HEADER]
    return redirect(f"{SCHEME}://{request.headers['HOST']}{origin}")


# route for interactive authentication
#   this one is called if the non-interactive authentication returns status 401 unauthorized
@app.get(LOCATION + '/login')
def form():
    debug(loc='/login', msg=f"REQUEST | {request.__dict__}")

    if has_valid_session():
        response = _redirect_origin()
        debug(loc='/login', msg=f"RESPONSE | {response.__dict__}")
        return response

    debug(loc='/login', msg="RESPONSE | 200 - Rendering template")
    return render_template(
        'login.html',
        LOCATION=LOCATION, SCHEME=SCHEME, HOST=request.headers['HOST'],
        FORM_PARAM_PWD=FORM_PARAM_PWD, FORM_PARAM_USER=FORM_PARAM_USER, FORM_PARAM_TOKEN=FORM_PARAM_TOKEN
    )


# route to validate interactive authentication (to create session)
@app.post(LOCATION + '/login')
def login():
    debug(loc='/login', msg=f"REQUEST | {request.__dict__}")
    user = request.form[FORM_PARAM_USER]
    secret_user = request.form[FORM_PARAM_PWD]
    secret_token = request.form[FORM_PARAM_TOKEN] if FORM_PARAM_TOKEN in request.form else None

    if _authenticate(
            user=user,
            secret_user=secret_user,
            secret_token=secret_token
    ):
        response = _redirect_origin()
        token, session_time = create_session_token(user)
        response.set_cookie(
            key=COOKIE_SESSION,
            value=token,
            expires=session_time + SESSION_LIFETIME,
        )
        response.set_cookie(
            key=COOKIE_USER,
            value=user,
        )
        debug(loc='/login', msg=f"RESPONSE | {response.__dict__}")
        return response

    debug(loc='/login', msg='RESPONSE | 401')
    return 'unauthorized', 401


# route for non-interactive authentication (session cookie)
#   this one is called on every request that hits nginx
@app.get(LOCATION)
def auth_request():
    debug(loc='/', msg=f'REQUEST | {request.__dict__}')
    if has_valid_session():
        response = Response()
        response.status_code = 200
        response.headers['X_AUTH_REQUEST_USER'] = request.cookies[COOKIE_USER]
        debug(loc='/', msg=f"RESPONSE | {response.__dict__}")
        return response

    debug(loc='/', msg='RESPONSE | 401')
    return 'unauthorized', 401


@app.route('/<path:path>')
def catch_all(path):
    debug(loc=path, msg=f'REQUEST | {request.__dict__}')
    response = redirect(f"{SCHEME}://{request.headers['HOST']}")
    debug(loc=path, msg='RESPONSE | 200')
    return response


if __name__ == '__main__':
    serve(app, host='127.0.0.1', port=PORT)
