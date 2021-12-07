import pandas as pd
import numpy as np
from flask import Flask, render_template,g, request, session, redirect,make_response,url_for
from flask_moment import Moment
from datetime import timedelta
from datetime import datetime 

import json
##### BBDD LOGIN
from flask_sqlalchemy import SQLAlchemy

##### CUSTOM FUNCS #############
import queries_select as qs
import df_calculations as df_calcs
import formularios as forms
import funciones_inicializacion as fi 
################################


################################
#####      SAML IMPORTS    #####
import os
from urllib.parse import urlparse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

#############################
#####    APP  CONFIG    #####
#############################
#############################
app = Flask(__name__)
moment = Moment(app)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY']='key'
##BBDD logins usuarios
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{user}:{pass}@{ip}:{port}/{database}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
### DB ###
db = SQLAlchemy(app)

############################ SAML ####################################
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml')

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth

def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/', methods=["GET", "POST"])
def login_sso():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason  = None
    not_auth_warn = False
    success_slo   = False
    attributes    = False
    paint_logout  = False
    #sso es el boton de LOGIN, SSO2 es el boton de 'Login and access to attrs page'
    if 'sso' in request.args:
        attributes = auth.get_attributes();
        return redirect(auth.login())
    elif 'sso2' in request.args:
        return_to = '%sattrs/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']
        if 'samlNameIdFormat' in session:
            name_id_format = session['samlNameIdFormat']
        if 'samlNameIdNameQualifier' in session:
            name_id_nq = session['samlNameIdNameQualifier']
        if 'samlNameIdSPNameQualifier' in session:
            name_id_spnq = session['samlNameIdSPNameQualifier']
        return redirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))

    elif 'acs' in request.args:
        request_id = None
        if 'AuthNRequestID' in session:
            request_id = session['AuthNRequestID']
        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        attributes = auth.get_attributes();
        atributos=attributes
        if len(errors) == 0:
            if 'AuthNRequestID' in session:
                del session['AuthNRequestID']
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlNameIdFormat'] = auth.get_nameid_format()
            session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
            session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if self_url=='https://vision.vodafone.es':
                return redirect(url_for('index'))
            elif 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
            print("ERROR ACS: ",error_reason)
            return redirect(url_for('login_sso'))

    elif 'sls' in request.args:
        request_id = None
        if 'LogoutRequestID' in session:
            request_id = session['LogoutRequestID']
        dscb = lambda: session.clear()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True
                return redirect(url_for('login_sso'))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
            return redirect(url_for('login_sso'))

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template(
       'login.html',
        errors=errors,
        error_reason=error_reason,
        not_auth_warn=not_auth_warn,
        success_slo=success_slo,
        attributes=attributes,
        paint_logout=paint_logout
    )

@app.route('/attrs/')
def attrs():
    credentials=check_user_credentials()
    paint_logout = False
    attributes = False
    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()
    return render_template('attrs.html', paint_logout=paint_logout,
                           attributes=attributes)

@app.route('/metadata/')
def metadata():
    credentials=check_user_credentials()
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp



@app.route('/index', methods=["GET", "POST"])
def index():
    credentials=check_user_credentials()
    htm='index.html'
    return render_template(htm,name=credentials[3])


@app.route('/profile', methods=["GET", "POST"])
def profile():
    credentials=check_user_credentials()
    htm='index.html'
    return render_template(htm,name=credentials[3])

def check_user_credentials():
    '''
    retrieves the user credentials. Session parameters:
        'http://schemas.microsoft.com/claims/authnmethodsreferences':, 
        'http://schemas.microsoft.com/identity/claims/displayname': ,
        'http://schemas.microsoft.com/identity/claims/identityprovider',
        'http://schemas.microsoft.com/identity/claims/objectidentifier',
        'http://schemas.microsoft.com/identity/claims/tenantid',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'}
    '''
    my_session=session.get('samlUserdata',None)
    if my_session is None:
            return redirect(url_for('login_sso'))
    else: 
        connector_mistica =qs.connectMARIADB('mistica')
        email=my_session['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
        name=email[0].split('.')[0]
        name_surname=email[0].split('@')[0]
        user=name_surname.replace('.',' ')
        dataframe_users=fi.datos_usuarios(connector_mistica,name_surname)
        group=dataframe_users['grupo'].values[0]
        credentials=[name,user,email,name_surname,group]
        return credentials