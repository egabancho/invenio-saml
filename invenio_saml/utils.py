# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 Esteban J. G. Gabancho.
#
# Flask-SSO-SAML is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.
"""Utility functions."""

from functools import wraps
from itertools import chain
from urllib.parse import urlparse

from flask import request
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from invenio_saml.handlers import acs_handler_factory
from invenio_saml.proxies import current_sso_saml



def prepare_flask_request(request):
    """Prepare OneLogin-friendly request."""
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    uri_data = urlparse(request.url)
    return {
        "get_data": request.args.copy(),
        "http_host": request.host,
        "https": "on" if request.scheme == "https" else "off",
        "post_data": request.form.copy(),
        "script_name": request.path,
        "server_port": uri_data.port,
        # Uncomment if using ADFS as IdP,
        # https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
    }


def run_handler(handler_name):
    """Find a handler inside configuration and call it."""

    def decorated(f):
        @wraps(f)
        def inner(self, *args, **kwargs):
            res = f(self, *args, **kwargs)
            handler = current_sso_saml.get_handler(self.idp, handler_name)
            if handler:
                return handler(self, res)
            return res

        return inner

    return decorated


class SAMLAuth(OneLogin_Saml2_Auth):
    """Encapsulate OneLogin SP SAML instance."""

    def __init__(self, idp, settings, *args, **kwargs):
        """Initialization."""
        self.idp = idp
        self._settings = settings
        req = current_sso_saml.prepare_flask_request(request)
        super(SAMLAuth, self).__init__(req, self._settings, *args, **kwargs)

    @run_handler("settings_handler")
    def get_settings(self):
        """Get settings info and call handler.

        :return: ``OneLogin_Saml2_Setting`` object
        """
        settings = super(SAMLAuth, self).get_settings()
        return settings

    @run_handler("login_handler")
    def login(self, *args, **kwargs):
        """Wrapper around ``OneLogin_Saml2_Auth.login``."""
        next_url = super(SAMLAuth, self).login(*args, **kwargs)
        return next_url

    @run_handler("logout_handler")
    def logout(self, *args, **kwargs):
        """Wrapper around ``OneLogin_Saml2_Auth.logout``."""
        next_url = super(SAMLAuth, self).logout(*args, **kwargs)
        return next_url

    @run_handler("acs_handler")
    def acs_handler(self, next_url):
        """Call ACS handler from config."""
        return next_url

    @run_handler("sls_handler")
    def sls_handler(self, next_url):
        """Call SLS handler from config."""
        return next_url


def pick_squarest_logo(logo_dicts, default=""):
    """Pick from logo_dicts a logo whose width/height-ratio is closest to 1."""
    pick = default
    best_ratio = float("inf")
    for logo_dict in logo_dicts:
        text = logo_dict["text"]
        width = int(logo_dict["width"])
        height = int(logo_dict["height"])

        ratio = max(width, height) / min(width, height)
        if ratio < best_ratio:
            pick = text
            best_ratio = ratio

    return pick


def parse_into_saml_config(mds, idp_id, langpref="en"):
    """Parse SAML-XML into config compatible with `invenio-saml`.
    See invenio-saml's SSO_SAML_IDPS for structure of this function's output.
    """
    sso_urls: list[str] = mds.single_sign_on_service(
        idp_id,
        binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    )
    if len(sso_urls) != 1:
        msg = f"{idp_id} has {len(sso_urls)} SSO-URLs for SAML's `Redirect` binding"
        raise ValueError(msg)
    # NOTE: by .xsd, "location"-key must exist here
    sso_url = sso_urls[0]["location"]

    certs: list[tuple[None, str]] = mds.certs(
        idp_id,
        descriptor="idpsso",
        use="signing",
    )
    if len(certs) < 1:
        msg = f"{idp_id} has no signing certificates"
        raise ValueError(msg)
    # there might be multiple signing certificates, by spec they should all work
    x509cert = certs[-1][1]

    # names/titles can be gotten from <md:Organization> or <mdui:DisplayName>
    preferred_display_names = list(
        mds.mdui_uiinfo_display_name(idp_id, langpref=langpref),
    )
    display_names = list(mds.mdui_uiinfo_display_name(idp_id))
    preferred_names = [name] if (name := mds.name(idp_id, langpref=langpref)) else []
    names = [name] if (name := mds.name(idp_id)) else []
    preferred_descriptions = list(
        mds.mdui_uiinfo_description(idp_id, langpref=langpref),
    )
    descriptions = list(mds.mdui_uiinfo_description(idp_id))

    # for title, prefer name in <md:Organization>
    title_iterator = chain(
        preferred_names,
        preferred_display_names,
        names,
        display_names,
    )
    title = next(title_iterator)

    # description
    desc_iterator = chain(
        preferred_descriptions,
        descriptions,
        preferred_display_names,
        preferred_names,
        display_names,
        names,
    )
    description = next(desc_iterator)

    icon = pick_squarest_logo(mds.mdui_uiinfo_logo(idp_id))

    return {
        "title": title,
        "description": description,
        "icon": icon,
        # "sp_cert_file": "./saml/idp/cert/sp.crt",
        # "sp_key_file": "./saml/idp/cert/sp.key",
        "settings": {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            },
            "idp": {
                "singleSignOnService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": sso_url,
                },
                "singleLougoutService": {},
                "x509cert": x509cert,
            },
            "security": {},  # leave at defaults
        },
        "mappings": {},
        "acs_handler": acs_handler_factory(idp_id),
        "auto_confirm": True,  # no need to click confirmation-link in some email
    }
