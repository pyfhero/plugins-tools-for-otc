#!/usr/bin/env python
# encoding: utf-8

# @Author  : Pan Yuefeng
# @Contact : panyuefeng@huawei.com
# @File    : otc_adfs_auth.py
# @Created : 2018/7/14 9:58
# @Desc    : Implement Federated API Using SAML 2.0 and AD FS with Open Telekom Cloud (OTC)

# sys libs
import os
import sys
import requests
import json
import re
from bs4 import BeautifulSoup
from urlparse import urlparse


class ActiveDirectoryAuth:
    # This tag name and password depend on your AD login page. Please modify if necessary.
    TAG_NAME = "username"
    TAG_PWD = "password"

    def __init__(self, ad_name, ad_pwd, url_ad, url_otc, ssl_verify=True):
        self._url_idp_entry = "%s?logintorp=%s" % (url_ad, url_otc)
        self._ad_name = ad_name
        self._ad_pwd = ad_pwd

        # only one session for api calling
        self._session = requests.Session()
        self._cur_path = os.getcwd()
        self._ssl_verify = ssl_verify
        self._saml_assertion = None

    def saml_assertion_get(self):
        if self._saml_assertion is None:
            self._saml_assertion = self._saml_assertion_get()
        else:
            pass

        return self._saml_assertion

    def _html_file_write(self, file_name, context):
        with open(file_name, 'wb') as obj_file:
            obj_file.write(context)

    def _ad_login_form_get(self):
        # This flag is used to make sure that the right login page with name and password is displayed.
        flag_match = 0

        # Opens the initial IdP url and follows all of the HTTP302 redirects, and gets the resulting login page
        form_resp = self._session.get(self._url_idp_entry, verify=self._ssl_verify)

        # Set the default idp submit page
        url_idp_submit = form_resp.url

        # Parse the response page to build a form of values that the IdP expects.
        # This depends on your own login page. For example, the page may be in 'ascii' or 'utf8' form.
        form_soup = BeautifulSoup(form_resp.text.decode("utf8"), "lxml")
        auth_options = {}
        for tag_input in form_soup.find_all(re.compile("(INPUT|input)")):
            tag_name = tag_input.get("name", "")

            if self.TAG_NAME in tag_name.lower():
                auth_options[tag_name] = self._ad_name
                flag_match += 1
            elif self.TAG_PWD in tag_name.lower():
                auth_options[tag_name] = self._ad_pwd
                flag_match += 1
            else:
                auth_options[tag_name] = tag_input.get("value", "")

        if 2 != flag_match:
            page_login = "%s/login.html" % self._cur_path
            self._html_file_write(page_login, form_resp.text)

            err_msg = "Failed to get tag(%s, %s) from the login page, %d tags match. " \
                      "Please check the login page, which is saved to local %s" \
                      % (self.TAG_NAME, self.TAG_PWD, flag_match, page_login )
            raise Exception(err_msg)

        # please test on browser first, and add other form data in payload if necessary
        #auth_options["_eventId_proceed"] = ""

        # If any update of the action url
        for tag_input in form_soup.find_all(re.compile("(FORM|form)")):
            tag_action = tag_input.get("action")
            if tag_action:
                url_parse = urlparse(self._url_idp_entry)
                url_idp_submit = "%s://%s%s" % (url_parse.scheme, url_parse.netloc, tag_action)
                break

        # Overwrite the credential variables for safety
        self._ad_pwd = "********"

        return url_idp_submit, auth_options

    def _saml_assertion_get(self):
        url_submit, auth_option = self._ad_login_form_get()

        # Performs the submission of the IdP login form with the above auth data
        assertion_resp = self._session.post(url_submit, data=auth_option, verify=self._ssl_verify)
        # print assertion_resp.text.decode("utf8")

        # !!! ATTENTION: Please double check whether any more pages would prompt before the SAML response page or not.
        #                Please skip the pages before the SAML response page if necessary.

        # Decode the SAML response and extract the SAML assertion
        assertion_soup = BeautifulSoup(assertion_resp.text.decode("utf8"), "lxml")
        saml_response = None

        # Look for the SAMLResponse attribute of the input tag
        for tag_input in assertion_soup.find_all(re.compile("(INPUT|input)")):
            if "SAMLResponse" == tag_input.get("name"):
                saml_response = tag_input.get("value")
                break

        if saml_response is None:
            page_saml = "%s/samlresponse.html" % self._cur_path
            self._html_file_write(page_saml, assertion_resp.text)

            err_msg = "Failed to get the SAML assertion from the response page. " \
                      "Incorrect user ID(%s) or password." \
                      "Please check the html page, which is saved to local %s" \
                      % (self._ad_name, page_saml)
            raise Exception(err_msg)

        return saml_response


class OtcIamAuth:
    STS_TIMEOUT = 900

    def __init__(self, url_otc, idp_name, saml_assertion):
        self._url_token_unscoped = "%s/v3.0/OS-FEDERATION/tokens" % url_otc
        self._url_token_scoped = "%s/v3/auth/tokens" % url_otc
        self._url_token_sts = "%s/v3.0/OS-CREDENTIAL/securitytokens" % url_otc
        self._otc_idp_name = idp_name
        self._saml_assertion = saml_assertion

        # only one session for api calling
        self._session = requests.Session()

        self._token_unscoped = None
        self._token_scoped = None
        self._token_sts = None

    def token_unscoped_get(self):
        if self._token_unscoped is None:
            self._token_unscoped = self._token_unscoped_get()
        return self._token_unscoped

    def _token_unscoped_get(self):
        restful_header = {"X-Idp-Id": self._otc_idp_name}
        restful_body = {"SAMLResponse": self._saml_assertion}

        restful_resp = self._session.post(self._url_token_unscoped, data=restful_body,
                                          headers=restful_header, verify=True)
        if 201 != restful_resp.status_code:
            err_msg = "IDP(%s) failed to authenticate with saml assertion. " \
                      "Please check whether idp'%s' has been already created on OTC. Detail: %s" \
                       % (self._otc_idp_name, self._otc_idp_name, restful_resp.text)
            raise Exception(err_msg)

        token_unscoped = restful_resp.headers.get("X-Subject-Token", None)
        if token_unscoped is None:
            err_msg = "IDP(%s) failed to get unscoped token from response. Detail: %s" \
                      % (self._otc_idp_name, restful_resp.text)
            raise Exception(err_msg)
        return token_unscoped

    def token_sts_get(self, timeout):
        if timeout < self.STS_TIMEOUT:
            raise ValueError("Timeout for security token should not be less than %s." % self.STS_TIMEOUT)

        token_unscoped = self.token_unscoped_get()
        restful_header = {"X-Auth-Token": token_unscoped}
        restful_body = {
                            "auth": {
                                "identity": {
                                    "methods": ["token"],
                                    "token": {"duration-seconds": timeout}
                                }
                            }
                        }

        restful_resp = self._session.post(self._url_token_sts,
                                          json=restful_body, headers=restful_header, verify=True)
        if 201 != restful_resp.status_code:
            err_msg = "IDP(%s) failed to get %s seconds security token. Detail: %s" \
                      % (self._otc_idp_name, timeout, restful_resp.text)
            raise Exception(err_msg)
        else:
            token_sts = restful_resp.text
            self._token_sts = token_sts
        return token_sts

    def token_scoped_get(self, project):
        token_unscoped = self.token_unscoped_get()
        payload = {
            "auth": {
                "identity": {
                    "methods": ["token"],
                    "token": {
                        "id": token_unscoped
                    }
                },
                "scope": {
                    "project": {
                        "name": project
                    }
                }
            }
        }

        restful_resp = self._session.post(self._url_token_scoped, json=payload, verify=True)
        if 201 != restful_resp.status_code:
            err_msg = "IDP(%s) failed to get scoped token of project(%s). Detail: %s" \
                      % (self._otc_idp_name, project, restful_resp.text)
            raise Exception(err_msg)
        else:
            token_scoped = restful_resp.headers.get("X-Subject-Token", None)
            self._token_scoped = token_scoped
        return token_scoped


def conf_get(conf_file):
    with open(conf_file, 'r') as obj_conf:
        conf_info = json.load(obj_conf)
    return conf_info


def otc_adfs_auth():
    conf_file = "%s/.otc/ad_auth.conf" % os.path.expanduser("~")
    if not os.path.isfile(conf_file):
        print "Please create %s first." % conf_file
        sys.exit(1)

    conf_info = conf_get(conf_file)
    url_ad_login = conf_info["adlogin_url"]
    username = conf_info["username"]
    password = conf_info["password"]
    url_otc_iam = conf_info["iam_url"]
    project = conf_info["project"]
    idp_name = conf_info["idp"]
    timeout = conf_info["timeout"]

    ad_auth = ActiveDirectoryAuth(username, password, url_ad_login, url_otc_iam, False)
    saml_assertion = ad_auth.saml_assertion_get()

    otc_auth = OtcIamAuth(url_otc_iam, idp_name, saml_assertion)
    token_sts = otc_auth.token_sts_get(timeout)
    print "Security token (Ak/SK):\n", token_sts
    token_scoped = otc_auth.token_scoped_get(project)
    print "Scoped token:\n", token_scoped

    return


if __name__ == '__main__':
    otc_adfs_auth()
