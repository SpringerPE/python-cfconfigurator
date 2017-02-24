#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
python-cfconfigurator is a simple and small library to manage Cloud Foundry
(c) 2016 Jose Riguera Lopez, jose.riguera@springer.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
# Python 2 and 3 compatibility
from __future__ import unicode_literals, print_function

import json
import base64
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .exceptions import UAAException



class UAA(object):
    user_agent = "python-cfconfigurator"
    auth_token_url = '/oauth/token'
    user_url = '/Users'
    user_password_url = '/Users/%s/password'
    group_url = '/Groups'
    group_member_url = '/Groups/%s/members'
    client_url = '/oauth/clients'
    client_secret_url = '/oauth/clients/%s/secret'
    password_reset_url = '/password_resets'
    password_change_url = '/password_change'

    def __init__(self, api_url, client_id='cf', client_secret='',
                 identity_zone_id=None, identity_zone_subdomain=None,
                 ca_cert=None):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent
        })
        self.session.verify = True if ca_cert else False
        self.session.cert = ca_cert if ca_cert else None
        if identity_zone_id is not None:
            self.session.headers.update({
                "X-Identity-Zone-Id": str(identity_zone_id),
            })
        if identity_zone_subdomain is not None:
            self.session.headers.update({
                "X-Identity-Zone-Subdomain": str(identity_zone_subdomain),
            })
        self.api_url = api_url
        self.client_id = client_id
        self.client_secret = client_secret

    def _client(self, id, secret):
        """Performs client login with the provided credentials"""
        url = self.api_url + self.auth_token_url
        auth_string = '%s:%s' % (id, secret)
        authorization = base64.b64encode(auth_string.encode()).decode()
        headers = {
            'Authorization': "Basic " + authorization,
            'Content-Type': "application/x-www-form-urlencoded"
        }
        params = {
            'grant_type': 'client_credentials',
            'response_type': 'token'
        }
        return self.session.post(url, params=params, headers=headers)

    def _login(self, username, password, client_id, client_secret):
        """Performs login with the provided credentials"""
        url = self.api_url + self.auth_token_url
        auth_string = '%s:%s' % (client_id, client_secret)
        authorization = base64.b64encode(auth_string.encode()).decode()
        headers = {
            'Authorization': "Basic " + authorization,
            'Content-Type': "application/x-www-form-urlencoded"
        }
        params = {
            'username': str(username),
            'password': str(password),
            # 'client_id': client_id,
            'grant_type': 'password',
            'response_type': 'token'
        }
        return self.session.post(url, params=params, headers=headers)

    def _request(self, method, url, params=None, http_headers=None, data=None):
        if http_headers is not None:
            headers = dict(self.session.headers)
            headers.update(http_headers)
        else:
            headers = self.session.headers
        req = requests.Request(method, url, data=data, headers=headers, params=params)
        prepared_req = req.prepare()
        resp = self.session.send(prepared_req)
        response = {}
        error = {}
        try:
            response = resp.json()
        except ValueError as e:
            if resp.status_code == 400:
                error['description'] = "Unparseable, syntactically incorrect"
                error['message'] = "HTTP Bad request"
                raise UAAException(error, resp.status_code)
            elif resp.status_code == 401:
                error['description'] = "Invalid token"
                error['message'] = "HTTP Unauthorized"
                raise UAAException(error, resp.status_code)
            elif resp.status_code == 403:
                error['description'] = "Insufficient scope"
                error['message'] = "HTTP Forbidden"
                raise UAAException(error, resp.status_code)
            elif resp.status_code == 404:
                error['description'] = "ID not found"
                error['messae'] = "HTTP Not found"
                raise UAAException(error, resp.status_code)
            elif resp.status_code == 409:
                error['description'] = "Conflict, If-Match header, version mismatch"
                error['message'] = "HTTP Already exists"
                raise UAAException(error, resp.status_code)
            elif resp.status_code == 200 or resp.status_code == 201:
                if len(resp.content) != 0:
                    error['description'] = "HTTP response not valid, %s" % str(e)
                    raise UAAException(error, resp.status_code)
            else:
                error['description'] = "HTTP response code not valid"
                raise UAAException(error, resp.status_code)
        if 'error' in response:
            error['error'] = response.get('error')
            error['message'] = response.get('message')
            description = response.get('error_description')
            if description != error['message']:
                error['description'] = description
            raise UAAException(error, resp.status_code)
        return response, resp.status_code

    def _find(self, url, filters, op, attributes=[]):
        # attributes=['id', 'username']
        params = {}
        if attributes:
            params['attributes'] = ','.join(attributes)
        build_filters = []
        for f in filters:
            build_filters.append("%s eq '%s'" % (f, filters[f]))
        if build_filters:
            params['filter'] = (" %s " % op).join(build_filters)
        resp, rc = self._request('GET', url, params)
        return resp

    def _save(self, url, data, headers=None, id=None):
        method = 'POST'
        if id is not None:
            # update
            url = url + '/' + str(id)
            method = 'PUT'
        resp, rc = self._request(method, url, http_headers=headers, data=json.dumps(data))
        return resp

    def _delete(self, url, version=None):
        headers = None
        if version is not None:
            headers = {'If-Match': version }
        resp, rc = self._request('DELETE', url, http_headers=headers)
        return resp

    def login(self, username=None, password=''):
        """Performs login with the provided credentials"""
        auth = None
        if username is not None:
            # User login
            resp = self._login(username, password, self.client_id, self.client_secret)
            msg = "User Login"
        else:
            # client credentials
            resp = self._client(self.client_id, self.client_secret)
            msg = "Client credentials"
        if resp.status_code == requests.codes.ok:
            auth = resp.json()
            self.session.headers.update({
                'Authorization':
                    ("%s %s" % (auth['token_type'], auth['access_token']))
            })
        else:
            error = {'description': "%s not valid" % msg }
            raise UAAException(error, resp.status_code)
        return auth

    def user_find(self, filters, op='and', attributes=[]):
        url = self.api_url + self.user_url
        return self._find(url, filters, op, attributes)

    def user_get(self, id, version='*'):
        url = self.api_url + self.user_url + '/' + str(id)
        headers = {'If-Match': version }
        resp, rc = self._request('GET', url, http_headers=headers)
        return resp

    def user_save(self, name, usernames=[], password='', emails=[], active=True,
                  verified=True, phones=[], origin='uaa', externalId='',
                  id=None, version='*'):
        url = self.api_url + self.user_url
        data = {
            'userName': name,
            'origin': origin,
            'name': {},
            'emails': [],
            'phoneNumbers': [],
            'active': active,
            'verified': verified,
        }
        if usernames:
            data['name']['formatted'] = " ".join(usernames)
            data['name']['givenName'] = usernames[0]
            data['name']['familyName'] = usernames[-1]
        if emails:
            for i, e in enumerate(emails):
                email = {
                    'value': e,
                    'primary': (i == 0)
                }
                data['emails'].append(email)
        elif '@' in name:
            email = {
                'value': name,
                'primary': True
            }
            data['emails'].append(email)
        else:
            raise ValueError("Email required (username or emails)")
        for p in phones:
            phone = {
                'value': p
            }
            data['phoneNumbers'].append(phone)
        if origin == 'uaa':
            data['externalId'] = externalId
        headers = None
        if id is not None:
            # update
            headers = {'If-Match': version }
        else:
            # create
            data['password'] = password
        return self._save(url, data, headers, id)

    def user_set_password(self, id, password, version='*'):
        url = self.api_url + self.user_password_url % str(id)
        data = {"password": str(password) }
        headers = {'If-Match': version }
        resp, rcode = self._request('PUT', url, http_headers=headers, data=json.dumps(data))
        return resp

    def user_delete(self, id, version='*'):
        url = self.api_url + self.user_url + '/' + str(id)
        return self._delete(url, version)

    def group_find(self, filters, op='and', attributes=[]):
        url = self.api_url + self.group_url
        return self._find(url, filters, op, attributes)

    def group_get(self, id):
        url = self.api_url + self.group_url + '/' + str(id)
        resp, rc = self._request('GET', url)
        return resp

    def group_save(self, name, description='', members=[], id=None):
        url = self.api_url + self.group_url
        data = {
            'displayName': name,
            'description': description,
        }
        group_members = []
        for m in members:
            newm = {
                'value': str(m['value']),
                'type': str(m.get('type', 'USER')),
                'origin': str(m.get('origin', 'uaa'))
            }
            group_members.append(newm)
        if group_members:
            data['members'] = group_members
        return self._save(url, data, None, id)

    def group_delete(self, id, version='*'):
        url = self.api_url + self.group_url + '/' + str(id)
        return self._delete(url, version)

    def group_manage_member(self, id, member_id, member_type='USER',
                            member_origin='uaa', add=True):
        url = self.api_url + self.group_member_url % str(id)
        params = {'returnEntities': 'false'}
        resp, rc = self._request('GET', url, params)
        found = False
        member_id = str(member_id)
        for m in resp:
            if member_id == m['value']:
                found = True
                break
        if add:
            if not found:
                # add the member
                newm = {
                    'value': member_id,
                    'type': str(member_type),
                    'origin': str(member_origin)
                }
                self._request('POST', url, data=json.dumps(newm))
                return True
        else:
            if found:
                # delete member
                url = url + '/' + str(member_id)
                self._request('DELETE', url)
                return True
        return False

    def client_find(self, filters, op='and', attributes=[]):
        url = self.api_url + self.client_url
        return self._find(url, filters, op, attributes)

    def client_get(self, id):
        url = self.api_url + self.client_url + '/' + str(id)
        resp, rc = self._request('GET', url)
        return resp

    def client_save(self, client_id, name, client_secret=None,
                    token_salt=None, authorized_grant_types=['client_credentials'],
                    scope=['uaa.none'], authorities=['uaa.none'], autoapprove=['true'],
                    allowedproviders=['uaa'], resource_ids=[], redirect_uri=[],
                    access_token_validity=2700, refresh_token_validity=7000,
                    id=None):
        url = self.api_url + self.client_url
        data = {
            'name': str(name),
            'client_id': str(client_id),
            'scope': scope,
            'authorized_grant_types': authorized_grant_types,
            'access_token_validity': access_token_validity,
            'refresh_token_validity': refresh_token_validity,
            'authorities': authorities,
            'autoapprove': autoapprove,
            'allowedproviders': allowedproviders,
            'redirect_uri': redirect_uri,
            'resource_ids': resource_ids
        }
        if id is None and client_secret is not None:
            # secrect is only allowed at creation time
            # not for updates, in such case use client_set_secret
            data['client_secret'] = str(client_secret)
        if token_salt is not None:
            data['token_salt'] = str(token_salt)
        return self._save(url, data, None, id)

    def client_set_secret(self, id, secret):
        url = self.api_url + self.client_secret_url % str(id)
        data = {
            'clientId': str(id),
            'secret': str(secret)
        }
        resp, rcode = self._request('PUT', url, data=json.dumps(data))
        return resp

    def client_delete(self, id):
        url = self.api_url + self.client_url + '/' + str(id)
        return self._delete(url)
