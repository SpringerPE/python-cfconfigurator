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
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .exceptions import CFException, UAAException
from .uaa import UAA



class CF(object):
    user_agent = "python-cfconfigurator"
    info_url = '/v2/info'
    spaces_url = '/v2/spaces'
    users_url = '/v2/users'
    users_organizations_url = '/v2/users/%s/organizations'
    users_managed_organizations_url = '/v2/users/%s/managed_organizations'
    users_audited_organizations_url = '/v2/users/%s/audited_organizations'
    users_billing_managed_organizations_url = '/v2/users/%s/billing_managed_organizations'
    users_audited_spaces_url = '/v2/users/%s/audited_spaces'
    users_managed_spaces_url = '/v2/users/%s/managed_spaces'
    users_spaces_url = '/v2/users/%s/spaces'
    organizations_url = '/v2/organizations'
    organization_space_url = '/v2/organizations/%s/spaces'
    organization_domains_url = '/v2/organizations/%s/private_domains'
    secgroups_url = '/v2/security_groups'
    secgroups_running_url = '/v2/config/running_security_groups'
    secgroups_staging_url = '/v2/config/staging_security_groups'
    secgroups_space_url = '/v2/security_groups/%s/spaces'
    blobstores_builpack_cache_url = '/v2/blobstores/buildpack_cache'
    environment_variable_group_url = '/v2/config/environment_variable_groups'
    feature_flags_url = '/v2/config/feature_flags'
    quotas_url = '/v2/quota_definitions'
    shared_domains_url = '/v2/shared_domains'
    private_domains_url = '/v2/private_domains'

    def __init__(self, api_url, client_id='cf', client_secret='', ca_cert=None):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent}
        )
        self.session.verify = True if ca_cert else False
        self.session.cert = ca_cert if ca_cert else None
        self.api_url = api_url
        api_auth_url = self.info()['token_endpoint']
        self.uaa = UAA(api_auth_url, client_id, client_secret)
        self.username = None
        self.password = ''

    def _login(self):
        try:
            auth = self.uaa.login(self.username, self.password)
        except UAAException as e:
            error = {'description': str(e)}
            raise CFException(error)
        self.session.headers.update({
            'Authorization': ("%s %s" % (auth['token_type'], auth['access_token']))
        })
        return auth

    def info(self):
        """Gets info endpoint. Used to perform login auth."""
        url = self.api_url + self.info_url
        resp = self.session.get(url)
        if resp.status_code != 200:
            error = {'description': "Info HTTP response not valid"}
            raise CFException(error, resp.status_code)
        try:
            info = resp.json()
        except ValueError as e:
            error = {'description': "Info HTTP response not valid, %s" % str(e)}
            raise CFException(error, resp.status_code)
        return info

    def login(self, username=None, password=''):
        """Performs login with the provided credentials"""
        self.username = username
        self.password = password
        return self._login()

    def _request(self, method, url, params=None, http_headers=None, data=None):
        if http_headers:
            headers = dict(self.session.headers)
            headers.update(http_headers)
        else:
            headers = self.session.headers
        req = requests.Request(method, url,
                               data=data, headers=headers, params=params)
        prepared_req = req.prepare()
        resp = self.session.send(prepared_req)
        try:
            response = resp.json()
            if response:
                if ('error_code' in response and (
                    response['error_code'] == 'CF-InvalidAuthToken' or
                    response['error_code'] == 'CF-NotAuthenticated')):
                    # try again
                    self._login()
                    resp = self.session.send(prepared_req)
                    response = resp.json()
        except ValueError as e:
            if len(resp.content) == 0:
                response = {}
            else:
                error = {'description': "HTTP response not valid, %s" % str(e)}
                raise CFException(error, resp.status_code)
        return response, resp.status_code

    def request(self, method, url, params=None, http_headers=None, data=None):
        api = self.api_url
        if url.startswith('/'):
            url = api + url
        else:
            parsed = requests.compat.urlparse(url)
            if parsed.scheme == '' or parsed.netloc == '':
                raise ValueError("url not valid")
            api = parsed.scheme + "://" + parsed.netloc
        response, rcode = self._request(method, url, params, http_headers, data)
        if 'resources' in response and 'total_pages' in response:
            pages = response['total_pages']
            pages_counter = 1
            while response['next_url'] != None and rcode == 200:
                part_url = api + response['next_url']
                part_resp, rcode = self._request(method, part_url, None, http_headers, data)
                pages_counter += 1
                part_resp['resources'] = response['resources'] + part_resp['resources']
                response = part_resp
            if pages_counter != pages:
                msg = "number of expected pages different than actual pages"
                error = {'description': "Pagination error " + msg}
                raise CFException(error, rcode)
            response['next_url'] = None
            response['prev_url'] = None
        return response, rcode

    def _get(self, url, params=None):
        resp, rcode = self.request('GET', url, params)
        if rcode != 200:
            raise CFException(resp, rcode)
        return resp

    def _search(self, url, params):
        resp = self._get(url, params)
        if int(resp['total_results']) == 0:
            return None
        else:
            return resp['resources'][0]

    def _delete(self, url, params=None):
        resp, rcode = self.request('DELETE', url, params)
        if rcode != 204:
            raise CFException(resp, rcode)

    def _update(self, create, url, data=None):
        method = 'POST' if create else 'PUT'
        json_data = None if data is None else json.dumps(data)
        resp, rcode = self.request(method, url, None, None, json_data)
        if rcode != 201 and rcode != 200:
            raise CFException(resp, rcode)
        return resp


    def clean_blobstore_cache(self):
        """Deletes all of the existing buildpack caches in the blobstore"""
        url = self.api_url + self.blobstores_builpack_cache_url
        resp, rcode = self.request('DELETE', url)
        if rcode != 202:
            raise CFException(resp, rcode)
        return resp


    def get_variable_group(self, name="running"):
        url = self.api_url + self.environment_variable_group_url + '/' + name
        return self._get(url)

    def manage_variable_group(self, key, value='', name="running", add=True):
        url = self.api_url + self.environment_variable_group_url + '/' + name
        variable_value = str(value)
        variable_name = str(key)
        if '-' in variable_name:
            raise ValueError("name not valid for an enviroment variable")
        changed = False
        variables = self.get_variable_group(name)
        if add:
            if variable_name in variables:
                if variables[variable_name] != variable_value:
                    variables[variable_name] = variable_value
                    changed = True
            else:
                variables[variable_name] = variable_value
                changed = True
        else:
            try:
                del variables[variable_name]
                changed = True
            except:
                pass
        if changed:
            json_data = json.dumps(variables)
            resp, rcode = self.request('PUT', url, None, None, json_data)
            if rcode != 200:
                raise CFException(resp, rcode)
        return changed


    def get_feature_flags(self):
        url = self.api_url + self.feature_flags_url
        return self._get(url)

    def manage_feature_flags(self, name, enabled):
        url = self.api_url + self.feature_flags_url + '/' + name
        resp = self._get(url)
        if resp['enabled'] != enabled:
            data = {
                'enabled': enabled
            }
            resp, rcode = self.request('PUT', url, None, None, json.dumps(data))
            if rcode != 200:
                raise CFException(resp, rcode)
            return True
        return False


    def search_org(self, name):
        url = self.api_url + self.organizations_url
        params = {'q': "name:%s" % str(name) }
        return self._search(url, params)

    def delete_org(self, guid, async=False, recursive=False):
        url = self.api_url + self.organizations_url + '/' + guid
        params = {
            'async': str(async).lower(),
            'recursive': str(recursive).lower()
        }
        self._delete(url, params)

    def save_org(self, name, quota_guid=None, guid=None):
        url = self.api_url + self.organizations_url
        create = True
        if guid is not None:
            url = url + '/' + guid
            create = False
        data = {'name': name }
        if quota_guid:
            data['quota_definition_guid'] = str(quota_guid)
        return self._update(create, url, data)


    def search_quota(self, name):
        url = self.api_url + self.quotas_url
        params = {'q': "name:%s" % str(name) }
        return self._search(url, params)

    def delete_quota(self, guid, async=False):
        url = self.api_url + self.quotas_url + '/' + guid
        params = {'async': str(async).lower() }
        self._delete(url, params)

    def save_quota(self, name, non_basic_services_allowed, total_services,
                     total_routes, memory_limit, instance_memory_limit,
                     total_service_keys=-1, total_reserved_route_ports=-1,
                     total_private_domains=-1, app_instance_limit=-1, guid=None):
        url = self.api_url + self.quotas_url
        create = True
        if guid is not None:
            url = url + '/' + guid
            create = False
        data = {
            'name': str(name),
            "non_basic_services_allowed": non_basic_services_allowed,
            "total_services": total_services,
            "total_routes": total_routes,
            "memory_limit": memory_limit,
            "instance_memory_limit": instance_memory_limit,
            "total_service_keys": total_service_keys,
            "total_reserved_route_ports": total_reserved_route_ports,
            "total_private_domains": total_private_domains,
            "app_instance_limit": app_instance_limit
        }
        return self._update(create, url, data)


    def search_domain(self, name, kind="private"):
        if kind == "private":
            url = self.api_url + self.private_domains_url
        elif kind == "shared":
            url = self.api_url + self.shared_domains_url
        else:
            raise ValueError("invalid domain type, options: private or shared")
        params = {'q': "name:%s" % str(name)}
        return self._search(url, params)

    def delete_domain(self, guid, kind="private", async=False):
        if kind == "private":
            url = self.api_url + self.private_domains_url + '/' + guid
        elif kind == "shared":
            url = self.api_url + self.shared_domains_url + '/' + guid
        else:
            raise ValueError("invalid domain type, options: private or shared")
        params = {'async': str(async).lower() }
        self._delete(url, params)

    def create_shared_domain(self, name, router_group_guid=None):
        url = self.api_url + self.shared_domains_url
        data = {'name': str(name) }
        if router_group_guid is not None:
            data['router_group_guid'] = str(router_group_guid)
        return self._update(True, url, data)

    def create_private_domain(self, name, owning_organization_guid):
        url = self.api_url + self.private_domains_url
        data = {
            'name': str(name),
            'owning_organization_guid': str(owning_organization_guid)
        }
        return self._update(True, url, data)

    def manage_private_domain_organization(self, guid, org_guid, add=True):
        url = self.api_url + self.organization_domains_url % org_guid
        resp = self._get(url)
        found = False
        for d in resp['resources']:
            if d['metadata']['guid'] == guid:
                found = True
                break
        set_url = url + '/' + guid
        if add:
            if not found:
                # add domain to the org
                self._update(False, set_url)
                return True
        else:
            if found:
                # delete domain from org
                self._delete(set_url)
                return True
        return False


    def search_space(self, orguid, name):
        url = self.api_url + self.organization_space_url % orguid
        params = {'q': "name:%s" % str(name)}
        return self._search(url, params)

    def delete_space(self, guid, async=False, recursive=False):
        url = self.api_url + self.spaces_url + '/' + guid
        params = {
            'async': str(async).lower(),
            'recursive': str(recursive).lower()
        }
        self._delete(url, params)

    def save_space(self, orguid, name, allow_ssh=None, guid=None):
        url = self.api_url + self.spaces_url
        create = True
        if guid is not None:
            url = url + '/' + guid
            create = False
        data = {
            'name': str(name),
            'organization_guid': str(orguid),
        }
        if allow_ssh is not None:
            data['allow_ssh'] = allow_ssh
        return self._update(create, url, data)


    def search_secgroup(self, name):
        url = self.api_url + self.secgroups_url
        params = {'q': "name:%s" % str(name)}
        return self._search(url, params)

    def delete_secgroup(self, secguid, async=False):
        url = self.api_url + self.secgroups_url + '/' + secguid
        params = {'async': str(async).lower() }
        self._delete(url, params)

    def save_secgroup(self, name, rules=[], space_guids=[], secguid=None):
        url = self.api_url + self.secgroups_url
        create = True
        if secguid is not None:
            url = url + '/' + secguid
            create = False
        data = {'name': name }
        if rules is not None:
            data['rules'] = rules
        if space_guids is not None:
            data['space_guids'] = space_guids
        return self._update(create, url, data)

    def manage_secgroup_rule(self, secguid, rule, add=True):
        # add == True => add
        # add == False => del
        if 'description' not in rule:
            raise ValueError("rule must have a description")
        url = self.api_url + self.secgroups_url + '/' + secguid
        resp = self._get(url)
        rules = []
        changed = False
        found = False
        for r in resp['entity']['rules']:
            try:
                if r['description'] == rule['description']:
                    found = True
                    if add:
                        # add rule
                        rules.append(rule)
                        try:
                            for k in rule:
                                if rule[k] != r[k]:
                                    changed = True
                        except:
                            changed = True
                    else:
                        # del, no add rule
                        changed = True
                else:
                    # other rule
                    rules.append(r)
            except:
                # rule already defined without description field
                rules.append(r)
        if add and not found:
            changed = True
            rules.append(rule)
        if changed:
            secgroup_guid = resp['metadata']['guid']
            secgroup_name = resp['entity']['name']
            return self.save_secgroup(secgroup_name, rules, None, secgroup_guid)
        return None

    def manage_secgroup_space(self, secguid, space_guid, add=True):
        url = self.api_url + self.secgroups_space_url % secguid
        params = {'space_guid': space_guid }
        resp = self._get(url, params)
        found = False
        for sp in resp['resources']:
            if space_guid == sp['metadata']['guid']:
                found = True
                break
        set_url = url + '/' + space_guid
        if add:
            if not found:
                # add the space
                self._update(False, set_url)
                return True
        else:
            if found:
                # delete space
                self._delete(set_url)
                return True
        return False

    def manage_secgroup_defaults(self, secguid, name="running", add=True):
        url = self.api_url
        if name == "running":
            url += self.secgroups_running_url
        elif name == "staging":
            url += self.secgroups_staging_url
        else:
            raise ValueError("Invalid default sec group, options: running or staging")
        found = False
        resp = self._get(url)
        for sg in resp['resources']:
            if secguid == sg['metadata']['guid']:
                found = True
                break
        set_url = url + '/' + secguid
        if add:
            if not found:
                # add
                self._update(False, set_url)
                return True
        else:
            if found:
                self._delete(set_url)
                return True
        return False


    def search_user(self, name):
        # find by name or email
        search = {
            'userName': str(name),
            'emails.value': str(name)
        }
        try:
            result = self.uaa.user_find(search, 'or')
        except UAAException as e:
            error = {
                'description': str(e),
                'error_code': 'CF-UAA'
            }
            raise CFException(error)
        if result['totalResults'] == 0:
            return None
        elif result['totalResults'] == 1:
            user_id = result['resources'][0]['id']
            url = self.api_url + self.users_url + '/' + user_id
            return self._get(url)
        else:
            error = {'description': "Too many users found!"}
            raise CFException(error)

    def save_user(self, name, givenName, familyName, email=None, password=None,
                  active=True, origin='uaa', externalId=None,
                  default_space_guid=None, force_pass=True, user_id=None):
        url = self.api_url + self.users_url
        changed = False
        try:
            if user_id is not None:
                user = self.uaa.user_get(user_id)
                changed = not (
                    name == user['userName'] and
                    active == user['active'] and
                    origin == user['origin']
                )
                # Users should have user['name']['familyName'] and
                # user['name']['givenName'] but there are some special cases
                # (admin, doppler, etc) without those fields
                names_list = []
                if 'name' in user:
                    if 'givenName' in user['name']:
                        surname = user['name']['givenName']
                        if givenName != user['name']['givenName']:
                            changed = True
                            surname = givenName
                        names_list.append(surname)
                    if 'familyName' in user['name']:
                        surname = user['name']['familyName']
                        if familyName != user['name']['familyName']:
                            changed = True
                            surname = familyName
                        names_list.append(surname)
                if externalId is not None:
                    if 'externalId' not in user:
                        changed = True
                    elif externalId != user['externalId']:
                        changed = True
                elif 'externalId' in user:
                    changed = True
                email_list = []
                if email is not None:
                    email_list = [e['value'] for e in user['emails']]
                    if email not in email_list:
                        changed = True
                        email_list.insert(0, email)
                else:
                    # it allows other emails
                    email_list = [e['value'] for e in user['emails']]
                if changed:
                    self.uaa.user_save(
                        name, names_list, password, email_list,
                        active=active, origin=origin, externalId=externalId,
                        id=user_id)
                if force_pass:
                    # Special UAA privs are required to change passwords!
                    self.uaa.user_set_password(user_id, password)
            else:
                names_list = [givenName, familyName]
                changed = True
                email_list = [] if email is None else [email]
                user = self.uaa.user_save(
                    name, names_list, password, email_list,
                    active=active, origin=origin, externalId=externalId)
                user_id = user['id']
        except UAAException as e:
            error = {
                'description': str(e),
                'error_code': 'CF-UAA'
            }
            raise CFException(error)
        create = False
        try:
            self._get(url + '/' + user_id)
            url = url + '/' + user_id
        except CFException:
            # new user in CF
            create = True
        data = {'guid': user_id }
        if default_space_guid is not None:
            data['default_space_guid'] = default_space_guid
        return changed, self._update(create, url, data)

    def delete_user(self, guid, async=False, uaa=True):
        url = self.api_url + self.users_url + '/' + guid
        params = {'async': str(async).lower() }
        self._delete(url, params)
        if uaa:
            try:
                self.uaa.user_delete(guid)
            except UAAException as e:
                error = {
                    'description': str(e),
                    'error_code': 'CF-UAA'
                }
                raise CFException(error)

    def manage_organization_users(self, orguid, userid, role='user', add=True):
        url = self.api_url
        if role == 'user':
            url += self.users_organizations_url
        elif role == 'manager':
            url += self.users_managed_organizations_url
        elif role == 'auditor':
            url += self.users_audited_organizations_url
        elif role == 'billing_manager':
            url += self.users_billing_managed_organizations_url
        else:
            raise ValueError("Invalid role, options: user, manager, auditor or billing_manager")
        url = url % userid
        found = False
        resp = self._get(url)
        for org in resp['resources']:
            if orguid == org['metadata']['guid']:
                found = True
                break
        set_url = url + '/' + orguid
        if add:
            if not found:
                # add
                self._update(False, set_url)
                return True
        else:
            if found:
                self._delete(set_url)
                return True
        return False

    def manage_space_users(self, spuid, userid, role='user', add=True):
        url = self.api_url
        if role == 'developer':
            url += self.users_spaces_url
        elif role == 'manager':
            url += self.users_managed_spaces_url
        elif role == 'auditor':
            url += self.users_audited_spaces_url
        else:
            raise ValueError("Invalid role, options: developer, manager, auditor")
        url = url % userid
        found = False
        resp = self._get(url)
        for spa in resp['resources']:
            if spuid == spa['metadata']['guid']:
                found = True
                break
        set_url = url + '/' + spuid
        if add:
            if not found:
                # add
                self._update(False, set_url)
                return True
        else:
            if found:
                self._delete(set_url)
                return True
        return False
