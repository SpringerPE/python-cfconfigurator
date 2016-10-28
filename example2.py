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

from cfconfigurator.exceptions import CFException, UAAException
from cfconfigurator.cf import UAA
from cfconfigurator.cf import CF


def main():
    u = UAA("https://uaa.test.example.com", "admin", "admin-secret")
    a = u.login()
    print(a)

    user = u.user_find({'userName': 'jose'})
    if user['totalResults'] == 1:
        deleted = u.user_delete(user['resources'][0]['id'])
        print(deleted)
    new_user = u.user_save("jose", ["Jose", "Riguera"], "hola", ["jriguera@hola.com"])
    print(new_user)
    user = u.user_get(new_user['id'])
    pas = u.user_set_password(user['id'], 'adios')
    print(pas)

    print("=====================")

    group = u.group_find({'displayName': 'josegroup'})
    if group['totalResults'] == 1:
        deleted = u.group_delete(group['resources'][0]['id'])
        print(deleted)
    new_group = u.group_save("josegroup", "Jose Riguera Group")
    print(new_group)
    # add user
    group_member = u.group_manage_member(new_group['id'], user['id'])
    print(group_member)
    group = u.group_get(group_member['id'])
    print(group)
    # remove user
    group_member = u.group_manage_member(group['id'], user['id'], add=False)
    print(group_member)

    print("=====================")

    clients = u.client_find({'client_id': 'joseclient'})
    print(clients)
    if clients['totalResults'] == 1:
        deleted = u.client_delete(clients['resources'][0]['client_id'])
        print(deleted)
    new_client = u.client_save("joseclient", "Jose Riguera client", "hola", "adios", scope=['uaa.user'])
    print(new_client)
    client_secret = u.client_set_secret(new_client['client_id'], "pedro")
    print(client_secret)
    client = u.client_save("joseclient", "JoseRRRRRRRRRRRR", "hola", "token", scope=['uaa.user'], id=new_client['client_id'])
    print(client)
    clients = u.client_find({'client_id': 'joseclient'})
    print(clients)

    # delete
    u.group_delete(group['id'])
    u.user_delete(user['id'])
    u.client_delete(client['client_id'])

if __name__ == '__main__':
    main()
