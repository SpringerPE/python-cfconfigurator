#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cfconfigurator.cf import CF

api_url = "https://api.test.cf.springer-sbm.com"
admin_user = "admin"
admin_password = "password"

cf = CF(api_url)
cf.login(admin_user, admin_password)

org = cf.search_org("pivotal")
print(org)

services = cf.request('GET', "/v2/services", {"results-per-page": 1})
print(services)

services = cf.request('GET', "https://api.test.cf.springer-sbm.com/v2/services", {"results-per-page": 1})
print(services)

