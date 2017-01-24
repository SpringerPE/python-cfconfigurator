# python-cfconfigurator

`python-cfconfigurator` is a simple and small library to manage Cloud Foundry
common operations (not aimed to manage apps or service brokers). The idea
behind this implementation is having a library to be used for Configuration
Management tools, in particular for
[Ansible modules](https://github.com/SpringerPE/ansible-modules-cloudfoundry).

CF class implements support to manage: users, blobstore cache, environment
variable groups, feature flags, shared domains, private domains, organizations,
quotas, spaces, security groups and security group rules.

There is also a UAA implementation which adds support to manage users,
groups and clients directly with an UAA server.

Code compatible with Python 2 and Python 3

Documentation of the APIs used:

* https://apidocs.cloudfoundry.org
* https://docs.cloudfoundry.org/api/uaa


## Example

Install via pip: `pip install cfconfigurator`

```
from cfconfigurator.cf import CF

api_url = "https://api.test.cf.example.com"
admin_user = "admin"
admin_password = "admin"

cf = CF(api_url)
cf.login(admin_user, admin_password)

org = cf.search_org("pivotal")
print(org)
```

## Upload to PyPI

1. Create a `.pypirc` configuration file. This file holds your information for authenticating with PyPI.

   ```
   [distutils]
   index-servers = pypi
   
   [pypi]
   repository=https://pypi.python.org/pypi
   username=your_username
   password=your_password
   ```
2. Login and upload it to PyPI

   ```
   python setup.py register -r pypi
   python setup.py sdist upload -r pypi
   ```


## TODO

* Tests, tests ... fix me!
* Buildpack management


## Author

Springer Nature Platform Engineering, Jose Riguera Lopez (jose.riguera@springer.com)

Copyright 2017 Springer Nature
