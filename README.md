# python-cfconfigurator

`python-cfconfigurator` is a simple and small library to manage Cloud Foundry
common operations (not aimed to manage apps or service brokers). The idea
behind this implementation is having a library to be used for Configuration
Management tools, in particular for Ansible modules. 

It is compatible with Python 2 and Python 3


## Example


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

## Author

Jose Riguera Lopez, jose.riguera@springer-sbm.com
SpringerNature Platform Engineering
