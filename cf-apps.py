#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Program to query CF apps status based on filters
"""
# Python 2 and 3 compatibility
from __future__ import unicode_literals, print_function

__program__ = "cf-apps"
__version__ = "0.1"
__author__ = "Jose Riguera"
__year__ = "2017"
__email__ = "<jose.riguera@springer.com>"
__license__ = "MIT"
__purpose__ = """
List information about applications available in Cloud Foundry using `GET /v2/apps` endpoint

You can define lambda filters with the variable `x` which represents the CF API output, like this:
* "int(x['entity']['instances']) <= 1": will list all apps with 1 or less instances
* "int(x['entity']['instances']) <= 1 and x['entity']['state'] == 'STARTED'": same as before but only the started ones
* "x['entity']['state'] == 'STOPPED'": all apps stopped

For more information about the filter parameters and fields, see https://apidocs.cloudfoundry.org/
"""

from cfconfigurator.cf import CF
import argparse



def run(user, password, api, entity_filter, entity_fields=['name']):
    cf = CF(api)
    cf.login(user, password)
    result = cf.request('GET', "/v2/apps", {"results-per-page": 100})
    apps = result[0]
    print("* Total results: %s" % apps['total_results'])
    data = apps['resources']
    fun = "filter(lambda x: %s, data)" % entity_filter
    filtered = list(eval(fun))
    for entity in filtered:
      app = entity['entity']
      fields = [str(app[x]) if x in app else x for x in entity_fields]
      #print(app)
      print(" ".join(fields))
    print("* Apps: %d" % len(filtered))


def main():
    # Argument parsing
    epilog = __purpose__ + '\n'
    epilog += __version__ + ', ' + __year__ + ' '
    epilog += __author__ + ' ' + __email__
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=__doc__, epilog=epilog)
    parser.add_argument('filter', default="True", nargs='?', help='Entity filter definition for each item')
    parser.add_argument('-u', '--user', default="admin", type=str, help='User to query the CF API')
    parser.add_argument('-p', '--password', default="admin", type=str, help='Password for the user')
    parser.add_argument('-a', '--api', type=str, help='CF API url')
    parser.add_argument('-f', '--fields', default="name,is,state,with,instances,instances.", help='Fields and words to show in the output')

    args = parser.parse_args()
    fields = args.fields.split(',')
    print(fields)
    run(args.user, args.password, args.api, args.filter, fields)


if __name__ == "__main__":
    main()
