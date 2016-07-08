#!/usr/bin/python
# -*- coding: utf-8 -*-
__doc__ = """url_monitor

Extensible URL monitor that iterates through supplied json/yaml
files to pull remote data from fields in http, xml, or json
documents and sends data to remote sources.  To support zabbix,
Rackspace Cloud Monitoring, collectd, etc...
"""

# The package name, which is also the "UNIX name" for the project.
package = 'url_monitor'
project = "URL Monitor Module"
project_no_spaces = project.replace(' ', '')
version = '0.8.9'
description         = 'A zabbix plugin to perform URL endpoint monitoring for JSON and XML REST APIs,' \
                      + ' supporting multiple http auth mechinisms'
long_description    = 'A Zabbix plugin written in Python that creates low level discovery items containing ' \
                      + 'values from your JSON API. It supports multiple requests auth backends including ' \
                      + 'oauth, basicauth, and your even own custom requests auth provider plugins. The low' \
                      + ' level discovery items can generate item prototypes which can be used to represent' \
                      + ' your data through this plugin.'
authors = ['Jon Kelley', 'Nick Bales']
authors_string = ', '.join(authors)
emails = ['jon.kelley@rackspace.com',
          'nick.bales@rackspace.com']
license = 'ASLv2'
company = "Rackspace, Inc."
copyright = '2016 ' + company
url = 'https://github.com/rackerlabs/zabbix_url_monitor'
install_requires = ['python-daemon',
                    'requests',
                    'requests-oauthlib',
                    'oauthlib',
                    'argparse',
                    'PyYAML',
                    'importlib'
                    ]
rpm_requires = ['python',
                'python-daemon',
                'python-setuptools',
                'python-importlib',  # cent 6.5
                'python-requests',
                'python-requests-oauthlib',
                'python-argparse',
                'PyYAML'
                ]
software_classified = [
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 3',
    'Topic :: System :: Monitoring',
    'Topic :: System :: Networking :: Monitoring',
    'Topic :: System :: Systems Administration ',
]
