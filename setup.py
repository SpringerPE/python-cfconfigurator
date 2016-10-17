#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Setuptools module for python-cfconfigurator
See:
	https://packaging.python.org/en/latest/distributing.html
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path
from pip.download import PipSession
from pip.req import parse_requirements
import re


def find_version(*file_paths):
    # Open in Latin-1 so that we avoid encoding errors.
    # Use codecs.open for Python 2 compatibility
    here = path.abspath(path.dirname(__file__))
    with open(path.join(here, *file_paths), 'r', encoding='utf-8') as f:
        version_file = f.read()
    # The version line must have the form
    # __version__ = 'ver
    version_match = re.search(
	r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


def find_readme(f="README.md"):
    here = path.abspath(path.dirname(__file__))
    # Get the long description from the README file
    long_description = None
    with open(path.join(here, f), encoding='utf-8') as f:
    	long_description = f.read()
    return long_description


def find_requirements(f='requirements.txt'):
    # parse_requirements() returns generator of pip.req.InstallRequirement objects
    reqs = parse_requirements("requirements.txt", session=PipSession())
    install_reqs = [str(ir.req) for ir in reqs]
    return install_reqs


setup(
    name="cfconfigurator",
    url="https://github.com/SpringerPE/python-cfconfigurator",
    version=find_version('cfconfigurator/cf.py'),
    keywords='cf cloudfoundry cloud foundry lib',
    description="Simple and small library to manage Cloud Foundry",
    long_description=find_readme(),
    author="Jose Riguera Lopez",
    author_email="jose.riguera@springer.com",
    license='MIT',
    packages=find_packages(exclude=['docs', 'tests']),
    download_url="https://github.com/SpringerPE/python-cfconfigurator/releases/tag/v" + find_version('cfconfigurator/cf.py'),

    # Include additional files into the package
    include_package_data=True,

    # additional files need to be installed into
    data_files=[],

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',
        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',
        'Topic :: System :: Systems Administration',
        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3'
    ],

    # Dependent packages (distributions)
    install_requires=find_requirements(),
)
