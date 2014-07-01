#!/usr/bin/env python2
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import sys

# versioneer config
import versioneer
versioneer.versionfile_source = 'httpsig/_version.py'
versioneer.versionfile_build = 'httpsig/_version.py'
versioneer.tag_prefix = 'v'                 # tags are like v1.2.0
versioneer.parentdir_prefix = 'httpsig-'    # dirname like 'myproject-1.2.0'

# create long description
with open('README.rst') as file:
    long_description = file.read()
with open('CHANGES.rst') as file:
    long_description += '\n\n' + file.read()

setup(
    name='httpsig',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Secure HTTP request signing using the HTTP Signature draft specification",
    long_description=long_description,
    classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Development Status :: 4 - Beta",
    ],
    keywords='http,authorization,api,web',
    author='Adam Knight',
    author_email='adam@movq.us',
    url='https://github.com/ahknight/httpsig',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    install_requires=['pycrypto'],
    test_suite="httpsig.tests",
)
