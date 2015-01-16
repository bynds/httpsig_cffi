#!/usr/bin/env python
from setuptools import setup, find_packages

# versioneer config
import versioneer
versioneer.versionfile_source = 'httpsig_cffi/_version.py'
versioneer.versionfile_build = 'httpsig_cffi/_version.py'
versioneer.tag_prefix = 'v'                      # tags are like v1.2.0
versioneer.parentdir_prefix = 'httpsig_cffi-'    # dirname like 'myproject-1.2.0'

# create long description
with open('README.rst') as file:
    long_description = file.read()
with open('CHANGELOG.rst') as file:
    long_description += '\n\n' + file.read()

setup(
    name='httpsig_cffi',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Secure HTTP request signing using the HTTP Signature draft specification",
    long_description=long_description,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='http,authorization,api,web',
    author='HawkOwl',
    author_email='hawkowl@atleastfornow.net',
    url='https://github.com/hawkowl/httpsig_cffi',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    install_requires=['six', 'cryptography']
)
