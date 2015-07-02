#!/usr/bin/env python

import os
from setuptools import setup

setup(
    name = "bundlemanager",
    version = "1.0.5",
    author = "Hugh Nowlan",
    author_email = "nosmo@nosmo.me",
    description = "DDeflect bundle management system",
    license = "Hacktivismo Enhanced-Source Software License Agreement",
    keywords = "deflect bundler cms reverseproxy",
    url = "http://github.com/equalitie/DDeflect",
    packages=['bundlemaker'],
    package_data={'bundlemaker': [
        'templates/debundler_template.html.j2',
        'templates/bundle.json',
        'templates/debundler.js'
    ]},
    install_requires=[
        "flask>=0.10.1",
        "pycrypto",
        "requests",
        "nose",
        "redis",
        "pyyaml",
        "jinja2"
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        ],
    scripts = ["bundlemanager", "bundlemanager_tornado"],
    )
