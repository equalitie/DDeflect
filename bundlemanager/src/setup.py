import os
from setuptools import setup

setup(
    name = "bundlemanager",
    version = "1.0.0",
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
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        ],
    scripts = ["bundlemanager", "bundlemanager_tornado"],
    )
