import os
from pip.req import parse_requirements
from setuptools import setup

install_reqs = parse_requirements("../requirements.txt")
reqs = [str(ir.req) for ir in install_reqs]

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
    install_requires=reqs,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        ],
    scripts = ["bundlemanager", "bundlemanager_tornado"],
    )
