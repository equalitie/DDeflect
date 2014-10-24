#!/usr/bin/env python2
#Hey this looks familar :( 

import logging
import yaml
import sys
import os

if "BUNDLEMANAGER_CONFIG" in os.environ: 
    CONFIG_PATH=os.environ["BUNDLEMANAGER_CONFIG"]
else:
    CONFIG_PATH="/etc/bundlemanager.yaml"

setattr(sys.modules[__name__], "config_path", CONFIG_PATH)

logging.info("Loading config from %s", CONFIG_PATH)
config = yaml.load(open(CONFIG_PATH).read())

for key, value in config.iteritems():
    setattr(sys.modules[__name__], key, value)


