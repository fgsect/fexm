#!/usr/bin/env python3
"""
This script builds or installs a package, if possible with instrumentation.
"""
import argparse

import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import config_settings
from builders import builder
import logging

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be an apt package.")
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-l", "--logfile", required=False, help="The logfile path", default=None)
    # Either fuzz projects or binaries
    arguments = parser.parse_args()
    if arguments.logfile:
        logfile = arguments.logfile
        logging.basicConfig(filename=logfile, level=logging.INFO, format='%(levelname)s %(asctime)s: %(message)s',
                            filemode='a')
    package = arguments.package
    b = builder.Builder(package=arguments.package, qemu=arguments.qemu)
    if not b.install():
        print("Could not install package {0}, exiting".format(package))
        exit(config_settings.BUILDER_BUILD_FAILED)
    qemu = b.qemu
    if qemu:
        print("Package {0} installed with qemu".format(package))
        exit(config_settings.BUILDER_BUILD_QEMU)
    else:
        print("Package {0} build + installed".format(package))
        exit(config_settings.BUILDER_BUILD_NORMAL)
