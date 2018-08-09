#!/usr/bin/env python3
"""
Call this script to rerun all fuzzing queus through an asan compiled binary
"""
import argparse
import json
import shlex
import sys
import uuid

import config_settings
import os
import sh
import shutil

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from builders import builder
import logging
import helpers.utils


class AsanAnalyzer:
    def __init__(self, package: str, path: str):
        """

        :param package: The name of the package
        :param path: The path to the package
        :return:
        """
        self.package = package
        self.path = path

    def analyze_crashes_for_afl_session(self, afl_dir, out_dir, binary_path: str, parameter: str):
        os.makedirs(out_dir, exist_ok=True)
        aflcmin = sh.Command("afl-cmin")
        # First: Minimize the seeds
        cmin_out_dir = os.path.join("/tmp", str(uuid.uuid4()))
        cmin_params = []
        cmin_params += ["-C", "-i", os.path.join(afl_dir, "queue"), "-o", cmin_out_dir, "-m", "none", "-t",
                        str(config_settings.AFL_CMIN_INVOKE_TIMEOUT * 1000), "--", binary_path]
        cmin_params += shlex.split(parameter)
        try:
            aflcmin(cmin_params, _timeout=config_settings.AFL_CMIN_TIMEOUT,
                    _env=helpers.utils.get_fuzzing_env_for_invocation(parameter))
        except sh.ErrorReturnCode as e:
            if "Error: no traces obtained from test cases, check syntax!" in e.stdout.decode("utf-8"):
                print("No traces obtained from afl-cmin: Either wrong syntax or no crashing inputs")
            print("ASAN: afl cmin failed for {0}".format(binary_path))
            print("STDOUT:\n", e.stdout.decode("utf-8"))
            print("STDERR:\n", e.stderr.decode("utf-8"))
            print("CMD:\n", e.full_cmd)
            sys.exit(-1)
            # queue_files = [os.path.join(afl_dir,"queue/",f) for f in os.path.join(afl_dir,"queue/")]
            # for qfile in queue_files:
            #    try:
            #        sh.Command(binary_path)(parameter.replace("@@",qfile).split(" "))
            #    except sh.ErrorReturnCode as e:
            #        import shutil
            #        shutil.copyfile(qfile,os.path.join(out_dir,qfile))
        for f in os.listdir(cmin_out_dir):
            shutil.copyfile(os.path.join(cmin_out_dir, f), os.path.join(out_dir, f))

    def analyze_package(self):
        afl_config_files = [os.path.join(self.path, f) for f in
                            os.listdir(self.path) if f.endswith(".afl_config")]
        for afl_config_file in afl_config_files:
            with open(afl_config_file) as afl_config_fp:
                afl_confic_dict = json.load(afl_config_fp)
                parameter = afl_confic_dict.get("parameter")
                afl_out_dir = afl_confic_dict.get("afl_out_dir")
                binary_path = afl_confic_dict.get("binary_path")
                if afl_out_dir:
                    self.analyze_crashes_for_afl_session(afl_out_dir, afl_out_dir + "_asan_crashes",
                                                         parameter=parameter, binary_path=binary_path)


def main():
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be a pacman package.")
    parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    # Either fuzz projects or binaries
    arguments = parser.parse_args()
    logfilename = os.path.join(arguments.output_volume, arguments.package + ".log")
    logging.basicConfig(handlers=[logging.FileHandler(logfilename, 'w', 'utf-8')], level=logging.INFO,
                        format='%(levelname)s %(asctime)s: %(message)s')
    print("Now doing package {0}".format(arguments.package))
    print("Build package {0}".format(arguments.package))
    b = builder.Builder(package=arguments.package, qemu=False, asan=True)
    if not b.install():
        print("Could not build package with asan, exiting")
        logging.error("Could not build package with asan, exiting")
        exit(0)
    print("Building done, now analyzing!")
    analyzer = AsanAnalyzer(package=arguments.package, path=os.path.join(arguments.output_volume, arguments.package))
    analyzer.analyze_package()


if __name__ == "__main__":
    main()
