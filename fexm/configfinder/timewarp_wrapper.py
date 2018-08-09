#!/usr/bin/env python3
"""
Analyzes the crashes for a package.
"""
import argparse
import json
import shlex

import os
import sys
import uuid

from sh import afl_fuzz

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)

import helpers
import helpers.utils

logger = helpers.utils.init_logger(__name__)


def start_timewarp(binary_path: str, parameter: str, json_file) -> None:
    # TODO: Which are needed?
    if not os.path.exists(json_file):
        print("JSON Configuration file {0} does not exist!".format(json_file))
        exit(-1)
    with open(json_file, "r") as fp:
        config_dict = json.load(fp)
    user_defined_folder = config_dict.get("package_folder")
    # if not self.user_defined_folder:
    #    self.package = config_dict.get("package")
    # elif not:
    # self.package = "UserDefined"
    package = config_dict.get("package")
    if not package and user_defined_folder:
        package = "UserDefined"
    elif not package:
        print("Need a package name or custom user folder!")
        exit(0)
    output_volume = config_dict.get("volume")
    # fuzz_duration = config_dict.get("fuzz_duration") #TODO: Adapt...
    exec_timeout = config_dict.get("timeout")
    if not exec_timeout:
        exec_timeout = "1000+"
    tmp_in = "tmp" + str(uuid.uuid4())[:8]
    os.mkdir(tmp_in)
    with open(tmp_in + "/in_file", "w") as fp:
        fp.write("test")
    # qemu = config_dict.get("qemu")
    # logging.basicConfig(handlers=[logging.FileHandler(logfilename, 'w', 'utf-8')], level=logging.INFO,
    #                   format='%(levelname)s %(asctime)s: %(message)s')
    outdir = os.path.join(output_volume, package,
                          helpers.utils.get_filename_from_binary_path(binary_path) + "timewarp_fuzz" + str(
                              uuid.uuid4())[:8])
    new_env = {
        "AFL_IGNORE_INSTRUMENTATION": "1",
    }

    # output = os.system('tmux new-session -d -s "timewarp" {1}'.format(os.path.basename(os.path.basename(entry[1])),
    #                                                                  os.path.join(cd,
    # We want to run timewarp and then
    # Websockify 0xAF0
    # Websockify 0xAF1

    new_env.update(helpers.utils.get_fuzzing_env_for_invocation(parameter))
    afl_preload = "/libdislocator.so"
    new_env["ÄFL_PRELOAD"] = "{} {}".format(afl_preload, new_env.get("AFL_PRELOAD", ""))

    with open(os.path.join(output_volume, package,
                           helpers.utils.get_filename_from_binary_path(binary_path) + ".afl_config"), "r+") as f:
        afl_config_dict = json.load(f)
        afl_config_dict["afl_out_dir"] = outdir
        f.seek(0)
        json.dump(afl_config_dict, f)
        f.truncate()

    afl_fuzz(["-W", "-m", "none", "-i", tmp_in, "-t", exec_timeout, "-o", outdir, "-Q", "--", binary_path,
              " ".join(shlex.split(parameter))], _env=new_env, _out=sys.stdout)


def main():
    parser = argparse.ArgumentParser(description='Examine a package or a binary.')
    parser.add_argument("-b", "--binary", required=False, type=str, help="Path to the binary to fuzz.",
                        default=None)
    parser.add_argument("-param", "--parameter", required=False, type=str,
                        help="The parameter to the binary. Use = to pass hyphens(-)",
                        default=None)  # Must exists in docker
    parser.add_argument("-j", "--json", required=True, type=str,
                        help="json file with all configurations")
    args = parser.parse_args()

    start_timewarp(args.binary, args.parameter, args.json)
    """
    subparsers = parser.add_subparsers(help="sub-command help", dest="command")
    subparsers.required = True
    # Common arguments for both:
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be a pacman package.")
    parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl",
                        default=2000)  # Default timeout: 2 hours
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-v", "--output_volume", required=True, help="In which volume should the files be stored?")
    parser_binary = subparsers.add_parser("binary", help="Examine a binary.")  # type:argparse.ArgumentParser
    parser_package = subparsers.add_parser("package", help="Examine a package")
    parser_binary.add_argument("-a", "--afl_dir", required=True, type=str,
                               help="Afl dir, where the seeds should be collected from")

    parser_binary.add_argument("-d", "--database", required=True, help="Where should the database be stored?")
    parser_binary.add_argument("-c", "--collection_dir", required=True, help="Where should the crashes be stored?")
    arguments = parser.parse_args()
    fuzz_data = arguments.output_volume
    package = arguments.package
    print("Globbing {0}".format(os.path.join(fuzz_data, package) + "/*.json"))
    print(os.listdir(os.path.join(fuzz_data)))
    print(os.listdir(os.path.join(fuzz_data, package)))
    json_fuzzer_files = glob.glob(os.path.join(fuzz_data, package) + "/*.json")
    print(json_fuzzer_files)
    with open(json_fuzzer_files[0]) as fp:
        json_dict = json.load(fp)
    qemu = json_dict[0]["qemu"]
    b = builder.Builder(package=package, qemu=qemu, overwrite=False)
    if qemu:
        b.install()
    else:
        if not os.path.exists(json_dict[0]["binary_path"]):
            b = builder.Builder(package=package, qemu=qemu)
            b.try_build()
            b.install_deps()
    package_analyzer = PackageAnalyzer(package=package,
                                       volume=fuzz_data)  # collect_package(package_dir=package, volume=fuzz_data)
    package_analyzer.collect_package()
    return True
    """


if __name__ == "__main__":
    main()
