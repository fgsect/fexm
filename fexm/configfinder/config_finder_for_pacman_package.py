#!/usr/bin/env python3
"""
Find input vector for a pacman package.
"""
import argparse

import os
import sh

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from builders import builder
from cli_config import CliConfig
from helpers.exceptions import NoCoverageInformation
import helpers.utils
from heuristic_config_creator import HeuristicConfigCreator
import logging


def main(binary_path: str, timeout: float, volume_path: str, package: str, cores: int = 1) -> [CliConfig]:
    use_qemu = helpers.utils.qemu_required_for_binary(binary_path)
    logging.info("Now inferring invocation for {0}".format(binary_path))
    h = HeuristicConfigCreator(binary_path=binary_path,
                               results_out_dir=volume_path + "/" + package + "/" + os.path.basename(binary_path),
                               timeout=timeout, qemu=use_qemu, cores=cores)
    input_vectors = h.infer_input_vectors()
    best_input_vector = h.get_max_coverage_input_vector()
    return h.get_input_vectors_sorted(), best_input_vector


def process_output(line):
    print(line)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be a pacman package.")
    parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl", default=3)
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    parser.add_argument("-c", "--cores", required=False, type=int, default=1,
                        help="The number of cores that should be used")
    # Either fuzz projects or binaries
    arguments = parser.parse_args()
    logfilename = os.path.join(arguments.output_volume, arguments.package + ".log")
    logging.basicConfig(filename=logfilename, level=logging.INFO, format='%(levelname)s %(asctime)s: %(message)s')
    b = builder.Builder(package=arguments.package, qemu=arguments.qemu)
    if not b.install():
        print("Could not install package, exiting")
        logging.error("Could not install package, exiting")
        exit(0)
    qemu = b.qemu
    dpkg_query = sh.Command("pacman")
    query_command = dpkg_query("-Ql", "--quiet", arguments.package)  # type: sh.RunningCommand
    query_command_output = query_command
    # query_command_output = str(query_command).strip()[1:] # The first one is always ./ apparently (not in pacman)
    binaries = query_command_output.split("\n")
    file_command = sh.Command("file")
    volume = arguments.output_volume
    fuzzable_binaries = helpers.utils.return_fuzzable_binaries_from_file_list(binaries)
    logging.info("Fuzzable binaries detected: {0}".format(" ".join(fuzzable_binaries)))
    #
    for b in fuzzable_binaries:
        # for b in binaries:
        #    if os.path.isdir(b):
        #        continue
        #    if configfinder.helpers.helpers.is_fuzzable_binary(b):
        logging.info("Now inferring input vector for binary {0}".format(b))
        try:
            input_vectors, best_input_vector = main(binary_path=b, timeout=arguments.timeout,
                                                    volume_path=arguments.output_volume, package=arguments.package,
                                                    cores=arguments.cores)
        except NoCoverageInformation as e:
            print(e)
            print("Skipping binary {0}", b)
            continue
        if input_vectors is not None:
            print("Storing in volume")
            best_input_vector.binary_path = b
            helpers.utils.store_input_vectors_in_volume(package=arguments.package, binary=b,
                                                        volume_path=arguments.output_volume,
                                                        input_vectors=input_vectors)
    # else:
    #    logging.info("Skipping binary {0} as non fuzzable".format(b))
    chmod = sh.Command("chmod")
    chmod("-R", "0777", arguments.output_volume)  # Hacky fix for the problem that docker stores every as root
