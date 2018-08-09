#!/usr/bin/env python3
"""
Find input vector for binaries that are contained in an apt package.
"""
import argparse
import json

import os
import sh
from cli_config import CliConfig
from helpers.exceptions import NoCoverageInformation
from heuristic_config_creator import HeuristicConfigCreator


def store_input_vectors_in_volume(package: str, binary: str, volume_path: str, input_vectors: [CliConfig]):
    if not os.path.exists(volume_path + "/" + package):
        os.mkdir(volume_path + "/" + package)
    with open(volume_path + "/" + package + "/" + os.path.basename(binary) + ".json", "w") as jsonfp:
        print("Writing to {0}".format(volume_path))
        json.dump(list(map(lambda x: x.__dict__, input_vectors)), jsonfp)


def main(binary_path: str, timeout: float, qemu: bool, volume_path: str, package: str) -> [CliConfig]:
    h = HeuristicConfigCreator(binary_path=binary_path,
                               results_out_dir=volume_path + "/" + package + "/" + os.path.basename(binary_path),
                               timeout=timeout, qemu=qemu)
    input_vectors = h.infer_input_vectors()
    best_input_vector = h.get_best_input_vector()
    return input_vectors, best_input_vector


def process_output(line):
    print(line)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be an apt package.")
    parser.add_argument("-ve", "--version", required=True, type=str, help="The version of the package")
    parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl", default=1.5)
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    # Either fuzz projects or binaries

    arguments = parser.parse_args()
    apt_get = sh.Command("apt-get")
    install_command = apt_get.install("-y", arguments.package + "=" + arguments.version,
                                      _out=process_output)  # type: sh.RunningCommand
    if install_command.exit_code != 0:
        print("Could not install package, exiting")
    dpkg_query = sh.Command("dpkg-query")
    query_command = dpkg_query("-L", arguments.package)  # type: sh.RunningCommand
    query_commmand_output = str(query_command).strip()[1:]  # The first one is always ./ apparently
    binaries = query_commmand_output.split("\n")
    file_command = sh.Command("file")
    volume = arguments.output_volume
    for b in binaries:
        if "ELF" in file_command(b).split(":")[1]:
            try:
                input_vectors, = main(binary_path=b, timeout=arguments.timeout, qemu=True,
                                      volume_path=arguments.output_volume, package=arguments.package)
            except NoCoverageInformation as e:
                print(e)
                print("Skipping binary {0}", b)
                continue
            if input_vectors is not None:
                print("Storing in volume")
                store_input_vectors_in_volume(package=arguments.package, binary=b, volume_path=arguments.output_volume,
                                              input_vectors=input_vectors)
