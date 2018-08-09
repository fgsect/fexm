#!/usr/bin/env python3
"""
Find input vector for one binary.
"""
import argparse

import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder.heuristic_config_creator import HeuristicConfigCreator
import helpers.utils
import logging
import configfinder.config_settings
import config_settings

configfinder.config_settings.PREENY_PATH = "fexm/docker_scripts/afl_base_image/preeny"
config_settings.PREENY_PATH = "fexm/docker_scripts/afl_base_image/preeny"

"""
def crawl(binary_path :str,timeout : float,qemu : bool,seeds_dir : str) -> [CliConfig]:
    h = HeuristicConfigCreator(binary_path=binary_path,results_out_dir=os.path.basename(binary_path),timeout=timeout,qemu=qemu,seeds_dir=seeds_dir)
    input_vectors = h.infer_input_vectors()
    best_input_vector = h.get_max_coverage_input_vector()
    print(json.dumps(list(map(lambda x: x.__dict__,input_vectors))))
    return input_vectors,best_input_vector
"""


def main(binary_path: str, timeout: float, seeds_dir: str, cores: int = 8, parameter: str = "@@"):
    use_qemu = helpers.utils.qemu_required_for_binary(binary_path)
    if use_qemu:
        print("Using qemu for binary {0}".format(binary_path))
    logging.info("Now inferring invocation for {0}".format(binary_path))
    h = HeuristicConfigCreator(binary_path=binary_path, results_out_dir=os.path.basename(binary_path), timeout=timeout,
                               qemu=use_qemu, cores=cores, seeds_dir=seeds_dir)
    h.infer_filetype_via_coverage_for_parameter_parallel(parameter=parameter, probe=False)
    coverage_list = h.coverage_lists[parameter]
    import csv
    with open('some.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerows(coverage_list)

    # input_vectors = h.infer_input_vectors()
    # best_input_vector = h.get_max_coverage_input_vector()
    # print(json.dumps(list(map(lambda x: x.__dict__, h.get_input_vectors_sorted()))))
    # print("#########################################################################")
    # print("Input vector for {0} is most likely:".format(binary_path))
    # best_input_vector = h.get_best_input_vector()
    # print(best_input_vector.parameter)
    # print(best_input_vector.file_types)
    # print(h.get_input_vectors_sorted()[0].parameter)
    # print("K:", max(zip(best_input_vector.chebyshev_scores[0], best_input_vector.chebyshev_scores[1]), key=lambda x: x[1]))
    # return h.get_input_vectors_sorted(), best_input_vector


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get input vectors for a binary')
    parser.add_argument("-b", "--binary", required=True, type=str, help="The path to the binary.")
    parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for one execution", default=3)
    parser.add_argument("-s", "--seeds", required=True, type=str, help="Where are the seedfiles?")
    parser.add_argument("-c", "--cores", required=False, type=int, default=1,
                        help="The number of cores that should be used")
    parser.add_argument("-param", "--parameter", required=False, type=str,
                        help="The parameter to the json file. Use = to pass hyphens(-)",
                        default=None)  # Must exists in docker
    # Either fuzz projects or binaries

    arguments = parser.parse_args()
    main(binary_path=arguments.binary, timeout=arguments.timeout, seeds_dir=arguments.seeds, cores=arguments.cores,
         parameter=arguments.parameter)
