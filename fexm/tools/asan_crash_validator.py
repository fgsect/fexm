#!/usr/bin/env python3
"""
Call this script in order to run all fuzzing queues against asan compiled binary.
"""
import argparse
import json
import pathlib

import celery
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import configfinder.config_settings
from celery_tasks.tasks import run_asan_eval
from helpers import utils

""" 
This is an inference manger for apt files. 
"""
MAX_TIMEOUT_PACKAGE_INFERENCE = configfinder.config_settings.MAX_TIMEOUT_PACKAGE_INFERENCE
MAX_BUILD_TRESHOLD = configfinder.config_settings.MAX_BUILD_TRESHOLD  # Do not build packages above 15 MB
global MAX_INSTALL_TRESHOLD
MAX_INSTALL_TRESHOLD = configfinder.config_settings.MAX_INSTALL_TRESHOLD  # Do not consider packages above 20000 MB


class QueryClass:
    def __init__(self):
        self.tasks = []

    def query_asan_analyzer_for_package(self, package: str, configurations_dir: str, docker_image: str):
        print("Querying {0}".format(package))
        self.tasks.append(run_asan_eval.s(package, docker_image,
                                          os.path.realpath(os.path.join(os.getcwd() + "/", configurations_dir))))

    def run_queries(self):
        jobs = celery.group(self.tasks)
        res = jobs.apply_async()
        print(res.get())
        res.join()
        print(res.get())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start the fuzzing process.")
    parser.add_argument("json", help="The path to the json configuration file")
    args = parser.parse_args()
    if not os.path.exists(args.json):
        print("JSON Configuration file {0} does not exist!".format(args.json))
        exit(-1)
    config_dict = {}
    with open(args.json, "r") as fp:
        config_dict = json.load(fp)
    MAX_INSTALL_TRESHOLD = config_dict["MAX_SIZE"]
    MAX_BUILD_TRESHOLD = config_dict["max_build_size"]
    seeds = config_dict["seeds"]
    if not utils.helpers.is_valid_seeds_folder(seeds):
        print(
            "Seeds folder {0} is not valid. Please read the documentation and fix the seed directory structure.".format(
                seeds))
        exit(-1)
    packages_file = config_dict["packages_file"]
    docker_image = config_dict["base_image"]
    configuration_dir = config_dict["out_dir"]
    fuzz_duration = config_dict["fuzz_duration"]
    force = config_dict["force"]
    use_asan = False
    if config_dict.get("USE_ASAN"):  # Default: Don't use
        print("Warning: You already used asan for initial run - probably there is not point in doing this?")
    query_class = QueryClass()
    for package_dir in os.listdir(configuration_dir):
        if not os.path.isdir(os.path.join(configuration_dir, package_dir)):
            continue
        list_aflconfig_files = [os.path.join(configuration_dir, package_dir, f) for f in
                                os.listdir(os.path.join(configuration_dir, package_dir)) if f.endswith(".afl_config")]
        for afl_config_file in list_aflconfig_files:
            with open(afl_config_file) as afl_config_fp:
                try:
                    afl_confic_dict = json.load(afl_config_fp)
                except json.decoder.JSONDecodeError as e:
                    print("Json decoder error for {0}\n1".format(afl_config_file, str(e)))
                afl_out_dir = afl_confic_dict.get("afl_out_dir")
                if afl_out_dir:

                    try:
                        out_dir_path = pathlib.Path(afl_out_dir)
                        out_dir_path = str(out_dir_path.relative_to(*out_dir_path.parts[:2]))
                        afl_out_path = os.path.join(configuration_dir, out_dir_path)
                        if os.listdir(os.path.join(afl_out_path, "queue")):
                            query_class.query_asan_analyzer_for_package(package_dir, configuration_dir, docker_image)
                    except FileNotFoundError:
                        continue
    query_class.run_queries()

    # if not os.path.exists(packages_file):
    #    print("File with packages must exist!")
    #    exit(0)
    # else:
    #    with open(packages_file, "r") as filepointer:
    #        result_list = []
    #        for line in filepointer.readlines():
    #            if not line.strip():
    #                continue
    #            pacman_query = "name={0}&repo=Core&repo=Extra&repo=Community".format(line.strip())
    #            print(pacman_query)
    #            ac = archcrawlers.ArchCrawler(query=pacman_query)
    #            result_list += list(ac)
