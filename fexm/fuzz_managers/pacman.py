#!/usr/bin/env python3
"""
Fuzzes Pacman with additional bells and whistles.
eval_pacman_manager
(fuzzes each package once)
"""
import argparse
import json
import logging
import typing

import celery
import os
from typing import *

from helpers.typechecker import checked

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import configfinder.config_settings
from celery_tasks.tasks import run_eval
from repo_crawlers.archcrawler import ArchCrawler
import helpers.utils
import config_parser

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_package_list_from_query(query: str):
    pacman_query = "q={0}&repo=Core&repo=Extra&repo=Community".format(query)
    ac = ArchCrawler(query=pacman_query)
    result_list = list(ac)
    return result_list


def get_package_list_from_file(file_path: str):
    if not os.path.exists(file_path):
        raise FileNotFoundError("'{}' could not be found.".format(os.path.abspath(file_path)))
    else:
        with open(file_path, "r") as file_pointer:
            result_list = []
            for line in file_pointer.readlines():
                if not line.strip():
                    continue
                pacman_query = "name={0}&repo=Core&repo=Extra&repo=Community".format(line.strip())
                print(pacman_query)
                ac = ArchCrawler(query=pacman_query)
                result_list += list(ac)
    return result_list


def query_packages(packages: List):
    result_list = []
    for p in packages:
        pacman_query = "name={0}&repo=Core&repo=Extra&repo=Community".format(p)
        ac = ArchCrawler(query=pacman_query)
        package_result = list(ac)
        if not package_result:
            print("No results for package {0}".format(p))
        result_list += list(ac)
    return result_list


def sanity_checks() -> bool:
    """
    Performs the same sanity checks afl performs and offers to fix them.
    :return: True if sane
    """
    with open("/proc/sys/kernel/core_pattern") as core_patten_fp:
        if core_patten_fp.read()[0] != '|':
            return True
    print("System is configured to send core dump notifications to an external utility. "
          "This will prevent afl-fuzz from starting. ")
    change_core_pattern = helpers.utils.query_yes_no("Do you want me to change that for you?")
    if not change_core_pattern:
        return False
    else:
        try:
            with open("/proc/sys/kernel/core_pattern", "w") as core_patten_fp:
                core_patten_fp.write("core")
                return True
        except PermissionError:
            print("Permission denied!")
            return False


class PacmanFuzzer:
    def create_directory_structure(self):
        os.makedirs(os.path.join(self.configuration_dir, "build_data"), exist_ok=True)
        os.makedirs(os.path.join(self.configuration_dir, "fuzz_data"), exist_ok=True)
        os.makedirs(os.path.join(self.configuration_dir, "run_configurations"), exist_ok=True)

    def __init__(self, config_dict: Dict[str, Any]) -> None:
        config_dict = config_parser.apply_defaults_and_validate(config_dict)

        self.max_build_threshold = configfinder.config_settings.MAX_BUILD_TRESHOLD  # Do not build packages above 15 MB
        self.max_install_threshold = configfinder.config_settings.MAX_INSTALL_TRESHOLD  # Do not consider packages above 20000 MB

        if not sanity_checks():
            print("Can not perform fuzzing without passing sanity checks!")

        self.seeds = config_dict["seeds"]
        self.config_dict = config_dict
        if not helpers.utils.is_valid_seeds_folder(self.seeds):
            print(
                "Seeds folder {0} is not valid. Please read the documentation and fix the seed directory structure.".format(
                    self.seeds))
            exit(-1)
        self.docker_image = config_dict["base_image"]
        self.configuration_dir = config_dict["out_dir"]
        self.fuzz_duration = config_dict["fuzz_duration"] * 60
        self.force = config_dict["force"]  # Force reevaluation
        self.use_asan = config_dict["use_asan"]
        self.exec_timeout = config_dict["exec_timeout"]
        # TODO: Other vals to defaut_config!
        if config_dict.get("max_install_threshold"):
            self.max_install_threshold = config_dict.get("max_install_threshold")
        if config_dict.get("max_build_threshold"):
            self.max_build_threshold = config_dict.get("max_build_threshold")
        self.packages_list = []
        packages_file = config_dict.get("packages_file")
        if packages_file:
            self.packages_list += get_package_list_from_file(packages_file)
        query = config_dict.get("query")
        if query:
            self.packages_list += get_package_list_from_query(query)
        packages = config_dict.get("packages")
        if packages:
            if isinstance(packages, str):
                self.packages_list += query_packages([packages])
            else:
                self.packages_list += query_packages(packages)
        if not packages_file and not query and not packages:
            print("Please provide either query,package or a package file")
            exit(1)
        self.create_directory_structure()

    def fuzz(self):
        """
        Enqueue a list of packages for evaluation to celery and wait for the results.
        """
        tasks = []
        for package_dict in self.packages_list:
            package = package_dict["pkgname"]
            if not self.force and os.path.exists(
                    os.path.join(self.configuration_dir, "fuzz_data", package)) and os.path.isdir(
                os.path.join(self.configuration_dir, "fuzz_data", package)):
                print("Skipping {0}: Already have configuration".format(package))
                print("Configuration here: {0}".format(self.configuration_dir + "/" + package))
                continue
            if int(package_dict["installed_size"]) > self.max_install_threshold:
                print("Skipping {0}. Too big!".format(package))
                continue
            force_qemu = False
            if int(package_dict["installed_size"]) > self.max_build_threshold:
                print("Forcing qemu for package {0}".format(package))
                force_qemu = True
            print("Queuing package {0}".format(package))
            tasks.append(run_eval.s(package, self.docker_image,
                                    os.path.realpath(os.path.join(os.getcwd() + "/", self.configuration_dir)),
                                    os.path.realpath(os.path.join(os.getcwd() + "/", self.seeds)), self.fuzz_duration,
                                    self.use_asan,
                                    self.exec_timeout, force_qemu, {"fuzzing_cores_per_binary": self.config_dict["fuzzing_cores_per_binary"]}))
        jobs = celery.group(tasks)
        results = jobs.apply_async()
        results.get()
        results.join()
        for res in results.get():
            if not res:
                return False
        return True


def fuzz(config):
    return PacmanFuzzer(config).fuzz()


def main():
    parser = argparse.ArgumentParser(description="Start the fuzzing process.")
    parser.add_argument("json", help="The path to the json configuration file")
    args = parser.parse_args()
    if not os.path.exists(args.json):
        print("JSON Configuration file {0} does not exist!".format(args.json))
        exit(-1)
    with open(args.json, "r") as fp:
        config = json.load(fp)
        eval_manager = PacmanFuzzer(**config)
        exit(eval_manager.fuzz())
    exit(1)


if __name__ == "__main__":
    exit(main())
