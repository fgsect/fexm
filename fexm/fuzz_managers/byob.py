#!/usr/bin/env python3
"""
Fuzzes own binaries.
"""
import argparse
import json
import uuid

import os
import sh
# noinspection PyUnresolvedReferences
from sh import docker as docker_bin

import config_parser

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)

from helpers import utils


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
    change_core_pattern = utils.query_yes_no("Do you want me to change that for you?")
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


class ByobFuzzer:
    def create_directory_structure(self):
        os.makedirs(os.path.join(self.configuration_dir, "build_data"), exist_ok=True)
        os.makedirs(os.path.join(self.configuration_dir, "fuzz_data"), exist_ok=True)
        os.makedirs(os.path.join(self.configuration_dir, "run_configurations"), exist_ok=True)

    def __init__(self, config):
        config = config_parser.apply_defaults_and_validate(config)

        if not sanity_checks():
            print("Can not perform fuzzing without passing sanity checks!")
        self.seeds = config["seeds"]
        if not utils.is_valid_seeds_folder(self.seeds):
            raise ValueError("Seeds folder {0} is not valid. "
                             "Please read the documentation and fix the seed directory structure.".format(self.seeds))
        self.base_image = config["base_image"]
        self.configuration_dir = config["out_dir"]
        self.fuzz_duration = config["fuzz_duration"] * 60
        self.build_folder = config["build_folder"]
        self.name = config["name"]
        self.package_folder = config["name"]  # TODO: is hit okay?
        self.fuzzing_cores_per_binary = config["fuzzing_cores_per_binary"]
        self.create_directory_structure()

    def fuzz(self):
        print("Building your dockerimage")
        print("Running docker build", ["-t", self.base_image, self.build_folder])
        build_command = docker_bin.build("-t", self.base_image, self.build_folder)  # type: sh.RunningCommand
        # TODO: Catch "pull access denied for pacmanfuzzer, repository does not exist or may require 'docker login'"
        #       >>  User needs to init first!"

        import docker
        docker_client = docker.from_env()
        dict = {
            "asan": True,
            "exec_timeout": "1000+",
            "fuzz_duration": self.fuzz_duration,
            "fuzzing_cores_per_binary": self.fuzzing_cores_per_binary,
            "package_folder": "/data/" + self.package_folder,
            "package": self.name,
            "qemu": False,
            "seeds": "/fuzz/seeds",
            "volume": "/results"
        }
        with open(os.path.join(self.configuration_dir, "run_configurations/", self.name + ".json"), "w") as fp:
            json.dump(dict, fp)
        print("Doing the magic now!")
        volumes_dict = {
            os.path.abspath(os.path.join(self.configuration_dir, "fuzz_data")): {"bind": "/results", "mode": "rw"},
            os.path.abspath(os.path.join(self.configuration_dir, "build_data")): {"bind": "/build", "mode": "rw"},
            os.path.abspath(os.path.join(self.configuration_dir, "run_configurations")): {"bind": "/run_configurations",
                                                                                          "mode": "ro"},
            os.path.abspath(self.seeds): {"bind": "/fuzz/seeds", "mode": "ro"},

        }
        eval_args = ["/inputinferer/configfinder/eval_package.py", "/run_configurations/" + self.name + ".json"]
        container = docker_client.containers.run(image=self.base_image, remove=True, cap_add=["SYS_PTRACE"],
                                                 security_opt=["seccomp=unconfined"],
                                                 entrypoint="python",
                                                 volumes=volumes_dict,
                                                 command=eval_args,
                                                 detach=True, stream=True, stdout=True, stderr=True,
                                                 name=self.name + "_fuzz_" + str(uuid.uuid4())[:4])
        container_output = ""
        for line in container.logs(stream=True):
            print(line.decode("utf-8").strip())
            container_output += line.decode("utf-8")
        status = container.wait()
        if status["StatusCode"] != 0:
            print(
                "Error while running docker command. Docker Output:\n {0}. Return value {1}".format(container_output,
                                                                                                    status[
                                                                                                        "StatusCode"]))
            return False
        return True


def fuzz(config):
    return ByobFuzzer(config).fuzz()


def main():
    parser = argparse.ArgumentParser(description="Start the fuzzing process.")
    parser.add_argument("json", help="The path to the json configuration file")
    args = parser.parse_args()
    if not os.path.exists(args.json):
        print("JSON Configuration file {0} does not exist!".format(args.json))
        exit(-1)

    with open(args.json, "r") as fp:
        config = json.load(fp)

    fuzz(config)


if __name__ == "__main__":
    main()
