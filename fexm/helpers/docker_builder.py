import argparse
import json
import sys
import time
import uuid

import os
import sh
from sh import docker

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder import config_settings


def build_and_commit(package: str, fuzzer_image: str, json_output_path: str = None, qemu=False, timeout=None) -> str:
    """
    This builds a package inside a docker container and then commits the container to an image.
    :return: 
    """
    start = time.time()
    docker_image_name = package + "_" + str(uuid.uuid4())[:8]
    docker_container_name = str(uuid.uuid4())
    try:
        if not qemu:
            build_process = docker.run('--cpus=0.90', "--privileged", "--name", docker_container_name, "--entrypoint",
                                       "python", fuzzer_image, "/inputinferer/configfinder/builder_wrapper.py", "-p",
                                       package, _out=sys.stdout, _ok_code=[config_settings.BUILDER_BUILD_NORMAL,
                                                                           config_settings.BUILDER_BUILD_FAILED,
                                                                           config_settings.BUILDER_BUILD_QEMU],
                                       _timeout=timeout)  # type: sh.RunningCommand
        else:
            build_process = docker.run('--cpus=0.90', "--privileged", "--name", docker_container_name, "--entrypoint",
                                       "python", fuzzer_image, "/inputinferer/configfinder/builder_wrapper.py",
                                       "-p", package, "-Q",
                                       _out=sys.stdout,
                                       _ok_code=[config_settings.BUILDER_BUILD_NORMAL,
                                                 config_settings.BUILDER_BUILD_FAILED,
                                                 config_settings.BUILDER_BUILD_QEMU],
                                       _timeout=timeout)  # type: sh.RunningCommand
    except sh.TimeoutException as e:
        print("Building {0} timed out!".format(package))
        return None
    exit_code = build_process.exit_code
    if exit_code == -1:
        print("Failed to build image for package {0}, not commiting".format(package))
        return None
    docker.commit(docker_container_name, docker_image_name, _out=sys.stdout)
    end = time.time()
    if json_output_path is not None:
        json_dict = {}
        json_dict["docker_image_name"] = docker_image_name
        if exit_code == config_settings.BUILDER_BUILD_NORMAL:
            json_dict["qemu"] = False
        elif exit_code == config_settings.BUILDER_BUILD_QEMU:
            json_dict["qemu"] = True
        json_dict["time"] = end - start
        with open(json_output_path, "w") as json_output_fp:
            json.dump(json_dict, json_output_fp)
    docker.rm(docker_container_name)  # Remove the image after we commited
    return docker_image_name


def return_current_package_image(package: str, fuzzer_image: str, package_image: str, json_output_path: str = None,
                                 qemu=False, timeout=None) -> str:
    """
    Checks if the current package_image still exists and if not creates a new one.
    """
    output = str(docker.images(package_image))
    print(output.split("\n"))
    if len(output.split("\n")) > 2:
        return package_image
    else:
        return build_and_commit(package, fuzzer_image=fuzzer_image, json_output_path=json_output_path, qemu=qemu,
                                timeout=timeout)


def get_image_or_store_in_buildfile(package: str, fuzzer_image, buildfile_path: str, qemu=False):
    if not os.path.exists(buildfile_path):
        return build_and_commit(package, fuzzer_image=fuzzer_image, json_output_path=buildfile_path, qemu=qemu)
    else:
        with open(buildfile_path, "r") as fp:
            build_dict = json.load(fp)
            return return_current_package_image(package, fuzzer_image, build_dict["docker_image_name"],
                                                json_output_path=buildfile_path, qemu=qemu)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the building Process')
    parser.add_argument("-di", "--base_image", required=True, type=str, help="Fuzzer image.")
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to build")
    parser.add_argument("-out", "--output_path", required=False, type=str, default=None,
                        help="Where to store the json configuration?")
    arguments = parser.parse_args()
    build_and_commit(package=arguments.package, fuzzer_image=arguments.docker_image,
                     json_output_path=arguments.output_path)
