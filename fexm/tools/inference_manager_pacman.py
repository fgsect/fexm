#!/usr/bin/env python3
"""
This is an inference manger for pacman packages - query pacman and infer input vector for number of packages.
"""
import argparse
import uuid

import celery
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import configfinder.config_settings
from celery_tasks.tasks import run_inference
from repo_crawlers.archcrawler import ArchCrawler

MAX_TIMEOUT_PACKAGE_INFERENCE = configfinder.config_settings.MAX_TIMEOUT_PACKAGE_INFERENCE
MAX_BUILD_TRESHOLD = configfinder.config_settings.MAX_BUILD_TRESHOLD  # Do not build packages above 15 MB
global MAX_INSTALL_TRESHOLD
MAX_INSTALL_TRESHOLD = configfinder.config_settings.MAX_INSTALL_TRESHOLD  # Do not consider packages above 20000 MB


def query_package_list(package_list: [str], pacman_fuzzer_image: str, configurations_dir: str, max_build_treshold: int,
                       force=False):
    tasks = []
    for package_dict in package_list:
        package = package_dict["pkgname"]
        if not force and os.path.exists(configurations_dir + "/" + package) and os.path.isdir(
                configurations_dir + "/" + package):
            print("Skipping {0}: Already have configuration".format(package))
            print("Configuration here: {0}".format(configurations_dir + "/" + package))
            continue
        docker_name = str(uuid.uuid4())[:8]
        if int(package_dict["installed_size"]) > MAX_INSTALL_TRESHOLD:
            print("Skipping {0}. Too big!".format(package))
            continue
        print("Queuing package {0}".format(package))
        docker_command_args = ["--name", docker_name, "--rm", "--cap-add=SYS_PTRACE", "-v",
                               os.path.join(os.getcwd() + "/", configurations_dir) + ":/results", "--entrypoint",
                               "python"]

        inference_command_args = ["/inputinferer/configfinder/config_finder_for_pacman_package.py", "-p", package,
                                  "--output_volume", "/results"]
        use_qemu = False
        if int(package_dict["installed_size"]) > max_build_treshold:
            print("Appending QEMU because of package size")
            inference_command_args.append("-Q")
            use_qemu = True
        build_file = os.path.join(os.getcwd() + "/", configurations_dir + "/" + package + "/" + package + ".build")
        tasks.append(run_inference.s(docker_name, package, docker_command_args, pacman_fuzzer_image, build_file,
                                     inference_command_args, MAX_TIMEOUT_PACKAGE_INFERENCE, use_qemu))
    jobs = celery.group(tasks)
    res = jobs.apply_async()
    print(res.get())
    res.join()
    print(res.get())


def main(pacman_fuzzer_image: str, query: str, configurations_dir: str, max_build_treshold: int):
    pacman_query = "q={0}&repo=Core&repo=Extra&repo=Community".format(query)
    ac = ArchCrawler(query=pacman_query)
    result_list = list(ac)
    # try:
    #    dr = docker.run("--rm","--cap-add=SYS_PTRACE", "-v", os.getcwd() + "/"+configurations_dir+":/results","--entrypoint","/bin/bash",pacman_fuzzer_image,"-c","pacman -Ssq  {0}".format(query),_ok_code=[0,1])  # type: sh.RunningCommand
    # except sh.ErrorReturnCode as e:
    #    print("Error for query {0}".format(query))
    #    print("STDOUT:\n", e.stdout.decode("utf-8"))
    #    print(str(e.stderr))
    #    raise e
    # if dr.exit_code==1:
    #    print("No results for query {0}. Skipping".format(query.strip()))
    #    return
    # package_list = list(filter(lambda x[""]: x,package_list))
    query_package_list(result_list, pacman_fuzzer_image, configurations_dir, max_build_treshold)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the building Process')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-q", "--query", type=str, help="The search query for pacman.")
    group.add_argument("-p", "--package", type=str, help="Package to analyze.")
    group.add_argument("-f", "--file", type=str, help="A file containing search queries for pacman.")
    group.add_argument("-fp", "--packagesfile", type=str, help="A file containing packages for pacman")
    parser.add_argument("-di", "--base_image", required=True, type=str, help="Time apt fuzzer image.")
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str,
                        help="Where should the configuration be stored?.")
    parser.add_argument("-ms", "--max_size", required=False, type=int,
                        help="The maximum package size that should be downloaded in KB. Default {0}".format(
                            configfinder.config_settings.MAX_INSTALL_TRESHOLD),
                        default=MAX_INSTALL_TRESHOLD)
    parser.add_argument("-mb", "--max_build_size", required=False, type=int,
                        help="The maximum package size that should be build in KB. Default {0}".format(
                            configfinder.config_settings.MAX_BUILD_TRESHOLD),
                        default=MAX_BUILD_TRESHOLD)
    parser.add_argument("--force", dest="force", action="store_true", default=False,
                        help="Force reevaluation")

    arguments = parser.parse_args()
    MAX_INSTALL_TRESHOLD = arguments.max_size
    max_build_treshold = arguments.max_build_size
    if not arguments.query and not arguments.file and not arguments.package and not arguments.packagesfile:
        main(query="", pacman_fuzzer_image=arguments.docker_image,
             configurations_dir=arguments.configuration_dir, max_build_treshold=max_build_treshold)
    if arguments.query:
        main(query=arguments.query, pacman_fuzzer_image=arguments.docker_image,
             configurations_dir=arguments.configuration_dir, max_build_treshold=max_build_treshold)
    elif arguments.file:
        if not os.path.exists(arguments.file):
            print("File with queries must exists!")
            exit(0)
        else:
            with open(arguments.file, "r") as filepointer:
                for line in filepointer:
                    query = line
                    main(query=query.strip(),
                         pacman_fuzzer_image=arguments.docker_image, configurations_dir=arguments.configuration_dir,
                         max_build_treshold=max_build_treshold)
    elif arguments.packagesfile:
        if not os.path.exists(arguments.packagesfile):
            print("File with packages must exist!")
            exit(0)
        else:
            with open(arguments.packagesfile, "r") as filepointer:
                result_list = []
                for line in filepointer.readlines():
                    if not line.strip():
                        continue
                    pacman_query = "name={0}&repo=Core&repo=Extra&repo=Community".format(line.strip())
                    print(pacman_query)
                    ac = ArchCrawler(query=pacman_query)
                    result_list += list(ac)
                query_package_list(result_list, arguments.docker_image, configurations_dir=arguments.configuration_dir,
                                   max_build_treshold=max_build_treshold)
    elif arguments.package:
        pacman_query = "name={0}&repo=Core&repo=Extra&repo=Community".format(arguments.package)
        ac = ArchCrawler(query=pacman_query)
        result_list = list(ac)
        query_package_list(result_list, arguments.docker_image, configurations_dir=arguments.configuration_dir,
                           max_build_treshold=max_build_treshold, force=arguments.force)
