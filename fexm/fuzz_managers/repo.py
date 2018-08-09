#!/usr/bin/env python3
"""
Fuzzes a repo (arch, apt, ....)
(fuzzes packages round robin)
"""
import json
import pathlib
import queue
import time

import os
from celery.result import AsyncResult

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from enum import Enum
import argparse
import configfinder.config_settings
from celery_tasks.tasks import run_fuzzer, run_minimizer, build_package
from celery import group
import datetime
import uuid
from helpers import utils
import logging
import docker
import docker.errors
from helpers.utils import get_afl_metadata, get_seeds_dir_from_input_vector_dict

logger = logging.getLogger("myLogger")
hdlr = logging.FileHandler('tasks.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)


def exception_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}".format(str(value)))


# sys.excepthook = exception_handler
""" 
Given a list of configurations, fuzz the fuzzing. 
The configurations should be in the following order: 
Directory, file, ...
"""
DEFAULT_MAX_TIMEOUT_PER_PACKAGE = 1800  # 30 Minutes should be enough
MAX_TIMEOUT_PER_PACKAGE = configfinder.config_settings.MAX_TIMEOUT_PER_PACKAGE + (
        10 * 60)  # Reserve max. 10 Minuten for building


def print_output(chunk):
    print(chunk)


class ConfigTypes(Enum):
    INFERENCE_CONFIG = 1
    AFL_CONFIG = 2
    MINIMIZE = 3


from enum import Enum


class TaskStatus(Enum):
    BUILDING = 0
    MIMIZING = 1
    STARTED_FUZZING = 2
    RESUMED_FUZZING = 3


class FuzzTask:
    def __init__(self, package: str, status: TaskStatus, conf_dict: {}, build_file: str, taskid: str,
                 afl_json_file: str = None, afl_out_dir: str = None):
        self.package = package
        self.status = status
        self.conf_dict = conf_dict
        self.build_file = build_file
        self.afl_json_file = afl_json_file
        self.afl_out_dir = afl_out_dir
        self.taskid = taskid


class RepoFuzzer(object):
    """
    This class controls the fuzzing for multiple objects. 
    
    """

    # noinspection PyUnusedLocal
    def __init__(self, logfile: str, fuzzer_image: str, configuration_dir: str, qemu: bool = False, timeout: int = None,
                 blacklist_file: str = None, binary_list: str = None, **kwargs):
        if not os.path.isdir(configuration_dir):
            raise NotADirectoryError("Configurations directory {0} does not exist".format(configuration_dir))
        self.q = queue.Queue()
        self.queue_list = []  # Jobs to put in queue when starting
        self.logfile = logfile
        self.fuzzer_image = fuzzer_image
        self.configuration_dir = configuration_dir
        self.qemu = qemu
        self.timeout = timeout
        self.task_lists = []
        self.ignore_package = set()
        self.currently_fuzzed = []
        self.already_enqueued = set()
        self.first_start = True
        self.binary_list = binary_list
        self.docker_client = docker.from_env()
        self.packages_building_enqueued = set()
        self.packages_to_build = set()
        try:
            self.minimize = int(os.environ.get("LARGEFUZZ_MINIMIZATION", default=True))
        except ValueError:
            print("Please provide 0 or 1 value for LARGEFUZZ_MINIMIZATION")
            exit(0)
        try:
            self.start_fuzzing = int(os.environ.get("LARGEFUZZ_START_FUZZING", default=True))
        except ValueError:
            print("Please provide 0 or 1 value for LARGEFUZZ_START_FUZZING")
            exit(0)
        try:
            self.resume_fuzzing = int(os.environ.get("LARGEFUZZ_RESUMING", default=True))
        except ValueError:
            print("Please provide 0 or 1 value for LARGEFUZZ_MINIMIZATION")
            exit(0)
        try:
            self.skip_after_crash_found = int(os.environ.get("LARGEFUZZ_SKIPAFTERCRASH", default=True))
        except ValueError:
            print()
        self.blacklisted_packages = []
        if blacklist_file:
            if not os.path.exists(blacklist_file):
                print("Blacklist file {0} does not exist!".format(blacklist_file))
                exit(0)
            with open(blacklist_file, "r") as fp:
                for line in fp.readlines():
                    if line.strip():
                        self.blacklisted_packages.append(line.strip())
        self.binary_list = None
        if binary_list:
            if not os.path.exists(binary_list) or not os.path.isfile(binary_list):
                print("Binary list file {0} does not exist!".format(binary_list))
                exit(0)
            with open(binary_list, "r") as fp:
                for line in fp.readlines():
                    if line.strip():
                        self.binary_list.append(line.strip())

    def found_crash_for_package(self, package: str):
        contents = [os.path.join(dirpath, filename)
                    for (dirpath, dirs, files) in os.walk(os.path.join(self.configuration_dir, package))
                    for filename in (dirs + files)]
        for entity in contents:
            if "afl_fuzz" in entity and "crashes" in entity:  # entity.endswith("crashes"):
                if len(os.listdir(entity)) > 0:
                    return True
        return False

    def scan(self):
        self.collect_info()
        self.build_packages()
        self.prepare_task_lists()
        self.first_start = False

    def fuzz(self):
        self.scan()
        self.scheduler()

    def build_packages(self):
        packages_to_build = []
        for package_dir in self.packages_to_build:
            if package_dir in self.blacklisted_packages:
                continue
            if self.found_crash_for_package(package_dir) and self.skip_after_crash_found:
                if self.first_start:
                    print("Already have a crash for package {0}! Skipping".format(package_dir))
                continue
            if os.path.isfile(os.path.join(self.configuration_dir, package_dir)):
                continue
            if not any([file.endswith(".json") or file.endswith(".afl_config") for file in
                        os.listdir(os.path.join(self.configuration_dir, package_dir))]):
                continue
            image = None
            build_file = os.path.join(os.getcwd(),
                                      self.configuration_dir + "/" + package_dir + "/" + package_dir + ".build")
            if os.path.exists(build_file):
                with open(build_file) as fp:
                    image_name = json.load(fp).get("docker_image_name")
                    if image_name:
                        try:
                            image = self.docker_client.images.get(image_name)
                        except docker.errors.ImageNotFound:
                            image = None
            if not image:  # We have no build image yet!
                packages_to_build.append({"package": package_dir, "build_file": build_file})
                print("Building package {0}".format(package_dir))
        jobs = group(build_package.s(p["package"], self.fuzzer_image, p["build_file"]) for p in packages_to_build)
        results = jobs.apply_async()
        results.join()
        # print("Build results:")
        # print(results.get())

    def valid_config(self, file: str):
        if not os.path.exists(file):
            return False
        if file.endswith(".afl_config"):
            with open(file) as json_filepointer:
                conf = json.load(json_filepointer)
            if conf.get("status"):
                status = TaskStatus(int(conf.get("status")))
            else:
                print("No status")
                return False
            if (status == TaskStatus.RESUMED_FUZZING) and conf.get("afl_out_dir"):
                out_dir_path = pathlib.Path(conf.get("afl_out_dir"))
                out_dir_path = str(out_dir_path.relative_to(*out_dir_path.parts[:2]))
                afl_out_path = os.path.join(self.configuration_dir, out_dir_path)
                if not os.path.exists(os.path.join(afl_out_path, "fuzzer_stats")):
                    return False
                elif os.path.exists(os.path.join(afl_out_path, "fuzzer_stats")):
                    return True
                return False
            elif status == TaskStatus.STARTED_FUZZING:
                if (not conf.get("min_seeds_dir")):
                    print("No new seeds dir")
                    return False
                else:
                    p = pathlib.Path(conf.get("min_seeds_dir"))
                    p = str(p.relative_to(*p.parts[:2]))
                    min_seeds_dir_path = os.path.join(self.configuration_dir, p)
                    if os.path.exists(min_seeds_dir_path):
                        return True
                    else:
                        print("path {0} does not exists", min_seeds_dir_path)
                return False
        else:
            return False

    def get_status_for_configfile(self, file):
        with open(file) as json_filepointer:
            conf = json.load(json_filepointer)
        if conf.get("status"):
            status = TaskStatus(int(conf.get("status")))
            return status
        else:
            print("No status for file {0}".format(file))
            return False

    def collect_info(self):
        self.queue_list = []
        self.packages_to_build = set()
        # self.task_lists = []
        first_process_list = []
        minimizer_list = []
        start_fuzz_list = []
        resume_fuzz_list = []
        for package_dir in os.listdir(self.configuration_dir):
            if package_dir in self.blacklisted_packages:
                continue
            if self.found_crash_for_package(package_dir) and self.skip_after_crash_found:
                # print("Already have a crash for package {0}! Skipping".format(package_dir))
                continue
            if os.path.isdir(os.path.join(self.configuration_dir + "/", package_dir)):  # We got a binary
                files = os.listdir(os.path.join(self.configuration_dir + "/", package_dir))
                configtype = ConfigTypes.AFL_CONFIG
                for file in files:
                    configfile = None
                    if self.valid_config(os.path.join(self.configuration_dir, package_dir, file)):
                        configfile = file
                        configtype = ConfigTypes.AFL_CONFIG
                    elif file.endswith(".json") and not self.valid_config(
                            os.path.join(self.configuration_dir + "/", package_dir,
                                         file[:-len(".json")] + ".afl_config")):
                        jsonconfigfile = file
                        configfile = jsonconfigfile
                        configtype = ConfigTypes.INFERENCE_CONFIG
                    if configfile:
                        if self.binary_list and configfile.rsplit(".", 1) not in self.binary_list:
                            continue
                        append_tuple = (
                            package_dir, os.path.join(self.configuration_dir + "/", package_dir + "/" + configfile),
                            configtype)
                        if configtype == ConfigTypes.INFERENCE_CONFIG:
                            first_process_list.append(append_tuple)
                        else:
                            status = self.get_status_for_configfile(
                                os.path.join(self.configuration_dir, package_dir, configfile))
                            if status == False:
                                continue
                            if status == TaskStatus.MIMIZING and self.minimize:
                                minimizer_list.append(append_tuple)
                                self.packages_to_build.add(package_dir)
                            elif status == TaskStatus.STARTED_FUZZING and self.start_fuzzing:
                                start_fuzz_list.append(append_tuple)
                                self.packages_to_build.add(package_dir)
                            elif status == TaskStatus.RESUMED_FUZZING and self.resume_fuzzing:
                                resume_fuzz_list.append(append_tuple)
                                self.packages_to_build.add(package_dir)
                        # self.queue_list.append((package_dir,os.path.join(self.configuration_dir+"/",package_dir+"/"+configfile),configtype))
        self.queue_list = first_process_list + minimizer_list + start_fuzz_list + resume_fuzz_list

    def append_minimize_to_tasklist(self, package, conf_dict: {}, docker_args, build_file, docker_name: str):
        binary_path = conf_dict.get("binary_path")
        afl_json_file = os.path.basename(binary_path) + ".afl_config"
        fuzzer_command_args = ["/inputinferer/configfinder/controller.py", "minimize"]
        fuzzer_command_args += ["-p", package]
        seeds = None
        if conf_dict.get("parameter"):
            fuzzer_command_args.append(
                '--parameter="{0}"'.format(conf_dict["parameter"]))  # --we need the quotation marks int the parameter
        try:
            seeds = get_seeds_dir_from_input_vector_dict(conf_dict, package, binary_path)
        except TypeError as e:
            print("Something is wrong for {0}/{1}".format(package, binary_path))
        if not seeds:
            return False
        if conf_dict.get("qemu"):
            fuzzer_command_args.append("-Q")
        fuzzer_command_args += ["--afl_out_file", afl_json_file]
        fuzzer_command_args += ["-s", seeds, "-b", binary_path, "-v", "/results/"]
        call_dict = {"package": package, "docker_name": docker_name, "docker_args": docker_args,
                     "fuzzer_image": self.fuzzer_image, "build_file": build_file,
                     "fuzzer_command_args": fuzzer_command_args, "timeout_per_package": MAX_TIMEOUT_PER_PACKAGE}
        print("Minimizing seeds for {0}".format(package + " : " + binary_path))
        logging.info("Minimizing seeds for {0}".format(package + " : " + binary_path))
        t = run_minimizer.delay(**call_dict)
        fuzztask = FuzzTask(package=package, conf_dict=conf_dict, build_file=build_file, taskid=t.task_id,
                            afl_json_file=afl_json_file, status=TaskStatus.MIMIZING)
        self.task_lists.append(fuzztask)
        # if package + "/" + binary_path not in self.ignore_package:
        #    print("Minimizing for {0}".format(package+" : "+binary_path))
        #    self.task_lists.append((os.path.join(package + "/",binary_path), run_minimizer.s(**call_dict)))
        # self.currently_fuzzed.append(package)
        return True

    def append_start_fuzzer_to_tasklist(self, package, conf_dict: {}, docker_args, build_file, afl_json_filepath: str,
                                        docker_name: str):
        fuzzer_command_args = ["/inputinferer/configfinder/controller.py", "fuzz"]
        fuzzer_command_args += ["-p", package]
        if conf_dict.get("parameter"):
            fuzzer_command_args.append(
                '--parameter="{0}"'.format(conf_dict["parameter"]))  # --we need the quotation marks int the parameter
        if conf_dict.get("qemu"):
            fuzzer_command_args.append("-Q")
        seeds_dir_usable = False
        binary_path = conf_dict.get("binary_path")
        if conf_dict.get("min_seeds_dir"):
            seeds = conf_dict.get("min_seeds_dir")
            p = pathlib.Path(seeds)
            local_seeds_dir = os.path.join(self.configuration_dir, str(p.relative_to(*p.parts[:2])))
            for file in os.listdir(local_seeds_dir):
                if os.path.getsize(os.path.join(local_seeds_dir, file)) > 0:
                    seeds_dir_usable = True
            if not seeds_dir_usable:
                print("The given seeds dir for {0}:{1} seems unusable".format(package, binary_path))
                print(
                    "The seeds dir is empty: This strongly suggests that the command line invocation does not lead to file processing.")
                print("Please check the invocation for {0}:{1}".format(package, binary_path))
                return False
        if not seeds_dir_usable:  # As a fallback option, just use the filetype
            seeds = conf_dict.get("file_type")
        if "seeds" not in locals():
            raise ValueError("Seeds were not set.")
        # noinspection PyUnboundLocalVariable
        fuzzer_command_args += ["-s", seeds, "-b", binary_path, "-v", "/results/"]
        fuzzer_command_args += ["--afl_out_file", os.path.basename(afl_json_filepath)]
        if self.timeout:
            fuzzer_command_args += ["--timeout", self.timeout]
        call_dict = {"docker_name": docker_name,
                     "package": package,
                     "docker_args": docker_args,
                     "fuzzer_image": self.fuzzer_image,
                     "build_file": build_file,
                     "fuzzer_command_args": fuzzer_command_args,
                     "timeout_per_package": MAX_TIMEOUT_PER_PACKAGE
                     }
        print("{0} Starting fuzzing {1}".format(str(datetime.datetime.now()), package + " : " + binary_path))
        logging.info("Starting fuzzing for {0}".format(package + " : " + binary_path))
        t = run_fuzzer.delay(**call_dict)
        fuzztask = FuzzTask(package=package, conf_dict=conf_dict, build_file=build_file, taskid=t.task_id,
                            afl_json_file=os.path.basename(afl_json_filepath),
                            status=TaskStatus.STARTED_FUZZING)
        self.task_lists.append(fuzztask)
        # if package + "/" + binary_path not in self.ignore_package:
        #    print("Starting fuzzing {0}".format(package+" : "+binary_path))
        #    self.task_lists.append((os.path.join(package + "/",binary_path), run_fuzzer.s(**call_dict)))
        return True

    def append_resume_fuzzer_to_tasklist(self, package, conf_dict: {}, docker_args, build_file, docker_name: str,
                                         afl_out_dir: str = None):
        if afl_out_dir is None:
            afl_out_dir = conf_dict.get("afl_out_dir")
            if afl_out_dir is None:  # Skip
                return False

        out_dir_path = pathlib.Path(afl_out_dir)
        out_dir_path = str(out_dir_path.relative_to(*out_dir_path.parts[:2]))
        afl_out_path = os.path.join(self.configuration_dir, out_dir_path)

        afl_metadata_dict = get_afl_metadata(afl_out_path)
        if afl_metadata_dict is None:
            print(
                "No afl metadata - it probably does not make sense to resume? for fuzzing fuzz {0}".format(afl_out_dir))
        if int(afl_metadata_dict["unique_crashes"]) > 0:
            print("We have already found a crash for fuzzing fuzz {0}! Skipping this package".format(afl_out_dir))
            return
        fuzzer_command_args = ["/inputinferer/configfinder/controller.py", "fuzz"]
        fuzzer_command_args += ["-p", package]
        if conf_dict.get("parameter"):
            fuzzer_command_args.append(
                '--parameter="{0}"'.format(conf_dict["parameter"]))  # --we need the quotation marks int the parameter
        if conf_dict.get("qemu"):
            fuzzer_command_args.append("-Q")
        binary_path = conf_dict.get("binary_path")
        fuzzer_command_args += ["-b", binary_path, "-v", "/results/"]
        fuzzer_command_args += ["-adir", afl_out_dir]
        if self.timeout:
            fuzzer_command_args += ["--timeout", self.timeout]
        call_dict = {"docker_name": docker_name, "package": package, "docker_args": docker_args,
                     "fuzzer_image": self.fuzzer_image, "build_file": build_file,
                     "fuzzer_command_args": fuzzer_command_args, "timeout_per_package": MAX_TIMEOUT_PER_PACKAGE}
        print("{0} Resuming fuzzing for for {1}".format(str(datetime.datetime.now()), package + " : " + binary_path))
        logging.info("Resuming fuzzing for {0}".format(package + " : " + binary_path))
        t = run_fuzzer.delay(**call_dict)
        fuzztask = FuzzTask(package=package, conf_dict=conf_dict, build_file=build_file, taskid=t.task_id,
                            afl_out_dir=afl_out_dir,
                            status=TaskStatus.RESUMED_FUZZING)
        self.task_lists.append(fuzztask)
        # if package + "/" + binary_path not in self.ignore_package:
        #    print("Resuming fuzzing for {0}".format(package+" : "+binary_path))
        #    self.task_lists.append((package + "/" + binary_path, run_fuzzer.s(**call_dict)))
        return True

    def prepare_task_lists(self):
        for item in self.queue_list:
            next_item = item
            # print("Evaluating Item", next_item)
            if next_item is None:
                break
            package, json_file, configtype = next_item  # json_file is full path, package is just package name
            if configtype == ConfigTypes.INFERENCE_CONFIG:
                with open(json_file) as json_filepointer:
                    configurations = json.load(json_filepointer)
                    conf = configurations[0]
            elif configtype == ConfigTypes.AFL_CONFIG:
                with open(json_file) as json_filepointer:
                    conf = json.load(json_filepointer)
            if conf.get("binary_path") is None:
                print("No binary_path for", package, "Skipping...")
                continue
            binary_path = conf.get("binary_path")
            if package + ":" + binary_path in self.already_enqueued:
                continue
            if conf.get("coverage") == 0 or (not conf.get("file_type")) and (not conf.get("best_chebyshev_tuple")):
                print("No coverage for", package + " : " + conf.get("binary_path"), "Skipping...")
                continue
            docker_name = str(uuid.uuid4())[:8]
            result_dir = os.path.join(os.getcwd(), self.configuration_dir + "/")
            docker_args = ["--name", docker_name, "--rm", "--cap-add=SYS_PTRACE", "-v", result_dir + ":/results",
                           "--entrypoint", "python"]
            build_file = os.path.join(os.getcwd(), self.configuration_dir + "/" + package + "/" + package + ".build")
            if not conf.get("status") and self.minimize:  # No status - fuzz to minize
                self.append_minimize_to_tasklist(package=package, conf_dict=conf, docker_args=docker_args,
                                                 build_file=build_file, docker_name=docker_name)
            elif conf.get("status") == configfinder.config_settings.Status.MINIMIZE_DONE and self.start_fuzzing:
                self.append_start_fuzzer_to_tasklist(package=package, conf_dict=conf, docker_args=docker_args,
                                                     build_file=build_file, afl_json_filepath=json_file,
                                                     docker_name=docker_name)
            elif conf.get("status") == configfinder.config_settings.Status.FUZZING and self.resume_fuzzing:
                if conf.get("afl_out_dir"):
                    self.append_resume_fuzzer_to_tasklist(package=package, conf_dict=conf, docker_args=docker_args,
                                                          build_file=build_file, afl_out_dir=conf["afl_out_dir"],
                                                          docker_name=docker_name)
            self.already_enqueued.add(package + ":" + binary_path)
        return True

    def scheduler(self):
        RESCAN_AFTER = 10
        count = 0
        while True:
            task_list = list(self.task_lists)
            for task in task_list:  # type: FuzzTask
                # print("Querying task:")
                # print(task_list)
                res = AsyncResult(task.taskid)
                # print(res.status)
                if res.ready():
                    self.task_lists.remove(task)
                    print("task", task.taskid, "done")
                    print(res.get())
                    if res.get()[1] != True:
                        continue
                    if task.status == TaskStatus.MIMIZING:
                        docker_name = str(uuid.uuid4())[:8]
                        result_dir = os.path.join(os.getcwd(), self.configuration_dir + "/")
                        docker_args = ["--name", docker_name, "--rm", "--cap-add=SYS_PTRACE", "-v",
                                       result_dir + ":/results", "--entrypoint", "python"]
                        with open(os.path.join(self.configuration_dir, task.package + "/" + task.afl_json_file)) as fp:
                            conf_dict = json.load(fp)
                        self.append_start_fuzzer_to_tasklist(package=task.package, conf_dict=conf_dict,
                                                             docker_args=docker_args, build_file=task.build_file,
                                                             afl_json_filepath=task.afl_json_file,
                                                             docker_name=docker_name)
                    elif task.status == TaskStatus.STARTED_FUZZING:
                        docker_name = str(uuid.uuid4())[:8]
                        result_dir = os.path.join(os.getcwd(), self.configuration_dir + "/")
                        docker_args = ["--name", docker_name, "--rm", "--cap-add=SYS_PTRACE", "-v",
                                       result_dir + ":/results", "--entrypoint", "python"]
                        with open(os.path.join(self.configuration_dir, task.package + "/" + task.afl_json_file)) as fp:
                            conf_dict = json.load(fp)
                        self.append_resume_fuzzer_to_tasklist(package=task.package, conf_dict=conf_dict,
                                                              docker_args=docker_args, build_file=task.build_file,
                                                              docker_name=docker_name)
                    elif task.status == TaskStatus.RESUMED_FUZZING:
                        docker_name = str(uuid.uuid4())[:8]
                        result_dir = os.path.join(os.getcwd(), self.configuration_dir + "/")
                        docker_args = ["--name", docker_name, "--rm", "--cap-add=SYS_PTRACE", "-v",
                                       result_dir + ":/results", "--entrypoint", "python"]
                        self.append_resume_fuzzer_to_tasklist(package=task.package, conf_dict=task.conf_dict,
                                                              docker_args=docker_args, build_file=task.build_file,
                                                              docker_name=docker_name)
            time.sleep(5)
            count += 1
            count = count % RESCAN_AFTER
            if count == 0:
                utils.helpers.temp_print("{0} Rescanning for any new projects....".format(datetime.datetime.now()))
                self.scan()
            utils.helpers.temp_print("{0}: Polling Tasks...".format(datetime.datetime.now()))


def sanity_checks():
    """
    Basically perform the same sanitify checks that afl performs
    :return: 
    """
    pattern_change_needed = False
    with open("/proc/sys/kernel/core_pattern") as core_patten_fp:
        if core_patten_fp.read()[0] == '|':
            pattern_change_needed = True
    if pattern_change_needed:
        print(
            "System is configured to send core dump notifications to an external utility. This will prevent afl-fuzz from starting. ")
        change_core_pattern = utils.helpers.query_yes_no("Do you want me to change that for you?")
        if not change_core_pattern:
            return False
        else:
            with open("/proc/sys/kernel/core_pattern", "w") as core_patten_fp:
                core_patten_fp.write("core")
                return True


def fuzz(config):
    return RepoFuzzer(**config).fuzz()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the building Process')
    parser.add_argument("-l", "--logfile", required=False, type=str,
                        help="The path to the logfile this program should write to", default="log.log")
    parser.add_argument("-pd", "--plots_directory", required=False, type=str,
                        help="The directory where the plot images should be saved.", default="figures/")
    parser.add_argument("-plot_format", "--plot_format", required=False, choices=["png", "tex"],
                        help="In which format should the plots be saved", default="png")
    parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl. Default None",
                        default=None)
    parser.add_argument("-pt", "--package_timeout", required=False, type=int, help="The timeout for the fuzzer",
                        default=DEFAULT_MAX_TIMEOUT_PER_PACKAGE)
    parser.add_argument("-di", "--base_image", required=True, type=str, help="Time apt fuzzer image.")
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str,
                        help="The directory that contains the configurations")
    parser.add_argument("-bl", "--blacklist", required=False, type=str, default=None,
                        help="The path to a blacklist file.")
    parser.add_argument("-b", "--binary_list", required=False, type=str, default=None,
                        help="Fuzz certain binaries only. Give list here.")
    arguments = parser.parse_args()
    logfilename = arguments.logfile
    logging.basicConfig(filename=os.path.join(os.getcwd(), logfilename), level=logging.INFO,
                        format='%(levelname)s %(asctime)s: %(message)s',
                        filemode='a')
    logging.info("Starting the fuzz manager.")
    MAX_TIMEOUT_PER_PACKAGE = arguments.package_timeout
    if not os.path.exists(arguments.configuration_dir) or not os.path.isdir(arguments.configuration_dir):
        raise NotADirectoryError("Configuration Path must be Directory!")
    if not sanity_checks():
        print("Can not perform fuzzing without passing sanity checks!")
        exit(1)
    fuzz({"logfile": arguments.logfile,
          "fuzzer_image": arguments.docker_image,
          "configuration_dir": arguments.configuration_dir,
          "timeout": arguments.timeout,
          "blacklist_file": arguments.blacklist,
          "binary_list": arguments.binary_list
          })
