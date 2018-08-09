import json
import pathlib
import socket
import sqlite3
import telnetlib
import time
import uuid
from threading import Thread
from typing import Dict

import docker.api.container
import os
from ansi2html import Ansi2HTMLConverter
from enum import Enum
from websockify import LibProxyServer

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import tools.analyze_manager
import helpers.utils

# This should include a port range accessible by the client
AFL_TW_PORT_RANGE = (53007, 53107)

CRASH_ORDERING = ["EXPLOITABLE", "PROBABLY_EXPLOITABLE", "UNKNOWN", "PROBABLY_NOT_EXPLOITABLE", "NOT_EXPLOITABLE", "",
                  None]
CRASH_ORDERING.reverse()


class TaskStatus(Enum):
    BUILDING = 0
    MIMIZING = 1
    STARTED_FUZZING = 2
    RESUMED_FUZZING = 3


logger = helpers.utils.init_logger(__name__)
docker_client = docker.from_env()


class UsageScraper:

    def __init__(self):
        self.cache_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "cached_usages.json"))
        self.cached_usages = {}
        self.read_cache()

    def read_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "r") as fp:
                self.cached_usages = json.load(fp)

    def cache_package(self, package, usage):
        self.cached_usages[package] = usage
        with open(self.cache_file, "w") as fp:
            json.dump(self.cached_usages, fp)

    def get_package_usage(self, package: str) -> float:
        """
        Given a package, this function makes
        a request to the arch linux package server and returns usage or None if package not found/connection error.
        :param package:
        :return:
        """
        import requests
        import json
        cached_usage = self.cached_usages.get(package)
        if cached_usage:
            return cached_usage
        print("Querying for package usage {0}".format(package))
        request_string = "https://pkgstats.archlinux.de/package/datatables?draw=6&columns[0][data]=pkgname&columns[" \
                         "0][name]=&columns[0][searchable]=true&columns[0][orderable]=false&columns[0][search][" \
                         "value]=&columns[0][search][regex]=false&columns[1][data]=count&columns[1][name]=&columns[" \
                         "1][searchable]=false&columns[1][orderable]=true&columns[1][search][value]=&columns[1][" \
                         "search][regex]=false&order[0][column]=1&order[0][dir]=desc&fuzz=0&length=25&" \
                         "search[value]={0}&search[regex]=false&_=1529960847177".format(package)
        response_dict = json.loads(requests.get(request_string).text)
        for package_dict in response_dict.get("data"):
            if package_dict.get("pkgname") == package:
                package_count = package_dict["count"]
                num_users = response_dict["recordsTotal"]
                usage = round((int(package_count) * 100) / float(num_users), 2)
                self.cache_package(package, usage=usage)
                return usage
                # return float(package_dict["count"])/float(response_dict["recordsTotal"])
        return None


class Package:

    def __init__(self, usage_scraper: UsageScraper, name: str, directory: str, analyzer: "FexmDataAnalyzer",
                 version: str = None):
        self.name = name
        self.version = version
        self.binaries = {}  # type: Dict[str, Binary]
        self.directory = directory
        p = pathlib.Path(directory)
        p = p.parts[:-1]
        self.fuzz_data_directory = str(p)
        self.find_binaries()
        self.usage = usage_scraper.get_package_usage(name)
        self.total_number_of_crashing_binaries = 0
        self.total_number_of_crashes = 0
        self.overall_worst_crash = None
        self.summarize_crash_data()
        self.current_status = None
        self.set_current_status()
        self.analyzer = analyzer

    def set_current_status(self):
        with open(os.path.join(self.directory, "status.log"), "r") as fp:
            self.current_status = fp.readlines()[-1]

    def summarize_crash_data(self):
        self.total_number_of_crashing_binaries = 0
        self.total_number_of_crashes = 0
        self.overall_worst_crash = None

        for binary in self.binaries.values():
            if len(binary.crashes_list) > 1:
                self.total_number_of_crashing_binaries += 1
            for crash in binary.crashes_list:
                if CRASH_ORDERING.index(self.overall_worst_crash) <= CRASH_ORDERING.index(crash.exploitability):
                    self.overall_worst_crash = crash.exploitability
            self.total_number_of_crashes += len(binary.crashes_list)

    def get_binary_name_from_json(self, json_filepath):
        with open(json_filepath) as fp:
            json_dict = json.load(fp)
        if type(json_dict) is list:
            return helpers.utils.get_filename_from_binary_path(json_dict[0].get("binary_path"))
        else:
            return helpers.utils.get_filename_from_binary_path(json_dict.get("binary_path"))

    def find_binaries(self):
        for entity in os.listdir(self.directory):
            if os.path.isdir(entity):
                continue
            if entity.endswith(".afl_config"):
                binary_name = self.get_binary_name_from_json(os.path.join(self.directory, entity))
                try:
                    self.binaries[binary_name].update_binary_object_from_afl_config(self.binaries[binary_name],
                                                                                    os.path.join(self.directory,
                                                                                                 entity))
                except KeyError:
                    self.binaries[binary_name] = Binary.from_afl_config(os.path.join(self.directory, entity), self.name)
            elif entity.endswith(".json"):
                binary_name = self.get_binary_name_from_json(os.path.join(self.directory, entity))
                try:
                    self.binaries[binary_name].update_binary_object_from_json_config(self.binaries[binary_name],
                                                                                     os.path.join(self.directory,
                                                                                                  entity))
                except KeyError:
                    self.binaries[binary_name] = Binary.from_json_config(os.path.join(self.directory, entity),
                                                                         self.name)
            elif entity.endswith(".crash_config"):
                binary_name = self.get_binary_name_from_json(os.path.join(self.directory, entity))
                try:
                    self.binaries[binary_name].update_binary_object_from_crash_config(self.binaries[binary_name],
                                                                                      os.path.join(self.directory,
                                                                                                   entity))
                except KeyError:
                    self.binaries[binary_name] = Binary.from_crash_config(os.path.join(self.directory, entity),
                                                                          self.name)


class Binary:

    @staticmethod
    def update_binary_object_from_afl_config(binary, afl_config_path: str):
        with open(afl_config_path) as fp:
            afl_dict = json.load(fp)
        binary.status = TaskStatus(afl_dict["status"])
        if binary.status == TaskStatus.RESUMED_FUZZING:  # TasksStatus always displays "next" task
            p = pathlib.Path(afl_dict["afl_out_dir"])
            p = pathlib.Path(*p.parts[2:])
            logger.debug(binary.fuzz_data_directory)
            binary.afl_out_dir = os.path.join(binary.fuzz_data_directory, str(p))
            logger.debug("fuzz stats")
            binary.fuzz_stats = helpers.utils.get_afl_stats_from_syncdir(binary.afl_out_dir)

    @staticmethod
    def update_binary_object_from_json_config(binary, json_config_path: str):
        with open(json_config_path) as fp:
            json_dict = json.load(fp)
        binary.parameter = json_dict[0]["parameter"]
        binary.file_types = json_dict[0]["file_types"]
        if json_dict[0].get("took_max_file"):
            binary.took_max_file = True
        else:
            binary.took_max_file = False

    @staticmethod
    def update_binary_object_from_crash_config(binary, crash_config_path: str):
        with open(crash_config_path) as fp:
            crash_config_dict = json.load(fp)
        binary.parameter = crash_config_dict.get("parameter")
        binary.file_types = crash_config_dict.get("file_types")
        p = pathlib.Path(crash_config_dict.get("afl_out_dir"))
        p = pathlib.Path(*p.parts[2:])
        binary.afl_out_dir = os.path.join(binary.fuzz_data_directory, str(p))
        binary.database_file_name = crash_config_dict["database_file_name"]
        binary.crashes_dir = crash_config_dict["crashes_dir"]
        binary.crashes_list = []
        binary.overall_worst_crash = None
        binary.assemble_crash_list()

    def assemble_crash_list(self):
        crash_db_full_path = os.path.join(self.fuzz_data_directory, self.package,
                                          self.database_file_name)
        crash_directory_full_path = os.path.join(self.fuzz_data_directory, self.package,
                                                 self.crashes_dir)
        if not os.path.exists(crash_db_full_path):
            print("Error: The database {0} does not exist".format(crash_db_full_path))
            print(crash_db_full_path)
            return
        print("Opening database {0}".format(crash_db_full_path))
        connect = sqlite3.connect(crash_db_full_path)
        c = connect.cursor()
        c.execute("select count(*) from sqlite_master where type='table' and name='Data';")
        if c.fetchone()[0] != 1:
            print("Error: The table Data does not exist")
            return
        c.execute("select count(*) from Data;")
        conv = Ansi2HTMLConverter(inline=True)
        if c.fetchone()[0] > 0:
            logger.info("Crashes for binary {0}".format(self.path))
            for row in c.execute('SELECT * FROM Data'):
                # logger.debug(row[0])
                # logger.debug(os.path.join(crash_directory_full_path, row[0]))
                if not os.path.exists(os.path.join(crash_directory_full_path, row[0])):
                    continue
                try:
                    rendered_text = conv.convert(row[5].decode("utf-8"), full=False)
                except Exception as e:
                    rendered_text = ""
                crash = Crash(exploitability=row[1], description=row[2],
                              file_path=os.path.join(crash_directory_full_path, row[0]),
                              file_name=row[0],
                              execution_output=rendered_text)
                self.crashes_list.append(crash)
        else:
            print("No crashes for package {0} binary {1}".format(self.package, self.path))

        for crash in self.crashes_list:
            print(crash.exploitability)
            if CRASH_ORDERING.index(self.overall_worst_crash) <= CRASH_ORDERING.index(crash.exploitability):
                self.overall_worst_crash = crash.exploitability

    @classmethod
    def from_afl_config(cls, afl_config_path: str, package: str):
        with open(os.path.join(afl_config_path)) as fp:
            afl_dict = json.load(fp)
        p = pathlib.Path(afl_config_path)
        p = pathlib.Path(*p.parts[:-2])
        fuzz_data_directory = str(p)
        binary_path = afl_dict["binary_path"]
        binary = cls(binary_path,
                     fuzz_data_directory=fuzz_data_directory,
                     package=package)
        Binary.update_binary_object_from_afl_config(binary, afl_config_path)
        return binary

    @classmethod
    def from_json_config(cls, json_config_path, package: str):
        with open(os.path.join(json_config_path)) as fp:
            json_dict = json.load(fp)
        p = pathlib.Path(json_config_path)
        p = pathlib.Path(*p.parts[:-2])
        fuzz_data_directory = str(p)
        binary = cls(path=json_dict[0]["binary_path"],
                     fuzz_data_directory=fuzz_data_directory,
                     package=package)
        cls.update_binary_object_from_json_config(binary, json_config_path)
        return binary

    @classmethod
    def from_crash_config(cls, crash_config_path, package: str):
        with open(os.path.join(crash_config_path)) as fp:
            crash_config_dict = json.load(fp)
        p = pathlib.Path(crash_config_path)
        p = pathlib.Path(*p.parts[:-2])
        fuzz_data_directory = str(p)
        binary = cls(path=crash_config_dict["binary_path"],
                     fuzz_data_directory=fuzz_data_directory,
                     package=package)
        binary.update_binary_object_from_crash_config(binary, crash_config_path)
        return binary

    def __init__(self, path: str, fuzz_data_directory: str, package: str):
        self.path = path
        self.name = helpers.utils.get_filename_from_binary_path(self.path)
        self.fuzz_data_directory = fuzz_data_directory
        self.package = package
        self.crashes_list = []
        self.overall_worst_crash = None
        self.afl_out_dir = None
        self.fuzz_stats = None

    def update_with_afl_config(self, afl_config_path: str):
        self.update_binary_object_from_afl_config(self, afl_config_path)

    def update_with_json_config(self, json_config_path: str):
        self.update_binary_object_from_json_config(self, json_config_path)

    def refresh_fuzz_stats(self):
        print("Refreshing fuzz stats")
        if self.afl_out_dir:
            self.fuzz_stats = helpers.utils.get_afl_stats_from_syncdir(self.afl_out_dir)

    def start_timewarp(self, fexm_analyzer):
        """
        Spawns a docker container containing a tmux with an attached afl-timewarp session.
        :return: name of the binary and port.
        """
        configuration_dir = os.path.realpath(fexm_analyzer.configuration_dir)
        volumes_dict = {
            os.path.join(configuration_dir, "fuzz_data"): {"bind": "/results", "mode": "rw"},
            os.path.join(configuration_dir, "build_data"): {"bind": "/build", "mode": "rw"},
            os.path.join(configuration_dir, "run_configurations"): {"bind": "/run_configurations", "mode": "ro"},
        }
        timewarp_args = ["/inputinferer/configfinder/timewarp_wrapper.py", "-b", self.path,
                         "-param={0}".format(self.parameter),
                         "-j", "/run_configurations/" + self.package + ".json"]

        taken_ports = set()
        stdio_port = helpers.utils.find_free_port(*AFL_TW_PORT_RANGE, already_allocated=taken_ports)
        taken_ports.add(stdio_port)
        cnc_port = helpers.utils.find_free_port(*AFL_TW_PORT_RANGE, already_allocated=taken_ports)
        taken_ports.add(cnc_port)
        stdio_ws_port = helpers.utils.find_free_port(*AFL_TW_PORT_RANGE, already_allocated=taken_ports)
        taken_ports.add(stdio_ws_port)
        cnc_ws_port = helpers.utils.find_free_port(*AFL_TW_PORT_RANGE, already_allocated=taken_ports)

        print("stdio_port: {}:ws{}".format(stdio_port, stdio_ws_port))
        print("cnc_port: {}:ws{}".format(cnc_port, cnc_ws_port))

        container = docker_client.containers.run(image=fexm_analyzer.docker_image, remove=True, cap_add=["SYS_PTRACE"],
                                                 security_opt=["seccomp=unconfined"],
                                                 entrypoint="python",
                                                 volumes=volumes_dict,
                                                 command=timewarp_args,
                                                 detach=True, stream=True, stdout=True, stderr=True,
                                                 name="timewarp_" + self.name + "_fuzz_" + str(uuid.uuid4())[:4],
                                                 ports={'{0}/tcp'.format(2800): stdio_port,  # TODO: Random port
                                                        '{0}/tcp'.format(2801): cnc_port})

        time.sleep(8)
        #container_output = ""
        #for line in container.logs(stream=True):
        #    logger.info(line.decode("utf-8").strip())
        #    container_output += line.decode("utf-8")
        #print(container_output)
        #status = container.wait()
        #if status["StatusCode"] != 0:
        #    logger.error("Error while running docker command. "
        #                 "Docker Output:\n {1}. Return value {1}".format(container_output, status["StatusCode"]))

        print("stdio: {}, cnc: {}".format(stdio_port, cnc_port))

        stdio_server = helpers.utils.forward_port_to_websocket(port=stdio_port, ws_port=stdio_ws_port)
        #cnc_server = helpers.utils.forward_port_to_websocket(port=cnc_port, ws_port=cnc_ws_port)
        logger.info("Started stdio and cnc forwarder.")

        return {"name": self.name, "stdio": stdio_ws_port, "stdio_raw": stdio_port, "cnc_raw": cnc_port}
        # return {"name": self.name, "port": ssh_port}


class Crash:
    def __init__(self, exploitability: str, description: str, file_path: str, file_name: str, execution_output: str):
        self.exploitability = exploitability
        self.description = description
        self.file_path = file_path  # The path to the crash input
        self.file_name = file_name
        self.execution_output = execution_output


class FexmDataAnalyzer:

    def __init__(self, configuration_dir: str, docker_image):
        self.configuration_dir = configuration_dir
        self.fuzz_data = os.path.join(configuration_dir, "fuzz_data")
        self.package_dict = {}
        self.docker_image = docker_image
        self.usage_scraper = UsageScraper()
        self.create_package_dict()

    def create_package_dict(self):
        if not os.path.exists(self.configuration_dir) or not os.path.exists(self.fuzz_data):
            print("No fuzz data available yet")
            return
        self.package_dict = {}
        for entity in os.listdir(self.fuzz_data):
            if os.path.isdir(os.path.join(self.fuzz_data, entity)):
                p = Package(usage_scraper=self.usage_scraper, name=entity,
                            directory=os.path.join(self.fuzz_data, entity), analyzer=self)
                self.package_dict[entity] = p

    def refresh(self):
        self.create_package_dict()

    def analyze(self):
        am = tools.analyze_manager.AnaylzeManager(fuzzer_image=self.docker_image,
                                                  configurations_dir=self.configuration_dir)
        am.execute_tasks_through_celery()
