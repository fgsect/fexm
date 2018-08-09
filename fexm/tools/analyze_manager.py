#!/usr/bin/env python3
"""
Call this script in order to analyze all founds crashes.
"""
import json
import pathlib

import celery
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import helpers.utils
from celery_tasks.tasks import analyze_package


class AnaylzeManager:
    def __init__(self, fuzzer_image: str, configurations_dir: str):
        self.fuzzer_image = fuzzer_image
        self.configuration_dir = configurations_dir

    def execute_tasks_through_celery(self):
        tasks = []
        for package_dir in os.listdir(os.path.join(self.configuration_dir, "fuzz_data")):
            if os.path.isdir(os.path.join(self.configuration_dir, "fuzz_data", package_dir)):
                import glob
                afl_multicore_conf_files = glob.glob(
                    os.path.join(self.configuration_dir, "fuzz_data", package_dir, "*.afl_config"))
                for cfile in afl_multicore_conf_files:
                    with open(cfile) as fp:
                        conf_dict = json.load(fp)
                    afl_out_dir = conf_dict.get("afl_out_dir")
                    if not afl_out_dir:
                        print("Analyzer: Skipping {0}, no afl_out_dir found!".format(cfile))
                        continue
                    p = pathlib.Path(afl_out_dir)
                    out_dir = os.path.join(self.configuration_dir, "fuzz_data", str(pathlib.Path(*p.parts[2:])))
                    if int(helpers.utils.get_afl_stats_from_syncdir(out_dir).get("unique_crashes")) > 0:
                        print("Querying {0} for analyze!".format(out_dir))
                        tasks.append(
                            analyze_package.s(self.fuzzer_image, os.path.abspath(self.configuration_dir), package_dir))
                    else:
                        print("Analyzer: Skipping {0}, no crashes found!".format(out_dir))
        jobs = celery.group(tasks)
        results = jobs.apply_async()
        results.get()
        results.join()
        for res in results.get():
            if not res:
                return False
        return True


"""
Given a list of configurations, start the fuzzing. 
The configurations should be in the following order: 
Directory, file, ...
"""

# def print_output(chunk):
#     print(chunk)
#
#
# q = queue.Queue()
#
# docker_client = docker.from_env()
#
#
# def worker(fuzzer_image, configurations_dir):
#     """
#     One thread - constantly gets binaries from the queue and works them.
#     :return:
#     """
#     global q
#     print("Worker spawned")
#     while True:
#         next_item = q.get()
#         print("Next Item", next_item)
#         if next_item is None:
#             break
#         package, afl_config_file = next_item  # json_file is full path, package is just package name
#         crashes_config = {}
#         conf = {}
#         with open(afl_config_file) as afl_config_filepointer:
#             try:
#                 conf.update(json.load(afl_config_filepointer))
#             except ValueError:  # includes simplejson.decoder.JSONDecodeError
#                 print('Decoding JSON has failed {0}'.format(afl_config_file))
#                 continue
#             if conf.get("binary_path") is None:
#                 print("No binary_path for", package)
#                 continue
#             elif not conf.get("invocation_always_possible"):
#                 print("Invocation not possible", package)
#                 continue
#             else:
#                 database_file_name = os.path.basename(conf["binary_path"]) + ".db"
#                 crashes_dir = os.path.basename(conf["binary_path"]) + "_crashes_dir"
#                 volumes_dict = {
#                     os.path.abspath(os.path.join(configurations_dir, "fuzz_data")): {"bind": "/results", "mode": "rw"},
#                     os.path.abspath(os.path.join(configurations_dir, "build_data")): {"bind": "/build", "mode": "rw"},
#                 }
#                 analyze_command_params = ["/inputinferer/configfinder/analyze_wrapper.py", "-p", package, "-v",
#                                           "/results/"]
#                 analyze_command_params += ["-a", conf["afl_out_dir"], "-b", conf["binary_path"], "-v", "/results/",
#                                            "-d", "/results/" + package + "/" + database_file_name, "-c",
#                                            "/results/" + package + "/" + crashes_dir]
#                 container = docker_client.containers.run(image=fuzzer_image, remove=False, privileged=True,
#                                                          entrypoint="python",
#                                                          volumes=volumes_dict,
#                                                          command=analyze_command_params,
#                                                          detach=True, stream=True, stdout=True, stderr=True,
#                                                          name=package + "_anaylze_" + str(uuid.uuid4())[:4])
#                 container_output = ""
#                 for line in container.logs(stream=True):
#                     print(line.decode("utf-8").strip())
#                     container_output += line.decode("utf-8")
#                 status = container.wait()
#                 if status["StatusCode"] != 0:
#                     print(
#                         "Error while running docker command. Docker Output:\n {0}. Return value {1}".format(
#                             container_output,
#                             status[
#                                 "StatusCode"]))
#                 else:
#                     crashes_config.update(conf)
#                     crashes_config["database_file_name"] = database_file_name
#                     crashes_config["crashes_dir"] = crashes_dir
#                     crashes_config["package_info"] = package + "_info.txt"
#                     crash_config_file = configurations_dir + "/" + package + "/" + os.path.basename(
#                         crashes_config["binary_path"]) + "_" + ".crash_config"
#                     print("Writing crash config file {0}".format(crash_config_file))
#                     with open(crash_config_file, "w") as crash_config_filepointer:
#                         json.dump(crashes_config, crash_config_filepointer)
#         print("Task done")
#         q.task_done()
#
#
# def worker_package(fuzzer_image, configurations_dir):
#     """
#     One thread - constantly gets packages from the queue and works them.
#     :return:
#     """
#     global q
#     print("Worker spawned")
#     while True:
#         next_item = q.get()
#         print("Next item", next_item)
#         if next_item is None:
#             break
#
#
#
# def found_crash_for_package(self, package: str):
#     contents = [os.path.join(dirpath, filename)
#                 for (dirpath, dirs, files) in os.walk(os.path.join(self.configuration_dir, package))
#                 for filename in (dirs + files)]
#     for entity in contents:
#         if "afl_fuzz" in entity and "crashes" in entity:  # entity.endswith("crashes"):
#             if len(os.listdir(entity)) > 0:
#                 return True
#     return False
#
#
# def main(number_of_worker_threads: int, logfile: str, fuzzer_image: str, configuration_dir: str):
#     global q
#     number_of_worker_threads = 1
#     afl_config_files = []
#     for package_dir in os.listdir(configuration_dir):
#         if os.path.isdir(configuration_dir + "/" + package_dir):
#             for file in os.listdir(configuration_dir + "/" + package_dir):
#                 if file.endswith(".afl_config") and found_crash_for_package(configuration_dir):
#                     afl_config_files.append((package_dir, file))
#     threads = []
#     for i in range(number_of_worker_threads):
#         t = threading.Thread(target=lambda: worker(fuzzer_image, configuration_dir))
#         t.start()
#         threads.append(t)
#     for entity in afl_config_files:
#         package = entity[0]
#         afl_config_file = configuration_dir + "/" + package + "/" + entity[1]
#         print("Putting", afl_config_file, "in queue")
#         if not package:
#             continue
#         q.put((package, afl_config_file))
#     q.join()
#     for i in range(number_of_worker_threads):
#         q.put(None)
#     print("Waiting for thread")
#     for t in threads:
#         t.join()
#
#
# def main_package(number_of_worker_threads: int, logfile: str, fuzzer_image: str, configuration_dir: str):
#     global q  # type: queue.Queue()
#     threads = []
#     for i in range(number_of_worker_threads):
#         t = threading.Thread(target=lambda: worker_package(fuzzer_image, configuration_dir))
#         t.start()
#         threads.append(t)
#     for package_dir in os.listdir(os.path.join(configuration_dir, "fuzz_data")):
#         if os.path.isdir(os.path.join(configuration_dir, "fuzz_data", package_dir)):
#             import glob
#             afl_multicore_conf_files = glob.glob(os.path.join(configuration_dir, "fuzz_data", package_dir,"*.conf"))
#             for cfile in afl_multicore_conf_files:
#                 with open(cfile) as fp:
#                     conf_dict = json.load(fp)
#                 p = pathlib.Path(conf_dict["output"])
#                 out_dir = os.path.join(configuration_dir, "fuzz_data", str(pathlib.Path(*p.parts[2:])))
#                 if int(helpers.helpers.get_afl_stats_from_syncdir(out_dir).get("unique_crashes")) > 0:
#                     q.put(package_dir)
#                     break
#                 else:
#                     print("Package {0} has no crashes, skipping!".format(package_dir))
#     if q.qsize() > 0:
#         print("Waiting for queue")
#         q.join()
#     for i in range(number_of_worker_threads):
#         q.put(None)
#     print("Waiting for thread")
#     for t in threads:
#         t.join()
#     print("Analyzing Done!")
#
#
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description='Start the building Process')
#     parser.add_argument("-c", "--cores", required=False, type=int,
#                         help="The number of threads to spawn at max, usually how much cores your machine has. Default value for your computer " + str(
#                             len(os.sched_getaffinity(0))), default=len(os.sched_getaffinity(0)))
#     parser.add_argument("-l", "--logfile", required=False, type=str,
#                         help="The path to the logfile this program should write to", default="log.log")
#     parser.add_argument("-pd", "--plots_directory", required=False, type=str,
#                         help="The directory where the plot images shoud be saved.", default="figures/")
#     parser.add_argument("-plot_format", "--plot_format", required=False, choices=["png", "tex"],
#                         help="In which format should the plots be saved", default="png")
#     parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl", default=1.5)
#     parser.add_argument("-di", "--base_image", required=True, type=str, help="Time apt fuzzer image.")
#     parser.add_argument("-cd", "--configuration_dir", required=True, type=str,
#                         help="The directory that contains the configurations")
#     arguments = parser.parse_args()
#     if not os.path.exists(arguments.configuration_dir) or not os.path.isdir(arguments.configuration_dir):
#         raise NotADirectoryError("Configuration Path must be Directory!")
#     main(number_of_worker_threads=arguments.cores, logfile=arguments.logfile, fuzzer_image=arguments.base_image,
#          configuration_dir=arguments.configuration_dir)
