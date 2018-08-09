#!/usr/bin/env python3
"""
Wraps afl-fuzz fuzzing calls.
"""
import argparse
import json
import shlex
import time

import os
import shutil
from shutil import copyfile

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import signal
import sys
import multiprocessing as mp
import uuid
from typing import List
import logging
import analyze_wrapper
import sh
import config_settings
import helpers.utils
from cli_config import CliConfig
import typing
from sh import afl_fuzz, tail

""" 
Wraps afl-fuzz
"""

global aflfuzzerprocess


def signal_term_handler(signal, frame):
    print('got SIGTERM')
    if aflfuzzerprocess:
        aflfuzzerprocess.kill()
    sys.exit(0)


class AflFuzzWrapper:
    @staticmethod
    def seeds_dir_usable(seeds_dir: str):
        seeds_dir_useable = False
        for file in os.listdir(seeds_dir):
            if os.path.getsize(os.path.join(seeds_dir, file)) > 0:
                seeds_dir_useable = True
        if not seeds_dir_useable:
            print("The given seeds dir {0} seems unusable".format(seeds_dir))
            logging.error("The given seeds dir {0} seems unusable".format(seeds_dir))
        return seeds_dir_useable

    @staticmethod
    def get_dict_file_from_filetypes(file_types: typing.List[str]):
        """
        Get a dict file is possible
        :return:
        """
        for file_type in file_types:
            if file_type and os.path.exists(
                    os.path.join("/fuzz_dictionaries/dictionaries/",
                                 str(os.path.basename(file_type).split("_")[0]) + ".dict")):
                dict_file = os.path.join("/fuzz_dictionaries/dictionaries/",
                                         str(os.path.basename(file_type).split("_")[0]) + ".dict")
                return dict_file
        return None

    @classmethod
    def from_existing_afl_config(cls, afl_config_path: str, volume_path: str, fuzz_duration: int = 45,
                                 timeout: str = "1000+", mem: str = "none", log_dict: typing.Dict[str, object] = None):
        with open(afl_config_path) as fp:
            afl_config_dict = json.load(fp)

        binary_path = afl_config_dict["binary_path"]
        package = afl_config_dict["package"]
        parameter = afl_config_dict["parameter"]
        file_types = afl_config_dict["file_types"].split(";")
        volume_path = volume_path
        fuzz_duration = fuzz_duration
        timeout = timeout
        mem = mem

        if afl_config_dict["status"] == config_settings.Status.INFERENCE_DONE:

            seeds_dir = helpers.utils.make_combined_seeds_dir(file_types,
                                                              os.path.join(volume_path, package,
                                                                             os.path.basename(binary_path),
                                                                             os.path.basename(
                                                                                 (binary_path) + "_combinedseeds")))
        elif afl_config_dict["status"] == config_settings.Status.MINIMIZE_DONE:
            seeds_dir = afl_config_dict["min_seeds_dir"]
        else:
            raise ValueError("Already fuzzing, you need to call the resume method!")
        return cls(package=package, binary_path=binary_path, parameter=parameter, seeds_dir=seeds_dir,
                   volume_path=volume_path, fuzz_duration=fuzz_duration,
                   timeout=timeout, mem=mem, log_dict=log_dict, file_types=file_types)

    def prepare_log_dict(self):
        if not isinstance(self.log_dict, dict):
            self.log_dict = {}
        if self.log_dict.get(self.binary_path) is None:
            self.log_dict[self.binary_path] = {}
        if self.log_dict[self.binary_path].get("fuzz_debug") is None:
            self.log_dict[self.binary_path]["fuzz_debug"] = {}

    def get_afl_multi_core_config_dict(self):
        multicore_dict = {"input": self.seeds_dir,
                          "output": os.path.join(self.volume_path, self.package, self.binary_basename,
                                                 "multicore_fuzz" + self.session_uuid), "target": self.binary_path,
                          "cmdline": self.parameter}
        if self.fuzzing_dict_path:
            multicore_dict["dict"] = self.fuzzing_dict_path
        multicore_dict["qemu"] = helpers.utils.qemu_required_for_binary(self.binary_path)
        multicore_dict["session"] = self.session_name
        multicore_dict["interactive"] = False
        multicore_dict["mem_limit"] = "none"
        if self.timeout:
            multicore_dict["timeout"] = self.timeout
        # multicore_dict["environment"] = [k+"="+v for k,v in config_settings.get_fuzzing_env().items()]
        return multicore_dict

    def __init__(self, package: str, binary_path: str, parameter: str, seeds_dir: str, volume_path: str,
                 file_types: typing.List[str] = None, fuzzing_dict_path: str = None, fuzz_duration: int = 45,
                 timeout: str = "1000+", mem: str = "none", afl_config_file_path: str = None,
                 log_dict: typing.Dict[str, object] = None) -> None:
        self.package = package
        self.binary_path = binary_path
        self.parameter = parameter
        if not self.seeds_dir_usable(seeds_dir):
            raise ValueError("Seeds dir {0} unusable".format(seeds_dir))
        self.seeds_dir = seeds_dir
        self.volume_path = volume_path
        self.fuzz_duration = fuzz_duration
        self.timeout = timeout
        self.mem = mem
        self.log_dict = log_dict
        self.prepare_log_dict()
        if fuzzing_dict_path:
            self.fuzzing_dict_path = fuzzing_dict_path
        elif file_types:
            self.fuzzing_dict_path = self.get_dict_file_from_filetypes(file_types=file_types)
        else:
            self.fuzzing_dict_path = None
        self.afl_config_file_path = afl_config_file_path
        self.session_uuid = str(uuid.uuid4())[:8]
        self.binary_basename = os.path.basename(self.binary_path)
        self.session_name = "fuzz_" + self.binary_basename + "_" + self.session_uuid
        self.session_name = self.session_name[:29]  # Otherwise it's too long
        self.multicore_dict = self.get_afl_multi_core_config_dict()
        self.multicore_config_path = os.path.join(self.volume_path, self.package,
                                                  self.binary_basename + "_multicorefuzz_" + self.session_uuid + ".conf")
        print(self.multicore_dict["output"])
        self.afl_config_dict = None
        os.makedirs(os.path.dirname(self.multicore_config_path), exist_ok=True)

    def update_afl_config(self):
        if not self.afl_config_file_path:
            return
        self.afl_config_dict = {}
        if self.afl_config_file_path and os.path.exists(self.afl_config_file_path):
            with open(self.afl_config_file_path) as fp:
                self.afl_config_dict = json.load(fp)
        if self.afl_config_dict.get("parameter") is None:
            self.afl_config_dict["parameter"] = self.parameter
        self.afl_config_dict["afl_out_dir"] = self.get_afl_multi_core_config_dict()["output"]
        self.afl_config_dict["fuzzer_started"] = True
        self.afl_config_dict["status"] = config_settings.Status.FUZZING
        self.afl_config_dict["binary_path"] = self.binary_path
        with open(self.afl_config_file_path, "w") as jsonfp:
            json.dump(self.afl_config_dict, jsonfp)

    def analyze_current_crashes(self):
        binary_analyzer = analyze_wrapper.BinaryAnalyzer(binary_path=self.binary_path, parameter=self.parameter,
                                                         afl_dir=self.multicore_dict["output"],
                                                         volume=self.volume_path,
                                                         database_path=os.path.join(self.volume_path, self.package,
                                                                                    helpers.utils.get_filename_from_binary_path(
                                                                                        self.binary_path) + ".db"),
                                                         collection_dir=os.path.join(self.volume_path, self.package,
                                                                                     helpers.utils.get_filename_from_binary_path(
                                                                                         self.binary_path) + "_crashes_dir"),
                                                         conf=self.afl_config_dict,
                                                         package=self.package
                                                         )
        binary_analyzer.collect_for_binary()
        binary_analyzer.write_crash_config()

    def start_fuzzer(self, cores: int = 2):
        afl_multicore = sh.Command("afl-multicore")
        afl_multikill = sh.Command("afl-multikill")
        print("Starting to fuzz {0}:{1} with {2} cores".format(self.package, self.binary_path, cores), flush=True)
        logging.getLogger().info(
            "Starting to fuzz {0}:{1} with {2} cores".format(self.package, self.binary_path, cores))
        with open(self.multicore_config_path, "w") as fp:
            json.dump(self.get_afl_multi_core_config_dict(), fp, indent=4, sort_keys=True)
        os.makedirs(self.get_afl_multi_core_config_dict()["output"], exist_ok=True)
        outfile_path = os.path.join(self.volume_path, self.package,
                                    self.binary_basename + "_multicorefuzz_" + self.session_uuid + ".out")
        try:
            afl_multicore(["-c", self.multicore_config_path, "--redirect", outfile_path, "start", str(cores)],
                          _env=helpers.utils.get_fuzzing_env_for_invocation(self.parameter))
        except sh.ErrorReturnCode as e:
            self.log_dict[self.binary_path]["fuzz_debug"]["afl_multicore_stdout"] = e.stdout.decode("utf-8")
            self.log_dict[self.binary_path]["fuzz_debug"]["afl_mulitcore_stderr"] = e.stderr.decode("utf-8")
            return False
        start = time.time()
        output_so_far = ""
        success = True
        self.update_afl_config()
        chmod = sh.Command("chmod")
        chmod("-R", "0777", os.path.join(self.volume_path, self.package))
        old_unique_crashes = 0
        while True:
            time.sleep(5)
            if round(time.time() - start) >= self.fuzz_duration:
                print("Aborting the fuzzing run after {0} seconds".format(time.time() - start))
                logging.getLogger().info("Aborting the fuzzing run after {0} seconds".format(time.time() - start))
                break
        #for line in tail("-f", outfile_path, _iter=True):
            new_unique_crashes = helpers.utils.get_afl_stats_from_syncdir(self.multicore_dict["output"])[
                "unique_crashes"]
            if old_unique_crashes < new_unique_crashes:
                p = mp.Process(target=self.analyze_current_crashes())
                p.start()
                p.join()
                old_unique_crashes = new_unique_crashes
            with open(outfile_path) as fp:
                lines = fp.readlines()
            for line in lines:
                output_so_far += line
                if "PROGRAM ABORT" in line.upper() or "SYSTEM_ERROR" in line.upper():
                    self.log_dict[self.binary_path]["fuzz_debug"]["afl_out"] = output_so_far
                    logging.getLogger().error("Error while fuzzing {0}: {1}".format(self.binary_path, output_so_far))
                    success = False
                    break


        afl_multikill("-S", self.session_name)
        self.analyze_current_crashes()
        return success


def afl_fuzz_wrapper(fuzzer_args: List[str], binary_path: str, fuzz_duration: float = None, log_dict=None):
    """
    Start the fuzzer for the given binary.
    :param fuzzer_args: The args for afl.
    :param binary_path: The path to the binary.
    :param fuzz_duration: The timeout for afl
    :return: 
    """
    global aflfuzzerprocess
    if not log_dict:
        log_dict = {}  # Log to empty dict.
    if not log_dict.get(binary_path):
        log_dict[binary_path] = {}
    if not log_dict[binary_path].get("fuzz_debug"):
        log_dict[binary_path]["fuzz_debug"] = {}
    if helpers.utils.qemu_required_for_binary(binary_path):
        print("Binary is not instrumented, trying with QEMU Mode")
        if '-Q' not in fuzzer_args:
            fuzzer_args.insert(0, "-Q")
    elif "-Q" in fuzzer_args:
        print("Binary is already instrumented, trying without QEMU Mode")
        fuzzer_args.remove("-Q")
    aflfuzzerprocess = None
    try:
        afl_fuzz_duration = config_settings.MAX_TIMEOUT_PER_PACKAGE
        timeout_signal_send = None
        if fuzz_duration is not None:
            afl_fuzz_duration = fuzz_duration
            timeout_signal_send = signal.SIGINT
        else:
            afl_fuzz_duration = None
            timeout_signal_send = None
        logging.getLogger().info("Starting fuzzing of {0} with args: {1}".format(binary_path, " ".join(fuzzer_args)))
        log_dict[binary_path]["fuzz_debug"]["invocation"] = "afl-fuzz " + " ".join(fuzzer_args)
        aflfuzzerprocess = afl_fuzz(fuzzer_args, _env=helpers.utils.get_fuzzing_env_for_invocation(parameter),
                                    _tty_size=(1024, 1024),
                                    _timeout=afl_fuzz_duration, _timeout_signal=timeout_signal_send, _bg=False)
        log_dict[binary_path]["fuzz_debug"]["invocation"] = " ".join(
            [part.decode("utf-8") for part in aflfuzzerprocess.cmd])
        aflfuzzerprocess.wait()
    except sh.ErrorReturnCode as e:
        # if aflerrors["AFL_ALREADY_INSTRUMENTED"] in e.stdout.decode("utf-8"):
        #    print("Binary is already instrumented, trying without QEMU Mode")
        #    fuzzer_args.remove("-Q")
        #    return afl_fuzz_wrapper(fuzzer_args,binary_path,timeout=timeout)
        # elif aflerrors["AFL_NOT_INSTRUMENTED"] in e.stdout.decode("utf-8"):
        #    print("Binary is not instrumented, trying with QEMU Mode")
        #    fuzzer_args.insert(0,"-Q")
        #    return afl_fuzz_wrapper(fuzzer_args,binary_path,timeout=timeout)
        if log_dict:
            if not log_dict.get("fuzzing_fail"):
                log_dict["fuzzing_fail"] = []
            log_dict["fuzzing_fail"].append(binary_path)
            log_dict[binary_path]["fuzz_debug"]["afl_fuzz_stdout"] = e.stdout.decode("utf-8")
            log_dict[binary_path]["fuzz_debug"]["afl_fuzz_stderr"] = e.stderr.decode("utf-8")
            log_dict[binary_path]["fuzz_debug"]["invocation"] = e.full_cmd
        print("afl-fuzz failed for {0}".format(binary_path))
        print("STDOUT:\n", e.stdout.decode("utf-8"))
        print("STDERR:\n", e.stderr.decode("utf-8"))
        print("command line: {0}".format(e.full_cmd))
        logging.error("afl-fuzz failed for {0}".format(binary_path))
        logging.error("Invocation: {0}".format(e.full_cmd))
        logging.error("STDOUT:\n {0}".format(e.stdout.decode("utf-8")))
        logging.error("STDERR:\n {0}".format(e.stderr.decode("utf-8")))
        return False
    except sh.TimeoutException as e:
        print("Fuzzing {0} timed out... ".format(binary_path))
        logging.info("Fuzzing {0} timed out.".format(binary_path))
        return True
    return True


def general_fuzzing_args(qemu: bool, timeout, dict_file=None):
    fuzzer_args = []
    if qemu:
        fuzzer_args += ["-Q"]
    if timeout:
        fuzzer_args += ["-t", timeout]  # +: Skip test cases that take too long.
    if dict_file:
        fuzzer_args += ["-x", dict_file]
    if config_settings.MEM_LIMIT and config_settings.MEM_LIMIT > 0:
        fuzzer_args += ["-m", str(config_settings.MEM_LIMIT)]
    elif config_settings.MEM_LIMIT == 0:
        fuzzer_args += ["-m", "none"]
    return fuzzer_args


def resume_fuzzer(afl_dir: str, binary_path: str, parameter: str, qemu: bool = False, timeout: str = None,
                  dict_file=None, reseed=True, fuzz_duration=None):
    binary_invocation = [shutil.which(binary_path)]
    if not binary_invocation[0]:
        raise FileNotFoundError("Could not resolve path for {0}".format(binary_path))
    if parameter is not None:
        binary_invocation += shlex.split(parameter)
    if reseed:
        aflminimize = sh.Command("afl-minimize")
        aflminimize_commands = ["-j", "1", "-c", "reseed_" + os.path.basename(binary_path) + str(uuid.uuid4())]
        aflminimize_commands += ["--reseed"]
        aflminimize_commands += ["--cmin"]
        aflminimize_commands += ["--cmin-mem-limit=none"]
        if qemu:
            aflminimize_commands += ["--cmin-qemu"]
        if timeout:
            aflminimize_commands += ["--cmin-timeout", str(timeout.replace("+", ""))]  # Remove the + out of timeout
        aflminimize_commands += [afl_dir]
        aflminimize_commands += ["--"] + binary_invocation
        print("Reseeding {0}".format(afl_dir))
        print("afl-minimize {0}".format(" ".join(aflminimize_commands)))
        try:
            aflminimize(aflminimize_commands, _out=sys.stdout, _err=sys.stderr,
                        _env=helpers.utils.get_fuzzing_env_for_invocation(parameter))
        except sh.ErrorReturnCode as e:
            print("Got an exception for afl-minimize")
            print(e.stdout)
            print(e.stderr)
    fuzzer_args = general_fuzzing_args(qemu, timeout, dict_file)
    fuzzer_args += ["-i-", "-o", afl_dir, "--"] + binary_invocation
    print("Resuming afl_fuzz, for", binary_path, "parameter:", parameter, flush=True)
    logging.info("Resuming afl_fuzz for {0} {1}".format(binary_path, parameter))
    return afl_fuzz_wrapper(fuzzer_args=fuzzer_args, binary_path=binary_path, fuzz_duration=fuzz_duration)


def start_fuzzer(input_dir: str, afl_out_dir: str, binary_path: str, parameter: str, qemu: bool = False,
                 timeout: str = None, wrapper_function=afl_fuzz_wrapper, fuzz_duration: int = None, dict_file=None,
                 log_dict=None):
    fuzzer_args = general_fuzzing_args(qemu, timeout, dict_file)
    afl_input_dir = input_dir
    if any(os.path.getsize(os.path.join(input_dir, file)) >= 850 * 1000 for file in os.listdir(input_dir)):
        afl_input_dir = input_dir + "_minimized" + str(uuid.uuid4())
        for file in os.listdir(input_dir):
            if os.path.getsize(
                    os.path.join(input_dir, file)) < 850 * 1000:  # If file is smaller than 850 kb just copy it
                copyfile(os.path.join(input_dir, file), os.path.join(afl_input_dir, file))
            else:  # Reduce the file to 1kb
                helpers.utils.crop_file(os.path.join(input_dir, file), os.path.join(afl_input_dir, file),
                                        1 * 1000)

    fuzzer_args += ["-i", afl_input_dir, "-o", afl_out_dir]
    fuzzer_args += ["--", binary_path]
    if parameter is not None:
        fuzzer_args += parameter.split(" ")  # Remeber to split!

    # fuzzer_args.append("@@")
    print("Starting afl_fuzz, for", binary_path, "parameter:", parameter, "seeds", input_dir, flush=True)
    if wrapper_function is afl_fuzz_wrapper:
        return afl_fuzz_wrapper(fuzzer_args=fuzzer_args, binary_path=binary_path, fuzz_duration=fuzz_duration,
                                log_dict=log_dict)
    else:
        return wrapper_function(fuzzer_args=fuzzer_args, binary_path=binary_path, timeout=None, afl_out_dir=afl_out_dir,
                                fuzz_duration=fuzz_duration)


def prepare_and_start_fuzzer(parameter: str, seeds_dir: str, binary_path: str, package: str,
                             volume_path: str, afl_config_file_name: str, qemu: bool = False, name: str = None,
                             timeout: str = None, wrapper_function=afl_fuzz_wrapper, fuzz_duration: int = None,
                             log_dict=None, file_types=None):
    if file_types is None:
        file_types = []
    print("Now starting the fuzzing", flush=True)
    package_str = ""
    if package:
        package_str = package
    else:
        package_str = os.path.basename(binary_path)
    out_dir = os.path.join(volume_path + "/", os.path.join(package_str, os.path.basename(binary_path)))
    os.makedirs(os.path.join(volume_path + "/", os.path.join(package_str, os.path.basename(binary_path))),
                exist_ok=True)
    afl_config_file_path = os.path.join(volume_path + "/", os.path.join(package_str, afl_config_file_name))
    afl_seeds_dir = seeds_dir
    afl_out_dir = out_dir + "/afl_fuzz_" + str(uuid.uuid4())
    dict_file = None
    seeds_dir_usable = False
    file_types = []
    if os.path.exists(afl_config_file_path):
        with open(afl_config_file_path) as fp:
            input_vector_dict = json.load(fp)
            if input_vector_dict.get("min_seeds_dir"):
                afl_seeds_dir = input_vector_dict.get("min_seeds_dir")
                for file in os.listdir(afl_seeds_dir):
                    if os.path.getsize(os.path.join(afl_seeds_dir, file)) > 0:
                        seeds_dir_usable = True
                if not seeds_dir_usable:
                    print("The given seeds dir for {0}:{1} seems unusable".format(package, binary_path))
                    return
            if not seeds_dir_usable:  # As a fallback option, just use the filetype
                return
                # afl_seeds_dir = input_vector_dict.get("file_type")
                os.makedirs("mockseeds", exist_ok=True)
                with open("mockseeds/mockseed", "w") as fp:
                    fp.write("0")
                afl_seeds_dir = "mockseeds"

            if input_vector_dict.get("file_types"):
                # file_type_dir = input_vector_dict.get("file_types")
                file_types = input_vector_dict.get(
                    "file_types")  # os.path.basename(file_type_dir).split("_")[0] # Format is: seeds//jpg_samples

            # if input_vector_dict.get("min_seeds_dir"):
            #    afl_seeds_dir = input_vector_dict.get("min_seeds_dir")
            # else:
            #    afl_seeds_dir = input_vector_dict["seeds_dir"]
            input_vector_dict["fuzzer_started"] = True
            input_vector_dict["status"] = config_settings.Status.FUZZING
            input_vector_dict["afl_out_dir"] = afl_out_dir

    else:
        input_vector = CliConfig(invocation=parameter, filetypes=seeds_dir, binary_path=binary_path)
        input_vector_dict = input_vector.__dict__
        input_vector_dict["afl_out_dir"] = afl_out_dir
        input_vector_dict["package"] = package
        afl_seeds_dir = seeds_dir
        if name:
            input_vector_dict["name"] = name
        input_vector_dict["fuzzer_started"] = True
        input_vector_dict["status"] = config_settings.Status.FUZZING
    binary_path = binary_path
    with open(afl_config_file_path, "w") as jsonfp:
        json.dump(input_vector_dict, jsonfp)
    if os.path.exists(
            os.path.join("/fuzz_dictionaries/dictionaries/", os.path.basename(afl_seeds_dir).split("_")[0] + ".dict")):
        dict_file = os.path.join("/fuzz_dictionaries/dictionaries/",
                                 os.path.basename(afl_seeds_dir).split("_")[0] + ".dict")
    for file_type in file_types:
        if file_type and os.path.exists(
                os.path.join("/fuzz_dictionaries/dictionaries/", os.path.basename(file_type).split("_")[0] + ".dict")):
            dict_file = os.path.join("/fuzz_dictionaries/dictionaries/",
                                     os.path.basename(file_type).split("_")[0] + ".dict")
            break
    res = start_fuzzer(input_dir=afl_seeds_dir, afl_out_dir=afl_out_dir, binary_path=binary_path, parameter=parameter,
                       qemu=qemu, timeout=timeout, wrapper_function=wrapper_function,
                       fuzz_duration=fuzz_duration, dict_file=dict_file, log_dict=log_dict)
    if res == False and not log_dict:
        sys.exit(-1)
    elif res == False and log_dict:
        return False
    else:
        # with open(os.path.join(volume_path + "/", package + "/" + afl_config_file_name), "w") as jsonfp:
        #    json.dump(input_vector_dict, jsonfp)
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=False, type=str,
                        help="The package to be examined. Must be a pacman package.")
    parser.add_argument("-t", "--timeout", required=False, type=str,
                        help="The timeout for afl (the whole fuzzer process)",
                        default=None)  # Default timeout: None ( take the one from config)
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-param", "--parameter", required=False, type=str,
                        help="The parameter to the json file. Use = to pass hyphens(-)",
                        default=None)  # Must exists in docker
    parser.add_argument("-s", "--seeds", required=True, type=str, help="Which seeds do we need?")
    parser.add_argument("-b", "--binary", required=True, type=str, help="Path to the binary to fuzz.")
    parser.add_argument("-v", "--output_volume", required=True, help="In which should the files be stored?")
    parser.add_argument("-n", "--name", required=False, help="The name of the docker container", default=None)
    parser.add_argument("-l", "--logfile", required=False, help="The logfile path", default=None)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-adir", "--afl_resume_dir", help="Resume from afl out dir.")
    group.add_argument("-afile", "--afl_out_file", type=str,
                       help="Start over. Where should the afl configuration be stored?")
    # Either fuzz projects or binaries
    signal.signal(signal.SIGTERM, signal_term_handler)
    arguments = parser.parse_args()
    parameter = None
    if arguments.parameter:
        if arguments.parameter[0] == '"' and arguments.parameter[-1] == '"':  # Make sure param is not enclosed by " "
            parameter = arguments.parameter[1:-1]
        else:
            parameter = arguments.parameter
    if arguments.package:
        from builders import builder

        b = builder.Builder(package=arguments.package, qemu=arguments.qemu)
        if not b.install():
            print("Could not install package, exiting")
        with_qemu = b.qemu
        logfilename = os.path.join(os.path.join(arguments.output_volume, arguments.package),
                                   os.path.basename(arguments.binary) + ".fuzzlog")
    else:
        logfilename = os.path.join(
            os.path.join(arguments.output_volume, os.path.basename(arguments.binary) + ".fuzzlog"))
        with_qemu = arguments.qemu
    if arguments.logfile:
        logfilename = arguments.logfile
    logging.basicConfig(filename=logfilename, level=logging.INFO, format='%(levelname)s %(asctime)s: %(message)s')

    config = CliConfig(invocation=parameter, filetype=arguments.seeds, binary_path=arguments.binary)
    chmod = sh.Command("chmod")
    chmod("-R", "0777", arguments.output_volume)  # Hacky fix for the problem that docker stores every as root
    try:
        if arguments.afl_out_file:
            res = prepare_and_start_fuzzer(parameter=parameter, seeds_dir=arguments.seeds, binary_path=arguments.binary,
                                           package=arguments.package, volume_path=arguments.output_volume,
                                           afl_config_file_name=arguments.afl_out_file, qemu=with_qemu,
                                           name=arguments.name, timeout=arguments.timeout)
            if not res:
                sys.exit(-1)
        else:
            res = resume_fuzzer(afl_dir=arguments.afl_resume_dir, binary_path=arguments.binary, parameter=parameter,
                                qemu=with_qemu, timeout=arguments.timeout)
            if not res:
                sys.exit(-1)
    except KeyboardInterrupt:
        signal_term_handler(1, 1)
    chmod = sh.Command("chmod")
    chmod("-R", "0777", arguments.output_volume)  # Hacky fix for the problem that docker stores every as root
