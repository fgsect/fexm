import argparse
import json
import threading
import time
from typing import List

import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import sh
from shutil import copyfile
from evalscripts import sumresults
from config_settings import aflerrors
import config_settings
import subprocess
import sys
import signal
import fuzzer_wrapper

newenv = os.environ.copy()
newenv["AFL_SKIP_CPUFREQ"] = "1"
newenv["AFL_EXIT_WHEN_DONE"] = "1"

aflfuzz = sh.Command("afl-fuzz")

global aflfuzzerprocess
global syncqueue


def signal_term_handler(signal, frame):
    global aflfuzzerprocess
    global syncqueue
    if syncqueue:
        syncqueue.alive = False
        syncqueue._stop()
    print('got SIGTERM')
    if aflfuzzerprocess:
        aflfuzzerprocess.kill()
    sys.exit(0)


class SyncQueue(threading.Thread):
    def __init__(self, fuzzer_dir: str, target_dir: str):
        threading.Thread.__init__(self)
        self.fuzzer_dir = fuzzer_dir
        self.queue_dir = os.path.join(self.fuzzer_dir, "queue")
        self.target_dir = target_dir
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir, exist_ok=True)
        self.alive = True

    def run(self):
        while self.alive:
            time.sleep(5)  # sleep five seconds
            copy_to_dir = os.path.join(self.target_dir, "queue" + str(int(time.time())))
            os.mkdir(copy_to_dir)
            src_files = os.listdir(self.queue_dir)
            for file in src_files:
                if os.path.isfile(os.path.join(self.queue_dir, file)):
                    copyfile(os.path.join(self.queue_dir, file), copy_to_dir + "/" + file)

    def _stop(self):
        self.alive = False


def afl_evaluate_fuzz_wrapper(fuzzer_args: List[str], binary_path: str, afl_out_dir: str, timeout: float = None,
                              fuzz_duration: int = None):
    global aflfuzzerprocess
    save_dir = os.path.join(os.path.abspath(os.path.join(afl_out_dir, '..')),
                            os.path.join("eval_data/", os.path.basename(afl_out_dir)))
    global syncqueue
    syncqueue = SyncQueue(afl_out_dir, save_dir)
    try:
        afl_timeout = config_settings.MAX_TIMEOUT_PER_PACKAGE
        if fuzz_duration is not None:
            afl_timeout = fuzz_duration
        syncqueue.start()
        print("afl-fuzz {0} for {1}".format(" ".join(fuzzer_args), afl_timeout))
        aflfuzzerprocess = aflfuzz(fuzzer_args, _env=newenv, _tty_size=(1024, 1024), _timeout=afl_timeout,
                                   _timeout_signal=signal.SIGTERM, _bg=True)
        aflfuzzerprocess.wait()
        syncqueue.alive = False
    except sh.ErrorReturnCode as e:
        syncqueue.alive = False
        if aflerrors["AFL_ALREADY_INSTRUMENTED"] in e.stdout.decode("utf-8"):
            print("Binary is already instrumented, trying without QEMU Mode")
            fuzzer_args.remove("-Q")
            return afl_evaluate_fuzz_wrapper(fuzzer_args, binary_path, afl_out_dir, timeout)
        elif aflerrors["AFL_NOT_INSTRUMENTED"] in e.stdout.decode("utf-8"):
            print("Binary is not instrumented, trying with QEMU Mode")
            fuzzer_args.insert(0, "-Q")
            return afl_evaluate_fuzz_wrapper(fuzzer_args, binary_path, afl_out_dir, timeout)
        print("afl-fuzz failed for {0}".format(binary_path))
        print("STDOUT:\n", e.stdout.decode("utf-8"))
        print("STDERR:\n", e.stderr.decode("utf-8"))
        print("command line: {0}".format(e.full_cmd))
        return False
    except subprocess.CalledProcessError as e:
        syncqueue.alive = False
        print(e.stdout)
        print(e.stderr)
        return False
    except sh.TimeoutException as e:
        syncqueue.alive = False
        print("Fuzzing {0} timed out... ".format(binary_path))
        return True
    return True


def read_afl_config_file_to_dict(file_path: str):
    with open(file_path) as fp:
        return json.load(fp)


def eval_fuzzing(qemu, parameter, seeds, binary, output_volume, afl_out_file, name, timeout, fuzzer_timeout,
                 package=None):
    signal.signal(signal.SIGTERM, signal_term_handler)
    if package:
        from builders import builder
        b = builder.Builder(package=package, qemu=qemu)
        if not b.install():
            print("Could not install package, exiting")
        with_qemu = b.qemu
    else:
        with_qemu = qemu
    try:
        res = fuzzer_wrapper.prepare_and_start_fuzzer(parameter=parameter, seeds_dir=seeds, binary_path=binary,
                                                      package=package, volume_path=output_volume,
                                                      afl_config_file_name=afl_out_file, qemu=with_qemu, name=name,
                                                      wrapper_function=afl_evaluate_fuzz_wrapper, timeout=timeout,
                                                      fuzz_duration=fuzzer_timeout)
        if res == True:
            if not package:
                package = ""
            afl_config_dict = read_afl_config_file_to_dict(os.path.join(output_volume, package, afl_out_file))
            afl_out_dir = afl_config_dict["afl_out_dir"]
            save_dir = os.path.join(os.path.abspath(os.path.join(afl_out_dir, '..')), "eval_data/",
                                    os.path.basename(afl_out_dir))
            sumresults.create_eval_table_for_run(save_dir, package=package, binary_path=binary, eval_dir=output_volume,
                                                 rundir="", qemu=with_qemu, parameter=afl_config_dict["parameter"])
    except KeyboardInterrupt:
        signal_term_handler(1, 1)
    chmod = sh.Command("chmod")
    chmod("-R", "0777", output_volume)  # Hacky fix for the problem that docker stores everything as root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=False, type=str,
                        help="The package to be examined. Must be a pacman package.", default=None)
    parser.add_argument("-ft", "--fuzzer_timeout", required=False, type=float,
                        help="The timeout for afl (the whole fuzzer process)",
                        default=None)  # Default timeout: None ( take the one from config)
    parser.add_argument("-t", "--timeout", required=False, type=float,
                        help="The timeout for afl (per run)",
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
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-afile", "--afl_out_file", type=str,
                       help="Start over. Where should the afl configuration be stored?")
    # Either fuzz projects or binaries
    arguments = parser.parse_args()
    eval_fuzzing(package=arguments.package, qemu=arguments.qemu, parameter=arguments.parameter, seeds=arguments.seeds,
                 binary=arguments.binary, output_volume=arguments.output_volume,
                 afl_out_file=arguments.afl_out_file, name=arguments.name, timeout=arguments.timeout,
                 fuzzer_timeout=arguments.fuzzer_timeout)
