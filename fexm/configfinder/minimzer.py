#!/usr/bin/env python3
"""
Use this tool to minimize seeds for a given binary.
"""
import os
import shutil

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import sh
import uuid
from cli_config import CliConfig
import json
import config_settings
from shutil import copyfile
import signal
import sys
from config_settings import aflerrors
import helpers.utils
from sh import afl_tmin, afl_cmin


def dump_into_json(input_vector: CliConfig, min_seeds_dir: str, package: str, name: str, volume_path: str,
                   afl_config_file_name: str):
    input_vector_dict = input_vector.__dict__
    input_vector_dict["min_seeds_dir"] = min_seeds_dir
    input_vector_dict["package"] = package
    input_vector_dict["fuzzer_started"] = False
    input_vector_dict["status"] = config_settings.Status.MINIMIZE_DONE
    if name:
        input_vector_dict["name"] = name
    with open(os.path.join(volume_path, os.path.join(package, afl_config_file_name)), "w") as jsonfp:
        json.dump(input_vector_dict, jsonfp)


def minize(parameter: str, seeds_dir: str, binary_path: str, package: str, volume_path: str, afl_config_file_name: str,
           qemu: bool = False, name: str = None, tmin_total_time: int = None, do_tmin: bool = True,
           cores: int = 1) -> bool:
    # if package:
    #    b = builder.Builder(package=package, qemu=qemu)
    #    if not b.install():
    #        print("Could not install package, exiting")
    if not package:
        package = os.path.basename(binary_path)
    input_vector = CliConfig(invocation=parameter, filetypes=seeds_dir.split(";"), binary_path=binary_path)
    out_dir = volume_path + "/" + package + "/" + os.path.basename(input_vector.binary_path)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    min_seeds_dir = os.path.join(out_dir, "minseeds_" + str(uuid.uuid4()))
    file_list = []
    print(seeds_dir)
    for filetype_seeds in seeds_dir.split(";"):
        for file in os.listdir(filetype_seeds):
            file_path = os.path.join(filetype_seeds, file)
            if os.path.isfile(file_path):
                file_list.append(file_path)
            else:
                print("Ignored non-file at {}".format(file_path))

    os.makedirs(min_seeds_dir, exist_ok=True)
    for file in file_list:
        if os.path.getsize(file) < 850 * 1000:  # If file is smaller than 850 kb just copy it
            copyfile(file, os.path.join(min_seeds_dir, os.path.basename(file)))
        else:  # Reduce the file to 1kb
            helpers.utils.crop_file(file, os.path.join(min_seeds_dir, os.path.basename(file)), 1 * 1000)
    dump_into_json(input_vector=input_vector, min_seeds_dir=min_seeds_dir, package=package, name=name,
                   volume_path=volume_path, afl_config_file_name=afl_config_file_name)
    use_qemu = helpers.utils.qemu_required_for_binary(
        input_vector.binary_path)  # TODO: There seems to be an issue here
    # First: Minimize the seeds
    cmin_dir = os.path.join(out_dir, "afl_cmin_" + str(uuid.uuid4()))
    cmin_params = []
    if use_qemu:
        cmin_params.append("-Q")
    cmin_params += ["-I", "-i", min_seeds_dir, "-o", cmin_dir, "-m", "none", "-t",
                    str(config_settings.AFL_CMIN_INVOKE_TIMEOUT * 1000), "--", input_vector.binary_path]
    if input_vector.parameter:
        cmin_params += input_vector.parameter.split(" ")
    print("Calling afl-cmin {0}".format(" ".join(cmin_params)), flush=True)
    try:
        afl_cmin(cmin_params, _timeout=config_settings.AFL_CMIN_TIMEOUT,
                 _env=helpers.utils.get_fuzzing_env_for_invocation(parameter), _out=sys.stdout, _error=sys.stderr)
        print("afl cmin done", flush=True)
    except sh.ErrorReturnCode as e:
        print("afl cmin failed for {0}".format(input_vector.binary_path))
        print("STDOUT:\n", e.stdout.decode("utf-8"))
        print("STDERR:\n", e.stderr.decode("utf-8"))
        sys.exit(-1)
    except sh.TimeoutException as e:
        print("afl cmin timed out for {0}".format(input_vector.binary_path))
        # print("STDOUT:\n", e.stdout.decode("utf-8"))
        # print("STDERR:\n", e.stderr.decode("utf-8"))
        for f in os.listdir(min_seeds_dir):
            shutil.copyfile(os.path.join(min_seeds_dir, f), os.path.join(cmin_dir, f))
    dump_into_json(input_vector=input_vector, min_seeds_dir=cmin_dir, package=package, name=name,
                   volume_path=volume_path, afl_config_file_name=afl_config_file_name)
    shutil.rmtree(min_seeds_dir)  # We do not want to store the minimized seeds again
    if not do_tmin:
        return True
    tmin_dir = out_dir + "/afl_tmin_" + str(uuid.uuid4())
    os.makedirs(tmin_dir, exist_ok=True)
    for iter_num, file in enumerate(os.listdir(cmin_dir)):
        tmin_params = []
        if use_qemu:
            tmin_params.append("-Q")
        if os.path.isdir(os.path.join(cmin_dir, file)):  # Maybe .traces is still in there or so?
            continue
        tmin_params += ["-t", str(config_settings.AFL_TMIN_INVOKE_TIMEOUT * 1000), "-i", cmin_dir + "/" + file, "-o",
                        tmin_dir + "/" + file, "-m", "none", "--",
                        input_vector.binary_path]
        if input_vector.parameter:
            tmin_params += input_vector.parameter.split(" ")
        if iter_num == 0:
            print("Minimizing seed file size", flush=True)
        print("Calling afl-tmin {0}".format(" ".join(tmin_params)), flush=True)
        if tmin_total_time:
            afl_tmin_timeout_per_file = tmin_total_time / len(os.listdir(cmin_dir))  # Divide time per file
        else:
            afl_tmin_timeout_per_file = config_settings.AFL_TMIN_TIMEOUT / len(
                os.listdir(cmin_dir))  # Divide time per file
        try:
            helpers.utils.temp_print("Calling afl-tmin {0}".format(" ".join(tmin_params)))
            afl_tmin(tmin_params, _out=sys.stdout,
                     _timeout=afl_tmin_timeout_per_file,
                     _timeout_signal=signal.SIGTERM,
                     _env=config_settings.get_fuzzing_env_without_desock())  # AFL tmin can be very slow. We should only use a limited amount of time on it. If we send SIGTERM though, the current progress is saved
        except sh.ErrorReturnCode as e:
            print("afl tmin failed for {0}".format(input_vector.binary_path))
            print("STDOUT:\n", e.stdout.decode("utf-8"))
            print("STDERR:\n", e.stderr.decode("utf-8"))
            if aflerrors["AFL_TIMEOUT"] in e.stderr.decode("utf-8"):
                print("afl-tmin timed out for {0}. Going to use current progress or raw file".format(package))
                if not os.path.exists(os.path.join(tmin_dir, file)):
                    copyfile(os.path.join(cmin_dir, file), os.path.join(tmin_dir, file))
            else:
                sys.exit(-1)
        except sh.TimeoutException as e:
            # print("STDOUT:\n", e.stdout.decode("utf-8"))
            # print("STDERR:\n", e.stderr.decode("utf-8"))
            print("afl-tmin timed out for {0}. Going to use current progress or raw file".format(package))
            if not os.path.exists(os.path.join(tmin_dir, file)):
                copyfile(os.path.join(cmin_dir, file), os.path.join(tmin_dir, file))
                # seeds_dir = cmin_dir
    dump_into_json(input_vector=input_vector, min_seeds_dir=tmin_dir, package=package, name=name,
                   volume_path=volume_path, afl_config_file_name=afl_config_file_name)
    return True
