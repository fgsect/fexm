import datetime
import json
import logging
import pathlib
import socket
import subprocess
import time
import typing
import uuid

import shlex
from functools import wraps
from logging.handlers import RotatingFileHandler
from threading import Thread
from typing import *

import enum
import os
import re
import requests
import sh
from shutil import copyfile
from websockify import LibProxyServer

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import configfinder.config_settings
from pwd import getpwnam
from helpers import constants
import helpers

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

LOG_FORMAT = '%(asctime)-15s %(message)s'
LOG_MAX_SIZE = 1024 * 1024

fexm_path = os.path.dirname(
    os.path.dirname(os.path.abspath(helpers.__file__)))  # type: str # Gets the absolute path to fexm.


def init_logger(name: str, use_celery: bool = False,
                log_path: str = os.path.join(fexm_path, "logs")) -> logging.Logger:
    """
    Initializes a logger
    """
    formatter = logging.Formatter(LOG_FORMAT)
    if use_celery:
        from celery.utils.log import get_task_logger
        logger = get_task_logger(__name__)
    else:
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        logger.addHandler(console_handler)

    if log_path:
        os.makedirs(log_path, exist_ok=True)
        fh = RotatingFileHandler(os.path.join(log_path, name + ".error"), maxBytes=LOG_MAX_SIZE)
        fh.setLevel(logging.ERROR)
        fh.setFormatter(formatter)

        info_fh = RotatingFileHandler(os.path.join(log_path, name + ".log"), maxBytes=LOG_MAX_SIZE)
        info_fh.setLevel(logging.DEBUG)
        info_fh.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(info_fh)
    return logger


def get_afl_stats_from_syncdir(sync_dir: str):
    from afl_utils import afl_stats
    stats = afl_stats.load_stats(sync_dir, summary=False)
    sum_stats = afl_stats.summarize_stats(stats)
    return sum_stats


def get_inference_env_for_invocation(invocation):
    """
    Get the appropriate environment for invocation inference,
    based on the testing invocation
    :param invocation:
    :return:
    """
    if "@@" in invocation:
        return configfinder.config_settings.get_inference_env_without_desock()
    else:
        return configfinder.config_settings.get_inference_env_with_desock()


def get_fuzzing_env_for_invocation(invocation):
    """
    Get the appropriate environment for fuzzing
    based on the testing invocation
    :param invocation:
    :return:
    """
    if "@@" in invocation:
        return configfinder.config_settings.get_fuzzing_env_without_desock()
    else:
        return configfinder.config_settings.get_fuzzing_env_with_desock()


def crop_file(infile: str, outfile: str, remaining_bytes: int):
    if os.path.getsize(infile) <= remaining_bytes:
        copyfile(infile, outfile)
    else:
        with open(os.path.join(infile), "rb") as fp:
            remaining_data = fp.read()[:remaining_bytes]
        with open(os.path.join(outfile), "wb") as fp:
            fp.write(remaining_data)


def make_combined_seeds_dir(seed_directories: typing.List[str], new_seeds_directory: str):
    """
    Take a bunch of seed directories and make a new directory,
    containing the cropped seeds of all directories
    :param seed_directories:
    :return:
    """
    os.makedirs(new_seeds_directory, exist_ok=True)
    for seed_directory in seed_directories:
        for file in os.listdir(seed_directory):
            full_file_path = os.path.join(seed_directory, file)
            if os.path.isdir(full_file_path):
                continue
            crop_file(full_file_path, os.path.join(new_seeds_directory, file), 850)
    return new_seeds_directory


# !/usr/bin/env python
import sys
import os
import hashlib


def chunk_reader(fobj, chunk_size=1024):
    """Generator that reads a file in chunks of bytes"""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def get_hash(filename: str, first_chunk_only: bool = False, hash: Callable = hashlib.sha1) -> str:
    """"
    hashes a file
    """
    hashobj = hash()
    file_object = open(filename, 'rb')

    if first_chunk_only:
        hashobj.update(file_object.read(1024))
    else:
        for chunk in chunk_reader(file_object):
            hashobj.update(chunk)
    hashed = hashobj.digest()

    file_object.close()
    return hashed


def filter_out_duplicates(files_full_path: Iterable[str]):
    hashes_by_size = {}
    hashes_on_1k = {}
    hashes_full = {}

    for full_path in files_full_path:
        if os.path.isdir(full_path):
            continue
        try:
            file_size = os.path.getsize(full_path)
        except (OSError,) as e:
            # not accessible (permissions, etc) - pass on
            print("Error: {0}".format(e))
            continue

        duplicate = hashes_by_size.get(file_size)

        if duplicate:
            hashes_by_size[file_size].append(full_path)
        else:
            hashes_by_size[file_size] = []  # create the list for this file size
            hashes_by_size[file_size].append(full_path)

    # For all files with the same file size, get their hash on the 1st 1024 bytes
    unique_files = []
    for __, files in hashes_by_size.items():
        if len(files) < 2:
            unique_files.append(files[0])
            continue  # this file size is unique, no need to spend cpy cycles on it

        for filename in files:
            small_hash = get_hash(filename, first_chunk_only=True)

            duplicate = hashes_on_1k.get(small_hash)
            if duplicate:
                hashes_on_1k[small_hash].append(filename)
            else:
                hashes_on_1k[small_hash] = []  # create the list for this 1k hash
                hashes_on_1k[small_hash].append(filename)

    # For all files with the hash on the 1st 1024 bytes, get their hash on the full file - collisions will be duplicate

    for __, files in hashes_on_1k.items():
        if len(files) < 2:
            continue  # this hash of fist 1k file bytes is unique, no need to spend cpy cycles on it

        for filename in files:
            full_hash = get_hash(filename, first_chunk_only=False)

            duplicate = hashes_full.get(full_hash)
            if duplicate:
                print("Duplicate found: %s and %s" % (filename, duplicate))
            else:
                hashes_full[full_hash] = filename
                unique_files.append(filename)
    return unique_files


def showmap_inference_possible(binary_path: str, qemu: bool = False, log_dict=None):
    aflshowmap = sh.Command("afl-showmap")
    tmp_out = os.path.join("/tmp", str(uuid.uuid4())[:8])
    showmap_args = ["-t", str(1000), "-m", "none", "-o", tmp_out, "--", binary_path]
    if qemu:
        showmap_args.insert(0, "-Q")
    try:
        showmap_process = aflshowmap(showmap_args,
                                     _in="y\n" + chr(4),
                                     _env=configfinder.config_settings.get_fuzzing_env_with_desock(),
                                     _ok_code=[0, 1])  # Returncode 1: Timeout and non instrumented
    except sh.ErrorReturnCode as e:
        return False
    try:
        with open(tmp_out) as fp:
            if fp.read():  # We caught some tuples, probably timeout - nothing to worry about!
                return True
    except FileNotFoundError:
        if log_dict:
            if not log_dict.get(binary_path):
                log_dict[binary_path] = {}
            log_dict[binary_path]["fuzzable_debug"] = {}
            log_dict[binary_path]["is_fuzzable"] = False
            log_dict[binary_path]["fuzzable_debug"]["afl-showmap_invocation"] = showmap_process.cmd
            log_dict[binary_path]["fuzzable_debug"]["afl-showmap_stdout"] = showmap_process.stdout.decode("utf-8")
            log_dict[binary_path]["fuzzable_debug"]["afl-showmap_stdout"] = showmap_process.stderr.decode("utf-8")
    return False


def binary_is_instrumented_with_afl(binary_path: str) -> bool:
    """
    This should be the same check afl-showmap is performing.
    Looks or constants.SHM_ENV_VAR in the binary.
    Retruns true if instrumented.
    """
    with open(str(pathlib.Path(binary_path).resolve()), "rb") as fp:
        if constants.SHM_ENV_VAR.encode("utf-8") in fp.read():
            return True
        else:
            return False


def binary_uses_asan(binary_path: str) -> bool:
    """
    Returns true if compiled with asan (== contains ASAN_LIBRARY_STRING)
    """
    with open(str(pathlib.Path(binary_path).resolve()), "rb") as fp:
        if constants.ASAN_LIBRARY_STRING.encode("utf-8") in fp.read():
            return True
        else:
            return False


def inference_possible(binary_path: str, log_dict=None) -> bool:
    """
    Call the binary to see if any inference at all is possible?
    :param binary_path:
    :param log_dict:
    :return: True if inference is possible, False if not
    """
    if binary_is_instrumented_with_afl(binary_path):
        if not showmap_inference_possible(binary_path, qemu=False, log_dict=log_dict):
            # In this case, something weird is going on - The binary is instrumented but no inference possible?
            return False
        else:
            return True  # Binary is instrumented + inference possible
    else:  # No instrumentation
        return showmap_inference_possible(binary_path, qemu=True, log_dict=log_dict)


def qemu_required_for_binary(binary_path: str) -> bool:
    """
    Returns true if not instrumented
    """
    return not binary_is_instrumented_with_afl(binary_path)


def count_number_of_tuples_per_binary(path: str) -> int:
    objdump = sh.Command("objdump")
    output = objdump(["-d", path]).stdout.decode("utf-8")
    number_of_tuples = len([line for line in output.split("\n") if "afl_area_ptr" in line])
    return number_of_tuples


def get_libs_for_elf_binary(path: str) -> [str]:
    """
    For a given elf binary, returns a list of used libraries.
    :param path: The path the elf binary
    :return: A list of strings, each string is one library used by the elf binary.
    """
    command = "ldd"
    try:
        output = subprocess.check_output([command, path]).decode("utf-8")
    except subprocess.CalledProcessError as e:
        if e.stdout:
            logger.info("Could not execute {0}: {1}".format(path, e.stdout.decode("utf-8").strip()))
        else:
            logger.info("Could not execute {} - ret: {}".format(path, e.returncode))
        print(e)
        return [""]
    return output.split("\n\t")


def filter_out_gui_libs_from_libraries(libs: [str]) -> [str]:
    # Save the list of gui libaries as a list of regexes
    # Taken from here:
    # https://github.com/fffaraz/awesome-cpp#gui
    gui_libs = [
        "libgtk.*",
        "libQt([0-9])Gui.*",
        "CEGUI.*",
        "FLTK.*",
        "GacUI.*",
        "GTK+.*",
        "gtkmm.*",
        "imgui.*",
        "libRocket.*",
        "MyGUI.*",
        "nana.*",
        "QCustomPlot.*",
        "Qwt.*",
        "QwtPlot3D.*",
        "PDCurses.*",
        "Sciter.*",
        "wxWidgets.*",
    ]

    # Make a regex that matches if any of our regexes match.
    # TODO: Note: 	This method doesn't work if there are more than 100 regexes in the array (Python 2.6). Try nosklo's answer below
    # See: https://stackoverflow.com/questions/3040716/python-elegant-way-to-check-if-at-least-one-regex-in-list-matches-a-string
    combined = "(" + ")|(".join(gui_libs) + ")"
    remaining_elfs = list(filter(lambda l: not re.match(combined, l), libs))
    return remaining_elfs


def is_gui_elf(path: str) -> bool:
    """
    Checks if the given elf is a gui.
    :param path: The path to the elf.
    :return: True, if elf is gui, False if not 
    """
    libs = get_libs_for_elf_binary(path)
    filtered_libs = filter_out_gui_libs_from_libraries(libs)
    if len(libs) > len(filtered_libs):
        return True
    else:
        return False


def get_filename_from_binary_path(binary_path: str):
    import pathlib
    p = pathlib.Path(binary_path)
    return p.parts[-2] + "_" + os.path.basename(binary_path)


def store_input_vectors_in_volume(package: str, binary: str, volume_path: str, input_vectors):
    if not os.path.exists(volume_path + "/" + package):
        os.mkdir(volume_path + "/" + package)
    with open(volume_path + "/" + package + "/" + get_filename_from_binary_path(binary) + ".json", "w") as jsonfp:
        print("Writing to {0}".format(volume_path))
        json.dump(list(map(lambda x: x.__dict__, input_vectors)), jsonfp)


def is_fuzzable_binary(path: str) -> bool:
    """
    Checks if binary is fuzzable. A fuzzable binary is an
    elf binary that does not link a gui library.
    :param path: Path to the binary.
    :return: Whether the binary is fuzzable.
    """
    real_binary_path = os.path.realpath(path)  # Resolve all symbolic links
    file_command = sh.Command("file")
    file_command_output = file_command(real_binary_path).split(":")
    print(file_command_output)
    if len(file_command_output) < 2:  # Something went wrong (apparently, file also outputs something weird like '...'
        return False
    if "ELF" in file_command_output[1]:
        if is_gui_elf(real_binary_path):
            return False
        try:
            sh.Command(path)(_timeout=3)  # Try the command without any parameters.
            return True
        except sh.SignalException as e:  # Program crashes
            return False
        except sh.TimeoutException as e:
            return False
        except sh.ErrorReturnCode as e:  # Ignore
            return True
    else:
        return False


def get_afl_metadata(afl_dir_path) -> {}:
    fuzzer_stats_dict = {}
    try:
        with open(afl_dir_path + "/fuzzer_stats") as package_info_filepointer:
            text = package_info_filepointer.read()
            tmp_list = [item.strip().split(":", 1) for item in text.split("\n")]
            for item in tmp_list:
                if len(item) == 2:
                    fuzzer_stats_dict[item[0].strip()] = item[1].strip()
        return fuzzer_stats_dict
    except FileNotFoundError:
        return None


def is_executable_binary(binary_path: str) -> bool:
    """
    Uses readelf to determine if program is library or not
    :param binary_path:
    :return: True if executable binary, false otherwise
    """
    binary_command = sh.Command(binary_path)
    try:
        binary_command(_timeout=2)
    except sh.SignalException as e:  # Weird, probably library
        return False
    except sh.TimeoutException as e:
        return True
    except sh.ErrorReturnCode as e:  # Can happen!
        return True
    return True

    # TODO: This code is incorrect! In fact, what we are trying to do here might be impossible
    readelf = sh.Command("readelf")
    readelf_output = readelf(["-h", binary_path])
    type_lines = [line for line in readelf_output.split("\n") if "TYPE" in line.upper()]
    print(readelf_output.split("\n"))
    if len(type_lines) != 1:
        print("ERROR: No type for binary {0}".format(binary_path))
        logger.error("ERROR: No type for binary {0}".format(binary_path))
        return False
    type_line = type_lines[0]
    if "EXECUTABLE" in type_line:
        return True
    else:
        return False


def is_elf_binary(path):
    with open(path, "rb") as fp:
        if b"\x7fELF" == fp.read(4):
            return True
        else:
            return False


def extract_elf_binaries_from_directory(directory: str):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            real_path = os.path.realpath(os.path.join(dirpath, f))

            if not os.path.isdir(real_path) and os.path.exists(real_path) and is_elf_binary(
                    real_path):  # Resolve symlink with os.path.exists
                yield real_path


def extract_elf_binaries_using_file(directory: str):
    h = list(absoluteFilePaths(directory))
    from sh import file
    file_command_output = file(h)
    result_list = []
    lines = file_command_output.split("\n")
    for line in lines:
        line_split = line.split(":")
        if len(line_split) < 2:
            continue
        binary_desc = line_split[1]
        if "ELF" in binary_desc:
            result_list.append(line_split[0])
    return result_list


def return_fuzzable_binaries_from_file_list(file_list: [str], log_dict=None) -> [str]:
    real_paths = [os.path.realpath(f) for f in file_list if os.path.exists(f) and not os.path.isdir(f)]
    elf_files = [f for f in real_paths if is_elf_binary(f)]
    unique_binary_paths = filter_out_duplicates(set(elf_files))
    from helpers.elf_deduplicator import ElfDeDuplicator
    unique_binaries = ElfDeDuplicator.deduplicate_binaries(unique_binary_paths)
    result_list = []
    if not log_dict:
        log_dict = {}
    log_dict["elf_files"] = []
    log_dict["executable_elf_files"] = []
    log_dict["fuzzable_bins"] = []
    for elf in unique_binaries:
        if log_dict:
            log_dict["elf_files"].append(elf)
        chmod = sh.Command("chmod")
        try:
            chmod(["+x", elf])
        except sh.ErrorReturnCode as e:
            logger.error(
                "Setting {0} as executable did not work. Exception: {1}".format(elf, e))
        if log_dict:
            if not log_dict.get(elf):
                log_dict[elf] = {}
        if is_gui_elf(elf):
            log_dict[elf]["is_gui_elf"] = True
            continue
        else:
            log_dict[elf]["is_gui_elf"] = False
        if is_executable_binary(elf):
            # assert isinstance(log_dict, object)
            if log_dict:
                log_dict[elf]["is_executable_elf"] = True
                log_dict["executable_elf_files"].append(elf)
        else:
            if log_dict:
                log_dict[elf]["is_executable_elf"] = False
            continue
        if inference_possible(binary_path=elf, log_dict=log_dict):
            if binary_is_instrumented_with_afl(elf):
                log_dict["fuzzable_bins"].append(elf)
                log_dict[elf]["number_of_tuples"] = count_number_of_tuples_per_binary(
                    elf)
            else:
                log_dict["fuzzable_bins"].append(elf)
            result_list.append(elf)
        else:
            logger.info("Skipping binary {0}, inference is not possible.".format(elf))
    return result_list

    # unique_real_paths = filter_out_duplicates(set(real_binary_paths))
    # print(unique_real_paths)
    # file_command = sh.Command("file")
    # file_command_output = file_command(unique_real_paths)
    # count = -1
    # result_list = []
    # if not log_dict:
    #    log_dict = {}
    # log_dict["elf_files"] = []
    # log_dict["executable_elf_files"] = []
    # log_dict["fuzzable_bins"] = []
    # lines = file_command_output.split("\n")
    elf_binaries = []
    # for line in lines:
    #    line_split = line.split(":")
    #    if len(line_split) < 2:
    #        continue
    #    binary_desc = line_split[1]
    #    if "ELF" in binary_desc:

    # for line in lines:
    #    count += 1
    #    line_split = line.split(":")
    #    if len(line_split) < 2:
    #        continue
    #    binary_desc = line_split[1]#

    #    if "ELF" in binary_desc:
    #        if log_dict:
    #            log_dict["elf_files"].append(unique_real_paths[count])
    #        chmod = sh.Command("chmod")
    #        try:
    #            chmod(["+x", unique_real_paths[count]])
    #        except sh.ErrorReturnCode as e:
    #            logging.error(
    #                "Setting {0} as executable did not work. Exception: {1}".format(unique_real_paths[count], e))
    #        if log_dict:
    #            if not log_dict.get(unique_real_paths[count]):
    #                log_dict[unique_real_paths[count]] = {}
    #        if is_gui_elf(unique_real_paths[count]):
    #            log_dict[unique_real_paths[count]]["is_gui_elf"] = True
    #            continue
    #       else:
    #           log_dict[unique_real_paths[count]]["is_gui_elf"] = False
    #       if is_executable_binary(unique_real_paths[count]):
    #           # assert isinstance(log_dict, object)
    #           if log_dict:
    #               log_dict[unique_real_paths[count]]["is_executable_elf"] = True
    #              log_dict["executable_elf_files"].append(unique_real_paths[count])
    #        else:
    #            if log_dict:
    #                log_dict[unique_real_paths[count]]["is_executable_elf"] = False
    #            continue
    #        if inference_possible(binary_path=unique_real_paths[count], log_dict=log_dict):
    #            if binary_is_instrumented_with_afl(unique_real_paths[count]):
    #                log_dict["fuzzable_bins"].append(unique_real_paths[count])
    #                log_dict[unique_real_paths[count]]["number_of_tuples"] = count_number_of_tuples_per_binary(
    #                    unique_real_paths[count])
    #            else:
    #                log_dict["fuzzable_bins"].append(unique_real_paths[count])
    #            result_list.append(unique_real_paths[count])
    #        else:
    #            logging.info("Skipping binary {0}, inference is not possible.".format(unique_real_paths[count]))
    # return result_list


class AutoToolsProjectType(enum.Enum):
    MAKEFILE = 1,
    CONFIGURE = 2


def query_yes_no(question, default=None):
    """Ask a yes/no question via raw_input() and return their answer.
    :param question a string that is presented to the user 
    :param default is the presumed answer if user just hits <Enter>
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    :return The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while True:
        print(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with 'yes' or 'no' "
                  "(or 'y' or 'n').\n")
    return False


def check_output_with_timeout_command(process: str, args: [str], timeout: float = 0.5, test_stdin=False,
                                      dummyfile_path=None, **kwargs) -> (str, bool):
    """
    This function runs a process with a timeout and returns the output.
    It uses unix tools (timeout) instead of check_output with the timeout parameter,
    as a fix for the problem that the timeout parameter does not work for some programs, e.g. strace
    and because neither the solution proposed here:
    https://stackoverflow.com/questions/36952245/subprocess-timeout-failure
    nor  here:
    https://stackoverflow.com/questions/44335403/subprocess-popen-get-output-even-in-case-of-timeout
    seem to be capable of dealing with every case. This is not the ideal solution,
    but the best solution I could come up with so far.
    :param process: The path to the process.
    :param args: arguments to the process.
    :param timeout: The maximum running time.
    :param test_stdin: If true, dummyfile is redirected to stdin
    :param dummyfile_path: Input is redirected to stdin
    :return: A tuple: (output, timeout?).
    """
    timed_out = False
    exec_list = []
    if timeout:
        exec_list.append("timeout")  # Start the process using the timeout programm
        exec_list.append(str(timeout))  # With the timeout parameter
    exec_list.append(process)
    exec_list += args
    try:
        # Also use the timeout argument because the timeout process (linux) sometimes failes!
        if test_stdin:
            with open(dummyfile_path, "r") as dummyfile_fd:
                output = subprocess.check_output(exec_list, stderr=subprocess.STDOUT, stdin=dummyfile_fd, **kwargs)
        else:
            output = subprocess.check_output(exec_list, stderr=subprocess.STDOUT, **kwargs)
    except subprocess.CalledProcessError as e:
        output = e.output
        if e.returncode == 124:
            timed_out = True
    except subprocess.TimeoutExpired as e:
        output = e.output
        timed_out = True
    output = output.decode("utf-8", errors="ignore")
    return output, timed_out


def temp_print(*args):
    """
    Print a line such that it will be eaten up by the next line printed.
    """
    CURSOR_UP = '\033[F'
    ERASE_LINE = '\033[K'
    print(*args)
    sys.stdout.write(CURSOR_UP)
    sys.stdout.write(ERASE_LINE)


def get_seeds_dir_from_input_vector_dict(conf_dict, package="", binary_path=""):
    seeds = None
    if conf_dict.get("coverage") == 0 or (not conf_dict.get("file_type")):
        if conf_dict.get("file_types"):
            seeds = ";".join(conf_dict.get("file_types"))
            return seeds
        if conf_dict.get("best_chebyshev_tuple"):
            if len(conf_dict.get("best_chebyshev_tuple")) > 0:
                print("For {0}:{1} there is no file_type defined! Taking chebyshev tuple instead".format(package,
                                                                                                         binary_path))
                seeds = "seeds/" + conf_dict.get("best_chebyshev_tuple")[0] + "_samples"
                return seeds
        else:
            print("For {0}:{1} there is no file_type defined!".format(package, binary_path))
            return None
    elif conf_dict.get("file_type"):
        seeds = conf_dict.get("file_type")
        return seeds
    elif conf_dict.get("file_types"):
        seeds = conf_dict.get("file_types")
        return seeds
    else:
        print("For {0}:{1} there is no file_type defined!".format(package, binary_path))
        return None
    if not seeds:
        print("No seeds for {0}:{1}!".format(package, binary_path))
        return None
    return seeds


def absoluteFilePaths(directory):
    for dirpath, _, filenames in os.walk(directory):
        for f in filenames:
            yield os.path.abspath(os.path.join(dirpath, f))


def is_valid_seeds_folder(path: str):
    """
    Determines if the given directory is a valid seeds folder
    :param path: The path to the seeds
    :return: True if valid, False if no
    """
    if not os.path.exists(path) or not os.path.isdir(path):
        raise NotADirectoryError("{0} must be a directory".format(path))
    for entity in os.listdir(path):
        if entity == ".git":  # Ignore .git directory
            continue
        if os.path.isdir(os.path.join(path, entity)):
            for file in os.listdir(os.path.join(path, entity)):
                if os.path.isdir(os.path.join(path, entity, file)):
                    print("Not valid: {0}".format(os.path.join(path, entity, file)))
                    return False
    return True


def temp_print(*args):
    """
    Print a line such that it will be eaten up by the next line printed.
    """
    CURSOR_UP = '\033[F'
    ERASE_LINE = '\033[K'
    print(*args)
    sys.stdout.write(CURSOR_UP)
    sys.stdout.write(ERASE_LINE)


def md5(fname):
    """
    Calculate the md5 hash of the file.
    :param fname: The path to the file.
    :return: The md5 name.
    """
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_unique_legal_name(name: str, directory: str) -> str:
    """
    Get a filename that is unique in the given folder.
    Will also strip out illegal chars.
    :param name: the desired filename
    :param directory: the directory to look for the name
    :return: the given name or a name with appended numeric counter if exists
    """
    name = re.sub(r'[\\/*?:"<>|]', "_", name)
    new_name = name
    counter = 0

    path = os.path.join(directory, new_name)
    while os.path.exists(path):
        counter += 1
        new_name = "{}.".format(counter).join(name.rsplit(".", 1))
        if new_name == name:
            new_name = "{}{}".format(name, counter)

        path = os.path.join(directory, new_name)

    return new_name


def download_file(directory: str, url: str) -> str:
    """
    Downloads a file.
    If you want unique files in a folder, use download_seed_to_folder instead.
    :param url: the url to download
    :param directory: the directory to download it to
    :return: the filename, taken from the url. The file will be renamed if a file of this name already existed
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError("{} is not a folder.".format(directory))

    filename = url.split('/')[-1]
    filename = get_unique_legal_name(filename, directory)
    path = os.path.join(directory, filename)

    logger.info("Download of {}({}) started".format(filename, url))

    r = requests.get(url, stream=True)

    with open(path, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)

    logger.info("Finished download of {}.".format(filename))
    return filename


def download_seed_to_folder(download_link: str, to_directory: str, filename: str) -> bool:
    """
    Download the the file from download_link to the given folder.
    Will not store it if a file with the given hash already exists.
    :param download_link: The download link to the file.
    :param to_directory: The directorry to download the file to.
    :param filename: The name the file should be downlaoded to.
    :return: True if downloaded, False if not.
    """
    r = requests.get(download_link, stream=True)
    hash_md5 = hashlib.md5()
    file_content = b""
    for chunk in r.iter_content(chunk_size=1024):
        if chunk:  # filter out keep-alive new chunks
            file_content += chunk
            hash_md5.update(chunk)
    md5_hash = hash_md5.hexdigest()
    for file in os.listdir(to_directory):
        file_hash = md5(to_directory + "/" + file)
        if file_hash == md5_hash:
            print("Not downloading {0}: Seed already in dataset".format(filename))
            return False
    print("Downloading {0}".format(filename))
    with open(to_directory + "/" + filename, "wb") as file:
        file.write(file_content)
    return True


def download_seed_to_folder_with_maximum(download_link: str, to_directory: str, filename: str, max: int):
    """
    Download the the file from download_link to the folder,
    but only if the folder does not contain a file that has the same hash.
    Also checks if the folder already contains enough files
    (and if so, does not download the file).
    :param download_link: The download link to the file.
    :param to_directory: The directorry to download the file to.
    :param filename: The name the file should be downlaoded to.
    :return: True if downloaded, False if not.
    """
    number_of_files_of_so_far = len(
        [name for name in os.listdir(to_directory) if os.path.isfile(to_directory + os.sep + name)])
    if number_of_files_of_so_far < max:
        return download_seed_to_folder(download_link=download_link, to_directory=to_directory, filename=filename)
    return False


def get_utc_now() -> datetime.datetime:
    """
    This function does the exact same thing as datetime.datetime.utcnow().
    But by putting this into a separate file, the method can easily be mocked
    and our code is more testable.
    See: https://stackoverflow.com/questions/43799206/python-how-do-i-mock-datetime-utcnow
    :return: datetime.datetime.utcnow()
    """
    return datetime.datetime.utcnow()


def wait_for_rate_limit(reset_at: str):
    """
    This function waits for the ratelimit for the ratelimit to be reset.
    :param reset_at: The date (but as a string) when our RateLimit is going to be reset.
    """
    # 2017 - 10 - 18T02:00:00Z
    reset_at_date = datetime.datetime.strptime(reset_at, "%Y-%m-%dT%H:%M:%SZ")
    now_date = get_utc_now()
    diff = reset_at_date - now_date
    diff_seconds = diff.total_seconds()
    if diff_seconds > 0:
        print("Waiting", diff_seconds / float(60), "minutes for GitHub rate-limit")
        time.sleep(int(diff_seconds))


def set_euid_to_sudo_parent_user():
    """
    Set the effective uid to either the current user
    or the user that invoked the sudo command in case we are root.
    """
    parent_user = os.environ['SUDO_USER'] if 'SUDO_USER' in os.environ else os.environ['USER']
    parent_user_id = getpwnam(parent_user).pw_uid
    parent_group_id = getpwnam(parent_user).pw_gid
    os.setegid(parent_group_id)
    os.seteuid(parent_user_id)


# noinspection PyDefaultArgument
def find_free_port(startport: int, endport: int, already_allocated: Optional[Set[int]] = set()) -> int:
    """
    Finds a free port between two port numbers by trying them all out.
    This should be good enough since ports are usually reserved for a process for a while.
    :param startport:  the start port to try
    :param endport:  the end port (exclusive) to try
    :param already_allocated: a set of already allocated ports (optional)
    :return: a free port number
    :raises ValueError if no free port in the given range was found.
    """
    for port in range(startport, endport):
        if port in already_allocated:
            continue
        try:
            s = socket.socket()
            s.bind(("0.0.0.0", port))
            s.listen(1)
            s.close()
            return port
        except OSError as ex:
            logger.debug("Port {} was already taken.".format(port))
    raise ValueError(
        "No open port between startport {} and endport {}(excl) could be found!".format(startport, endport))


def forward_port_to_websocket(port: int, ws_port: int, host: str = "localhost", ws_listen: str = "0.0.0.0",
                              run_once: bool = True) -> Thread:
    """
    Forwards a port to a websocket
    :param port: the port
    :param ws_port: the websocket port
    :param host: the host to forward from
    :param ws_listen: what to listen on
    :param run_once: close after first forward? (defaults to true)
    This function returns the started thread.
    """
    stdio_server = LibProxyServer(target_host=host, target_port=port,
                                  listen_host=ws_listen, listen_port=ws_port,
                                  run_once=run_once)
    t = Thread(name="ws_forward_{}:{}".format(port, ws_port), target=stdio_server.serve_forever, daemon=True)
    # stdio_server.serve_forever()
    t.start()
    return t


def snakeify(camel_case):
    """
    Make snake from caMel
    https://stackoverflow.com/questions/1175208/elegant-python-function-to-convert-camelcase-to-snake-case
    :param camel_case:
    :return: snake_cased version of the given camelCase string.
    """
    s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camel_case)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()


def snakeify_params(func: Callable[[Any], Any]) -> Callable[[Any], Any]:
    """
    Wrapper function to do snakeify every param.
    :return:
    """

    @wraps(func)
    def decorator(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **{snakeify(k): v for k, v in kwargs})

    return decorator()


def run_celery(command: str) -> None:
    """
    Runs a command in celery.
    :param command: The command to run, including args
    """
    from celery_tasks.tasks import app as celery_app
    celery_app.worker_main(argv=shlex.split(command))
