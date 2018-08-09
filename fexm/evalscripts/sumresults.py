import argparse
import json

import os
import pandas as pd
import shutil

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import sh
import re


def get_coverage_from_afl_cmin_ouput(afl_cmin_output: str) -> int:
    """
    Extract the number of tuples covered from the afl-cmin output. 
    :param afl_cmin_output: A string that is the terminal output of afl-cmin
    :return: The number of tuples covered, 0 if unable to extract from output.
    """
    if isinstance(afl_cmin_output, str):
        afl_cmin_output_lines = afl_cmin_output.split("\n")  # type: [str]
    elif isinstance(afl_cmin_output, list) and all(isinstance(s, str) for s in afl_cmin_output):
        afl_cmin_output_lines = afl_cmin_output  # We assume the output has already been split
    else:
        raise TypeError("The afl-cmin ouptut must be given as a string or as a list of strings.")
    tuples_found_re = "\[\+\] Found (\d*) unique tuples across (.*) files."
    matcher = re.compile(tuples_found_re)
    for line in afl_cmin_output_lines:
        result = matcher.match(line)
        if result:
            return int(result.groups(0)[0])  # We need the first group
    return 0


def create_eval_table_for_run(queuedirectories: str, package: str, binary_path: str, eval_dir: str, rundir: str,
                              qemu=False, parameter=None):
    table_dict = {}
    table_dict["timestamp"] = []
    runevalpath = os.path.join(eval_dir, os.path.join(rundir, package))
    table_dict[runevalpath] = []
    for qdir in os.listdir(queuedirectories):
        qdirfullpath = os.path.join(queuedirectories, qdir)
        print(os.path.abspath(qdirfullpath))
        afl_cmin = sh.Command("afl_cmin_cov_only")
        cminargs = ["-i", qdirfullpath, "-m", "none", "--", binary_path]
        if parameter:
            cminargs.append(parameter)
        cminargs.append("@@")
        if qemu:
            cminargs.insert(0, "-Q")
        cminqueue = afl_cmin(cminargs)
        print(cminqueue.stdout.decode("utf-8"))
        cov = get_coverage_from_afl_cmin_ouput(cminqueue.stdout.decode("utf-8"))
        tstamp = int(qdir.replace("queue", ""))
        table_dict["timestamp"].append(tstamp)
        table_dict[runevalpath].append(cov)
    cov_table_df = pd.DataFrame.from_dict(table_dict)
    cov_table_df.sort_values(by=["timestamp"])
    cov_table_df.to_csv(os.path.join(os.path.join(eval_dir, rundir + "_covtable.csv")))
    shutil.rmtree(queuedirectories)


def create_eval_table_for_dir(eval_dir: str, package: str, binary_name: str, qemu=False, parameter=None):
    for rundir in os.listdir(eval_dir):
        table_dict = {}
        table_dict["timestamp"] = []
        runevalpath = os.path.join(eval_dir, os.path.join(rundir, package))
        table_dict[runevalpath] = []
        if os.path.isdir(runevalpath):
            with open(runevalpath + "/" + binary_name + ".afl_config") as fp:
                json_dict = json.load(fp)
                afl_out_dir = os.path.basename(json_dict["afl_out_dir"])
                binary_path = json_dict["binary_path"]
                queuedirectories = os.path.join(runevalpath, binary_name, "eval_data", afl_out_dir)
            create_eval_table_for_run(queuedirectories, package, binary_path, eval_dir=os.path.join(eval_dir, rundir),
                                      rundir=rundir, qemu=qemu, parameter=parameter)
            # for qdir in os.listdir(runevalpath + "/" + binary_name + "/eval_data/" + afl_out_dir):
            #    qdirfullpath = runevalpath + "/" + binary_name + "/eval_data/" + afl_out_dir + "/" + qdir
            #    print(os.path.abspath(qdirfullpath))
            #    afl_cmin = sh.Command("afl_cmin_cov_only")
            #    cminargs = ["-i", qdirfullpath, "-m", "none", "--", binary_path]
            #    if parameter:
            #        cminargs.append(parameter)
            #    cminargs.append("@@")
            #    if qemu:
            #        cminargs.insert(0, "-Q")
            #    cminqueue = afl_cmin(cminargs)
            #    print(cminqueue.stdout.decode("utf-8"))
            #    cov = get_coverage_from_afl_cmin_ouput(cminqueue.stdout.decode("utf-8"))
            #    tstamp = int(qdir.replace("queue", ""))
            #    table_dict["timestamp"].append(tstamp)
            #    table_dict[runevalpath].append(cov)
            # shutil.rmtree(runevalpath + "/" + binary_name + "/eval_data/" + afl_out_dir)
        # cov_table_df = pd.DataFrame.from_dict(table_dict)
        # cov_table_df.sort_values(by=["timestamp"])
        # cov_table_df.to_csv(os.path.join(os.path.join(eval_dir, rundir + "_covtable.csv")))


def main(package: str, eval_dir: str, binary_path: str, build_required, parameter: str):
    if build_required:
        from builders.builder import Builder
        b = Builder(package)
        b.install()
        with_qemu = b.qemu
    else:
        from helpers.utils import qemu_required_for_binary
        with_qemu = qemu_required_for_binary(binary_path)
    for dir in os.listdir(eval_dir):
        if os.path.isdir(os.path.join(eval_dir, dir)):
            create_eval_table_for_dir(os.path.join(eval_dir, dir), package=package, binary_name=binary_path,
                                      parameter=parameter,
                                      qemu=with_qemu)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be an apt package.", default=None)
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str, help="Where to store the results?")
    parser.add_argument("-b", "--binary_path", required=True, type=str,
                        help="The name of ther binary.")
    parser.add_argument("-build", dest="build", action="store_true", default=False,
                        help="Building required.")
    parser.add_argument("-p", "--parameter", required=False, type=str, help="The parameter for binary invocation.")
    arguments = parser.parse_args()
    main(arguments.package, arguments.configuration_dir, arguments.binary_path, arguments.build,
         parameter=arguments.parameter)
