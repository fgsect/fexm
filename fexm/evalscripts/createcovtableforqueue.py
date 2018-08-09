import argparse

import os
import pandas as pd

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


def main(binary_path: str, queuedirectories: str, qemu=False, parameter=None, outfile=None):
    table_dict = {}
    table_dict["timestamp"] = []
    table_dict[os.path.basename(binary_path)] = []
    for qdir in os.listdir(queuedirectories):
        if not qdir:
            return
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
        table_dict[os.path.basename(binary_path)].append(cov)
    cov_table_df = pd.DataFrame.from_dict(table_dict)
    cov_table_df.sort_values(by=["timestamp"])
    cov_table_df.to_csv(outfile)
    # shutil.rmtree(queuedirectories)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-b", "--binary_path", required=True, type=str,
                        help="The name of ther binary.")
    parser.add_argument("-p", "--parameter", required=False, type=str, help="The parameter for binary invocation.")
    parser.add_argument("-q", "--queuedir", required=True, type=str, help="The parameter for binary invocation.")
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-o", "--outfile", required=True, type=str, help="The outfile.")
    arguments = parser.parse_args()
    main(arguments.binary_path, qemu=arguments.qemu, parameter=arguments.parameter, queuedirectories=arguments.queuedir,
         outfile=arguments.outfile)
