import argparse

import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from evalscripts.evalscript import run


def main(package, configuration_dir, binary_name, timeout):
    run(package, os.path.join(os.getcwd(), configuration_dir + "/" + package + "test"), binary_name,
        timeout=timeout, qemu=True, minimize=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be an apt package.")
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str, help="Where to store the results?")
    parser.add_argument("-t", "--timeout", required=False, type=float, default=30 * 60, help="Maximum fuzzing timeout?")
    parser.add_argument("-b", "--binary_path", required=True, type=str,
                        help="The name of ther binary.")
    # Either fuzz projects or binaries
    arguments = parser.parse_args()
    main(arguments.package, arguments.configuration_dir, arguments.binary_path, timeout=arguments.timeout)
