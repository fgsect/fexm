#!/usr/bin/env python3
"""
Analyzes the crashes for a package.
"""
import argparse
import glob
import json
import shlex
import sqlite3

import os
import sh

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from builders import builder
import helpers.utils
import typing


class BinaryAnalyzer:
    def __init__(self, binary_path: str, parameter: str, afl_dir: str, volume: str, database_path: str,
                 collection_dir: str, conf: typing.Dict[str, object],
                 package: str = None):
        if package:
            self.package = package
        else:
            self.package = "UserDefinedBinary"
        self.binary_path = binary_path
        self.parameter = parameter
        self.afl_dir = afl_dir
        self.volume = volume
        self.database_path = database_path
        self.collection_dir = collection_dir
        self.uses_asan = helpers.utils.binary_uses_asan(self.binary_path)
        self.logger = helpers.utils.init_logger(os.path.join(self.collection_dir, self.package, self.binary_path))
        if self.uses_asan:
            self.logger.info("Using asan for {0}".format(self.binary_path))
        self.conf_dict = conf

    def collect_for_binary(self):

        afl_collect = sh.Command("afl-collect")
        command_args = []
        if self.uses_asan:
            command_args.append("-a")
        command_args += ["-e", "gdb_script", "-d", self.database_path,
                         "-r", self.afl_dir, self.collection_dir,
                         "--", self.binary_path]
        if self.parameter:
            command_args += shlex.split(self.parameter)

        self.logger.debug("afl-collect " + " ".join(command_args))
        self.logger.debug("Environment: {0}".format(helpers.utils.get_inference_env_for_invocation(self.parameter)))
        self.logger.info("Collecting results for {0}/{1}".format(self.package, self.binary_path))
        self.logger.debug(helpers.utils.get_inference_env_for_invocation(self.parameter))
        try:
            process = afl_collect(command_args, _env=helpers.utils.get_inference_env_for_invocation(
                self.parameter))  # type: sh.Command # TODO: Set LD_PRELOAD correctly
            self.logger.debug(process.__dict__)
        except sh.ErrorReturnCode as e:
            self.logger.error("afl-collect error:")
            self.logger.error(e.stdout.decode("utf-8"))
            self.logger.error(e.stderr.decode("utf-8"))
            raise e
        self.create_logs()

    def write_crash_config(self):
        crashes_config = {}
        crashes_config.update(self.conf_dict)
        crashes_config["database_file_name"] = os.path.basename(self.database_path)
        crashes_config["crashes_dir"] = os.path.basename(self.collection_dir)
        crashes_config["package_info"] = self.package + "_info.txt"
        crashes_config_file_path = os.path.join(self.volume, self.package,
                                                helpers.utils.get_filename_from_binary_path(
                                                    binary_path=self.binary_path) + ".crash_config")
        self.logger.debug("Writing crash config file {0}".format(crashes_config_file_path))
        self.logger.debug("Writing database to {0}".format(os.path.join(self.volume, self.package, self.database_path)))
        with open(crashes_config_file_path, "w") as crash_config_filepointer:
            json.dump(crashes_config, crash_config_filepointer)

    def create_logs(self):
        connect = sqlite3.connect(self.database_path)
        c = connect.cursor()
        table_name = "Data"
        # Retrieve column information
        # Every column will be represented by a tuple with the following attributes:
        # (id, name, type, notnull, default_value, primary_key)
        c.execute('PRAGMA TABLE_INFO({})'.format(table_name))

        # collect names in a list
        names = [str(tup[1]).upper() for tup in c.fetchall()]

        if not helpers.utils.constants.CRASH_EXECUTE_LOG_COLUMN.upper() in names:
            c.execute(
                "ALTER TABLE Data ADD {column} BLOB".format(column=helpers.utils.constants.CRASH_EXECUTE_LOG_COLUMN))
        results = c.execute("select * From Data WHERE {column} is null".format(
            column=helpers.utils.constants.CRASH_EXECUTE_LOG_COLUMN))
        for r in results:
            sample_file = r[0]
            stdin = False
            if "@@" not in self.parameter:
                stdin = True
            crash_file_path = os.path.join(self.collection_dir, sample_file)
            if not os.path.exists(crash_file_path):
                self.logger.error("Eror: {} does not exist".format(crash_file_path))
                continue
            binary_command = sh.Command(self.binary_path)
            try:
                if not stdin:
                    binary_command(shlex.split(self.parameter.replace("@@", crash_file_path)), _err_to_out=True,
                                   _env=helpers.utils.get_inference_env_for_invocation(self.parameter))
                else:
                    binary_command(shlex.split(self.parameter), _in=crash_file_path, _err_to_out=True,
                                   _env=helpers.utils.get_inference_env_for_invocation(self.parameter))
            except sh.ErrorReturnCode as e:
                output = e.stdout
                connect.execute("UPDATE Data SET {column}=? where Sample=?".format(
                    column=helpers.utils.constants.CRASH_EXECUTE_LOG_COLUMN
                ), (output, sample_file))
                connect.commit()
        connect.close()


class PackageAnalyzer:
    def __init__(self, package: str, volume: str):
        self.package = package
        self.volume = volume
        self.write_info_file()

    def write_info_file(self):
        from sh import pacman
        info = pacman("-Si", self.package)
        info_string = str(info)  # # .decode("utf-8")
        with open(os.path.join(self.volume, self.package, self.package + "_info.txt"), "w") as fp:
            fp.write(info_string)

    def collect_package(self):
        afl_config_files = glob.glob(os.path.join(self.volume, self.package) + "/*.afl_config")
        conf = {}
        for afl_config_file in afl_config_files:
            afl_config_file_path = os.path.join(self.volume, self.package, str(afl_config_file))
            with open(afl_config_file_path) as afl_config_filepointer:
                try:
                    conf.update(json.load(afl_config_filepointer))
                except ValueError:
                    print('Decoding JSON has failed {0}'.format(afl_config_file))
                    continue
                binary_path = conf.get("binary_path")
                if binary_path is None:
                    print("No binary_path for", afl_config_file)
                    continue
                if not conf.get("afl_out_dir"):
                    print("No afl_out_dir for {0}".format(binary_path))
                    continue
                database_file_name = helpers.utils.get_filename_from_binary_path(binary_path) + ".db"
                crashes_dir = helpers.utils.get_filename_from_binary_path(binary_path) + "_crashes_dir"
                b_analyzer = BinaryAnalyzer(binary_path=binary_path, parameter=conf["parameter"],
                                            afl_dir=conf["afl_out_dir"], volume=self.volume,
                                            database_path=os.path.join(self.volume, self.package, database_file_name),
                                            collection_dir=os.path.join(self.volume, self.package, crashes_dir),
                                            conf=conf, package=self.package)
                b_analyzer.collect_for_binary()
                b_analyzer.write_crash_config()


def main():
    parser = argparse.ArgumentParser(description='Examine a package or a binary.')
    subparsers = parser.add_subparsers(help="sub-command help", dest="command")
    subparsers.required = True
    # Common arguments for both:
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be a pacman package.")
    parser.add_argument("-t", "--timeout", required=False, type=float, help="The timeout for afl",
                        default=2000)  # Default timeout: 2 hours
    parser.add_argument("-Q", dest="qemu", action="store_true", default=False,
                        help="Activate qemu mode when inferring file types.")
    parser.add_argument("-v", "--output_volume", required=True, help="In which volume should the files be stored?")
    parser_binary = subparsers.add_parser("binary", help="Examine a binary.")  # type:argparse.ArgumentParser
    parser_package = subparsers.add_parser("package", help="Examine a package")
    parser_binary.add_argument("-param", "--parameter", required=False, type=str,
                               help="The parameter to the json file. Use = to pass hyphens(-)",
                               default=None)  # Must exists in docker
    parser_binary.add_argument("-a", "--afl_dir", required=True, type=str,
                               help="Afl dir, where the seeds should be collected from")
    parser_binary.add_argument("-b", "--binary", required=False, type=str, help="Path to the binary to fuzz.",
                               default=None)
    parser_binary.add_argument("-d", "--database", required=True, help="Where should the database be stored?")
    parser_binary.add_argument("-c", "--collection_dir", required=True, help="Where should the crashes be stored?")
    arguments = parser.parse_args()
    fuzz_data = arguments.output_volume
    package = arguments.package
    print("Globbing {0}".format(os.path.join(fuzz_data, package) + "/*.json"))
    # print(os.listdir(os.path.join(fuzz_data)))
    # print(os.listdir(os.path.join(fuzz_data, package)))
    json_fuzzer_files = glob.glob(os.path.join(fuzz_data, package) + "/*.json")
    print(json_fuzzer_files)
    with open(json_fuzzer_files[0]) as fp:
        json_dict = json.load(fp)
    qemu = json_dict[0]["qemu"]
    b = builder.Builder(package=package, qemu=qemu, overwrite=False)
    if qemu:
        b.install()
    else:
        if not os.path.exists(json_dict[0]["binary_path"]):
            b = builder.Builder(package=package, qemu=qemu)
            b.try_build()
        else:
            b.install_deps()
            b.install_opt_depends_for_pacman()
    package_analyzer = PackageAnalyzer(package=package,
                                       volume=fuzz_data)  # collect_package(package_dir=package, volume=fuzz_data)
    package_analyzer.collect_package()
    return True


if __name__ == "__main__":
    main()
