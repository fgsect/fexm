import argparse
import json
import sqlite3

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

# Ensure settings are read
from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()

# Your application specific imports
from data.models import *
import pathlib
from ansi2html import Ansi2HTMLConverter
from repo_crawlers.archcrawler import ArchCrawler


def store_in_database(basepath: str, package_info_filepath: str, binary_path: str, parameter: str, crash_dir_path: str,
                      crash_db_path: str, afl_dir_path: str, configuration_dir: str):
    print("Package info for package {0}".format(package_info_filepath))
    package_info_dict = {}
    with open(basepath + "/" + package_info_filepath) as package_info_filepointer:
        text = package_info_filepointer.read()
        tmp_list = [item.strip().split(":", 1) for item in text.split("\n")]
        for item in tmp_list:
            if len(item) == 2:
                package_info_dict[item[0].strip()] = item[1].strip()
    package, created = Package.objects.get_or_create(name=package_info_dict["Name"],
                                                     version=ArchCrawler.get_package_version(
                                                         package_info_dict["Name"]))
    binary, created = Binary.objects.get_or_create(path=binary_path, package=package)
    p = pathlib.Path(afl_dir_path)
    p = p.relative_to(*p.parts[:2])  # type: pathlib.PosixPath
    binary.afl_dir = os.path.abspath(configuration_dir + "/" + str(p))  # First path is the volume path
    # binary.afl_dir= configuration_dir+"/"+afl_dir_path
    binary.save()
    crash_db_full_path = basepath + "/" + crash_db_path
    if not os.path.exists(crash_db_full_path):
        print("Error: The database {0} does not exist".format(crash_db_full_path))
        print(crash_db_path)
        return
    print("Opening database {0}".format(crash_db_full_path))
    connect = sqlite3.connect(basepath + "/" + crash_db_path)
    c = connect.cursor()
    c.execute("select count(*) from sqlite_master where type='table' and name='Data';")
    if c.fetchone()[0] != 1:
        print("Error: The table Data does not exist")
        return
    c.execute("select count(*) from Data;")
    conv = Ansi2HTMLConverter()
    if c.fetchone()[0] > 0:
        print("Crashes for package {0} binary {1}".format(package, binary_path))
        for row in c.execute('SELECT * FROM Data'):
            print(basepath + "/" + crash_dir_path + "/" + row[0])

            if not os.path.exists(basepath + "/" + crash_dir_path + "/" + row[0]):
                continue
            with open(basepath + "/" + crash_dir_path + "/" + row[0], "rb") as crash_filepointer:
                crash_data = crash_filepointer.read()
            try:
                rendered_text = conv.convert(row[5].decode("utf-8"))
            except Exception as e:
                rendered_text = ""
            crash, created = Crash.objects.get_or_create(binary=binary, parameter=parameter, exploitability=row[1],
                                                         file_blob=crash_data, description=row[2],
                                                         execution_output=rendered_text)
            crash.name = row[0]
    else:
        print("No crashes for package {0} binary {1}".format(package, binary_path))


def store_binary_in_databse(binary_path: str, package: str, afl_dir_path, configuration_dir: str):
    p = pathlib.Path(afl_dir_path)
    p = p.relative_to(*p.parts[:2])
    package, created = Package.objects.get_or_create(name=package,
                                                     version=ArchCrawler.get_package_version(
                                                         package))
    binary, created = Binary.objects.get_or_create(path=binary_path, package=package)
    binary.afl_dir = os.path.abspath(os.path.join(configuration_dir, str(p)))
    binary.save()


def main(fuzz_data: str):
    # Add user
    for package_dir in os.listdir(fuzz_data):
        if os.path.isdir(fuzz_data + "/" + package_dir):
            for file in os.listdir(fuzz_data + "/" + package_dir):
                crash_config = {}
                crash_config_found = False
                if file.endswith(".crash_config"):
                    print("Crash config", file)
                    crash_config_found = True
                    with open(fuzz_data + "/" + package_dir + "/" + file) as crash_config_filepointer:
                        crash_config = json.load(crash_config_filepointer)
                        package_info_file = crash_config["package_info"]
                        crash_dir = crash_config["crashes_dir"]
                        crash_db = crash_config["database_file_name"]
                        afl_dir = crash_config["afl_out_dir"]
                        parameter = crash_config["parameter"] if crash_config["parameter"] else ""
                        store_in_database(basepath=fuzz_data + "/" + package_dir,
                                          package_info_filepath=package_info_file,
                                          binary_path=crash_config["binary_path"], parameter=parameter,
                                          crash_dir_path=crash_dir, crash_db_path=crash_db, afl_dir_path=afl_dir,
                                          configuration_dir=fuzz_data)
                        crash_config_found = True
                elif file.endswith(".afl_config") and not crash_config_found:
                    with open(fuzz_data + "/" + package_dir + "/" + file) as afl_config_filepointer:
                        afl_config_dict = json.load(afl_config_filepointer)
                    binary_path = afl_config_dict.get("binary_path")
                    afl_dir_path = afl_config_dict.get("afl_out_dir")
                    if not afl_dir_path:
                        continue
                    store_binary_in_databse(binary_path=binary_path, package=package_dir, afl_dir_path=afl_dir_path,
                                            configuration_dir=fuzz_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the building Process')
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str,
                        help="The directory that contains the configurations")
    arguments = parser.parse_args()
    if not os.path.exists(arguments.configuration_dir) or not os.path.isdir(arguments.configuration_dir):
        raise NotADirectoryError("Configuration Path must be Directory!")
    main(fuzz_data=arguments.configuration_dir)
