import json
import sys

import requests


def get_json_for_package(package: str):
    package_info_dict = requests.get(
        "https://www.archlinux.org/packages/search/json/?name={0}".format(package.lower())).json()
    if len(package_info_dict["results"]) < 1:
        #    print("Too too few results for packakge {0}".format(package))
        #   input("Continue (Else strg+c)?")
        return None
    return package_info_dict["results"][0]


def main(list_path: str):
    with open(list_path) as fp:
        package_list = [x.strip() for x in fp.readlines()]
    package_info_list = []
    for package in package_list:
        print("Processing package {0}".format(package))
        package_json = get_json_for_package(package)
        if package_json is not None:
            package_info_list.append(package_json)
    with open("package_info.json", "w") as fp:
        json.dump(package_info_list, fp)


if __name__ == "__main__":
    main(sys.argv[1])
