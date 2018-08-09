import json
import sys

import os
import pandas as pd
import requests


def read_file_to_dict(file_path: str):
    with open(file_path) as fp:
        return json.load(fp)


def main(eval_dir: str, out_csv: str):
    # resultdf = pd.DataFrame(columns=["package","description","version","url","binary_path","qemu","parameter","filetype","deviation_score","chebyshev_score","deviationparameter","deviationfiletype","chebychevparameter","chebychevfiletype","right parameter","right filetype","correct?"])
    resultdf = pd.DataFrame(columns=["package", "binary_path", "parameter", "filetype", "description", "url"])
    row_count = 0
    for package in os.listdir(eval_dir):
        packagedir = os.path.join(eval_dir, package)
        if not os.path.isdir(packagedir):
            continue
        jsonfiles = [os.path.join(packagedir, file) for file in os.listdir(packagedir) if file.endswith(".json")]
        if not jsonfiles:
            continue

        package_info_dict = requests.get(
            "https://www.archlinux.org/packages/search/json/?name={0}".format(package)).json()
        package_name = package_info_dict["results"][0]["pkgname"]
        package_desc = package_info_dict["results"][0]["pkgdesc"]
        package_version = package_info_dict["results"][0]["pkgver"]
        package_url = package_info_dict["results"][0]["url"]
        for jsonfile in jsonfiles:
            with open(jsonfile) as binary_inference_fp:
                inference_list = json.load(binary_inference_fp)
            best_coverage_dict = inference_list[0]
            print("Processing {0}".format(jsonfile))
            binary_path = best_coverage_dict["binary_path"]
            parameter = best_coverage_dict["parameter"]
            filetype = best_coverage_dict["file_type"]
            max_coverage = best_coverage_dict["max_coverage"]
            qemu = best_coverage_dict["qemu"]
            best_deviation_dict = None
            best_chebyshev_dict = None
            if max_coverage == 0:
                if best_coverage_dict.get("best_chebyshev_tuple"):
                    if len(best_coverage_dict.get("best_chebyshev_tuple")) > 0:
                        filetype = "seeds/" + best_coverage_dict.get("best_chebyshev_tuple")[0] + "_samples"
                        max_coverage = best_coverage_dict.get("best_chebyshev_tuple")[0]
                    else:
                        resultdf.loc[row_count] = [package_name, binary_path, "failed", "failed", "failed", "failed",
                                                   "failed", "failed", "", "", "", "", ""]
                        row_count += 1
                        print("failed")
                        continue

            resultdf.loc[row_count] = [package_name, binary_path, parameter, filetype, package_desc, package_url]
            row_count += 1
    resultdf.to_csv(out_csv)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
