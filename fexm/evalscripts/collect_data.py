import pathlib

import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import pandas as pd
import sys
import json
from fuzz_manager.fuzztask import TaskStatus
from helpers.utils import get_afl_metadata
from typing import Dict


def main(collect_dir: str):
    # plot_df = pd.DataFrame([], columns=["Package", "Binary", "Total Execs", "Exec/s","paths_total","paths_favored","qemu","cycles_done","pending_favs"])
    # plot_bucket_dict = {}
    plot_dict = {"package": [], "binary": []}
    for package_dir in os.listdir(collect_dir):
        if not os.path.isdir(os.path.join(collect_dir, package_dir)):
            continue
        for file in os.listdir(os.path.join(collect_dir, package_dir)):
            if file.endswith(".afl_config"):
                file_full_path = os.path.join(collect_dir, package_dir, file)
                afl_out_dir = None
                with open(file_full_path) as afl_config_fp:
                    afl_dict = json.load(afl_config_fp)
                    print(afl_dict.get("file_type"))
                    if afl_dict.get("status"):
                        if TaskStatus(afl_dict.get("status")) == TaskStatus.STARTED_FUZZING:
                            seeds_dir_usable = False
                            seeds = afl_dict.get("min_seeds_dir")
                            p = pathlib.Path(seeds)
                            local_seeds_dir = os.path.join(collect_dir, str(p.relative_to(*p.parts[:2])))
                            if not local_seeds_dir:
                                for file in os.listdir(local_seeds_dir):
                                    if os.path.getsize(os.path.join(local_seeds_dir, file)) > 0:
                                        seeds_dir_usable = True
                            if not seeds_dir_usable:
                                print("Zero seeds dir for {0}".format(package_dir, afl_dict.get("binary_path")))
                                continue
                                # print("The given seeds dir for {0}:{1} seems unusable".format(package_dir, afl_dict.get("binary_path")))
                                # print(
                                #    "The seeds dir is empty: This strongly suggests that the command line invocation does not lead to file processing.")
                                # print("Please check the invocation for {0}:{1}".format(package_dir, afl_dict.get("binary_path")))
                        else:
                            afl_out_dir = afl_dict.get("afl_out_dir")

                    else:
                        afl_out_dir = afl_dict.get("afl_out_dir")

                if afl_out_dir is None:  # Skip
                    continue
                out_dir_path = pathlib.Path(afl_out_dir)
                out_dir_path = str(out_dir_path.relative_to(*out_dir_path.parts[:2]))
                afl_out_path = os.path.join(collect_dir, out_dir_path)
                metadata_dict = get_afl_metadata(afl_out_path)  # type: Dict[str,str]
                if metadata_dict is None:
                    continue
                plot_dict["package"].append(package_dir)
                plot_dict["binary"].append(afl_dict.get("binary_path"))
                for k, v in metadata_dict.items():
                    if plot_dict.get(k):
                        plot_dict[k].append(v)
                    else:
                        plot_dict[k] = [v]
        plot_df = pd.DataFrame.from_dict(plot_dict)
        plot_df.to_csv("collected.csv")


if __name__ == "__main__":
    main(sys.argv[1])
