import sys
import time

import os
import scipy as sp


def get_afl_metadata(afl_dir_path) -> {}:
    fuzzer_stats_dict = {}
    try:
        # print(afl_dir_path+"/fuzzer_stats")
        with open(afl_dir_path + "/fuzzer_stats") as package_info_filepointer:
            text = package_info_filepointer.read()
            tmp_list = [item.strip().split(":", 1) for item in text.split("\n")]
            for item in tmp_list:
                # print(tmp_list)
                if len(item) == 2:
                    fuzzer_stats_dict[item[0].strip()] = item[1].strip()
        # print(fuzzer_stats_dict)
        return fuzzer_stats_dict
    except FileNotFoundError:
        return None


def main(afl_out_dir: str):
    measurements = []
    execs_done = []
    try:
        while True:
            time.sleep(5)  # sleep five seconds
            if os.path.exists(afl_out_dir):
                afl_dict = get_afl_metadata(afl_out_dir)
                measurements.append(float(afl_dict["execs_per_sec"]))
                execs_done.append(int(afl_dict["execs_done"]))
                print("Measured", measurements[-1])
    except KeyboardInterrupt:
        print("Measurements:")
        print(measurements)
        print("Average exec/s")
        print(sp.mean(measurements))
        print("Execs Done:", execs_done)


if __name__ == "__main__":
    main(sys.argv[1])
