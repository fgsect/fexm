import glob
import json
import pathlib
import sys

import os
import pandas as pd


def read_file_to_dict(file_path: str):
    with open(file_path) as fp:
        return json.load(fp)


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


def get_time_to_first_crash(afl_dir_path, start_time) -> int:
    plot_data = pd.read_csv(afl_dir_path + "/plot_data")
    # print(plot_data.columns.values)
    return int(plot_data[plot_data[" unique_crashes"] > 0].iloc[0]["# unix_time"]) - start_time


def generate_table_for_methoddir(method_dir: str):
    # print(glob.glob(method_dir+"/*.csv"))
    # data_table_dict = {}
    # data_table_dict["time_elapsed"] = [x*5 for x in range(300)]
    method_table = None
    method_crash_table = pd.DataFrame(columns=["firstcrash"])
    for rundir in os.listdir(method_dir):
        if os.path.isdir(os.path.join(method_dir, rundir)):
            afl_config_files = glob.glob(os.path.join(method_dir, rundir) + "/**/*afl_config", recursive=True)
            if afl_config_files:
                afl_dict = read_file_to_dict(afl_config_files[0])
                afl_out_dir = afl_dict["afl_out_dir"]
                p = pathlib.Path(afl_out_dir)
                p = p.relative_to(*p.parts[:2])
                afl_out_dir = os.path.join(os.path.join(method_dir, rundir), str(p))
                afl_metadata = get_afl_metadata(afl_out_dir)
                df = pd.read_csv(os.path.join(method_dir, rundir, "_covtable.csv"), dtype="int64")
                df["timestamp"] = df["timestamp"] - int(afl_metadata["start_time"])
                df = df.drop(df.columns.values[0], 1)
                df = df.rename(index=str, columns={df.columns.values[0]: rundir})
                df = df.sort_values(by=["timestamp"])
                df = df.reset_index(drop=True)
                df = df.drop("timestamp", 1)
                if method_table is None:
                    method_table = df  # .set_index("timestamp")
                else:
                    method_table = pd.merge(method_table, df, left_index=True, right_index=True, how='outer')
                method_crash_table.loc[method_crash_table.shape[0] + 1] = [
                    get_time_to_first_crash(afl_out_dir, int(afl_metadata["start_time"]))]
                # print(data_table_dict.values())
                # print(df)
    normalmax = method_table.max(axis=1, skipna=True)
    cummax = normalmax.cummax()
    normalmin = method_table.min(axis=1, skipna=True)
    method_table["mean"] = method_table.mean(axis=1, skipna=True)
    method_table["low"] = normalmin
    method_table["high"] = cummax
    method_table["timestamp"] = pd.Series([x * 5 for x in range(df.shape[0] + 1)])
    method_table.to_csv(os.path.basename(method_dir) + ".csv")
    method_crash_table.to_csv(os.path.basename(method_dir) + "_timetofirstcrash.csv")


def main(eval_dir: str):
    for methoddir in os.listdir(eval_dir):
        if os.path.isdir(os.path.join(eval_dir, methoddir)):
            generate_table_for_methoddir(os.path.join(eval_dir, methoddir))


if __name__ == "__main__":
    main(sys.argv[1])
