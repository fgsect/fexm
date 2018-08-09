import json
import sys

import matplotlib.pyplot as plt
import os
import pandas as pd
import requests


def read_file_to_dict(file_path: str):
    with open(file_path) as fp:
        return json.load(fp)


"""
def main(build_csv: str):
    build_df = pd.read_csv(build_csv)
    size_list = []
    for index,row in build_df.iterrows():
        print(row)
        package = row["Package"]
        package_info_dict = requests.get("https://www.archlinux.org/packages/search/json/?name={0}".format(package.lower())).json()
        package_size = package_info_dict["results"][0]["installed_size"]
        size_list.append(package_size)
    build_df = build_df.assign(Size=pd.Series(size_list).values)
    cols = build_df.columns.tolist()
    cols = cols[:3] + cols[4:5] #+ cols[3:4]
    build_df = build_df[cols]
    build_df["Size"] = build_df["Size"]/1e+6
    build_df["Build Time (in S)"] = build_df["Build Time (in S)"]/60.0
    print(build_df.to_latex(na_rep="",bold_rows=True,index=False))
    build_df.plot.scatter(x='Size',y="Build Time (in S)")
    plt.show()
    print(build_df.corr())
    print(build_df.size)
"""


def main(build_dir: str):
    build_dict_table = {"package": [], "qemu": [], "time": [], "size": [], "color": []}
    qemu_dict = {"package": [], "qemu": [], "time": [], "size": [], "color": []}
    qemuCount = 0
    overall = 0
    for file in (os.listdir(build_dir)):
        if not file.endswith(".build"):
            continue
        package = ".".join(file.split(".")[:-1])
        print("Processing package {0}".format(package))
        package_info_dict = requests.get(
            "https://www.archlinux.org/packages/search/json/?name={0}".format(package.lower())).json()
        package_size = package_info_dict["results"][0]["installed_size"]
        build_dict = read_file_to_dict(os.path.join(build_dir, file))
        qemu = build_dict["qemu"]
        time = build_dict["time"]
        # if package_size>
        if package_size > 500000:
            continue
        if qemu:
            qemuCount += 1
            qemu_dict["package"].append(package)
            qemu_dict["size"].append(package_size)
            qemu_dict["qemu"].append(qemu)
            qemu_dict["color"].append("r")
            qemu_dict["time"].append(time)
        else:
            build_dict_table["package"].append(package)
            build_dict_table["size"].append(package_size)
            build_dict_table["qemu"].append(qemu)
            build_dict_table["color"].append("b")
            build_dict_table["time"].append(time)
        overall += 1
    fig, ax = plt.subplots()

    # qemu_df = pd.DataFrame.from_dict(qemu_dict)
    ax.scatter(x=qemu_dict["size"], y=qemu_dict["time"], marker="x", color="r", label="QEMU required", alpha=0.3,
               edgecolors='none')
    ax.scatter(x=build_dict_table["size"], y=build_dict_table["time"], marker="o", color="b",
               label="Compile time instrumentation", alpha=0.3, edgecolors='none')
    plt.xlabel("Package Size (in Bytes)", fontsize=14)
    plt.ylabel("Installation Time (in s)", fontsize=14)
    ax.legend()
    plt.show()
    print("Overall", overall)
    print("Qemu", qemuCount)
    print("(overall-qemu)/overall", (overall - qemuCount) / overall)
    build_df = pd.DataFrame.from_dict(build_dict_table)
    print("Build df correlation")
    print(build_df.corr())


if __name__ == "__main__":
    main(sys.argv[1])
