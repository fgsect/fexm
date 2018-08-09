import subprocess
import sys

import matplotlib.pyplot as plt
import os
import pandas as pd


def get_file_bucket(file):
    file_bucket = " ".join(str(subprocess.check_output("file {0}".format(file),
                                                       shell=True).strip()).split(":")[1].split(",")[0].strip().split(
        " ")[:2])
    if file_bucket[-1] == "'":
        file_bucket = file_bucket[:-1]
    return file_bucket


def main(seeds_dir: str):
    df = pd.DataFrame([], columns=["id", "filetype", "size_bucket"])

    filetypes = []
    file_buckets = []

    count = 0
    for file_dir in os.listdir(seeds_dir):
        filedir_full_path = os.path.join(seeds_dir, file_dir)
        if not os.path.isdir(filedir_full_path):
            continue
        if not os.listdir(filedir_full_path):
            continue
        # for file in os.listdir(filedir_full_path):
        #    print("Pre-Processing file {0}".format(file))
        #    file_full_path = os.path.join(filedir_full_path,file)
        #    file_bucket = get_file_bucket(file_full_path)
        #    file_buckets.append(file_bucket)
        filetypes.append(file_dir.split("_")[0])

    plot_df = pd.DataFrame([], columns=["<1KB", "<=500KB", "<=1000KB", ">1000KB"], index=filetypes)
    plot_bucket_dict = {}
    for filetype in filetypes:
        plot_df.loc[filetype]["<1KB"] = 0
        plot_df.loc[filetype]["<=500KB"] = 0
        plot_df.loc[filetype]["<=1000KB"] = 0
        plot_df.loc[filetype][">1000KB"] = 0
    for file_dir in os.listdir(seeds_dir):
        filedir_full_path = os.path.join(seeds_dir, file_dir)
        if not os.path.isdir(filedir_full_path):
            continue
        if not os.listdir(filedir_full_path):
            continue
        for file in os.listdir(filedir_full_path):
            print("Processing file {0}".format(file))
            file_full_path = os.path.join(filedir_full_path, file)
            bucket = ""
            size = os.path.getsize(file_full_path)
            if size <= 1 * 1000:
                bucket = "<1KB"
            elif size <= 500 * 1000:
                bucket = "<=500KB"
            elif size <= 1000 * 1000:
                bucket = "<=1000KB"
            else:
                bucket = ">1000KB"
            df.loc[count] = [file, file_dir.split("_")[0], bucket]
            count += 1
            plot_df.loc[file_dir.split("_")[0]][bucket] += 1
            file_bucket = get_file_bucket(file_full_path)

            if not plot_bucket_dict.get(file_bucket):
                plot_bucket_dict[file_bucket] = {"<1KB": 0, "<=500KB": 0, "<=1000KB": 0, ">1000KB": 0}
                plot_bucket_dict[file_bucket][bucket] = 1
            elif not plot_bucket_dict.get(file_bucket).get(bucket):
                plot_bucket_dict[file_bucket][bucket] = 1
            else:
                plot_bucket_dict[file_bucket][bucket] += 1
            # plot_bucket_df.loc[get_file_bucket(file_full_path)bucket] +=1
    plot_bucket_df = pd.DataFrame([], columns=["<1KB", "<=500KB", "<=1000KB", ">1000KB"], index=plot_bucket_dict.keys())

    for file_bucket in plot_bucket_dict.keys():
        plot_bucket_df.loc[file_bucket, "<1KB"] = plot_bucket_dict[file_bucket]["<1KB"]
        plot_bucket_df.loc[file_bucket, "<=500KB"] = plot_bucket_dict[file_bucket]["<=500KB"]
        plot_bucket_df.loc[file_bucket, "<=1000KB"] = plot_bucket_dict[file_bucket]["<=1000KB"]
        plot_bucket_df.loc[file_bucket, ">1000KB"] = plot_bucket_dict[file_bucket][">1000KB"]

    plot_bucket_df.plot.barh(stacked=True, figsize=(80, 80))
    plot_bucket_df.to_csv("bucket_seeds_eval.csv")
    plot_df.to_csv("fileendings_seeds_eval.csv")
    plt.show()


if __name__ == "__main__":
    main(sys.argv[1])
