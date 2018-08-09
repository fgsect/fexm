import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import helpers.docker_builder
import sys
import time
import pandas
import docker

start = time.time()


def main():
    packages_file = sys.argv[1]
    table_dict = {"package": [], "Success": [], "Build Time (in S)": [], "Reason For Failure": []}
    docker_client = docker.from_env()
    with open(packages_file) as fp:
        for line in fp.readlines():
            print("Starting to build", line)
            start = time.time()
            try:
                res = helpers.docker_builder.build_and_commit(line.strip(), "pacmanfuzzer", qemu=False,
                                                              json_output_path=line.strip() + ".build")
            except Exception as e:
                continue
            end = time.time()
            docker_client.images.remove(res)
            table_dict["package"] += [line.strip()]
            if res:
                table_dict["Success"] = True
            else:
                table_dict["Success"] = False
            table_dict["Build Time (in S)"] = end - start
            table_dict["Reason For Failure"] = end - start
            print("Finished building and commiting", line, "took {0}", end - start)
    df = pandas.DataFrame.from_dict(table_dict)  # type:pandas.DataFrame
    df.to_csv("eval_building_results.csv")


if __name__ == "__main__":
    main()
