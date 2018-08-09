import sys

import networkx as nx
import pandas as pd


def main(package_csv: str, package: str):
    package_dict = {}
    count = 0
    df = pd.read_csv(package_csv)
    df.fillna("")
    dep_graph = nx.DiGraph()
    for index, row in df.iterrows():
        dependencies = str(row["depends"]).split(" ") if str(row["depends"]) != "nan" else []
        dependencies += str(row["makedepends"]).split(" ") if str(row["makedepends"]) != "nan" else []
        dependencies += str(row["opt_depends"]).split(" ") if str(row["opt_depends"]) != "nan" else []
        dependencies = set(dependencies)
        if row["package"] not in package_dict:
            package_dict[row["package"]] = row["package"]
            count += 1
            dep_graph.add_node(package_dict[row["package"]])
        for dep in dependencies:
            if dep not in package_dict:
                package_dict[dep] = dep
                count += 1
                dep_graph.add_node(package_dict[dep])
            dep_graph.add_edge(package_dict[row["package"]], package_dict[dep])
    print("Graph done! ######")
    depend_counter = 0
    for index, row in df.iterrows():
        if package in nx.neighbors(dep_graph, package_dict[row["package"]]):
            print("{0} directly depends on {1}".format(row["package"], package))
            depend_counter += 1
            # print("For ",row["package"])
            # print(nx.descendants(dep_graph,package_dict[row["package"]]))
    print("{0} is used in ".format(package), depend_counter, "packages")
    # nx.draw(dep_graph)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
