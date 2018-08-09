import sys

import os
import pandas as pd

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from repo_crawlers.archcrawler import ArchCrawler


def main(package):
    df = pd.DataFrame(
        columns=["package", "version", "update_date", "depends", "makedepends", "checkdepends", "opt_depends"])
    pacman_query = "repo=Core&repo=Extra&repo=Community"
    ac = ArchCrawler(query=pacman_query)
    result_list = list(ac)
    for i, package in enumerate(result_list):
        df.loc[i] = [package["pkgname"], package["pkgver"], package["last_update"], " ".join(package["depends"]),
                     " ".join(package["makedepends"]), " ".join(package["checkdepends"]),
                     " ".join(package["optdepends"])]
    df.to_csv("packages.csv")


if __name__ == "__main__":
    main(sys.argv[1])
