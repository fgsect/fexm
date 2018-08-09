#!/usr/bin/env python3
"""
Crawls all links on a webpage for pcaps.
"""
import argparse
import logging
from multiprocessing.pool import ThreadPool
from urllib.parse import urljoin

import os
import requests
from bs4 import BeautifulSoup
from functools import partial

from helpers import utils
from seed_crawlers import pcap_parser

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

POOL_WORKER_COUNT = 8  # How many downloads we should run at the same time


def download_and_depcapize(url: str, out_dir: str, keep_pcaps: bool = False, ignore_exts: bool = False,
                           skip_analysis: bool = False) -> None:
    """
    Downloads to a tmp folder inside the given folder (./pcap_tmp) and then parses each pcap to a text file
    :param url: the page to crawl (depth 1)
    :param out_dir: the download folder
    :param keep_pcaps: if the pcaps inside ./pcap_tmp should be removed after finish
    :param ignore_exts: If true, we'll also download unsupported file extensions (not .cap, .pcap, .gz or .pcapng)
    :param skip_analysis: If true, we'll only download, not `depcapize` (run pcap parser) on the files.
    """
    if not keep_pcaps and skip_analysis:
        raise ValueError("Deleting PCAPs after a run while also skipping the analysis part would not make any sense.")

    pool = ThreadPool(POOL_WORKER_COUNT)

    logger.info("Downloading and parsing {}".format(url))
    page = BeautifulSoup(requests.get(url).text, "html.parser")
    link_anchors = page.find_all("a")
    links = list(map(lambda x: x.get("href"), link_anchors))  # type: [str]

    tmpdir = os.path.join(out_dir, "pcap_tmp")

    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(tmpdir, exist_ok=True)

    download_list = []
    for link in links:
        if not ignore_exts and "{}.".format(link).rsplit(".", 2)[1].lower() not in pcap_parser.SUPPORTED_EXTENSIONS:
            logger.info("Ignoring file {} - unsupported extension.".format(link))
            continue
        download_url = urljoin(url, link)
        download_list.append(download_url)

    logger.info("Downloading {} files as network seeds.".format(len(download_list)))

    downloader = partial(utils.download_file, tmpdir)
    pool.map(downloader, download_list)

    logger.info("Done downloading all files from {}".format(url))
    if not skip_analysis:
        pcap_parser.Overmind(backend=pcap_parser.FileBackend(outfolder=out_dir)).analyze_folder(
            tmpdir).finish_analysis()

    if not keep_pcaps:
        logger.info("Removing tmpdir.")
        os.unlink(tmpdir)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Downloads all PCAPS from a webpage, stores them to a tmp folder "
                                                     "and then converts them to plaintext")
    # arg_parser.add_argument("-f", "--filter",
    #                        default="port not 22 and host 10.7.14.2",
    #                        help="TCPdump style filter to use")
    arg_parser.add_argument("-o", "--outdir", default="./out", help="Folder to write output files to.")
    arg_parser.add_argument("-u", "--url",
                            default="https://wiki.wireshark.org/SampleCaptures", help="The url to crawl pcaps from")
    arg_parser.add_argument("-e", "--ignore-exts", default=False, help="If true, unknown extensions will be downloaded")
    arg_parser.add_argument("--keep-pcaps", default=True, help="Keep or remove pcaps in ./pcap_tmp")
    arg_parser.add_argument("--skip-analysis", default=False, help="Skip the analysis, only download to ./pcap_tmp.")

    args = arg_parser.parse_args()

    download_and_depcapize(out_dir=args.outdir, url=args.url, ignore_exts=args.ignore_exts, keep_pcaps=args.keep_pcaps,
                           skip_analysis=args.skip_analysis)
