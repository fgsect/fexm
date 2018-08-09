#!/usr/bin/env python3
import argparse
import multiprocessing
import sys
from threading import Thread
from typing import List, Optional

import config_parser
from helpers import utils
from helpers.utils import run_celery

from docker_scripts import pacmanfuzzer_setup, aptfuzzer_setup, githubfuzzer_setup
from seed_crawlers.pcap_crawler import download_and_depcapize
from tools import seedcrawler_github
from webserver import webserver


def exit_info(info: str, ret: int = 1) -> None:
    """
    Print error, then exit
    :param info: the info to print
    :param ret: the return value
    :return: Will never return.
    """
    print(info, file=sys.stderr)
    exit(ret)


def crawl(args: argparse.Namespace):
    if args.url:
        print("Downloading PCAPs for Network Fuzzing")
        download_and_depcapize(out_dir=args.outdir, url=args.url)  # , ignore_exts=True)
    else:
        print("No valid URL supplied, ignoring Network Fuzz Testcases.")

    print("Starting to crawl GitHub for non-network files.")
    seedcrawler_github.crawl(args.outdir, args.max, args.infile, auth_token=args.auth_token)


def init(args: argparse.Namespace):
    def fixme():
        raise NotImplemented("Fix me! :)")

    initer = {
        "pacmanfuzzer": pacmanfuzzer_setup.init,
        "aptfuzzer": aptfuzzer_setup.init,
        "githubfuzzer": githubfuzzer_setup.init,
        "byob": pacmanfuzzer_setup.init,
    }

    initer[args.base]()
    print("Initialized {}".format(args.base))


def fuzz(args: argparse.Namespace):
    config = config_parser.load_config(args.config)

    log_level = "DEBUG" if args.verbose else "INFO"

    Thread(name="celery", daemon=True, target=run_celery,
           args=["worker -l {} --concurrency={}".format(log_level, multiprocessing.cpu_count())]).start()

    Thread(name="fuzz", daemon=True, target=config["fuzz_func"]).start()

    host = "0.0.0.0"
    port = utils.find_free_port(5307, 7000)
    print("Open http://localhost:{} for the Dasboard.".format(port))
    # This never returns until we Strg+c. Perfect.
    webserver.listen(host, int(port), config)


def worker():
    Thread(name="celery", daemon=True, target=run_celery,
           args=["worker -l INFO --concurrency={}".format(multiprocessing.cpu_count())]).start()


def fexm(argv: Optional[List[str]] = None) -> None:
    """
    Wrapper for all things FExM
    :param argv: argv. Custom argvs. Will default to sys.argv if not provided.
    :return: args object
    """
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description="FuzzExMachina - Fully Automated Fuzz-Testing")
    subparsers = parser.add_subparsers(help="The FExM command to execute. First crawl, then init, then fuzz",
                                       dest="method")
    subparsers.required = True

    parser.add_argument("-v", "--verbose", action='store_true')

    # Get seeds
    seed_parser = subparsers.add_parser("crawl", help="Crawls GitHub for Seeds and an additional Webpage for PCAPs.")
    seed_parser.add_argument("-m", "--max", required=False, type=int,
                             help="The maximum number of sample files to download for each filetype. Default 40",
                             default=40)
    seed_parser.add_argument("-i", "--infile", required=False, type=str,
                             help="The path to a file that contains a list of filetypes.")
    seed_parser.add_argument("-a", "--auth_token", required=False, type=str, default="authtoken",
                             help="40 character long GitHub authtoken (https://github.com/settings/tokens) "
                                  "or the path to a file containing said token")
    seed_parser.add_argument("-u", "--url",
                             default="https://wiki.wireshark.org/SampleCaptures",
                             help="An additional URL to download PCAPs from."
                                  "This should like to a webpage including links to pcaps. "
                                  "The PCAPs should include all protocols needed as seeds. Defaults to WireShark wiki.")
    seed_parser.add_argument("-o", "--outdir", metavar="outdir", type=str, default="/seeds",
                             help="The path to store seed files at.")
    seed_parser.set_defaults(func=crawl)

    init_parser = subparsers.add_parser("init", help="Initializes containers for a specific fuzz job")
    init_parser.add_argument("-b", "--base", default='pacmanfuzzer',
                             choices=['pacmanfuzzer', 'byob', 'aptfuzzer', 'githubfuzzer'],
                             help="Initializes the base container needed for Fuzzing. "
                                  "Run this before running fuzz for the first time. :)")
    init_parser.set_defaults(func=init)

    # TODO: Simple version for single repo?
    fuzz_parser = subparsers.add_parser("fuzz", help="Start fuzzing.")
    fuzz_parser.add_argument("config", type=str,
                             help="The config file to work with.")
    fuzz_parser.set_defaults(func=fuzz)

    # TODO: Automate client creation
    # worker_parser = subparsers.add_parser("worker", help="Run worker")
    # worker_parser.add_argument("server", help="The FExM server address to connect to.")
    # seed_parser.set_defaults(func=work)

    args = parser.parse_args(args=argv)  # type: argparse.Namespace
    params = vars(args).copy()
    del params["func"]
    del params["method"]

    print("Running {} with {}".format(args.method, params))
    args.func(args)


if __name__ == "__main__":
    fexm()
