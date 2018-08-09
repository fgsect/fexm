#!/usr/bin/env python3
"""
Crawls seeds from Github.
"""
import argparse
import json
import uuid
from multiprocessing.pool import ThreadPool
from queue import Queue

import os
import requests

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from seed_crawlers.graphql_githubsearcher import GraphQlGithubSearcher
from helpers import utils

# Top filetypes as defaults for the crawler.
DEFAULT_FILETYPES = [
    '3ga', '3gp', '7z', 'ai', 'arj', 'arw', 'ar', 'ashx', 'asm', 'aspx', 'asx', 'avi', 'bak', 'bat', 'bmp', 'bzip2',
    'cab', 'cfg', 'cgi', 'cnf', 'compress', 'com', 'config', 'cpio', 'cpp', 'cr2', 'crx', 'csr', 'css', 'csv', 'cs',
    'c', 'dat', 'db', 'dll', 'docx', 'doc', 'dtd', 'elf', 'eot', 'eps', 'exe', 'fla', 'flv', 'gif', 'gzip', 'gz',
    'html', 'htm', 'h', 'icns', 'ico', 'ics', 'inc', 'ini', 'jar', 'java', 'jp2', 'jpg', 'json', 'js', 'jxr', 'lha',
    'log', 'lrzip', 'lua', 'lzip', 'lzma', 'lzo', 'm2ts', 'm4v', 'map', 'mdb', 'md', 'mid', 'mkv', 'mod', 'mov', 'mp3',
    'mp4', 'mpg', 'mts', 'm', 'ods', 'ogg', 'ogv', 'old', 'otf', 'pbm', 'pcap', 'pcapng', 'pcx', 'pdb', 'pdf', 'pem',
    'php', 'plist', 'pl', 'png', 'pot', 'ppm', 'pptx', 'ppt', 'psd', 'pspimage', 'ps', 'py', 'rar', 'rb', 'rec', 'rmvb',
    'rtf', 'rzip', 'safariextz', 'scpt', 'sgml', 'sh', 'sln', 'sqlite', 'sql', 'src', 'svg', 'swf', 'swift', 'swp',
    'tar', 'template', 'tex', 'tga', 'tgz', 'theme', 'tif', 'tpl', 'tp', 'ts', 'ttf', 'txt', 'vb', 'vob', 'wav', 'webm',
    'webp', 'wlmp', 'wmv', 'woff', 'xhtml', 'xlsx', 'xls', 'xml', 'xsd', 'xz', 'yml', 'zip', 'zoo'
]
# How many repos to search concurrently per search. (Too many are considered abuse)
CONCURRENT_SEARCHES = 2
# How many files to download concurrently per searched repo
CONCURRENT_DOWNLOADS = 5


# rate limits: https://developer.github.com/v3/#rate-limiting


class GitHubTreeEntry(object):
    def __init__(self, repo_name: str, repo_owner: str, filename: str, oid: str, path: str):
        """
        :param repo_name:
        :param repo_owner:
        :param filename:
        :param oid:
        :param path 
        :param size The filesize in bytes.
        """
        self.repo_name = repo_name
        self.repo_owner = repo_owner
        self.filename = filename
        self.oid = oid
        self.path = path
        self.size = 10

    def get_blob_text(self):
        """
        Get the actual blob text.

        :return:
        """
        query = 'query GetBlobText($repoName:String!,$repoOwner:String!, $objectid:GitObjectID!){  repository(name: ' \
                '$repoName, owner: $repoOwner) {    object(oid: $objectid) {      ... on Blob {        text      }   ' \
                ' }  }} '
        variables = {"repoName": self.repo_name, "repoOwner": self.repo_owner, "objectid": self.oid}

    def __hash__(self):
        return hash(self.repo_name + self.repo_owner + self.oid)

    def __eq__(self, other):
        return self.oid == other.oid

    def __str__(self):
        return "{0}/{1}:{2}".format(self.repo_name, self.repo_owner, self.filename)


class TreeBuilder(object):
    def __init__(self, repo_name: str, repo_owner: str, auth_token: str):
        """
        Build the repo
        :param repo_name:
        :param repo_owner:
        """
        self.repo_name = repo_name
        self.repo_owner = repo_owner
        self.blob_set = set()
        self.node_set = set()
        self.max_blob_size = 400000  # In byte, do want over 1MB, since this would lead to afl-fuzz failing
        self.auth_token = auth_token
        self.default_branch = self.get_default_branch()

    def get_default_branch(self):
        """
        Given the repo_name and the repo_owner, 
        return the default branch. 
        :return: 
        """
        query = "query TreeQuery($repo_name: String!,$repo_owner: String!) {repository(name: $repo_name, " \
                "owner: $repo_owner) { \n name \n id \n defaultBranchRef \n{ \n id \n name \n  } \n} rateLimit { \n " \
                "limit \n cost \n remaining \n resetAt }} "
        data_dict = {'query': query, "variables": {"repo_name": self.repo_name, "repo_owner": self.repo_owner}}
        answer = requests.post("https://api.github.com/graphql", json=data_dict,
                               headers={"Authorization": "token {0}".format(self.auth_token)})
        try:
            name = json.loads(answer.text)["data"]["repository"]["defaultBranchRef"]["name"]
        except TypeError:
            return "master"
        remaining = json.loads(answer.text)["data"]["rateLimit"]["remaining"]
        reset_at = json.loads(answer.text)["data"]["rateLimit"]["resetAt"]
        print("RateLimit:", remaining)
        if remaining <= 1:
            utils.wait_for_rate_limit(reset_at)
        return name

    def get_subtree_from_oid(self, oid: str):
        """
        Given an oid, return the subtree of object files from 
        the repository. 
        :param oid: The object id of the tree subentry to search. Start with None
        :return: A list with the entries contained in that tree. None if no such tree exists. 
        """
        query = 'query TreeQuery($subtree: GitObjectID,$branch: String!, $repo_name: String!,$repo_owner: String!) {' \
                'repository(name: $repo_name, owner: $repo_owner) { \n' \
                'name \n' \
                'id \n' \
                'object(expression: $branch,oid: $subtree) { \n' \
                '... on Tree { \n' \
                '  entries { \n' \
                '       oid \n' \
                '       name \n' \
                '       type \n' \
                '  }\n' \
                ' }\n' \
                '\n' \
                '}\n' \
                '}\n' \
                '  rateLimit {   ' \
                '\n limit  ' \
                '\n  cost ' \
                '\n   remaining ' \
                '\n   resetAt  }' \
                '}'

        data_dict = {'query': query,
                     "variables": {"branch": self.default_branch + ":", "subtree": oid, "repo_name": self.repo_name,
                                   "repo_owner": self.repo_owner}}
        answer = requests.post("https://api.github.com/graphql", json=data_dict,
                               headers={"Authorization": "token {0}".format(self.auth_token)})
        try:
            objects = json.loads(answer.text)["data"]["repository"]["object"]  # type:dict
        except Exception as ex:
            print("Error parsing github answer {}".format(answer.text))
            raise ex
        if objects and "entries" in objects:
            tree = objects["entries"]
        else:
            tree = []
        remaining = json.loads(answer.text)["data"]["rateLimit"]["remaining"]
        reset_at = json.loads(answer.text)["data"]["rateLimit"]["resetAt"]
        print("RateLimit:", remaining)
        if remaining <= 1:  # TODO: I think we should pause somewhere else, but it is sufficient for now
            utils.wait_for_rate_limit(reset_at)
        return tree

    def breadth_first_search(self, max_depth=4):
        # a FIFO open_set
        print("BFS on repo {0}/{1}".format(self.repo_owner, self.repo_name))
        open_queue = Queue()
        # an empty set to maintain visited nodes
        from collections import namedtuple
        subTree = namedtuple('Tree', ['oid', 'path', 'depth'])
        open_queue.put(subTree(oid=None, path="/", depth=0))
        closed_set = [None]
        while not open_queue.empty():  # Still Subtrees in the queue
            # next_entry,path = open_queue.get()
            next_subTree = open_queue.get()
            next_entry = next_subTree.oid
            path = next_subTree.path
            depth = next_subTree.depth
            print("Searching {0}:{1}/{2}".format(self.repo_owner, self.repo_name, path))
            for entry in self.get_subtree_from_oid(oid=next_entry):
                # print("Entry {0}".format(entry))
                if entry["type"] == "blob":
                    # if GithubSeedsDownloader.get_blob_size(self.repo_name,self.repo_owner,entry["oid"])<=self.max_blob_size:
                    self.blob_set.add(
                        GitHubTreeEntry(repo_name=self.repo_name, repo_owner=self.repo_owner, filename=entry["name"],
                                        oid=entry["oid"], path=path + "/" + entry["name"]))
                    # else:
                    #    print("Skipping {0} because of size".format(entry["oid"]))
                elif entry["type"] == "tree":
                    if entry["oid"] not in closed_set and (depth + 1) <= max_depth:
                        open_queue.put(subTree(oid=entry["oid"], path=path + entry["name"] + "/", depth=depth + 1))
                        closed_set.append(entry["oid"])
                        closed_set.append(entry["oid"])
                    elif (depth + 1) >= max_depth:
                        print("Skipping entry {0} because of path depth.".format(path + entry["name"] + "/"))
        return self.blob_set

    def depth_first_search(self):
        # a FIFO open_set
        print("DFS on repo {0}/{1}".format(self.repo_owner, self.repo_name))
        from collections import namedtuple
        subtree = namedtuple('Tree', ['oid', 'path', 'depth'])
        open_stack = [subtree(oid=None, path="/", depth=0)]
        # an empty set to maintain visited nodes
        closed_set = [None]
        while open_stack:  # Still Subtrees in the stack
            # next_entry,path,depth = open_stack.pop()
            next_subtree = open_stack.pop()
            next_entry = next_subtree.oid
            path = next_subtree.path
            depth = next_subtree.depth
            for entry in self.get_subtree_from_oid(oid=next_entry):
                if entry["type"] == "blob":
                    self.blob_set.add(
                        GitHubTreeEntry(repo_name=self.repo_name, repo_owner=self.repo_owner, filename=entry["name"],
                                        oid=entry["oid"], path=path + "/" + entry["name"]))
                elif entry["type"] == "tree":
                    if entry["oid"] not in closed_set:
                        open_stack.append(subtree(oid=entry["oid"], path=path + entry["name"] + "/", depth=depth + 1))
                        open_stack.append((entry["oid"], path + entry["name"] + "/"))
                        closed_set.append(entry["oid"])
                        closed_set.append(entry["oid"])
        return self.blob_set


class GithubSeedsDownloader(object):

    def get_blob_size(self, repo_name: str, repo_owner: str, oid: str):
        query = 'query GetBlobText($repoName:String!,$repoOwner:String!, $objectid:GitObjectID!){  repository(name: ' \
                '$repoName, owner: $repoOwner) {    object(oid: $objectid) {      ... on Blob {        byteSize      ' \
                '}    }  }} '
        variables = {"repoName": repo_name, "repoOwner": repo_owner, "objectid": oid}

        data_dict = {'query': query, "variables": variables}
        answer = requests.post("https://api.github.com/graphql", json=data_dict,
                               headers={"Authorization": "token {0}".format(self.auth_token)})
        byte_size = json.loads(answer.text)["data"]["repository"]["object"]["byteSize"]  # type:int
        return byte_size

    def __init__(self, desired_fileformats: set, max_download: int, out_dir: str, auth_token: str,
                 search_string: str = None):
        self.desired_fileformats = desired_fileformats
        self.max_download = max_download
        self.out_dir = out_dir
        if search_string:
            self.search_string = search_string
        else:
            self.search_string = "size>:5000"
        self.auth_token = auth_token

    # TODO: Time of Check Time of Use -> We might download too many files.
    def download(self, blob_entry: GitHubTreeEntry) -> int:
        """
        Given a GithubTreeEntry object, tries to download the respective file.
        """
        file_extension = os.path.splitext(blob_entry.filename)[1][1:]
        file_out_dir = "{0}/{1}_samples/".format(self.out_dir, file_extension)
        # Now: Download
        filename = file_extension + "_" + str(uuid.uuid4()) + "." + file_extension
        if not os.path.exists(file_out_dir):
            os.makedirs(file_out_dir)
        number_of_files_of_so_far = len(
            [name for name in os.listdir(file_out_dir) if os.path.isfile(file_out_dir + os.sep + name)])
        if number_of_files_of_so_far < self.max_download:
            # Download the file
            download_link = "https://raw.githubusercontent.com/{0}/{1}/master/{2}".format(blob_entry.repo_owner,
                                                                                          blob_entry.repo_name,
                                                                                          blob_entry.path)
            downloaded = utils.download_seed_to_folder(download_link=download_link, to_directory=file_out_dir,
                                                       filename=filename)
            return downloaded
        else:
            try:
                self.desired_fileformats.remove(file_extension)  # We don't need that extension anymore
            except KeyError:
                pass

    def get_files(self):
        githubsearcher = GraphQlGithubSearcher(auth=self.auth_token, max_number_of_results=100,
                                               searchparams=self.search_string)
        search_pool = ThreadPool(CONCURRENT_SEARCHES)
        search_pool.map(lambda x: self.search_repo(x["node"]), githubsearcher)

    def search_repo(self, repo):
        treebuilder = TreeBuilder(repo_name=repo["name"], repo_owner=repo["owner"]["login"],
                                  auth_token=self.auth_token)
        treebuilder.breadth_first_search()
        blobs = [x for x in treebuilder.blob_set if os.path.splitext(x.filename)[1][1:] in self.desired_fileformats]
        download_pool = ThreadPool(CONCURRENT_DOWNLOADS)
        download_pool.map(self.download_blob, blobs)

    def download_blob(self, blob):
        # if GithubSeedsDownloader.get_blob_size(self.repo_name,self.repo_owner,entry["oid"])<=self.max_blob_size:
        if self.get_blob_size(blob.repo_name, blob.repo_owner, blob.oid) <= 500000:
            print("Would download {0}/{1} Path: {2}".format(blob, blob.oid, blob.path))
            print("Download Link: https://raw.githubusercontent.com/{0}/{1}/master/{2}".format(
                blob.repo_owner, blob.repo_name, blob.path))
            self.download(blob)


def crawl(out_dir: str, max_number_of_seeds: int, infile_path: str, auth_token: str = None):
    try:
        with open(auth_token) as fp:
            auth_token = fp.readline().strip()
    except FileNotFoundError as ex:
        pass

    if len(auth_token) != 40:
        raise ValueError("No valid auth token at {}. "
                         "Create a token at https://github.com/settings/tokens and pass it with -a".format(auth_token))

    os.makedirs(out_dir, exist_ok=True)

    if infile_path:
        desired_filetypes = set()
        with open(infile_path, "r") as infile:
            for line in infile:
                filetype = line.strip()
                if not filetype:
                    continue
                if filetype[0] == ".":
                    filetype = filetype[1:]
                filetype = filetype.lower()
                os.makedirs(os.path.join(out_dir, filetype + "_samples"), exist_ok=True)
                if len(os.listdir(os.path.join(out_dir, filetype + "_samples"))) >= max_number_of_seeds:
                    continue
                desired_filetypes.add(filetype)
    else:
        desired_filetypes = set(DEFAULT_FILETYPES)

    # print(desired_filetypes)
    for filetype in desired_filetypes.copy():
        if filetype not in desired_filetypes:
            continue
        print("Querying for filetype {0}".format(filetype))
        gs = GithubSeedsDownloader(desired_filetypes, max_number_of_seeds, out_dir, auth_token=auth_token,
                                   search_string=filetype)
        gs.get_files()


if __name__ == "__main__":
    # import logging
    # logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="Crawl Seeds from GitHub.")
    parser.add_argument("-m", "--max", required=False, type=int,
                        help="The maximum number of sample files to download for each filetype. Default 40", default=40)
    parser.add_argument("-i", "--infile", required=False, type=str,
                        help="The path to a file that contains a list of filetypes.")
    parser.add_argument("-a", "--auth_token", required=False, type=str, default="authtoken",
                        help="40 character long GitHub authtoken (https://github.com/settings/tokens) "
                             "or the path to a file containing said token")
    parser.add_argument("-o", "--outdir", metavar="outdir", type=str,
                        help="The path where the crawled files should be saved.")

    args = parser.parse_args()
    crawl(args.outdir, args.max, args.infile, auth_token=args.auth_token)
