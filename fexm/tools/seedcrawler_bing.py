import argparse
import logging
import uuid
from urllib.parse import urljoin, urlparse

import os
import requests
import requests.exceptions
import tldextract
from bs4 import BeautifulSoup
from py_ms_cognitive import PyMsCognitiveWebSearch, PyMsCognitiveImageSearch

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from helpers import utils

DESC = """File sample crawler"""
MS_KEY = "YOUR_KEY"
# QUERY = "inurl:(htm|html|php) intitle:\"index of\""
QUERY = "surfing ext:pdf"

MAX_TIMEOUT = 2
LIMIT_RESULTS = 10

headers = {
    'User-Agent': 'TUBBOT',
}

image_list = ["jpg", "png", "gif", "tif"]


def download_files_from_website(website, filetype, out_dir):
    r = requests.get(website)
    html_text = r.text
    soup = BeautifulSoup(html_text, "html.parser")
    link_anchors = soup.find_all("a")
    links = list(map(lambda x: x.get("href"), link_anchors))  # type: [str]
    links = list(filter(lambda x: x is not None and x.lower().endswith(filetype), links))
    for link in links:
        rurl = urljoin(website,
                       link)  # Join the two urls. Urljoin handles every case: path is relative and path is absolute
        print("Yielded", rurl)
        filename = filetype + "_" + str(uuid.uuid4())
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        utils.download_seed_to_folder(download_link=rurl, to_directory=out_dir, filename=filename)
    return len(links)


class FileCrawler:
    """
    This class should be used to seeds a specific file and save it to a specific url
    """

    def __init__(self, filetype: str, ms_key: str, out_dir: str):
        """
        
        :param filetype: The filetype to seeds.
        :param ms_key: The api key for the bing search api. 
        """
        self.filetype = filetype.lower()
        self.ms_key = ms_key
        print("KEY", self.ms_key)
        self.out_dir = out_dir
        self.search_service = None

    @staticmethod
    def is_valid_file(filetype, url: str) -> bool:
        """
        Given an url, it checks if the content is a file and of the right fileformat or not.
        :param url: The url to check
        :return: True if url is not an html webpage, false if it is
        """

        utils.temp_print("Trying", url)
        try:
            response = requests.head(url, timeout=MAX_TIMEOUT, headers=headers)
        except Exception as e:
            return False
        if response.headers.get("content-type") is not None:
            # return False
            if "text/html" in response.headers["content-type"]:
                return False
            if filetype in response.headers["content-type"]:
                return True
        part = url.rpartition(".")  # Returns a three tuple, last tuple containing the part after the "."
        if part[2].lower() == filetype:
            return True
        return False

    def website_crawl(self, query):
        """
        This function issues the given query to ping, then crawls the websites 
        that were given in the ResultSet for links to a file. To be used with 
        queries such as "jpg example file" or "inurl:(avi) intitle:index of"
        :return: A generator - StopIteration is called when no more links can/should be found.
        """
        self.search_service = PyMsCognitiveWebSearch(self.ms_key, query)
        self.search_service.SEARCH_WEB_BASE = "https://api.cognitive.microsoft.com/bing/v7.0/search"
        results = self.search_service.search_all(format="json", quota=LIMIT_RESULTS)
        print(len(results))
        for item in results:
            try:
                r = requests.get(item.url, timeout=MAX_TIMEOUT)
            except Exception as e:
                print("Skipping ", item.url, "because of Exception", str(e))
                continue

            parsed_uri = urlparse(r.url)
            subdomain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
            # extract the top level domain:
            rootdomain = '{uri.scheme}://{ext.domain}.{ext.suffix}'.format(uri=parsed_uri,
                                                                           ext=tldextract.extract(r.url))
            try:
                if requests.head(subdomain + "/robots.txt").status_code == 404 and requests.head(
                        rootdomain + "/robots.txt").status_code == 404:
                    # No Robots TXT - Skip
                    print("Skipping", subdomain, "because it does not contain a robots.txt")
                    continue
            except Exception as e:
                print("Skipping", subdomain, "because of exception", str(e))
                continue
            print("Now scanning through", r.url)
            html_text = r.text
            if "index of" in query and not "index of" in html_text:
                # TODO: Really really hacky. This if statement shoud only be
                # TODO: in place if we are issuing the index of query
                # We probably did not reach a file repository
                continue
            soup = BeautifulSoup(html_text, "html.parser")
            link_anchors = soup.find_all("a")
            links = list(map(lambda x: x.get("href"), link_anchors))  # type: [str]
            links = list(filter(lambda x: x is not None and x.lower().endswith(self.filetype), links))
            for link in links:
                path = link
                filelink = urljoin(r.url,
                                   path)  # Join the two urls. Urljoin handles every case: path is relative and path is absolute
                if self.is_valid_file(self.filetype, filelink):
                    print("Yielding", filelink)
                    yield filelink

    def try_filetype_crawl(self):
        """
        Try to find download links to files of the given file format. 
        :return: A generator - StopIteration is called when no more links can/should be found.
        """

        # First: Try a simple  "filetype:" query - works for some, but not all filetypes
        query = "filetype:" + self.filetype
        PyMsCognitiveWebSearch.SEARCH_WEB_BASE = "https://api.cognitive.microsoft.com/bing/v7.0/search"
        self.search_service = PyMsCognitiveWebSearch(self.ms_key, query)
        results = self.search_service.search_all(format="json", quota=LIMIT_RESULTS + 20)
        for item in results:
            try:
                r = requests.get(item.url, timeout=MAX_TIMEOUT,
                                 headers=headers)  # Request the url to resolve the redirect
            except Exception as e:  # requests.exceptions.ConnectTimeout:
                print("Skipping ", item.url, "because of Exception", str(e))
                # Then just skip
                continue
            if self.is_valid_file(self.filetype, r.url):
                print("Yielding ", r.url)
                yield r.url
        # If this fails, maybe the requested filetype is an image? Then perform an image search
        if self.filetype in image_list:  # Perform an image Search
            query = self.filetype + " sample"
            PyMsCognitiveImageSearch.SEARCH_IMAGE_BASE = "https://api.cognitive.microsoft.com/bing/v7.0/images/search"
            self.search_service = PyMsCognitiveImageSearch(self.ms_key, query)

            results = self.search_service._search(limit=LIMIT_RESULTS,
                                                  format="json")  # TODO: Class does not implement pagination? :(
            for item in results:
                utils.temp_print("Checking item", item.content_url)
                try:
                    r = requests.get(item.content_url, timeout=MAX_TIMEOUT, headers=headers)
                except Exception as e:
                    print("Skipping ", item.url, "because of Exception", str(e))
                    # print("Timeout, checking next item")
                    continue

                print("Url is", r.url)
                if self.is_valid_file(self.filetype, r.url):
                    print("Yielding ", r.url)
                    yield r.url

        for result in self.website_crawl("." + self.filetype + " example file"):
            print("Yielding", result)
            yield result
        for result in self.website_crawl("." + self.filetype + " sample file"):
            print("Yielding", result)
            yield result

        # Last Resort: The index of trick. Note thatfi this can yield some undesired file samples, use with caution!
        query = "inurl:(" + self.filetype + ") intitle:\"index of:\""
        self.search_service = PyMsCognitiveWebSearch(self.ms_key, query)
        results = self.search_service.search_all(format="json", quota=LIMIT_RESULTS)
        print(len(results))
        for item in results:
            try:
                r = requests.get(item.url, timeout=MAX_TIMEOUT)
            except Exception as e:
                print("Skipping ", item.url, "because of Exception", str(e))
                continue

            parsed_uri = urlparse(r.url)
            domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
            try:
                if requests.head(domain + "/robots.txt").status_code == 404:
                    # No Robots TXT - Skip
                    print("Skipping", domain, "because it does not contain a robots.txt")
                    continue
            except Exception as e:
                print("Skipping", domain, "because of exception", str(e))
                continue
            print("Now scanning through", r.url)
            html_text = r.text
            if not "index of" in html_text:
                # We probably did not reach a file repository
                continue
            soup = BeautifulSoup(html_text, "html.parser")
            link_anchors = soup.find_all("a")
            links = list(map(lambda x: x.get("href"), link_anchors))  # type: [str]
            links = list(filter(lambda x: x is not None and x.lower().endswith(self.filetype), links))
            for link in links:
                path = link
                filelink = urljoin(r.url,
                                   path)  # Join the two urls. Urljoin handles every case: path is relative and path is absolute
                if self.is_valid_file(self.filetype, filelink):
                    print("Yielding", filelink)
                    yield filelink

    def download(self, max_download=1) -> int:
        """
        Tries to download max number of samples files of the given file format to the self.out_dir folder
        :return: The amount of downloaded files.
        """
        print("MAX", max_download)

        i = 0
        for rurl in self.try_filetype_crawl():
            print("Yielded", rurl)
            filename = self.filetype + "_" + str(uuid.uuid4())
            if (not os.path.exists(self.out_dir)):
                os.makedirs(self.out_dir)
            utils.download_seed_to_folder(download_link=rurl, to_directory=self.out_dir, filename=filename)
            # with open(self.out_dir + "/" + filename + "." + self.filetype, "wb") as file:
            #    for chunk in r.iter_content(chunk_size=1024):
            #        if chunk:  # filter out keep-alive new chunks
            #            file.write(chunk)
            i += 1
            if i >= max_download:
                return max_download
            # print("Downloaded",rurl)
        return i


def main():
    argParser = argparse.ArgumentParser(DESC)
    argParser.add_argument('-in', '--infile', type=str, required=True,
                           help="""List of new line seperated URLs to seeds""")
    argParser.add_argument("-k", "--key", type=str, required=True, help="The MS Key")
    argParser.add_argument("-d", "--dir", type=str, required=True, help="The directory to save the crawled files to.")
    argParser.add_argument("-m", "--max", type=int, required=False,
                           help="The number of samples to download per filetype. Default 2", default=2)
    _args = argParser.parse_args()
    ms_key = _args.key
    out_dir = _args.dir
    if not os.path.exists(out_dir):
        raise Exception("The specified dir " + str(out_dir) + " does not exist.")
    infile_path = _args.infile
    logging.basicConfig(filename="results.log", filemode="w", level=logging.INFO)
    success = []
    failures = []
    total = []
    with open(infile_path, "r") as infile:
        for line in infile:
            filetype = line.strip()
            if filetype[0] == ".":
                filetype = filetype[1:]
            filetype = filetype.lower()
            total.append(filetype)
            filetype_out_dir = out_dir + "/" + filetype + "_samples"
            filetype_max = _args.max  # The maximum for this filetype
            if not os.path.exists(filetype_out_dir):
                pass
            else:
                # We already have files - only download so much that we reach the maximum threshold
                filetype_max = filetype_max - len(
                    list(filter(lambda x: x.lower().endswith(filetype), os.listdir(filetype_out_dir))))
            if filetype_max > 0:
                print("Crawling for", filetype, "with max", filetype_max)
                fcrawler = FileCrawler(filetype=filetype, ms_key=ms_key, out_dir=filetype_out_dir)
                results = fcrawler.download(max_download=filetype_max)
                if results <= 0:
                    failures.append(str(filetype))
                    logging.warning("Found no samples for " + str(filetype))
                else:
                    success.append(str(filetype))
            else:
                success.append(str(filetype))
                print("Skipping", filetype, "already have", abs(filetype_max - _args.max))
    print("Found", len(success), "/", len(total), "filetypes")
    print("Done")


if __name__ == "__main__":
    main()
