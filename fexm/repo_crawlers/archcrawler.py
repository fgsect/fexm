#!/usr/bin/env python3
import json
import logging

import os
import requests

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from helpers import exceptions


class ArchCrawler(object):
    """
    This class implements an iterator interface: It starts a search and then returns repos.
    """
    BASE_URL = "https://www.archlinux.org/packages/search/json/?"

    def issue_query(self):
        logging.info("Requesting: {0}".format(self.BASE_URL + self.q + "&page=" + str(self.current_page)))
        return json.loads(requests.get(self.BASE_URL + self.q + "&page=" + str(self.current_page)).text)

    def get_next_page_results(self) -> {}:
        """
        Get the next page results. 
        Putting this function into an external method not only makes it easier to call, but also easier to mock the API call results.
        :return: The results from the search github API call.
        """
        return self.issue_query()

    def set_next_page_attributes(self):
        """
        Call get_next_page_results() and sets respective properties, e.g. self.total_count, self.current_results etc.
        """

        results = self.get_next_page_results()
        if results.get("valid") and results.get("valid") == False:
            raise exceptions.ParametersNotAcceptedException
        self.num_pages = int(results["num_pages"])
        logging.info("Our search query yielded a total number of " + str(self.num_pages) + " num_pages")
        self.current_results = results["results"]
        self.current_object_in_page = 0
        self.current_page += 1

    def reset_iter(self):
        """
        Restart the iteration by setting the specific attributes. 
        """
        # TODO: Look up style guides to determine where the github-api call should be made (init vs. iter vs. next)
        self.item_count = 0
        self.current_page = 1
        self.current_results = None
        self.set_next_page_attributes()

    def __init__(self, query: str = "desc=pcap", max_number_of_results: int = 100000):
        """
        :param searchparams: The parameters for search, e.g. language:C 
        :param sort:  The parameter for sorts, e.g. stars
        :param order: The order, asc vs. desc
        """
        # Sanity checks first:
        if not isinstance(query, str):
            raise TypeError("The search parameters must be given as a string.")
        if not isinstance(max_number_of_results, int):
            raise TypeError("The maximum number of results must be an integer.")

        self.max_number_of_results = max_number_of_results
        self.q = query
        # self.reset_iter()

    def __iter__(self):
        """
        Start a new iter - reset the iteration count
        """

        self.reset_iter()
        return self

    def __next__(self):
        """
        Next iter result.
        Basic idea: Call the paginated search function until a) the maximum number of results is reached or b) no more results can be found.
        :return: The next "Repo" description form the github api. Contains url,html_url,language,stars,etc...
        """
        if self.item_count >= self.max_number_of_results or self.current_page > (
                self.num_pages + 1) or not self.current_results:
            raise StopIteration
        else:
            if self.current_results is None or (
                    (self.current_results) and self.current_object_in_page >= len(self.current_results)):
                # We did not load a page yet or we are done with a page
                self.set_next_page_attributes()  # Call the next page and return the first object of it
                if self.current_page > (self.num_pages + 1):
                    raise StopIteration
                self.current_object_in_page = 1
                self.current_element = self.current_results[0]
                logging.info("Currently at page {0}".format(self.current_page))
            elif self.current_results and self.current_object_in_page < len(
                    self.current_results):  # We already have a page and are not done with it yet
                self.current_element = self.current_results[self.current_object_in_page]  # Return the next element
                self.current_object_in_page += 1
            self.item_count += 1
            return self.current_element

    @staticmethod
    def get_package_version(package: str):
        package_dict = json.loads(
            requests.get("https://www.archlinux.org/packages/search/json/?name={package}".format(package=package)).text)
        if not package_dict.get("results"):
            return None
        else:
            ver = package_dict["results"][0].get("pkgver")
            return ver
