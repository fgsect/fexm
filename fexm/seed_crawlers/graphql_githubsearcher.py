import json

import requests


class GraphQlGithubSearcher(object):
    """
    This class implements an iterator interface: It starts a search and then returns repos.
    """
    RESULTS_PER_PAGE = 100  # Set the number of results displayed per page to the maximum possible
    MESSAGE_VALIDATION_FAILED = "Validation Failed"

    def get_next_page_results(self) -> {}:
        """
        Get the next page results.
        Putting this function into an external method not only makes it easier to call, but also easier to mock the API call results.
        :return: The results from the search github API call.
        """
        query = "query RepoQuery($currentcursor : String) {  search(first: 100, after: $currentcursor, type: REPOSITORY, query: \"" + self.q + "\") {    edges {      node {        ... on Repository {          name          owner {            login            id          }        }      }      cursor    }    pageInfo {      endCursor      hasNextPage    }  }}"
        variables = {"currentcursor": self.current_cursor}
        data_dict = {'query': query, "variables": variables}
        answer = requests.post("https://api.github.com/graphql", json=data_dict,
                               headers={"Authorization": "token {0}".format(self.auth)})
        if not answer.ok:
            raise Exception("Answer not ok. Message is: {0}".format(answer.text))
        return answer.text

    def set_next_page_attributes(self):
        """
        Call get_next_page_results() and sets respective properties, e.g. self.total_count, self.current_results etc.
        """

        if self.current_results is None or self.current_results["pageInfo"][
            "hasNextPage"]:  # Can we call another page (or we do not know yet?)
            self.current_results = json.loads(self.get_next_page_results())["data"]["search"]
            self.current_nodes = self.current_results["edges"]
            self.current_cursor = self.current_results["pageInfo"]["endCursor"]
        else:
            raise StopIteration()  # Well, no more pages possible

    def reset_iter(self):
        """
        Restart the iteration by setting the specific attributes.
        """
        # TODO: Look up style guides to determine where the github-api call should be made (init vs. iter vs. next)
        self.current_cursor = None
        self.current_results = None
        self.current_nodes = None
        self.item_count = 0

        self.current_object_in_page = 0
        self.set_next_page_attributes()

    def __init__(self, auth: str, searchparams: str = "size:<5000", sort:
    str = None, order: str = None, max_number_of_results: int = 100):
        """
        :param auth: The auth token
        :param searchparams: The parameters for search, e.g. language:C
        :param sort:  The parameter for sorts, e.g. stars
        :param order: The order, asc vs. desc
        """
        # Sanity checks first:
        if not isinstance(auth, str):
            raise TypeError("The auth token must be given as a string")
        if not isinstance(searchparams, str):
            raise TypeError("The search parameters must be given as a string.")
        if not isinstance(sort, str) and not sort is None:
            raise TypeError("The sort parameter must be given as a string.")
        if not isinstance(order, str) and not order is None:
            raise TypeError("The order parameter must be given as a string.")
        if not isinstance(max_number_of_results, int):
            raise TypeError("The maximum number of results must be an integer.")

        self.max_number_of_results = max_number_of_results
        self.q = searchparams
        self.sort = sort
        self.order = order
        self.auth = auth
        self.current_results = None
        self.current_nodes = None
        self.current_cursor = None
        self.item_count = 0
        self.current_object_in_page = 0

        self.reset_iter()

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
        if self.item_count >= self.max_number_of_results or not self.current_nodes:
            raise StopIteration
        else:
            if self.current_results is None or (
                    (self.current_nodes) and self.current_object_in_page >= len(self.current_nodes)):
                # We did not load a page yet or we are done with a page
                self.set_next_page_attributes()  # Call the next page and return the first object of it
                self.current_object_in_page = 1
                self.current_element = self.current_nodes[0]
            elif self.current_results and self.current_object_in_page < len(
                    self.current_nodes):  # We already have a page and are not done with it yet
                self.current_element = self.current_nodes[self.current_object_in_page]  # Return the next element
                self.current_object_in_page += 1
            self.item_count += 1
            return self.current_element
