import unittest
import os

from helpers import configuration_utils

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder.heuristic_config_creator import HeuristicConfigCreator


class TestConfigurationUtils(unittest.TestCase):
    def test_get_repo_name_from_git_download_link(self):
        download_link = "https://github.com/google/pik"
        self.assertEqual(configuration_utils.get_repo_name_from_git_download_link(download_link=download_link), "pik")

    def test_get_author_name_from_git_download_link(self):
        download_link = "https://github.com/google/pik"
        self.assertEqual(configuration_utils.get_author_name_from_git_download_link(download_link=download_link),
                         "google")

    def test_get_relative_binary_path(self):
        binary_path = "/usr/bin/su"
        repo_path = "/usr/bin"
        self.assertEqual(configuration_utils.get_relative_binary_path(binary_path, repo_path), "su")
        binary_path = "/usr/bin/su"
        repo_path = "asdf"
        with self.assertRaises(ValueError):
            configuration_utils.get_relative_binary_path(binary_path, repo_path)


if __name__ == '__main__':
    unittest.main()
