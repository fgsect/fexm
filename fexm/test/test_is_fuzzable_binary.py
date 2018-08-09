from unittest import TestCase
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import helpers.utils
import subprocess


class TestIs_fuzzable_binary(TestCase):
    def test_is_fuzzable_binary(self):
        self.assertTrue(helpers.utils.is_fuzzable_binary("/usr/bin/convert"))
        self.assertFalse(helpers.utils.is_fuzzable_binary("/usr/bin/wireshark"))

    def test_return_fuzzable_binaries_from_file_list(self):
        self.assertEqual(helpers.utils.return_fuzzable_binaries_from_file_list(
            ["bin/", "/usr/bin/convert", "/usr/bin/wireshark", "/usr/bin/gif2png"]),
                         ["/usr/bin/convert", "/usr/bin/gif2png"])

    def test_count_number_of_tuples_per_binary(self):
        subprocess.check_output(
            "afl-gcc mock_data/input_mock/jpg_binary/main.c -o mock_data/input_mock/jpg_binary/main", shell=True)
        helpers.utils.count_number_of_tuples_per_binary("mock_data/input_mock/jpg_binary/main")
        subprocess.check_output(
            "afl-gcc -s mock_data/input_mock/jpg_binary/main.c -o mock_data/input_mock/jpg_binary/main", shell=True
            )
        helpers.utils.count_number_of_tuples_per_binary(
            "mock_data/input_mock/jpg_binary/main")  # This does not work yet...
