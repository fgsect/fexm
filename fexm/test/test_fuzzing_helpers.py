import json
import shutil
import unittest
import unittest.mock
import sys
from unittest import mock
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "configfinder/")))
sys.modules[
    'configfinder.builder'] = unittest.mock.Mock()  # Mocking builder like so:https://stackoverflow.com/questions/8658043/how-to-mock-an-import
sys.modules[
    'builder'] = unittest.mock.Mock()  # Mocking builder like so:https://stackoverflow.com/questions/8658043/how-to-mock-an-import
sys.modules["config_settings.MAX_TIMEOUT_PER_PACKAGE"] = 1  # unittest.mock.Mock(MAX_TIMEOUT_PER_PACKAGE=1)
import helpers.utils
import sh
import os


class TestInstrumentationHelpers(unittest.TestCase):
    def setUp(self):
        self.jpg_binary_path = "/tmp/jpg_binary_main"
        aflgcc = sh.Command("afl-gcc")
        aflgcc("test/mock_data/input_mock/jpg_binary/main.c", "-o", self.jpg_binary_path)
        self.timeout_binary_path = "/tmp/timeout_binary_main"
        aflgcc("test/mock_data/input_mock/timeout_binary/main.c", "-o", self.timeout_binary_path)
        self.shared_library_path = "/tmp/shared_library.so"
        aflgcc("test/mock_data/input_mock/shared_library_mock/shared.c", "-o", self.shared_library_path, "-shared", "-fPIC")

    def tearDown(self):
        os.remove(self.jpg_binary_path)
        os.remove(self.timeout_binary_path)
        os.remove(self.shared_library_path)

    def test_inference_possible(self):
        self.assertTrue(helpers.utils.inference_possible(self.jpg_binary_path))
        self.assertTrue(helpers.utils.inference_possible(self.timeout_binary_path))
        self.assertTrue(helpers.utils.inference_possible("/bin/echo"))
        self.assertFalse(helpers.utils.inference_possible(self.shared_library_path))

    def test_binary_is_instrumented_with_afl(self):
        self.assertTrue(helpers.utils.binary_is_instrumented_with_afl(self.jpg_binary_path))
        self.assertTrue(helpers.utils.binary_is_instrumented_with_afl(self.timeout_binary_path))
        self.assertFalse(helpers.utils.binary_is_instrumented_with_afl("/bin/echo"))
        self.assertTrue(helpers.utils.binary_is_instrumented_with_afl(self.shared_library_path))

    def test_return_fuzzable_binaries_from_file_list(self):
        list_of_fuzzable_bins = helpers.utils.return_fuzzable_binaries_from_file_list([self.jpg_binary_path,
                                                                                       self.timeout_binary_path, self.shared_library_path, "/bin/echo"])
        self.assertIn(self.jpg_binary_path, list_of_fuzzable_bins)
        self.assertIn("/bin/echo", list_of_fuzzable_bins)
        self.assertIn(self.timeout_binary_path, list_of_fuzzable_bins)
        self.assertNotIn(self.shared_library_path, list_of_fuzzable_bins)


class TestFuzzingHelpers(unittest.TestCase):
    def setUp(self):
        self.mock_fuzzing_session_path = "test/mock_data/fuzzing_session"
        import tarfile
        tar = tarfile.open("test/mock_data/fuzzing_session.tar")
        tar.extractall(path=self.mock_fuzzing_session_path)
        tar.close()

    def tearDown(self):
        shutil.rmtree(self.mock_fuzzing_session_path)

    def test_get_afl_stats_from_syncdir(self):
        self.assertEqual(int(helpers.utils.get_afl_stats_from_syncdir(os.path.join(self.mock_fuzzing_session_path, "fuzzing_ession/mock_multicore_session/"))["pending_total"]), 44)
        self.assertEqual(int(helpers.utils.get_afl_stats_from_syncdir(os.path.join(self.mock_fuzzing_session_path, "fuzzing_ession/mock_multicore_session/"))["unique_crashes"]), 0)
