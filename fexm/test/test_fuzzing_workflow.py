import json
import unittest.mock
from unittest import mock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "configfinder/")))
import configfinder
import helpers.utils

sys.modules[
    'configfinder.builder'] = unittest.mock.Mock()  # Mocking builder like so:https://stackoverflow.com/questions/8658043/how-to-mock-an-import
sys.modules[
    'builder'] = unittest.mock.Mock()  # Mocking builder like so:https://stackoverflow.com/questions/8658043/how-to-mock-an-import
sys.modules["config_settings.MAX_TIMEOUT_PER_PACKAGE"] = 1  # unittest.mock.Mock(MAX_TIMEOUT_PER_PACKAGE=1)
import configfinder.fuzzer_wrapper
from configfinder import minimzer
from configfinder.heuristic_config_creator import HeuristicConfigCreator
from configfinder import helpers
import sh
import shutil
import os


class TestFuzzManager(unittest.TestCase):
    """
    """

    def test_fuzzer_workflow(self):
        log_dict = {}
        log_dict["mock_data/input_mock/jpg_binary/main"] = {"fuzz_debug": {}}

        volume_path = "test_output_volume"
        package_name = ""
        shutil.rmtree(volume_path, ignore_errors=True)
        os.makedirs(os.path.join(os.path.join(volume_path, package_name), "main/"))
        clangfast = sh.Command("afl-clang-fast")
        clangfast(["mock_data/input_mock/mixed_fbinary/main.c", "-o", "mock_data/input_mock/mixed_fbinary/main"])
        h = HeuristicConfigCreator(binary_path="mock_data/input_mock/mixed_fbinary/main",
                                   results_out_dir=os.path.join(volume_path, package_name, "main/"), qemu=False,
                                   seeds_dir="mock_data/mock_seeds/")
        h.infer_input_vectors()
        input_vectors = h.get_input_vectors_sorted()
        helpers.utils.store_input_vectors_in_volume(package_name, "main", volume_path, input_vectors)
        with open(os.path.join(volume_path, package_name, "main.json")) as json_filepointer:
            configurations = json.load(json_filepointer)
            conf = configurations[0]
        seeds = helpers.utils.get_seeds_dir_from_input_vector_dict(conf, package_name, "main")
        print(conf)
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuidmin"
            m = minimzer.minize(parameter=conf["parameter"], seeds_dir=seeds,
                                binary_path="mock_data/input_mock/jpg_binary/main", package=package_name,
                                volume_path=volume_path, afl_config_file_name="main.afl_config", tmin_total_time=1000)
            uuidmock.return_value = "mockuuid"
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuid"
            configfinder.fuzzer_wrapper.prepare_and_start_fuzzer(parameter="@@",
                                                                 seeds_dir="mock_data/mock_seeds/jpg_samples",
                                                                 binary_path="mock_data/input_mock/jpg_binary/main",
                                                                 package=package_name, volume_path=volume_path,
                                                                 afl_config_file_name="main.afl_config",
                                                                 fuzz_duration=15, timeout=1500.0, log_dict=log_dict)
        with open(os.path.join(os.path.join(volume_path, "main"), "main.afl_config")) as testaflfp:
            aflconfigdict = json.load(testaflfp)
            self.assertEqual(aflconfigdict["afl_out_dir"], "test_output_volume/main/main/afl_fuzz_mockuuid")
            self.assertTrue(os.path.exists(aflconfigdict["afl_out_dir"]))
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "resume"
            configfinder.fuzzer_wrapper.resume_fuzzer("test_output_volume/main/main/afl_fuzz_mockuuid",
                                                      binary_path="mock_data/input_mock/jpg_binary/main",
                                                      parameter="@@", timeout=1500.0, fuzz_duration=1)
        shutil.rmtree(volume_path, ignore_errors=True)
