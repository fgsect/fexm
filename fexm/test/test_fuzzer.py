import json
import unittest
import unittest.mock
import sys
from unittest import mock
import sys
import os

from helpers import utils

sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "configfinder/")))
sys.modules[
    'configfinder.builder'] = unittest.mock.Mock()  # Mocking builder like so:https://stackoverflow.com/questions/8658043/how-to-mock-an-import
sys.modules[
    'builder'] = unittest.mock.Mock()  # Mocking builder like so:https://stackoverflow.com/questions/8658043/how-to-mock-an-import
sys.modules["config_settings.MAX_TIMEOUT_PER_PACKAGE"] = 1  # unittest.mock.Mock(MAX_TIMEOUT_PER_PACKAGE=1)
import configfinder.fuzzer_wrapper
from configfinder import minimzer
import sh
import shutil
import os


class TestAflFuzzerWrapper(unittest.TestCase):
    def setUp(self):
        os.makedirs("test_data", exist_ok=True)
        self.volume_path = "test_data/test_output_volume"
        os.makedirs(self.volume_path, exist_ok=True)
        self.jpg_binary_path = "test_data/jpg_binary_main"
        aflgcc = sh.Command("afl-gcc")
        aflgcc("test/mock_data/input_mock/jpg_binary/main.c", "-o", self.jpg_binary_path)
        self.timeout_binary_path = "test_data/timeout_binary_main"
        aflgcc("test/mock_data/input_mock/timeout_binary/main.c", "-o", self.timeout_binary_path)

    def tearDown(self):
        shutil.rmtree("test_data")

    def test_multi_core_fuzzing(self):
        package_name = "jpg_parser"
        binary_path = self.jpg_binary_path
        parameter = "@@"
        fuzz_duration = 30
        seeds_dir = "test/mock_data/mock_seeds/jpg_samples"
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuid"
            fuzzer_wrapper = configfinder.fuzzer_wrapper.AflFuzzWrapper(volume_path=self.volume_path, package=package_name, binary_path=binary_path, parameter=parameter, fuzz_duration=fuzz_duration,
                                                                    seeds_dir=seeds_dir, afl_config_file_path=os.path.join(self.volume_path, package_name, os.path.basename(binary_path))+".afl_conf")
        fuzzer_wrapper.start_fuzzer(cores=4)
        self.assertTrue(os.path.exists(os.path.join(fuzzer_wrapper.get_afl_multi_core_config_dict()["output"], fuzzer_wrapper.session_name + "000/fuzzer_stats")))
        self.assertGreater(int(utils.get_afl_stats_from_syncdir(fuzzer_wrapper.multicore_dict["output"])["execs_done"]), 0)

    def test_multi_core_fuzzing_timeout(self):
        package_name = "timeut_jpg_parser"
        binary_path = self.timeout_binary_path
        parameter = "@@"
        fuzz_duration = 20
        seeds_dir = "test/mock_data/mock_seeds/jpg_samples"
        log_dict = {}
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuid"
            fuzzer_wrapper = configfinder.fuzzer_wrapper.AflFuzzWrapper(volume_path=self.volume_path, package=package_name, binary_path=binary_path, parameter=parameter, fuzz_duration=fuzz_duration,
                                                                    seeds_dir=seeds_dir, log_dict=log_dict)
        self.assertFalse(fuzzer_wrapper.start_fuzzer(cores=4))
        print(log_dict)


"""
class TestFuzzingWrapper(unittest.TestCase):
    def test_wrong_qemu_invocation(self, ):
        if os.path.exists("afl_out"):
            shutil.rmtree("afl_out")
        aflgcc = sh.Command("afl-gcc")
        aflgcc("test/mock_data/input_mock/jpg_binary/main.c", "-o", "test/mock_data/input_mock/jpg_binary/main")
        fuzzer_args = ["-Q", "-i", "test/mock_data/mock_seeds", "-o", "afl_out", "--",
                       "test/mock_data/input_mock/jpg_binary/main", "@@"]
        self.assertEqual(
            configfinder.fuzzer_wrapper.afl_fuzz_wrapper(fuzzer_args, "test/mock_data/input_mock/jpg_binary/main",
                                                         fuzz_duration=6), True)
        self.assertEqual(os.path.exists("afl_out/fuzzer_stats"), True)
        shutil.rmtree("afl_out")

    def test_wrong_nonqemu_invocation(self, ):
        if os.path.exists("afl_out"):
            shutil.rmtree("afl_out")
        gcc = sh.Command("gcc")
        command = gcc(
            ["test/mock_data/input_mock/jpg_binary/main.c", "-o", "test/mock_data/input_mock/jpg_binary/main"],
            _out=sys.stdout)
        fuzzer_args = ["-i", "test/mock_data/mock_seeds", "-o", "afl_out", "--",
                       "test/mock_data/input_mock/jpg_binary/main", "@@"]
        self.assertEqual(
            configfinder.fuzzer_wrapper.afl_fuzz_wrapper(fuzzer_args, "test/mock_data/input_mock/jpg_binary/main",
                                                         fuzz_duration=6), True)
        self.assertEqual(os.path.exists("afl_out/fuzzer_stats"), True)
        shutil.rmtree("afl_out")

    def test_fuzzer_normal(self):
        volume_path = "test/test_output_volume"
        name = "test_package"
        shutil.rmtree(volume_path, ignore_errors=True)
        os.makedirs(os.path.join(os.path.join(volume_path, name), "main/"))
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuid"
            configfinder.fuzzer_wrapper.prepare_and_start_fuzzer(parameter=None,
                                                                 seeds_dir="test/mock_data/mock_seeds/jpg_samples",
                                                                 binary_path="test/mock_data/input_mock/jpg_binary/main",
                                                                 package=name, volume_path=volume_path,
                                                                 afl_config_file_name="main.afl_config",
                                                                 fuzz_duration=10)
        with open(os.path.join(os.path.join(volume_path, name), "main.afl_config")) as testaflfp:
            aflconfigdict = json.load(testaflfp)
            self.assertEqual(aflconfigdict["afl_out_dir"],
                             "test/test_output_volume/test_package/main/afl_fuzz_mockuuid")
            self.assertTrue(os.path.exists(aflconfigdict["afl_out_dir"]))
        shutil.rmtree(volume_path, ignore_errors=True)

    def test_fuzzer_minimized(self):
        volume_path = "test/test_output_volume"
        name = "main"
        shutil.rmtree(volume_path, ignore_errors=True)
        os.makedirs(os.path.join(os.path.join(volume_path, name), "main/"))
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuidmin"
            m = minimzer.minize(parameter="@@", seeds_dir="test/mock_data/mock_seeds/jpg_samples",
                                binary_path="test/mock_data/input_mock/jpg_binary/main", package=None,
                                volume_path=volume_path, afl_config_file_name="main.afl_config", tmin_total_time=1000)
            uuidmock.return_value = "mockuuid"
            configfinder.fuzzer_wrapper.prepare_and_start_fuzzer(parameter="@@",
                                                                 seeds_dir="test/mock_data/mock_seeds/jpg_samples",
                                                                 binary_path="test/mock_data/input_mock/jpg_binary/main",
                                                                 package=None, volume_path=volume_path,
                                                                 afl_config_file_name="main.afl_config",
                                                                 fuzz_duration=10)
        with open(os.path.join(os.path.join(volume_path, name), "main.afl_config")) as testaflfp:
            aflconfigdict = json.load(testaflfp)
            self.assertEqual(aflconfigdict["afl_out_dir"],
                             os.path.join(volume_path, name, "main/afl_fuzz_mockuuid"))
            self.assertTrue(os.path.exists(aflconfigdict["afl_out_dir"]))
        shutil.rmtree(volume_path, ignore_errors=True)

    def test_fuzzer_resume(self):
        volume_path = "test/test_output_volume"
        name = "test_package"
        shutil.rmtree(volume_path, ignore_errors=True)
        os.makedirs(os.path.join(os.path.join(volume_path, name), "main/"))
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuid"
            configfinder.fuzzer_wrapper.prepare_and_start_fuzzer(parameter="@@",
                                                                 seeds_dir="test/mock_data/mock_seeds/jpg_samples",
                                                                 binary_path="test/mock_data/input_mock/jpg_binary/main",
                                                                 package=name, volume_path=volume_path,
                                                                 afl_config_file_name="main.afl_config",
                                                                 fuzz_duration=15, timeout=1500.0)
        with open(os.path.join(os.path.join(volume_path, name), "main.afl_config")) as testaflfp:
            aflconfigdict = json.load(testaflfp)
            self.assertEqual(aflconfigdict["afl_out_dir"],
                             "test/test_output_volume/test_package/main/afl_fuzz_mockuuid")
            self.assertTrue(os.path.exists(aflconfigdict["afl_out_dir"]))
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "resume"
            configfinder.fuzzer_wrapper.resume_fuzzer("test/test_output_volume/test_package/main/afl_fuzz_mockuuid",
                                                      binary_path="test/mock_data/input_mock/jpg_binary/main",
                                                      parameter="@@", timeout=1500.0, fuzz_duration=10)
        shutil.rmtree(volume_path, ignore_errors=True)

    def test_fuzzer_minimized_failed(self):
        volume_path = "test/test_output_volume"
        name = "main"
        shutil.rmtree(volume_path, ignore_errors=True)
        os.makedirs(os.path.join(os.path.join(volume_path, name), "main/"))
        with mock.patch("uuid.uuid4") as uuidmock:
            uuidmock.return_value = "mockuuidmin"
            m = minimzer.minize(parameter="@@", seeds_dir="test/mock_data/mock_seeds/jpg_samples",
                                binary_path="test/mock_data/input_mock/jpg_binary/main", package=None,
                                volume_path=volume_path, afl_config_file_name="main.afl_config", tmin_total_time=1000)
            uuidmock.return_value = "mockuuid"
            for file in os.listdir(os.path.join(volume_path, name, "main/afl_tmin_mockuuidmin/")):
                with open(os.path.join(os.path.join(volume_path, name, "main/afl_tmin_mockuuidmin/", file)),
                          "w"):
                    pass
            # shutil.rmtree(os.path.join(volume_path,name,"main/afl_tmin_mockuuidmin/"))
            configfinder.fuzzer_wrapper.prepare_and_start_fuzzer(parameter=None,
                                                                 seeds_dir="test/mock_data/mock_seeds/jpg_samples",
                                                                 binary_path="test/mock_data/input_mock/jpg_binary/main",
                                                                 package=None, volume_path=volume_path,
                                                                 afl_config_file_name="main.afl_config",
                                                                 fuzz_duration=10)
        # with open(os.path.join(os.path.join(volume_path, name), "main.afl_config")) as testaflfp:
        #    aflconfigdict = json.load(testaflfp)
        #    self.assertEqual(aflconfigdict["afl_out_dir"],
        #                     os.path.join(volume_path, name, "main/afl_fuzz_mockuuid"))
        #   self.assertTrue(os.path.exists(aflconfigdict["afl_out_dir"]))
        shutil.rmtree(volume_path, ignore_errors=True)
"""