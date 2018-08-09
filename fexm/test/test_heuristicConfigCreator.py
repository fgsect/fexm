from unittest import TestCase
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.getcwd(), "configfinder/")))
from configfinder.heuristic_config_creator import HeuristicConfigCreator
import config_settings
import configfinder.config_settings


class TestServerInference(TestCase):
    def setUp(self):
        import sh
        self.server_binary_path = os.path.abspath("test/mock_data/input_mock/server_binary/main")
        aflgcc = sh.Command("afl-gcc")
        aflgcc("test/mock_data/input_mock/server_binary/main.c", "-o", self.server_binary_path)
        self.old_cwd = os.getcwd()
        self.new_cwd = "/tmp/input_inference_test"
        self.seeds_path = os.path.abspath("test/mock_data/mock_seeds")
        config_settings.PREENY_PATH = os.path.abspath("docker_scripts/afl_base_image/preeny")
        configfinder.config_settings.PREENY_PATH = os.path.abspath("docker_scripts/afl_base_image/preeny")
        os.makedirs(self.new_cwd, exist_ok=True)
        os.chdir(self.new_cwd)

    def tearDown(self):
        import shutil

        os.chdir(self.old_cwd)
        os.remove(self.server_binary_path)
        shutil.rmtree(self.new_cwd)

    def test_server_inference(self):
        h = HeuristicConfigCreator(binary_path=self.server_binary_path, timeout=1.5, qemu=False,
                                   results_out_dir=os.getcwd(), seeds_dir=self.seeds_path, verbose=False)
        self.assertTrue(h.try_invocation("", stdin=True))
        param_set = h.figure_out_parameters()
        self.assertTrue("" in param_set and len(param_set) == 1)


class TestStdinInference(TestCase):
    def setUp(self):
        import sh
        self.stdin_binary_path = os.path.abspath("test/mock_data/input_mock/stdin_binary/main")
        aflgcc = sh.Command("afl-gcc")
        aflgcc("test/mock_data/input_mock/stdin_binary/main.c", "-o", self.stdin_binary_path)
        self.old_cwd = os.getcwd()
        self.seeds_path = os.path.abspath("test/mock_data/mock_seeds")
        self.new_cwd = "/tmp/input_inference_test"
        os.makedirs(self.new_cwd, exist_ok=True)
        os.chdir(self.new_cwd)

    def tearDown(self):
        import shutil
        os.chdir(self.old_cwd)
        os.remove(self.stdin_binary_path)
        shutil.rmtree(self.new_cwd)

    def test_stdin_inference(self):
        h = HeuristicConfigCreator(binary_path=self.stdin_binary_path, timeout=1.5, qemu=False,
                                   results_out_dir=os.getcwd(), seeds_dir=self.seeds_path)
        self.assertTrue(h.try_invocation("", stdin=True))
        param_set = h.figure_out_parameters()
        self.assertTrue("" in param_set and len(param_set) == 1)

"""
class TestHeuristicConfigCreator(TestCase):
    def test_get_best_input_vector(self):
        h = HeuristicConfigCreator(binary_path="test/mock_data/input_mock/jpg_binary/main", timeout=1.5, qemu=False,
                                   results_out_dir=os.getcwd(), seeds_dir="test/mock_data/mock_seeds")
        print(h.infer_input_vectors())

    def test_xmllint_inference(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/xmllint", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="test/mock_data/mock_seeds")
        print("Libxml input vector", [h.__dict__ for h in h.infer_input_vectors()])

    def test_converter_inference(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/convert", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="test/mock_data/mock_seeds")
        print("Inferred filetype:", h.infer_input_vectors()[0].file_types)
        # h.parameters = ["@@ /dev/null"]
        # h.infer_filetypes()

    def test_probe_possible_filetypes_for_parameter(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/convert", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="test/mock_data/mock_seeds")
        print(h.probe_possible_filetypes_for_parameter("@@ /dev/null"))

    def test_try_invocation(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/aide", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="test/mock_data/mock_seeds")
        self.assertFalse(h.try_invocation("@@"))

    def test_get_invocation(self):
        h = HeuristicConfigCreator(binary_path="tcpdump", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="test/mock_data/mock_seeds")
        params = h.figure_out_parameters()
        self.assertTrue("-nvr @@" in params and "-nvr @@ /dev/null" not in params)

        # h = HeuristicConfigCreator(binary_path="/usr/bin/ccrypt",timeout=1.5,qemu=True,results_out_dir=os.getcwd(),seeds_dir="mock_data/mock_seeds")
        # print(h.try_inferring_parameter_candidates_from_help())
        # params = h.figure_out_parameters()
        # print("Param for ccrypt:",params)
        # self.assertTrue("-k @@" in params or "--keyfile @@" in params)
        h = HeuristicConfigCreator(binary_path="/usr/bin/convert", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="test/mock_data/mock_seeds")
        params = h.figure_out_parameters()
        self.assertTrue("@@ /dev/null" in params)
        h = HeuristicConfigCreator(binary_path="/usr/bin/composite", timeout=1.5, qemu=True,
                                   results_out_dir=os.getcwd(), seeds_dir="test/mock_data/mock_seeds")
        params = h.figure_out_parameters()
        print(params)
"""