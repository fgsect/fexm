from unittest import TestCase

# from configfinder.pcap_parser import Overmind, FileBackend
import os

from fexm.configfinder.pcap_parser import Overmind


class TestPcapParser(TestCase):
    def test_pcap_analysis(self):
        h = Overmind(backend=FileBackend(outfilder="/dev/null")).analyze(file="mock_data/pcap_sample/http.cap",
                                                                         backend=FileBackend(outfolder="/dev/null"))
        h.infer_input_vectors()
        h.print_json_input_vectors()

    def test_converter_inference(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/convert", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="mock_data/mock_seeds")
        print("Inferred filetype:", h.infer_input_vectors()[0].file_types)
        # h.parameters = ["@@ /dev/null"]
        # h.infer_filetypes()

    def test_probe_possible_filetypes_for_parameter(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/convert", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="mock_data/mock_seeds")
        print(h.probe_possible_filetypes_for_parameter("@@ /dev/null"))

    def test_try_invocation(self):
        h = HeuristicConfigCreator(binary_path="/usr/bin/aide", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="mock_data/mock_seeds")
        self.assertFalse(h.try_invocation("@@"))

    def test_get_invocation(self):
        h = HeuristicConfigCreator(binary_path="tcpdump", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="mock_data/mock_seeds")
        params = h.figure_out_parameters()
        self.assertTrue("-nvr @@" in params and "-nvr @@ /dev/null" not in params)

        # h = HeuristicConfigCreator(binary_path="/usr/bin/ccrypt",timeout=1.5,qemu=True,results_out_dir=os.getcwd(),seeds_dir="mock_data/mock_seeds")
        # print(h.try_inferring_parameter_candidates_from_help())
        # params = h.figure_out_parameters()
        # print("Param for ccrypt:",params)
        # self.assertTrue("-k @@" in params or "--keyfile @@" in params)
        h = HeuristicConfigCreator(binary_path="/usr/bin/convert", timeout=1.5, qemu=True, results_out_dir=os.getcwd(),
                                   seeds_dir="mock_data/mock_seeds")
        params = h.figure_out_parameters()
        self.assertTrue("@@ /dev/null" in params)
        h = HeuristicConfigCreator(binary_path="/usr/bin/composite", timeout=1.5, qemu=True,
                                   results_out_dir=os.getcwd(), seeds_dir="mock_data/mock_seeds")
        params = h.figure_out_parameters()
        print(params)
