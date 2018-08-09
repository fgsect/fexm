import os

import unittest.mock

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import wrapper.inference_wrapper
from docker import docker_setup_base


class TestInferenceWrapper(unittest.TestCase):
    def test_input_vector(self):
        # Build the base image:
        docker_setup_base.main(seeds_path="mock_data/mock_seeds/")
        iw = wrapper.inference_wrapper.InferenceWrapper(binary_path="mock_data/input_mock/jpg_binary/crawl",
                                                        repo_path="mock_data/input_mock/jpg_binary", qemu=True,
                                                        timeout=3)
        cli_config = iw.get_input_vectors()
        self.assertEqual(len(cli_config), 1)

    def test_input_vector_timeout(self):
        # Build the base image:
        docker_setup_base.main(seeds_path="mock_data/mock_seeds/")
        iw = wrapper.inference_wrapper.InferenceWrapper(binary_path="mock_data/input_mock/timeout_binary/crawl",
                                                        repo_path="mock_data/input_mock/timeout_binary", qemu=True,
                                                        timeout=1)
        cli_config = iw.get_input_vectors()

    def test_input_vector_timeout(self):
        # Build the base image:
        docker_setup_base.main(seeds_path="mock_data/mock_seeds/")
        iw = wrapper.inference_wrapper.InferenceWrapper(binary_path="mock_data/input_mock/timeout_binary/crawl",
                                                        repo_path="mock_data/input_mock/timeout_binary", qemu=True,
                                                        timeout=1)
        iw.DOCKER_TIMEOUT = 1
        cli_config = iw.get_input_vectors()

    def test_non_instrumented_binary(self):
        # Build the base image:
        docker_setup_base.main(seeds_path="mock_data/mock_seeds/")
        iw = wrapper.inference_wrapper.InferenceWrapper(binary_path="mock_data/input_mock/jpg_binary/crawl",
                                                        repo_path="mock_data/input_mock/jpg_binary", qemu=False,
                                                        timeout=3)
        cli_config = iw.get_input_vectors()

    def test_extract_cliconfig_json_from_docker_output(self):
        json_string = wrapper.inference_wrapper.InferenceWrapper.extract_cliconfig_json_from_docker_output(
            "[<cli_config.CliConfig object at 0x7fe1e5b04550>]\nJSON Result\n[{\"coverage\": 65, \"file_type\": \"seeds//jpg_samples\", \"parameter\": null}]\nEnd JSON Result")
        self.assertEqual(json_string, '[{"coverage": 65, "file_type": "seeds//jpg_samples", "parameter": null}]')

    def test_get_cli_config_list_from_docker_output(self):
        cli_config_list = wrapper.inference_wrapper.InferenceWrapper.get_cli_config_list_from_docker_output(
            "[<cli_config.CliConfig object at 0x7fe1e5b04550>]\nJSON Result\n[{\"coverage\": 65, \"file_type\": \"seeds//jpg_samples\", \"parameter\": null}]\nEnd JSON Result")
        self.assertEqual(len(cli_config_list), 1)
        self.assertEqual(cli_config_list[0].parameter, None)


if __name__ == '__main__':
    unittest.main()
