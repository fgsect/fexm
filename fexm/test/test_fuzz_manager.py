import unittest
import fuzz_manager.fuzz_manager_round_robin


@unittest.mock.path("os.path.isdir")
@unittest.mock.path("os.path.listdir")
@unittest.mock.patch("subprocess.check_output")
class TestFuzzManager(unittest.TestCase):
    """
    This class is for testing the subprocess invocations and thus 
    we need to mock subprocess.check_output
    """

    def test_invoke_afl_cmin(self, subprocess_check_output: unittest.mock.MagicMock):
        binary_path = "tshark"
        repo_path = ""
        max_timeout = 2500
        memory_limit = "none"
        h = HeuristicConfigCreator(binary_path=binary_path, repo_path=repo_path, dummyfile_path=__file__,
                                   dummyfiles_path=os.getcwd())
        h.MAX_TIMEOUT = max_timeout
        h.memory_limit = memory_limit
        h.afl_cmin_path = "afl-cmin"
        mocked_return_value = "cmin-output"
        subprocess_check_output.return_value = bytes(mocked_return_value, encoding="utf-8")
        self.assertEqual(h.invoke_afl_cmin("-f", "tmp_dir"), mocked_return_value)
