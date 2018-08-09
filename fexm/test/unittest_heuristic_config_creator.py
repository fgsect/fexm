import unittest
import os

from configfinder.cli_config import CliConfig
import unittest.mock

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder.heuristic_config_creator import HeuristicConfigCreator
import subprocess
import helpers.exceptions


class TestHeuristicConfigCreator(unittest.TestCase):
    def test_check_strace_for_fopen(self):
        strace = 'open("log.log", O_RDONLY)               = 4'
        self.assertEqual(HeuristicConfigCreator.check_strace_for_fopen(strace, "log.log"), True)
        strace = 'open("log.log", O_WRONLY)               = 4'
        self.assertEqual(HeuristicConfigCreator.check_strace_for_fopen(strace, "log.log"), False)
        strace = 'asfdlajsdf\nopen("log.log", O_RRDONLY)               = 4\nalsjsfdlsadjf'
        self.assertEqual(HeuristicConfigCreator.check_strace_for_fopen(strace, "log.log"), True)
        # Test a longer string:
        strace = 'stat("../data/getseeds/sample_dataset/dummyfile.txt.ecp", {st_mode = S_IFREG | 0664, st_size = 48, ...}) = 0 \n' \
                 'open("../data/getseeds/sample_dataset/dummyfile.txt.ecp", O_RDONLY) = 4 \n' \
                 'lseek(4, 0, SEEK_CUR)                   = 0'
        self.assertEqual(
            HeuristicConfigCreator.check_strace_for_fopen(strace, "../data/getseeds/sample_dataset/dummyfile.txt.ecp"),
            True)
        strace = 'openat(AT_FDCWD, "seeds/pcap_samples/pcap_aa75722c-a2fe-4e31-a751-15f606b34aa3.pcap", O_RDONLY) = 3'
        self.assertEqual(HeuristicConfigCreator.check_strace_for_fopen(strace,
                                                                       "seeds/pcap_samples/pcap_aa75722c-a2fe-4e31-a751-15f606b34aa3.pcap"),
                         True)

    def test_get_coverage_from_afl_cmin_ouput(self):
        afl_cmin_ouput = "[+] Found 964 unique tuples across 1 files.\n[*] Finding best candidates for each tuple..."
        self.assertEqual(HeuristicConfigCreator.get_coverage_from_afl_cmin_ouput(afl_cmin_ouput), 964)

    def test_get_best_input_vector(self):
        h = HeuristicConfigCreator(binary_path="test",
                                   dummyfiles_path=os.getcwd())  # We need to provide valid paths to pass the sanity checks
        c1 = CliConfig(invocation="-f", coverage=50, filetype=".test1")
        c2 = CliConfig(invocation="-g", coverage=80, filetype=".test2")
        h.cli_config_list = [c1, c2]
        self.assertEqual(h.get_max_coverage_input_vector(), c2)

    def test_get_routine_dict(self):
        binary_path = "bin/bla/test.bin"
        repo_path = "bin/"
        filetype = "testfiletype"
        h = HeuristicConfigCreator(binary_path=binary_path, repo_path=repo_path, dummyfiles_path=os.getcwd())
        c1 = CliConfig(invocation="-f", coverage=50, filetype=".testfiletype")
        h.cli_config_list = [c1]
        routine_dict = h.get_routine_dict()
        # Test certain key-value pairs in the routine dict
        self.assertEqual((routine_dict["job_desc"][0])["seed_dir"], os.getcwd() + "/.testfiletype_samples")
        self.assertEqual(routine_dict["fuzz_cmd"], "bla/test.bin -f @@")
        h = HeuristicConfigCreator(binary_path=binary_path, repo_path=repo_path,
                                   dummyfiles_path=os.getcwd())
        c1 = CliConfig(invocation=None, coverage=50, filetype=".testfiletype")
        h.cli_config_list = [c1]
        routine_dict = h.get_routine_dict()
        self.assertEqual(routine_dict["fuzz_cmd"], "bla/test.bin @@")


@unittest.mock.patch("subprocess.check_output")
class TestHeuristicConfigCreatorInvocations(unittest.TestCase):
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

    def test_try_filetype_with_coverage_via_afl_fail(self, subprocess_check_output: unittest.mock.MagicMock):
        binary_path = "tshark"
        repo_path = ""
        max_timeout = 2500
        memory_limit = "none"

        h = HeuristicConfigCreator(binary_path=binary_path, repo_path=repo_path,
                                   dummyfiles_path=os.getcwd())
        h.MAX_TIMEOUT = max_timeout
        h.memory_limit = memory_limit
        h.FAILED_INVOCATIONS_THRESHOLD = 2
        h.afl_cmin_path = "afl-cmin"
        mocked_return_value = "cmin-output"
        subprocess_check_output.return_value = bytes(mocked_return_value, encoding="utf-8")
        subprocess_check_output.side_effect = subprocess.CalledProcessError(returncode=-1, cmd="alja")
        h.try_filetype_with_coverage_via_afl("-f", os.getcwd(), file_type=".test")
        with self.assertRaises(helpers.exceptions.NoCoverageInformation):
            h.try_filetype_with_coverage_via_afl("-g", os.getcwd(), file_type=".test")


class TestHeuristicConfigCreatorFileHandlings(unittest.TestCase):
    def test_create_bash_in_execution_path(self):
        # For now, just test that the method does not raise an exception
        binary_path = os.getcwd() + "/" + "tshark"
        repo_path = os.getcwd()
        filetype = "testfiletype"
        h = HeuristicConfigCreator(binary_path=binary_path, repo_path=repo_path,
                                   dummyfiles_path=os.getcwd())
        c1 = CliConfig(invocation="-f", coverage=50, filetype=filetype)
        h.cli_config_list = [c1]
        with unittest.mock.patch('json.dump', return_value=True) as json_dump_function:
            with unittest.mock.patch("builtins.open") as open_object:
                fileobject = unittest.mock.MagicMock()
                fileobject.write.return_value = True  # Some random return value
                open_object.return_value = fileobject
                h.create_bash_in_execution_path()
                self.assertEqual(json_dump_function.call_count, 1)


if __name__ == '__main__':
    unittest.main()
