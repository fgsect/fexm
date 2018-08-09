import collections
import json
import multiprocessing
import multiprocessing.pool
import subprocess
import uuid

import operator
import os
import re
import scipy as sp
import shutil
from enum import Enum

import config_settings
import helpers.utils
from cli_config import CliConfig
from helpers.utils import check_output_with_timeout_command

logger = helpers.utils.init_logger(__name__)


class Channel(Enum):
    FILE = 1
    STDIN = 2
    NETWORK = 3


class Invocation:

    def __init__(self, invocation: str, input_channel: Channel):
        self.invocation = invocation
        self.input_channel = input_channel


class HeuristicConfigCreator(object):
    """
    In this class, an elf binary is taken and a configuration is returned.
    """
    MAX_TIMEOUT = 1.2  # the threshold after which a child process is killed ( when inferring command line arguments)
    MEMORY_LIMIT = config_settings.MEMORY_LIMIT  # afl-showmap Memory limit for child process. This need to be high, especially in QEMU mode.
    FAILED_INVOCATIONS_THRESHOLD = config_settings.FAILED_INVOCATIONS_THRESHOLD  # After how many failed invocations do we skip the whole binary?
    AFL_CMIN_COV_ONLY_PATH = "/usr/local/bin/afl_cmin_cov_only"  # Path to the modified afl script, that shows only the coverage but does not create an afl-cmin directory

    @staticmethod
    def check_strace_for_fopen(strace: str, dummyfile_path: str) -> bool:
        """
        Check the system of a binary for a syscall indicating that the file with path 
        dummyfile_path has been openen
        :param strace: The trace of the system cals
        :param dummyfile_path: The path to the dummyfile
        :return: True if yes, False if not
        """
        # print(strace)
        if isinstance(strace, str):
            strace_lines = strace.split("\n")  # type: [str]
        elif isinstance(strace, list) and all(isinstance(s, str) for s in strace):
            strace_lines = strace  # We assume the output has already been split
        else:
            raise TypeError("The system trace must be given as a string or as a list of strings.")
        open_strace_re = '^(.*?)open(at)?\((.*?)"(.*?)' + dummyfile_path + '"(.*?)$(.*)'
        matcher = re.compile(open_strace_re)
        id = None
        for line in strace_lines:
            # if (matcher.match(line)) and ("O_WRONLY" not in line):
            if dummyfile_path in line and ("read" in line or ("open" in line and "O_WRONLY" not in line)):
                id = int(line.split("=")[-1])
                break
        if not id:
            return False
        for line in strace_lines:
            if "read" in line and str(id) in line:
                return True
        return False

    @staticmethod
    def check_strace_for_stdinread(strace: str):
        """
        Check the system of a binary for a syscall indicating that the programm reads from stdin.
        :param strace: The trace of the system cals
        :return: True if yes, False if not
        """
        if isinstance(strace, str):
            strace_lines = strace.split("\n")  # type: [str]
        elif isinstance(strace, list) and all(isinstance(s, str) for s in strace):
            strace_lines = strace  # We assume the output has already been split
        else:
            raise TypeError("The system trace must be given as a string or as a list of strings.")
        open_strace_re = '^(.*?)read\(\d</dev/pts/0>(.*?)'
        matcher = re.compile(open_strace_re)
        for line in strace_lines:
            logger.debug(line)
            if (matcher.match(line)):
                return True
        return False

    @staticmethod
    def get_coverage_from_afl_cmin_ouput(afl_cmin_output: str) -> int:
        """
        Extract the number of tuples covered from the afl-cmin output. 
        :param afl_cmin_output: A string that is the terminal output of afl-cmin
        :return: The number of tuples covered, 0 if unable to extract from output.
        """
        if isinstance(afl_cmin_output, str):
            afl_cmin_output_lines = afl_cmin_output.split("\n")  # type: [str]
        elif isinstance(afl_cmin_output, list) and all(isinstance(s, str) for s in afl_cmin_output):
            afl_cmin_output_lines = afl_cmin_output  # We assume the output has already been split
        else:
            raise TypeError("The afl-cmin ouptut must be given as a string or as a list of strings.")
        tuples_found_re = "\[\+\] Found (\d*) unique tuples across (.*) files."
        matcher = re.compile(tuples_found_re)
        for line in afl_cmin_output_lines:
            result = matcher.match(line)
            if result:
                return int(result.groups(0)[0])  # We need the first group
        return 0

    @staticmethod
    def get_coverage_from_afl_showmap_output(afl_showmap_output: str) -> int:
        if isinstance(afl_showmap_output, str):
            afl_showmap_output_lines = afl_showmap_output.split("\n")  # type: [str]
        elif isinstance(afl_showmap_output, list) and all(isinstance(s, str) for s in afl_showmap_output):
            afl_showmap_output_lines = afl_showmap_output  # We assume the output has already been split
        else:
            raise TypeError("The afl-cmin ouptut must be given as a string or as a list of strings.")
        tuples_found_re = "\[\+\] Found (\d*) unique tuples across (.*) files."
        matcher = re.compile(tuples_found_re)
        # We use  the star  for to capute ascii-color codes
        # Example desired output
        # \x1b[1;32m[+] \x1b[0mCaptured 123 tuples in '/dev/null'.\x1b[0m
        for line in reversed(afl_showmap_output_lines):
            match = re.match("(.*)mCaptured (\d*) tuples in '/dev/null'.(.*)", line)
            if match:
                return int(match.groups(0)[1])

    def __init__(self, binary_path: str, results_out_dir: str, timeout: float = 1.5, qemu: bool = False,
                 seeds_dir: str = "seeds/", cores=1, verbose=False):
        """
        :param binary_path: The path to the elf bianry.
        :type binary_path: str 
        :param results_out_dir: Where to store the results
        :param dummyfiles_path: The path to the seeds files that can be used to invoke coverage. dummyfiles_path should lead to a directory of directories.
        :type dummyfiles_path: str
        :param timeout: The timeout
        :param qemu: Qemu mode? yes/no
        """
        # Perform sanity checks
        if not isinstance(binary_path, str):
            raise TypeError("Binary parameter must be a string.")
        self.binary_path = binary_path
        self.filetypes = []
        self.parameters = set()  # The argument to give the filetype
        self.dummyfile_path = "dummyfile_" + str(uuid.uuid4())
        while True:
            if not os.path.exists(self.dummyfile_path):
                break
            self.dummyfile_path = "dummyfile_" + str(uuid.uuid4())
        self.dummyfile_content = "CONTENT"
        # For dummyfiles_path we want to cut out the trailing / (if any)
        self.seeds_path = seeds_dir
        self.cli_config_list = []
        self.coverage_lists = {}  # Matches parameter to a list of filetypes and their corresponding coverage
        self.AFL_MAX_TIMEOUT = 20  # The threshold after which a child process is killed ( when using afl)
        self.qemu = qemu
        self.afl_cmin_path = os.path.dirname(os.path.realpath(
            __file__)) + "/../misc/afl_cmin_vincent.sh"  # Set this as a object variables since we modified the afl-cmin script
        self.failed_invocations = 0  # How many times did we fail so far?
        self.results_out_dir = results_out_dir
        self.cores = cores
        self.verbose = verbose

    def invoke_afl_cmin(self, invocation: str, sample_files_path: str, crash_only: bool = False, out_dir: str = None,
                        probe: bool = False) -> str:
        """
        Invoke afl-cmin and return the output.
        :param invocation: Call the examined binary with this parameter.
        :param sample_files_path: Examine coverage for files in this folder.
        :return: The afl-cmin output as a string. 
        """
        if not out_dir:
            out_dir_cmin = "tmp_" + str(uuid.uuid4())  # Save the traces in a random directory (for now)
        else:
            out_dir_cmin = out_dir
        if os.path.exists(
                HeuristicConfigCreator.AFL_CMIN_COV_ONLY_PATH) and not crash_only:  # If the modified cmin script exists
            call = [HeuristicConfigCreator.AFL_CMIN_COV_ONLY_PATH]
        else:
            call = ["/usr/local/bin/afl-cmin", "-I"]  # -I flag only when using afl-cmin
        if probe and not crash_only:
            call = ["/usr/local/bin/afl_probe"]
        if self.qemu:
            call.append("-Q")  # Append the QEMU Flag
        if crash_only:
            call.append("-C")
        call += ["-m", str(self.MEMORY_LIMIT), "-o", out_dir_cmin, "-t",
                 str(int(config_settings.AFL_CMIN_INVOKE_TIMEOUT * 1000)), "-i",
                 sample_files_path, "--", self.binary_path]
        logger.debug(invocation.split(" "))
        call += invocation.split(" ")
        logger.debug("afl-cmin: {0}".format(" ".join(call)))
        output = str(subprocess.check_output(call, cwd=os.getcwd(), stderr=subprocess.STDOUT,
                                             env=helpers.utils.get_fuzzing_env_for_invocation(invocation)),
                     errors="ignore")
        if not out_dir:
            shutil.rmtree(out_dir_cmin)
        return output

    def invoke_afl_showmap(self, invocation: str, file_path: str) -> str:
        call = ["/usr/local/bin/afl-showmap"]
        if self.qemu:
            call.append("-Q")
        call.append("-c")  # allow core dumps
        call += ["-m", str(self.MEMORY_LIMIT), "-o", "/dev/null", "-t",
                 str(int(config_settings.AFL_CMIN_INVOKE_TIMEOUT * 1000)), "--", self.binary_path]
        call += invocation.replace("@@", file_path).split(" ")
        logger.debug("afl-showmap: {0}".format(" ".join(call)))
        output = str(subprocess.check_output(call, cwd=os.getcwd(), stderr=subprocess.STDOUT,
                                             env=helpers.utils.get_fuzzing_env_for_invocation(invocation)),
                     errors="ignore")
        return output

    def invoke_afl_showmap_and_extract_coverage(self, invocation: str, file_path: str) -> int:
        try:
            output = self.invoke_afl_showmap(invocation, file_path)
        except subprocess.CalledProcessError as e:
            logger.error("Error while calling afl-cmin:")
            if e.stderr:
                logger.error("STDERR:", e.stderr.decode("utf-8"))
            if e.stdout:
                logger.error("STDOUT:", e.stdout.decode("utf-8"))
            self.failed_invocations += 1
            if self.failed_invocations >= self.FAILED_INVOCATIONS_THRESHOLD:
                logger.error(
                    "Could not infer coverage for {0} and parameter. Try to increase the time threshold?".format(
                        self.binary_path, invocation))
                # Do not raise the NoCoverageInfo: We could loose info! Instead, introduce a new flag
                # in the cliconfig
                return -1  # TODO: Do not return the same as "no coverage"
            else:
                return 0  # No coverage
        return HeuristicConfigCreator.get_coverage_from_afl_showmap_output(output)

    def invoke_afl_cmin_and_extract_coverage(self, invocation: str, sample_files_path: str, probe=False):
        output = None
        try:
            output = self.invoke_afl_cmin(invocation=invocation, sample_files_path=sample_files_path, probe=probe)
        except subprocess.CalledProcessError as e:  # Most likely: No instrumentation detected due to timeout.
            # But it could also be that it crashed...
            logger.info("Afl crashed: {0}".format(e.stdout))
            out_dir = self.results_out_dir + "/crashes" + str(uuid.uuid4())
            os.makedirs(out_dir, exist_ok=True)
            try:
                crash_output = self.invoke_afl_cmin(invocation=invocation, sample_files_path=sample_files_path,
                                                    crash_only=True, out_dir=out_dir, probe=probe)
                if "Narrowed down to" in crash_output:
                    logger.error("Found a crash for {0}, stored trace in {1}".format(self.binary_path, out_dir))
                    # result_dict[file_type] = 1
                    return 1
                else:
                    shutil.rmtree(out_dir)
            except subprocess.CalledProcessError as e:  # Most likely: No instrumentation detected due to timeout.
                logger.error("Error while calling afl-cmin:")
                if e.stderr:
                    logger.error("STDERR:", e.stderr.decode("utf-8"))
                if e.stdout:
                    logger.error("STDOUT:", e.stdout.decode("utf-8"))
                shutil.rmtree(out_dir)
                self.failed_invocations += 1
                if self.failed_invocations >= self.FAILED_INVOCATIONS_THRESHOLD:
                    logger.error(
                        "Could not infer coverage for {0} and parameter. Try to increase the time threshold?".format(
                            self.binary_path, invocation))
                    # Do not raise the NoCoverageInfo: We could loose info! Instead, introduce a new flag
                    # in the cliconfig
                    return -1  # TODO: Do not return the same as "no coverage"
                else:
                    return -1  # No coverage
        coverage = int(self.get_coverage_from_afl_cmin_ouput(output))
        return coverage

    def try_invocation(self, invocation, stdin=False, without_desock=False) -> bool:
        """
        Try the argument and see if it works correctly
        :param invocation: The argument to try.
        :param stdin: Check for stdin or file
        :param without_desock: Force without desock
        :return: True if the argument worked, False if not
        """
        # We try different heuristics to see if it worked:
        # We say that an argument worked if the program tried to open the file
        # We check that via strace
        if not os.path.exists(self.dummyfile_path):
            with open(self.dummyfile_path, "w") as dummyfile:
                dummyfile.write("CONTENT")
        file = os.path.abspath(self.dummyfile_path)
        # print("Trying invocation", invocation.replace("@@",file))
        # logging.info("Trying invocation {0}".format(invocation.replace("@@",file)))

        strace_arguments = ["-y", "-f", "-v", "-s", "65000", "--",
                            self.binary_path]  # No abbreviation of output, -f to trace forks, -y to show full file path
        if not stdin:
            strace_arguments += invocation.replace("@@", file).split(" ")
        else:
            strace_arguments += invocation.split(" ")
        # print(" ".join(strace_arguments))
        # Calling the binary with strace best works combined with the timeout command
        # print(strace_arguments)
        # print(check_output_with_timeout_command("strace",strace_arguments, timeout=self.MAX_TIMEOUT))
        if without_desock:
            env = config_settings.get_inference_env_without_desock()
        else:
            env = helpers.utils.get_inference_env_for_invocation(invocation)

        logger.info("Trying invocation strace {0}".format(" ".join(strace_arguments)))
        output, timeout = check_output_with_timeout_command("strace", strace_arguments, timeout=self.MAX_TIMEOUT,
                                                            test_stdin=stdin, dummyfile_path=self.dummyfile_path,
                                                            env=env)
        logger.info(output)
        if "/usr/bin/strace: ptrace(PTRACE_TRACEME, ...): Operation not permitted" in output:
            raise PermissionError("Strace is not allowed to trace. Try starting docker with --cap-add=SYS_PTRACE")
        if self.verbose:
            logger.debug(output)
        if timeout:  # The process timed out - we are not going to accept it as a parameter.
            return False

        output_lines = output.split("\n")  # We need to cut the first line here
        output_lines = [line for line in output_lines if not re.match(r'^\s*$', line)]
        # if stdin:
        # print(output_lines)
        # return self.check_strace_for_stdinread(output_lines)
        # return self.check_strace_for_fopen(output_lines,file)
        # output = "\n".join(output_lines[1:])
        for line in output_lines[1:]:
            # if file in line and ("read" in line or ("open" in line and "O_WRONLY" not in line)):
            if ("<" + file + ">") in line and ("read" in line or ("open" in line and "O_WRONLY" not in line)):
                return True
        return False

    def figure_out_parameters(self):
        """
        Figure out the argument which is needed to force the binary to take a file. 
        """

        # The parameter candidates are structured like this:
        # Each subset (initial_set,normal_parameter,depedent_arguments) is a list of lists.
        # For each list we try the parameters until one is accepted.
        # For example we accept if @@ is a valid parameter and if only if that is not the case we try @@ /dev/null
        # If we found at least one parameters for any of these sets, we are done.
        # If we find none, then we continue then with the next set.
        parameter_candidates = collections.OrderedDict()
        subcommand_list = ["", "convert ", "run ", "show "]
        # help_parameters = self.try_inferring_parameter_candidates_from_help()
        parameter_candidates["initial_set"] = [["@@", "@@ /dev/null"]]
        parameter_candidates["stdin_candidates"] = [["", "-"]]
        parameter_candidates["server_candidates"] = [["localhost:80", "localhost 80"]]
        parameter_candidates["normal_parameter"] = {"-a", "-b", "-c", "-d", "-e", "-f", "-g", "-i", "-j", "-k", "-l",
                                                    "-m", "-n", "-o", "-p", "-r", "-x", "-nr", "-ir", "-nvr"}
        parameter_candidates["normal_parameter"] = {p + " @@" for p in parameter_candidates["normal_parameter"]}
        parameter_candidates["normal_parameter"].update(self.try_inferring_parameter_candidates_from_help())
        parameter_candidates["normal_parameter"] = list(parameter_candidates["normal_parameter"])
        parameter_candidates["normal_parameter"] = [[p, p + " /dev/null", p + " -o /dev/nulll", p + " -w /dev/null"] for
                                                    p in parameter_candidates["normal_parameter"]]
        parameter_candidates["dependent arguments"] = []
        for sublist in parameter_candidates["normal_parameter"]:
            parameter_candidates["dependent arguments"].append([p + " -t" for p in sublist])
            parameter_candidates["dependent arguments"].append([p + " -c" for p in sublist])
            parameter_candidates["dependent arguments"].append([p + " -r" for p in sublist])
            parameter_candidates["dependent arguments"].append([p + " -d" for p in sublist])
            parameter_candidates["dependent arguments"].append([p + " -p" for p in sublist])

        valid_invocations = set()
        for subcommand in subcommand_list:
            # for h in help_parameters: # Try the help parameters in any case
            #    valid = self.try_invocation(invocation=subcommand+h)
            #    if valid:
            #        valid_invocations.add(h)
            for key, candidate_list in parameter_candidates.items():
                for candidatetuples in candidate_list:
                    for invocation in candidatetuples:
                        if key == "stdin_candidates" or key == "server_candidates":
                            valid = self.try_invocation(invocation=subcommand + invocation, stdin=True)
                        else:
                            valid = self.try_invocation(invocation=subcommand + invocation)
                        if valid:
                            valid_invocations.add(invocation)
                            break
                if valid_invocations:
                    self.parameters = valid_invocations
                    return valid_invocations
        self.parameters = valid_invocations
        return valid_invocations

    @staticmethod
    def get_parameters_from_help_output(output: str):
        file_regex_space_file_pattern = r"\s*(-[^\s]+)\s+.*file.*"  # For things like -r <infile>
        file_regex_equals_file_pattern = r"[\s]*(-[^\s]*?<file>[^\s]*)"  # For things like --include=<file>
        file_regex_space_file_pattern_compiled = re.compile(file_regex_space_file_pattern, re.IGNORECASE)
        file_regex_equals_file_pattern_compiled = re.compile(file_regex_equals_file_pattern, re.IGNORECASE)
        file_regex = re.compile("<file>", re.IGNORECASE)
        file_regex_equals_file = re.compile("=FILE", re.IGNORECASE)
        any_parameter_pattern = "\s*(-[^\s]+)\s+.*"
        any_parameter_pattern_compiled = re.compile(any_parameter_pattern, re.IGNORECASE)
        possible_parameters = set()
        output_lines = output.split("\n")
        for line in output_lines:
            matches = file_regex_space_file_pattern_compiled.findall(line)
            for m in matches:
                param_candidate = m
                if param_candidate[
                    -1] == ",":  # Some parameters have the form -k, --keyfile file. We want to filter that out
                    param_candidate = param_candidate[:-1]
                # print("Matched: ", line, "param", param_candidate)
                possible_parameters.add(param_candidate + " @@")
            matches = file_regex_equals_file_pattern_compiled.findall(line)
            for m in matches:
                param_candidate = m
                if param_candidate[
                    -1] == ",":  # Some parameters have the form -k, --keyfile file. We want to filter that out
                    param_candidate = param_candidate[:-1]
                logger.debug("Matched: ", line, "param", param_candidate)
                possible_parameters.add(file_regex.sub("@@", param_candidate))
                possible_parameters.add(file_regex_equals_file.sub("@@", param_candidate))
        # matches = any_parameter_pattern_compiled.findall(output)
        # possible_parameters.update({m.strip()+" @@" for m in matches})
        return possible_parameters

    def try_inferring_parameter_candidates_from_help(self) -> set():
        """ 
        Calling -h --help and try to infer some parameters for files from there. The assumption here is that
        the help text exposes parameters either like this: -r <infile> or like this: --include=<file>
        """
        valid_parameters = set()
        help_parameters = ["-h", "--help", "-H"]
        # file_regex = [
        #    ".*?\s(-.*?)\s(.*)?file.*?",  # For things like -r <infile>
        #    ".*\s(-.*?)\s(.)*file.*?",  # Same thing, but match greedily in the beginning
        #    "([^\s]+).*file.*" # blabal
        # (.*?file.*?)
        # ]

        possible_parameters = set()
        for help_param in help_parameters:
            # print("Help param:", help_param)
            try:
                output = str(subprocess.check_output([self.binary_path, help_param], timeout=self.MAX_TIMEOUT,
                                                     stderr=subprocess.STDOUT), errors="ignore")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                output = str(e.output, errors="ignore")
            except (PermissionError) as e:
                continue  # Permission denied for this parameter
            possible_parameters.update(HeuristicConfigCreator.get_parameters_from_help_output(output))

            # compile_regex = list(map(re.compile, file_regex))
            # for reg in compile_regex:
            #    for line in output_lines:
            #        matches = reg.findall(line)
            #        for m in matches:
            #            possible_pamameters.add(m[0])
        return possible_parameters

    def try_filetype_with_coverage_via_afl(self, parameter: str, dummyfiles_path: str, file_type: str,
                                           result_dict: {} = None, probe: bool = False) -> float:
        """
        Try to infer the code coverage a certain filetype gives. 
        :param parameter: The parameter that leads to the file processing
        :param dummyfiles_path: The path to a directory with files of that filetype
        :param file_type: The file type that is to be tested
        :return: The average code coverage.
        """
        # print("Now inferrring coverage (using afl-cmin) for", file_type)
        # if self.failed_invocations >= self.FAILED_INVOCATIONS_THRESHOLD:
        #    return 0.00
        if result_dict is None:
            result_dict = {}
        if self.failed_invocations >= self.FAILED_INVOCATIONS_THRESHOLD:
            result_dict[file_type] = -1
            return -1  # TODO: Do not return the same as "no coverage"
        dummyfiles = os.listdir(dummyfiles_path)
        if not dummyfiles:
            logger.error(dummyfiles_path, "has no dummyfiles!")
            result_dict[file_type] = 0
            return 0  # No dummyfile, no coverage
        coverage = self.invoke_afl_cmin_and_extract_coverage(invocation=parameter, sample_files_path=dummyfiles_path,
                                                             probe=probe)
        result_dict[file_type] = coverage
        logger.debug("Got {0} coverage for filetype: {1}".format(coverage, file_type))
        logger.info(
            "{0}: Got {1} coverage for filetype {2} and parameter {3}".format(self.binary_path, coverage, file_type,
                                                                              parameter))
        result_dict[file_type] = coverage
        return coverage

    def try_filetype_with_coverage(self, parameter: str, dummyfiles_path: str, file_type: str, result_dict: {} = None,
                                   probe: bool = False) -> float:
        """
        Tries to execute the executable with parameter <dummyfile_path> to check if the 
        file is a correct seed. Returns the coverage.
        :param parameter: The parameter to pass a file to the executable
        :param dummyfiles_path: The path to the directory that contains the dummy files.
        :return: The coverage in percent.
        """
        return self.try_filetype_with_coverage_via_afl(parameter, dummyfiles_path, file_type, result_dict, probe=probe)

    def probe_possible_filetypes_for_parameter(self, parameter: str) -> ([str], int, {}):
        """
        This functions does a first check for possible filetypes. In particular, it takes two random files out of each file
        type and calls afl-showmap on them. It returns only those filetypes that have a higher coverage than the lowest coverage yielded.
        :return: A list of subdirectories of self.seeds_path that could be the right file type and the minimum coverage.
        """
        PROBE_FILES = 3
        files_to_try = {}
        max_coverage_per_filetype = {}
        cmin_argument_list = []
        result_dict = {}
        for filetype in os.listdir(self.seeds_path):
            if filetype == ".git":  # Ignore .git directory
                continue
            if not os.path.isdir(os.path.join(self.seeds_path, filetype)):
                continue
            if len(os.listdir(os.path.join(self.seeds_path, filetype))) <= 0:
                continue
            cmin_argument_list.append(
                (parameter, self.seeds_path + "/" + filetype, "." + str(filetype.split("_")[0]), result_dict, True))
        with multiprocessing.pool.ThreadPool(processes=self.cores) as pool:  # instead of multiprocessor.cpu_count()
            results = pool.starmap(self.try_filetype_with_coverage, cmin_argument_list)
        coverage = [result_dict.get("." + filetype.split("_")[0], 0) for filetype in os.listdir(self.seeds_path)]
        max_coverage_per_filetype = {filetype: result_dict.get("." + filetype.split("_")[0], 0) for filetype in
                                     os.listdir(self.seeds_path)}
        # coverage = self.invoke_afl_cmin_and_extract_coverage(invocation=parameter,sample_files_path=os.path.join(self.seeds_path,filetype),probe=True)
        # print(coverage)
        # max_coverage_per_filetype[filetype] = int(coverage)
        # logging.info("{0}: Got {1} coverage probing filetype {2} and parameter {3}".format(self.binary_path, coverage, filetype,
        # parameter))
        value_list = list([abs(x) for x in max_coverage_per_filetype.values()])
        std = sp.std(value_list)
        avg_value = sp.mean(value_list)
        logger.debug("Average:", avg_value)
        logger.debug("Probing, std:", std)
        if std > 0:
            possible_filetypes = [k for k, v in max_coverage_per_filetype.items() if ((v - avg_value) / std) > 2]
            if len(possible_filetypes) >= 1:  # 4 ticks away, that is pretty obvious
                return possible_filetypes, avg_value, max_coverage_per_filetype
        possible_filetypes = [k for k, v in max_coverage_per_filetype.items() if v > avg_value]
        return possible_filetypes, avg_value, max_coverage_per_filetype

    def infer_filetype_via_coverage_for_parameter_parallel(self, parameter: str, probe: bool = True) -> (
            str, int, bool):
        """
        This function tries to infer the filetype of an executable via coverage. 
        The assumption is that the file that yields the most coverage is of the right filetype
        :parameter parameter The parameter that tells the binary to work with this file.
        :parameter probe probe Using "probing" when calculating coverage distribution
        :return: The filetype as str
        """
        self.failed_invocations = 0  # We want to reset the failed invocations for each parameter
        is_network_param = True
        if "@@" in parameter:
            is_network_param = False
        if self.try_invocation(parameter, stdin=True, without_desock=True):
            is_network_param = False
        PROBE = probe
        max_cov = 0
        max_file = None
        cov_list = []
        file_list = []
        result_dict = {}
        cmin_argument_list = []  # A list which contains the argument
        max_coverage_per_filetype = {}
        if PROBE:
            probed_filetypes, min_cov_value, max_coverage_per_filetype = self.probe_possible_filetypes_for_parameter(
                parameter=parameter)
            logger.debug("Probed filetypes: %s", probed_filetypes)
            for filetype, cov in max_coverage_per_filetype.items():
                result_dict["." + filetype.split("_")[0]] = cov
                file_list.append(filetype.split("_")[0])
                cov_list.append(cov)
                max_coverage_per_filetype[filetype] = cov
            if not probed_filetypes:  # They all yielded the same coverage :(
                return None
                # self.coverage_lists[parameter] = zip(["garbage"],[min_cov_value])
                # return self.seeds_path+"/garbage_samples",min_cov_value
            if len(probed_filetypes) == 1:  # We can already be sure
                max_file, max_cov = (
                    self.seeds_path + "/" + probed_filetypes[0], int(max(max_coverage_per_filetype.values())))
                p = "None"
                if parameter:
                    p = parameter
                self.coverage_lists[p] = zip(file_list, cov_list)
                return [max_file], [max_cov], False
        else:
            probed_filetypes = [entity for entity in os.listdir(self.seeds_path) if
                                os.path.isdir(os.path.join(self.seeds_path, entity))]
            cov_list = [0] * len(probed_filetypes)
            file_list = [None] * len(probed_filetypes)
        for entity in probed_filetypes:
            if not os.path.isdir(self.seeds_path + "/" + entity):
                continue
            if len(os.listdir(self.seeds_path + "/" + entity)) <= 0:
                continue
            if entity == ".git":
                continue
            if (entity == "pcap-network_samples" or entity == "pcap-network") and (
                    not is_network_param):  # Do not try the network seeds for file handling programs - it simply takes too long
                continue
            cmin_argument_list.append(
                (parameter, self.seeds_path + "/" + entity, "." + str(entity.split("_")[0]), result_dict))
        with multiprocessing.pool.ThreadPool(processes=self.cores) as pool:  # instead of multiprocessor.cpu_count()
            results = pool.starmap(self.try_filetype_with_coverage, cmin_argument_list)
        for counter, entity in enumerate(probed_filetypes):
            if not os.path.isdir(self.seeds_path + "/" + entity):
                continue
            cov = result_dict.get("." + str(entity.split("_")[0]))
            if cov is None:
                cov = 0
            if cov > 0:
                cov_list[counter] = cov
                file_list[counter] = entity.split("_")[0]
            if cov > max_cov:
                max_cov = cov
                max_file = self.seeds_path + "/" + entity
            # print("Max coverage per filetype", max_coverage_per_filetype)
            # print("Entity",entity)
            max_coverage_per_filetype[entity] = max(cov, max_coverage_per_filetype.get(entity, 0))
        p = "None"
        if parameter:
            p = parameter
        self.coverage_lists[p] = zip(file_list, cov_list)
        value_list = list([abs(x) for x in max_coverage_per_filetype.values()])
        std = sp.std(value_list)
        avg_value = sp.mean(value_list)
        logger.debug("Average: %s", avg_value)
        logger.debug("Std. Deviation: %s", std)
        if std > 0:
            possible_filetypes = [k for k, v in max_coverage_per_filetype.items() if ((v - avg_value) / std) > 2.5]
            if len(possible_filetypes) >= 1:  # 4 ticks away, that is pretty obvious
                return [os.path.join(self.seeds_path, p) for p in possible_filetypes], [
                    max_coverage_per_filetype[filetype] for filetype in possible_filetypes], False
        # No file over >4 ticks from std deviation:
        logger.debug("Max file")
        logger.debug(max_file)
        return [max_file], [max_cov], True

    def infer_input_vectors(self) -> [CliConfig]:
        """
        Infer the input vectors of the given binary. Input vectors 
        consist of a parameter and a filetype.
        :return: A list of CliConfig object, each representing one input vector.
        """
        logger.info("Figuring out parameters for {0}".format(self.binary_path))
        param = self.figure_out_parameters()
        if os.path.exists(self.dummyfile_path):
            os.remove(self.dummyfile_path)
        if not param:
            logger.error("No parameters found for %s", self.binary_path)
            return None
        else:
            logger.info("Now searching for right filetype for %s", self.binary_path)
            return self.infer_filetypes()

    def infer_filetypes_via_coverage(self) -> [(str, str, int)]:
        """
        For each inferred parameter, this function find the corresponding best fitting filetype.
        :return: A list of triples: (parameter,filetype,coverage)
        """
        self.cli_config_list = []
        for param in self.parameters:
            inference_result = self.infer_filetype_via_coverage_for_parameter_parallel(param)
            if inference_result is None:  # Everything yielded the same coverage
                continue  # Next one
            max_files, max_covs, took_max_file = inference_result
            p = "None"
            if param:
                p = param
            c = CliConfig(invocation=param, filetypes=max_files, coverage_list=self.coverage_lists[p],
                          coverages=max_covs, binary_path=self.binary_path, max_coverage=max(max_covs),
                          took_max_file=took_max_file)
            if self.failed_invocations >= self.FAILED_INVOCATIONS_THRESHOLD:
                c.invocation_always_possible = False
            c.qemu = self.qemu
            self.cli_config_list.append(c)
        return sorted(self.cli_config_list, key=operator.attrgetter("max_coverage"), reverse=True)

    def infer_filetypes(self):
        """
        Infer the filetypes the 
        """
        return self.infer_filetypes_via_coverage()

    def get_max_coverage_input_vector(self) -> CliConfig:
        """
        Out of all the possible input vectors (=combination of parameter and filetype)
        get the one that has the most coverage. In this case,
        choose the input vector that gives highest coverage.
        :return: The best input vector in terms of coverage.
        """
        if not self.cli_config_list:
            return None
        return max(self.cli_config_list, key=operator.attrgetter("max_coverage"))

    def get_best_input_vector(self) -> CliConfig:
        """
        Out of all the possible input vectors (=combination of parameter and filetype)
        get the one that has the most coverage. In this case,
        choose the input vector that gives highest coverage.
        :return: The best input vector in terms of coverage.
        """
        if not self.cli_config_list:
            return None
        return max(self.cli_config_list, key=lambda x: x.best_chebyshev_tuple[1])

    def get_input_vectors_sorted(self) -> [CliConfig]:
        if not self.cli_config_list:
            return None
        return sorted(self.cli_config_list, key=operator.attrgetter("max_coverage"), reverse=True)

    def print_json_input_vectors(self):
        logger.debug("JSON Result")
        logger.debug(json.dumps(list(map(lambda x: x.__dict__, self.cli_config_list))))
        logger.debug("End JSON Result")
