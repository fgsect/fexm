import json
import subprocess
import uuid

import os
import re
import sh
from docker.docker_wrapper import DockerWrapper

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder.cli_config import CliConfig
from helpers.utils import check_output_with_timeout_command
from helpers.exceptions import NoCoverageInformation
from helpers import configuration_utils
from helpers import utils
import operator
from configfinder.coverage_evaluator import CoverageEvaluator
from docker.docker_image import DockerImage


class DockerConfigCreator(object):
    """
    In this class, a docker image that contains an elf binary is taken and a configuration is returned.
    """
    MAX_TIMEOUT = 1  # the threshold after which a child process is killed ( when inferring command line arguments)
    MEMORY_LIMIT = "none"  # afl-showmap Memory limit for child process. This need to be high, especially in QEMU mode.
    FAILED_INVOCATIONS_THRESHOLD = 4  # After how many failed invocations do we skip the whole binary?

    @staticmethod
    def check_strace_for_fopen(strace: str, dummyfile_path: str) -> bool:
        """
        Check the system of a binary for a syscall indicating that the file with path 
        dummyfile_path has been openen
        :param strace: The trace of the system cals
        :param dummyfile_path: The path to the dummyfile
        :return: True if yes, False if not
        """
        if isinstance(strace, str):
            strace_lines = strace.split("\n")  # type: [str]
        elif isinstance(strace, list) and all(isinstance(s, str) for s in strace):
            strace_lines = strace  # We assume the output has already been split
        else:
            raise TypeError("The system trace must be given as a string or as a list of strings.")
        open_strace_re = '^(.*?)open\("(.*?)' + dummyfile_path + '"(.*?)$(.*)'
        matcher = re.compile(open_strace_re)
        for line in strace_lines:
            if (matcher.match(line)) and ("O_WRONLY" not in line):
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

    def __init__(self, docker_image: DockerImage, seeds_path: str, figure_path: str = None,
                 plot_format: str = "png", timeout: float = 1.5, qemu: bool = False):
        """

        :param docker_image: The docker image that contains the elf binary that is to be evaluated. The docker-image must be built in a way, such that the entrypoint is the binary.
        :param seeds_path: The path to the seeds in the docker image.
        :param figure_path: The path where the figures should be saved.
        :param plot_format: The plot format - allowed are "png" or "tex".
        :param timeout: When should the processes timeout?
        :param qemu: Activate qemu or not?
        """
        # Perform sanity checks
        utils.set_euid_to_sudo_parent_user()
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
        if dummyfiles_path[-1] == "/":
            self.dummyfiles_path = dummyfiles_path[:-1]
        else:
            self.dummyfiles_path = dummyfiles_path
        self.repo_path = repo_path
        self.figure_path = figure_path
        self.cli_config_list = []
        self.coverage_lists = {}  # Matches parameter to a list of filetypes and their corresponding coverage
        self.plot_format = plot_format
        self.repo_path = repo_path
        self.bash_script_directory = "bash_scripts/"  # The directory where to save the bash scripts.
        self.AFL_MAX_TIMEOUT = timeout  # The threshold after which a child process is killed ( when using afl)
        self.docker_image = DockerImage.create_afl_docker_image_from_repo_path(repo_path=repo_path)
        self.docker_wrapper = DockerWrapper(docker_image=self.docker_image.image_name)
        self.qemu = qemu
        if not os.path.exists(self.bash_script_directory):
            os.mkdir(self.bash_script_directory)
        self.afl_cmin_path = os.path.dirname(os.path.realpath(
            __file__)) + "/../misc/afl_cmin_vincent.sh"  # Set this as a object variables since we modified the afl-cmin script
        self.failed_invocations = 0  # How many times did we fail so far?
        if DockerImage.check_if_base_image_exists():
            DockerImage.create_afl_base_image_from_seeds_path(seeds_path=dummyfiles_path)  # Create the base image

    def plot(self, parameter, cov_list, file_list):
        """
        Plot the coverage as a function of the filetypes on x-axis and 
        coverage on the y-axis
        :param parameter: The parameter that was used to obtain the coverages
        :param cov_list: The list of coverage in tuples 
        :param file_list: The list of the corresponding file types
        """
        if cov_list and file_list:  # Only plot if there are things to plot
            ce = CoverageEvaluator([file_list, cov_list])
            ce.plot(binary_path=self.binary_path, figure_path=self.figure_path, parameter=parameter,
                    plot_format=self.plot_format)

    def invoke_afl_cmin(self, parameter: str, sample_files_path: str) -> str:
        """
        Invoke afl-cmin and return the output.
        :param parameter: Call the examined binary with this parameter.
        :param sample_files_path: Examine coverage for files in this folder.
        :return: The afl-cmin output as a string. 
        """
        tmpdir = "tmp_" + str(uuid.uuid4())  # Save the traces in a random directory (for now)
        call = ["/usr/local/bin/afl-cmin"]
        if self.qemu:
            call.append("-Q")  # Append the QEMU Flag
        self.docker_wrapper.set_mount(mount_source=sample_files_path, mount_target="/seeds")
        call += ["-m", str(self.MEMORY_LIMIT), "-o", tmpdir, "-t", str(int(self.AFL_MAX_TIMEOUT * 1000)), "-i",
                 "/seeds", "--", self.binary_path]
        if parameter:
            call.append(parameter)
        call.append("@@")
        # print(" ".join(call))
        output = self.docker_wrapper.run_command_in_docker_container_and_return_output(
            call)  # str(subprocess.check_output(call,cwd=os.getcwd(),stderr=subprocess.STDOUT),errors="ignore")
        # print(output)
        return output

    def try_parameter(self, parameter) -> bool:
        """
        Try the argument and see if it works correctly
        :param parameter: The argument to try. 
        :return: True if the argument worked, False if not
        """
        # We try different heuristics to see if it worked:
        # We say that an argument worked if the program tried to open the file
        # We check that via strace
        if os.path.exists(self.dummyfile_path):
            file = self.dummyfile_path
        else:
            with open(self.dummyfile_path, "w") as dummyfile:
                dummyfile.write("CONTENT")
            file = self.dummyfile_path
        print("Trying paramer", parameter)
        if parameter is None:
            # Calling the binary with strace best works combined with the timeout command
            output = check_output_with_timeout_command("strace", [self.binary_path, file], timeout=self.MAX_TIMEOUT)
        else:
            output = check_output_with_timeout_command("strace", [self.binary_path, parameter, file],
                                                       timeout=self.MAX_TIMEOUT)
        # Reset the dummyfile:
        # Check the strace:
        return self.check_strace_for_fopen(strace=output, dummyfile_path=file)

    def figure_out_parameters(self):
        """
        Figure out the argument which is needed to force the binary to take a file. 
        """

        valid_parameters = []
        valid_parameters += self.try_list_of_parameters()
        print("Trying to infer parameters from help")
        valid_parameters += self.try_inferring_parameters_from_help()
        print("Inferred", valid_parameters, "from help")
        self.parameters = set(valid_parameters)
        # print(self.parameters)
        return self.parameters

    def try_list_of_parameters(self) -> [str]:
        """
        Try a list of predefined list of paramters and see if any works
        """
        list_of_parameters = ["-f", "-r", "-nvr", "-w", None]  # Can be extended...
        valid_parameters = []
        for param in list_of_parameters:
            valid = self.try_parameter(parameter=param)
            if valid:
                print("Found valid parameter", param)
                valid_parameters.append(param)

        return valid_parameters

    def try_inferring_parameters_from_help(self) -> [str]:
        """ 
        Calling -h --help and try to infer some parameters for files from there
        """
        # Assumption: Instructions for files comes from
        # parameter file
        valid_parameters = []

        help_parameters = ["-h", "--help", "-H"]
        file_regex = [
            ".*?\s(-.*?)\s(.*)?file.*?",  # For things like -r <infile>
            ".*\s(-.*?)\s(.)*file.*?",  # Same thing, but match greedily in the beginning
        ]
        possible_pamameters = set()
        for help_param in help_parameters:
            print("Help param:", help_param)
            try:
                output = str(subprocess.check_output([self.binary_path, help_param], timeout=self.MAX_TIMEOUT,
                                                     stderr=subprocess.STDOUT), errors="ignore")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                output = str(e.output, errors="ignore")
            print(output)
            output_lines = output.split("\n")

            compile_regex = list(map(re.compile, file_regex))
            for reg in compile_regex:
                for line in output_lines:
                    matches = reg.findall(line)
                    for m in matches:
                        possible_pamameters.add(m[0])
            for p in possible_pamameters:
                correct = self.try_parameter(p)
                if correct:
                    valid_parameters.append(p)
        return valid_parameters

    def try_filetype_with_coverage_via_afl(self, parameter: str, dummyfiles_path: str, file_type: str) -> float:
        """
        Try to infer the code coverage a certain filetype gives. 
        :param parameter: The parameter that leads to the file processing
        :param dummyfiles_path: The path to a directory with files of that filetype
        :param file_type: The file type that is to be tested
        :return: The average code coverage.
        """
        # print("Now inferrring coverage (using afl-cmin) for", file_type)
        dummyfiles = os.listdir(dummyfiles_path)
        if not dummyfiles:
            print(dummyfiles_path, "has no dummyfiles!")
            return 0  # No dummyfile, no coverage
        try:
            output = self.invoke_afl_cmin(parameter=parameter, sample_files_path=dummyfiles_path)
        except (
                subprocess.CalledProcessError,
                sh.ErrorReturnCode):  # Most likely: No instrumentation detected due to timeout.
            self.failed_invocations += 1
            if self.failed_invocations >= self.FAILED_INVOCATIONS_THRESHOLD:
                raise NoCoverageInformation(
                    "Could not infer coverage for {0}. Try to increase the time threshold?".format(self.binary_path))
            else:
                return 0.0  # No coverage
        coverage = self.get_coverage_from_afl_cmin_ouput(output)
        print("Got {0} coverage for filetype: {1}".format(coverage, file_type))
        return coverage

    def try_filetype_with_coverage(self, parameter: str, dummyfiles_path: str, file_type: str) -> float:
        """
        Tries to execute the executable with parameter <dummyfile_path> to check if the 
        file is a correct seed. Returns the coverage.
        :param parameter: The parameter to pass a file to the executable
        :param dummyfiles_path: The path to the directory that contains the dummy files.
        :return: The coverage in percent.
        """
        return self.try_filetype_with_coverage_via_afl(parameter, dummyfiles_path, file_type)

    def infer_filetype_via_coverage_for_parameter(self, parameter: str, plot=True) -> (str, int):
        """
        This function tries to infer the filetype of an executable via coverage. 
        The assumption is that the file that yields the most coverage is of the right filetype
        :parameter The parameter that tells the binary to work with this file.
        :return: The filetype as str
        """
        max_cov = 0
        max_file = None
        cov_list = []
        file_list = []
        for entity in os.listdir(self.dummyfiles_path):
            print(entity)
            if not os.path.isdir(self.dummyfiles_path + "/" + entity):
                continue
            cov = self.try_filetype_with_coverage(parameter, self.dummyfiles_path + "/" + entity,
                                                  file_type="." + str(entity.split("_")[0]))
            if cov > 0:
                cov_list.append(cov)
                file_list.append(entity.split("_")[0])
            if cov > max_cov:
                max_cov = cov
                max_file = self.dummyfiles_path + "/" + entity
        p = "None"
        if parameter:
            p = parameter
        self.coverage_lists[p] = zip(file_list, cov_list)
        if plot:
            self.plot(parameter, cov_list, file_list)
        return max_file, max_cov

    def infer_input_vectors(self) -> [CliConfig]:
        """
        Infer the input vectors of the given binary. Input vectors 
        consist of a parameter and a filetype.
        :return: A list of CliConfig object, each representing one input vector.
        """
        print("Figuring out parameters for", self.binary_path)
        param = self.figure_out_parameters()
        if not param:
            print("No parameters found for", self.binary_path)
            os.remove(self.dummyfile_path)
            return None
        else:
            print("Now searching for right filetype for", self.binary_path)
            os.remove(self.dummyfile_path)
            return self.infer_filetypes()

    def infer_filetypes_via_coverage(self) -> [(str, str, int)]:
        """
        For each inferred parameter, this function find the corresponding best fitting filetype.
        :return: A list of triples: (parameter,filetype,coverage)
        """
        self.cli_config_list = []
        for param in self.parameters:
            max_file, max_cov = self.infer_filetype_via_coverage_for_parameter(param)
            c = CliConfig(invocation=param, filetype=max_file, coverage=max_cov)
            self.cli_config_list.append(c)
        print(self.cli_config_list)
        return sorted(self.cli_config_list, key=operator.attrgetter("coverage"))

    def infer_filetypes(self):
        """
        Infer the filetypes the  
        """
        return self.infer_filetypes_via_coverage()

    def get_best_input_vector(self) -> CliConfig:
        """
        Out of all the possible input vectors (=combination of parameter and filetype) 
        get the one that is most promising. In this case, 
        choose the input vector that gives highest coverage.
        :return: The best input vector in terms of coverage.
        """
        if not self.cli_config_list:
            return None
        return max(self.cli_config_list, key=operator.attrgetter("coverage"))

    def get_routine_dict(self) -> {}:
        """
        Return a dictionary object that can be used as a configuration for 
        Orthrus later on.
        :return: A dict object.
        """
        best_input_vector = self.get_best_input_vector()
        seed_dir = "../{0}".format(best_input_vector.file_type)  # Path relative to git repo
        relative_binary_path = configuration_utils.get_relative_binary_path(binary_path=self.binary_path,
                                                                            repo_path=self.repo_path)
        fuzz_cmd_line = relative_binary_path
        if best_input_vector.parameter:
            fuzz_cmd_line += " " + best_input_vector.parameter
        fuzz_cmd_line += " @@"
        routine_dict = {"job_type": "routine", "num_cores": 2,
                        "job_desc": [
                            {"seed_dir": seed_dir, "fuzzer": "afl-fuzz", "fuzzer_args": "", "qemu": self.qemu}],
                        "num_jobs": 1,
                        "fuzz_cmd": fuzz_cmd_line}
        return routine_dict

    def create_bash_in_execution_path(self):

        """

        :return: 
        """
        """
        # !/bin/bash
        set - x
        git
        clone < repo_name >
        cd < repo_name >
        orthrus
        create - asan - fuzz
        orthrus
        add - -jobconf = routine.conf
        jobid =$(orthrus
        show - conf | sed - r
        "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" | grep - Po
        '(?<!\d)\d{2,}(?!\d)')
        orthrus
        start - j $jobid
        sleep
        1200
        orthrus
        stop - j $jobid
        """
        if not self.cli_config_list:
            return
        # First: Get author and repo name from path
        if not self.repo_path:
            raise ValueError("repo_path is not set")
        random_string = str(uuid.uuid4())  # Required for unique filenames
        download_link = configuration_utils.get_git_clone_link_from_repo_path(self.repo_path)
        repo_name = configuration_utils.get_repo_name_from_git_download_link(download_link)
        author_name = configuration_utils.get_author_name_from_git_download_link(download_link)
        routine_dict_filename = random_string + ".conf"  # Path relative to the git repository
        with open(self.bash_script_directory + "/" + routine_dict_filename, "w") as routine_dict_file:
            json.dump(self.get_routine_dict(), routine_dict_file)
        git_output_link = "{0}_{1}".format(author_name, repo_name)
        bash_content = "!/bin/bash"
        bash_content += "\nset -x"
        bash_content += "\ngit clone --depth=1 {0} -out_dir {1}".format(download_link, git_output_link)
        bash_content += "\ncd {0}".format(git_output_link)
        bash_content += "\northrus create -asan -fuzz"
        bash_content += "\northrus add --jobconf=" + routine_dict_filename
        bash_content += "\njobid=$(orthrus show -conf | sed -r \"s/\\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g\" | grep -Po '(?<!\d)\d{2,}(?!\d)')"
        bash_content += "\northrus start -j $jobid"
        bash_content += "\nsleep 1200"
        bash_content += "\northrus stop -j $jobid"
        with open(self.bash_script_directory + "/" + "fuzz_{0}.sh".format(random_string), "w") as bash_file:
            bash_file.write(bash_content)

    def create_bash_caller_in_repo_path(self):
        """
        :return: 
        """
        if self.cli_config_list:
            with open("start_orthrus.sh", 'a+') as orthrus_config_file:
                for config in self.cli_config_list:  # type: CliConfig
                    orthrus_config_file.write(config.return_fuzzer_configuration(self.binary_path) + os.linesep)
            mode = os.stat("start_orthrus.sh").st_mode
            mode |= (mode & 0o444) >> 2  # copy R bits to X, make file executabe
            os.chmod("start_orthrus.sh", mode)
