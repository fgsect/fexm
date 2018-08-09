from coverage_evaluator import CoverageEvaluator


class CliConfig(object):
    def __init__(self, invocation: str, filetypes: [str], max_coverage: int = 0, coverages: [int] = None,
                 coverage_list: [(str, int)] = None, repo_str: str = None, binary_path: str = None,
                 took_max_file=False):
        """"
        A CliConfiguration Class, consists of a parameter, a filetype and the coverage this filetype yields.
        :param invocation: The invocation the program needs to be called with. Same format as afl "@@" stands for file.
        :param filetype: The filetype or the path to a specific file
        :param coverage: The coverage the file yields in percent
        :param repo_path: The repo path of the binary. Optional
        :param binary_path: The path to the binary. Optional.
        """
        if coverages is None:
            coverages = [0]
        self.parameter = invocation
        self.file_types = filetypes
        self.max_coverages = coverages
        self.binary_path = binary_path
        self.invocation_always_possible = True
        self.qemu = False
        self.file_list = []
        self.max_coverage = max_coverage
        self.best_chebyshev_tuple = (0, 0)
        self.took_max_file = took_max_file
        if coverage_list:
            self.coverage_list = list(zip(*coverage_list))
            unzipped_coverage_list = self.coverage_list
            if len(unzipped_coverage_list) != 2:
                return
            ce = CoverageEvaluator(type_coverage_list=unzipped_coverage_list)  # type:CoverageEvaluator
            self.chebyshev_scores = ce.calculate_chebyshev_score()
            print(self.chebyshev_scores)
            max_index, max_value = max(enumerate(self.chebyshev_scores[1]), key=lambda p: p[1])
            self.best_chebyshev_tuple = (self.chebyshev_scores[0][max_index], max_value)
            self.deviation_scores = ce.calculate_deviation_scores()
            max_index, max_value = max(enumerate(self.deviation_scores[1]), key=lambda p: p[1])
            self.best_deviation_tuple = (self.deviation_scores[0][max_index], max_value)

    def get_string_parameter(self):
        """
        Get the parameter as a string. In particular, 
        if the parameter is None, return an empty string instead.
        :return: 
        """
        if self.parameter is None:
            return ""
        else:
            return self.parameter

    def __str__(self):
        p = ""
        if self.parameter:
            p = self.parameter
        else:
            p = "None"
        ftype = ""
        if self.file_types:
            ftype = self.file_types
        else:
            ftype = ""
        cov = 0
        if self.max_coverage:
            cov = self.max_coverage
        if not ftype:
            return "Could not find a corresponding file for parameter: "
        return "Parameter: " + p + " called with: " + ftype + " gives coverage of " + str(cov)

    def setParameter(self, param: str):
        """
        Set the parameter that the program is called with, e.g. "-i" 
        :param param: The parameter that is called for the file, e.g. "-i"
        :return: //
        """
        self.parameter = param

    def getParameter(self) -> str:
        """
        Get the parameter that the program is called with, e.g. "-i" 
        :return: //
        """
        return self.parameter

    def setFileType(self, filetype: str):
        """
        Set the filetype that the program takes as input, e.g. txt, jpg, etc.
        :param filetype: The filetype, e.g. txt
        """
        self.file_type = filetype

    def getFileType(self) -> str:
        """
        Return the filetype the program takes as input, e.g. txt
        :return: The filetype the program takes as input
        """
        return self.file_type

    def getCoverage(self) -> float:
        return self.max_coverage

    def setCoverage(self, coverage):
        self.max_coverage = coverage

    def return_fuzzer_configuration(self, binary: str) -> str:
        # Fuzzer configuration template:
        # orthrus add --job="<cmd_line>" -s=./seeds --jobtype=routine
        # --jobconf=routine.conf
        if not self.file_type:
            return ""
            # return "No configuration found for"+str(binary)
        p_print = ""
        if self.parameter:
            p_print = self.parameter
        return "orthrus add --job=" + str(
            binary) + " " + p_print + " @@ " + "-s=./" + self.file_type + " --jobtype=routine --jobconf=routine.conf"

    def return_fuzzer_script(self, binary: str, repo_path: str) -> str:
        """
        Return the text for the fuzzer script.
        :param binary: The path to the bainry, relative to the repo_path.
        :param repo_path: The path to the repo_path.
        :return: The text for the fuzzer script.
        """
        clone_link = ""
        out_dir = ""
        # First: Get the clone link?
