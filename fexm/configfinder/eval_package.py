#!/usr/bin/env python3
"""
Evaluate on concrete package.
"""
import argparse
import json

import os
import sh

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from builders import builder
import helpers.utils
from heuristic_config_creator import HeuristicConfigCreator
from configfinder.minimzer import minize
from fuzzer_wrapper import AflFuzzWrapper
from sh import chmod


class PackageEvaluator:
    def __init__(self, json_config_file: str):
        if not os.path.exists(json_config_file):
            print("JSON Configuration file {0} does not exist!".format(json_config_file))
            exit(-1)
        with open(json_config_file, "r") as fp:
            config_dict = json.load(fp)
        self.user_defined_folder = config_dict.get("package_folder")
        # if not self.user_defined_folder:
        #    self.package = config_dict.get("package")
        # elif not:
        # self.package = "UserDefined"
        self.package = config_dict.get("package")
        if not self.package and self.user_defined_folder:
            self.package = "UserDefined"
        elif not self.package:
            print("Need a package name or custom user folder!")
            exit(0)
        self.output_volume = config_dict.get("volume")
        self.fuzz_duration = config_dict.get("fuzz_duration")
        self.exec_timeout = config_dict.get("timeout")
        if not self.exec_timeout:
            self.exec_timeout = "1000+"
        self.qemu = config_dict.get("qemu")
        self.seeds = config_dict.get("seeds")
        self.fuzzing_cores_per_binary = config_dict.get("fuzzing_cores_per_binary")
        self.use_asan = config_dict.get("asan")
        logfilename = os.path.join(self.output_volume, self.package)
        self.logger = helpers.utils.init_logger(logfilename)
        # logging.basicConfig(handlers=[logging.FileHandler(logfilename, 'w', 'utf-8')], level=logging.INFO,
        #                   format='%(levelname)s %(asctime)s: %(message)s')
        self.package_log_dict = {"name": self.package}
        os.makedirs(os.path.join(self.output_volume, self.package), exist_ok=True)

    def append_to_status(self, status_text):
        with open(os.path.join(self.output_volume, self.package, "status.log"), "a") as fp:
            fp.write(status_text + "\n")

    def run_package_eval(self):
        self.append_to_status("Building package")
        if not self.user_defined_folder:
            print("Now doing package {0}".format(self.package))
            print("Build package {0}".format(self.package))

            b = builder.Builder(package=self.package, qemu=self.qemu, overwrite=True)
            if not b.install():
                print("Could not install package, exiting")
                self.logger.error("Could not install package, exiting")
                exit(0)
            qemu = b.qemu
            self.package_log_dict["qemu"] = qemu
            packages_files = b.get_file_list()
        else:
            packages_files = helpers.utils.absoluteFilePaths(self.user_defined_folder)

        volume = self.output_volume
        self.append_to_status("Searching for fuzzable binaries")
        fuzzable_binaries = helpers.utils.return_fuzzable_binaries_from_file_list(packages_files,
                                                                                  log_dict=self.package_log_dict)
        self.logger.info("Fuzzable binaries detected: {0}".format(" ".join(fuzzable_binaries)))
        self.append_to_status("Fuzzable binaries detected: {0}".format(" ".join(fuzzable_binaries)))
        self.package_log_dict["inference_success"] = []
        self.package_log_dict["inference_fail"] = []
        self.package_log_dict["fuzzing_success"] = []
        self.package_log_dict["fuzzing_fail"] = []

        for b in fuzzable_binaries:
            self.eval_binary(binary_path=b)
        # else:
        #    logging.info("Skipping binary {0} as non fuzzable".format(b))

        self.package_log_dict["num_elf_files"] = len(self.package_log_dict["elf_files"])
        self.package_log_dict["num_fuzzable_bins"] = len(self.package_log_dict["fuzzable_bins"])
        self.package_log_dict["num_executable_elf_files"] = len(self.package_log_dict["executable_elf_files"])
        self.package_log_dict["num_inference_success"] = len(self.package_log_dict["inference_success"])
        self.package_log_dict["num_inference_fail"] = len(self.package_log_dict["inference_fail"])
        self.package_log_dict["num_fuzzing_success"] = len(self.package_log_dict["fuzzing_success"])
        self.package_log_dict["num_fuzzing_fail"] = len(self.package_log_dict["fuzzing_fail"])
        print(self.package_log_dict)
        with open(os.path.join(self.output_volume, "{0}_log.json".format(self.package)), "w") as fp:
            json.dump(self.package_log_dict, fp)
        try:
            chmod("-R", "0777",
                  os.path.join(volume, self.package))  # Hacky fix for the problem that docker stores every as root
        except sh.ErrorReturnCode as e:
            self.logger.error("Could not set chmod permissions for package volume. Error: {0}".format((str(e))))

    def eval_binary(self, binary_path: str):
        if self.package_log_dict:
            if not self.package_log_dict.get(binary_path):
                self.package_log_dict[binary_path] = {}
        use_qemu = helpers.utils.qemu_required_for_binary(binary_path)
        self.package_log_dict[binary_path]["qemu"] = use_qemu
        self.logger.info("Now inferring invocation for {0}".format(binary_path))
        self.append_to_status("Now inferring invocation for {0}".format(binary_path))
        h = HeuristicConfigCreator(binary_path=binary_path,
                                   results_out_dir=self.output_volume + "/" + self.package + "/" + os.path.basename(
                                       binary_path),
                                   qemu=use_qemu, cores=self.fuzzing_cores_per_binary, seeds_dir=self.seeds)
        input_vectors = h.infer_input_vectors()
        if not input_vectors:
            if self.package_log_dict:
                self.package_log_dict["inference_fail"].append(binary_path)
        input_vectors_sorted = h.get_input_vectors_sorted()
        if not input_vectors_sorted:
            if self.package_log_dict:
                self.package_log_dict["inference_fail"].append(binary_path)
            return
        if self.package_log_dict:
            self.package_log_dict["inference_success"].append(binary_path)
        helpers.utils.store_input_vectors_in_volume(package=self.package, binary=binary_path,
                                                    volume_path=self.output_volume,
                                                    input_vectors=input_vectors_sorted)
        print("Inference done! Minimizing now!")
        self.append_to_status("Minimizing seeds for {0}".format(binary_path))
        minize(parameter=input_vectors_sorted[0].parameter, binary_path=binary_path,
               seeds_dir=";".join(input_vectors_sorted[0].file_types), package=self.package,
               volume_path=self.output_volume,
               afl_config_file_name=helpers.utils.get_filename_from_binary_path(binary_path) + ".afl_config",
               tmin_total_time=120, do_tmin=True, cores=self.fuzzing_cores_per_binary)
        with open(os.path.join(self.output_volume, self.package, helpers.utils.get_filename_from_binary_path(
                binary_path) + ".afl_config")) as afl_config_fp:
            config_dict = json.load(afl_config_fp)
            seeds_dir = config_dict["min_seeds_dir"]
            config_dict["status"] = 2
        # with open(os.path.join(self.output_volume, self.package, helpers.helpers.get_filename_from_binary_path(
        #        binary_path) + ".afl_config"), "w") as afl_config_fp:
        #    json.dump(config_dict, afl_config_fp)
        self.append_to_status("Fuzzing {0}!".format(binary_path))
        fuzz_wrapper = AflFuzzWrapper(package=self.package, volume_path=self.output_volume, binary_path=binary_path,
                                      parameter=input_vectors_sorted[0].parameter,
                                      seeds_dir=seeds_dir, file_types=input_vectors_sorted[0].file_types,
                                      fuzz_duration=self.fuzz_duration,
                                      timeout=self.exec_timeout,
                                      afl_config_file_path=os.path.join(self.output_volume, self.package,
                                                                        helpers.utils.get_filename_from_binary_path(
                                                                            binary_path) + ".afl_config"),
                                      log_dict=self.package_log_dict)
        res = fuzz_wrapper.start_fuzzer(cores=self.fuzzing_cores_per_binary)
        if res:
            self.package_log_dict["fuzzing_success"].append(binary_path)
        else:
            self.package_log_dict["fuzzing_fail"].append(binary_path)
        self.package_log_dict["num_fuzzing_success"] = len(self.package_log_dict["fuzzing_success"])
        self.package_log_dict["num_fuzzing_fail"] = len(self.package_log_dict["fuzzing_fail"])
        self.append_to_status("IDLE")


def main():
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("json", help="The path to the json configuration file")
    args = parser.parse_args()
    package_evaluator = PackageEvaluator(json_config_file=args.json)
    package_evaluator.run_package_eval()


if __name__ == "__main__":
    main()
