import argparse
import json
import sys

import os
import sh
from sh import docker

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import time


# import multiprocessing

def reset(package: str):
    container_name = package + "_build"
    image_name = package + "_image"
    docker.rm("-f", container_name, _ok_code=[0, 1])
    docker.rmi(image_name, _ok_code=[0, 1])


def run(package: str, configuration_dir: str, binary_name: str, qemu: bool, minimize: bool, timeout: float,
        fuzz_duration: float):
    if os.path.exists(configuration_dir):
        print("Skipping {0}. Directory already exists".format(configuration_dir))
        return
    reset(package)
    print("Starting qemu={0},minimize={1},Fuzzing timeout={2}".format(qemu, minimize, timeout))
    start = time.time()
    container_name = package + "_build"  # +"_"+str(uuid.uuid4())[:8]
    image_name = package + "_image"  # +"_"+str(uuid.uuid4())[:8]
    timecommand = sh.Command("time")  # type: sh.Command
    docker_args = ["--name", container_name, "--entrypoint", "python", "pacmanfuzzer",
                   "/inputinferer/configfinder/builder_wrapper.py", "-p", package]
    if qemu:
        docker_args.append("-Q")
    with timecommand(_with=True) as timeprocess:
        print("Building")
        build_process = docker.run(docker_args, _ok_code=[0, 1, 2], _out=sys.stdout,
                                   _err=sys.stderr)  # type: sh.RunningCommand
    if not qemu and build_process.exit_code == 2:
        print("WITHOUT QEMU: Failed")
        return
    with timecommand(_with=True):
        docker.commit([container_name, image_name], _out=sys.stdout, _err=sys.stderr)
    docker_args = ["--rm", "--cap-add=SYS_PTRACE", "-v", configuration_dir + ":/results", "--entrypoint", "python",
                   image_name, "/inputinferer/configfinder/config_finder_for_pacman_package.py", "-p", package, "-v",
                   "/results/"]
    if qemu:
        docker_args.append("-Q")
    with timecommand(_with=True):
        print("Finding the input vector")
        input_process = docker.run(docker_args, _out=sys.stdout, _err=sys.stderr)
        print(input_process.cmd)
    with open(os.path.join(configuration_dir, package + "/" + binary_name + ".json")) as binary_name_fp:
        config_dict = json.load(binary_name_fp)[0]
    seeds = config_dict["file_type"]
    parameter = config_dict["parameter"]
    binary_path = config_dict["binary_path"]
    if not os.path.exists(os.path.join(configuration_dir, package + "/" + binary_name)):
        os.mkdir(os.path.join(configuration_dir, package + "/" + binary_name))
    if minimize:
        docker_args = ["--rm", "--cap-add=SYS_PTRACE", "-v", configuration_dir + ":/results", "--entrypoint", "python",
                       image_name, "/inputinferer/configfinder/controller.py", "minimize", "-p", package, "-v",
                       "/results", "-s", seeds,
                       "--parameter=" + parameter, "-b", binary_path, "-afile", binary_name + ".afl_config"]
        if qemu:
            docker_args.append("-Q")
        with timecommand(_with=True):
            print("Minimizing")
            docker.run(docker_args, _out=sys.stdout, _err=sys.stderr)
        with open(os.path.join(configuration_dir, package + "/" + binary_name + ".afl_config")) as afl_config_fp:
            seeds = json.load(afl_config_fp)["min_seeds_dir"]
    docker_args = ["--rm", "--cap-add=SYS_PTRACE", "-v", configuration_dir + ":/results", "--entrypoint", "python",
                   image_name, "/inputinferer/configfinder/controller.py", "evalfuzz"]
    if fuzz_duration:
        docker_args += ["-ft", fuzz_duration]
    if timeout:
        docker_args += ["-t", timeout]
    docker_args += ["-p", package, "-v", "/results", "-s", seeds, "--parameter=" + parameter, "-b", binary_path,
                    "-afile", binary_name + ".afl_config"]
    if qemu:
        docker_args.append("-Q")
    with timecommand(_with=True):
        print("Fuzzing")
        docker.run(docker_args, _out=sys.stdout, _err=sys.stderr)
    print("Done")
    end = time.time()
    print("Time elapsed: ", str(end - start))


def main(package: str, configuration_dir: str, binary_name: str, timeout: float, fuzz_duration: float):
    # p = mp.Pool(mp.cpu_count()-2)
    # a1 = p.map_async(lambda x: run(package,x,binary_name,timeout=timeout,qemu=False,minimize=False),[os.path.join(os.getcwd(), configuration_dir + "/" + package + "noqemu/" + "run" + str(i)) for i in range(10)])
    # a2 = p.map_async(lambda x: run(package, x, binary_name, timeout=timeout, qemu=False, minimize=True),[os.path.join(os.getcwd(), configuration_dir + "/" + package + "noqemuminimize/" + "run" + str(i)) for i in range(10)])
    # a3 = p.map_async(lambda x: run(package, x, binary_name, timeout=timeout, qemu=True, minimize=False),[os.path.join(os.getcwd(), configuration_dir + "/" + package + "qemu/" + "run" + str(i)) for i in range(10)])
    # a4 = p.map_async(lambda x: run(package, x, binary_name, timeout=timeout, qemu=True, minimize=True),[os.path.join(os.getcwd(), configuration_dir + "/" + package + "qemuminimize/" + "run" + str(i)) for i in range(10)])
    # a1.get()
    # a2.get()
    # a3.get()
    # a4.get()

    for i in range(10):
        run(package, os.path.join(os.getcwd(), configuration_dir + "/" + package + "noqemu/" + "run" + str(i)),
            binary_name,
            timeout=timeout, qemu=False, minimize=False, fuzz_duration=fuzz_duration)
        run(package, os.path.join(os.getcwd(), configuration_dir + "/" + package + "noqemuminimize/" + "run" + str(i)),
            binary_name, timeout=timeout, qemu=False, minimize=True, fuzz_duration=fuzz_duration)
        run(package, os.path.join(os.getcwd(), configuration_dir + "/" + package + "qemu/" + "run" + str(i)),
            binary_name, timeout=timeout, qemu=True, minimize=False, fuzz_duration=fuzz_duration)
        run(package, os.path.join(os.getcwd(), configuration_dir + "/" + package + "qemuminimize/" + "run" + str(i)),
            binary_name, timeout=timeout, qemu=True, minimize=True, fuzz_duration=fuzz_duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a package.')
    parser.add_argument("-p", "--package", required=True, type=str,
                        help="The package to be examined. Must be an apt package.")
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str, help="Where to store the results?")
    parser.add_argument("-ft", "--fuzzer_timeout", required=False, type=float,
                        help="The timeout for afl (the whole fuzzer process)",
                        default=None)  # Default timeout: None ( take the one from config)
    parser.add_argument("-t", "--timeout", required=False, type=float,
                        help="The timeout for afl (per run)",
                        default=None)  # Default timeout: None ( take the one from config)
    parser.add_argument("-b", "--binary_path", required=True, type=str,
                        help="The name of ther binary.")
    # Either fuzz projects or binaries
    arguments = parser.parse_args()
    main(arguments.package, arguments.configuration_dir, arguments.binary_path, timeout=arguments.timeout,
         fuzz_duration=arguments.fuzzer_timeout)
