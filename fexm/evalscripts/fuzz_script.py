import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import helpers.docker_builder
import uuid

from helpers import utils
import argparse
import os


def main(csv: str, cd: str, di: str):
    csv_entries = []
    packages = {}
    with open(csv) as fp:
        for line in fp.readlines():
            csv_entries.append(line.strip().split(","))  # Expect format: package,binary,invocation,seeds
    for entry in csv_entries:
        if packages.get(entry[0]):
            packages[entry[0]].append(entry)
        else:
            packages[entry[0]] = [entry]
    docker_images_dict = {}
    # for p,entry in packages.items():
    #    if docker_images_dict.get(p) is None:
    #        base_image = helpers.docker_builder.build_and_commit(p,di)
    #        docker_images_dict[p] = base_image
    #    else:
    #        base_image = docker_images_dict[p]
    for entry in csv_entries:
        print(entry)
        p = entry[0]
        # base_image = docker_images_dict[p]
        docker_name = "fuzz_" + os.path.basename(entry[1]) + "_" + str(uuid.uuid4())
        docker_args = ["--name", docker_name, "--rm", "--privileged", "-v",
                       os.path.join(os.getcwd(), cd + "/") + ":/results",
                       "--entrypoint", "python"]
        fuzzer_command_args = [
            "/inputinferer/configfinder/controller.py",
            "fuzz",
            "-p", p,
            '--parameter="{0}"'.format(entry[2]),
            "-b", entry[1],
            "-s", entry[3],
            "-v", "/results",
            "--afl_out_file", os.path.basename(entry[1]) + ".afl_config"
        ]
        os.makedirs(os.path.join(cd + "/", p + "/", os.path.basename(entry[1])), exist_ok=True)
        os.system("tmux set remain-on-exit on")
        with open(os.path.join(cd, os.path.basename(entry[1]) + ".sh"), "w") as fp:
            fp.write("/bin/sh -c 'docker run " + " ".join(docker_args) + " " + di + " " + " ".join(
                fuzzer_command_args) + "; exec bash'")
            os.system("chmod +x {0}".format(os.path.join(cd, os.path.basename(entry[1]) + ".sh")))
        output = os.system('tmux new-session -d -s "fuzz_{0}" {1}'.format(os.path.basename(os.path.basename(entry[1])),
                                                                          os.path.join(cd, os.path.basename(
                                                                              entry[1])) + ".sh"))
        print('tmux new-session -d -s "fuzz_{0}" {1}'.format(os.path.basename(os.path.basename(entry[1])),
                                                             os.path.join(cd, os.path.basename(entry[1]))) + ".sh")

        # docker.run(docker_args+[base_image]+fuzzer_command_args,_stdout=sys.stdout,_stderr=sys.stderr)


def sanity_checks():
    """
    Basically perform the same sanitify checks that afl performs
    :return:
    """
    pattern_change_needed = False
    with open("/proc/sys/kernel/core_pattern") as core_patten_fp:
        if core_patten_fp.read()[0] == '|':
            pattern_change_needed = True
    if pattern_change_needed:
        print(
            "System is configured to send core dump notifications to an external utility. This will prevent afl-fuzz from starting. ")
        change_core_pattern = helpers.utils.query_yes_no("Do you want me to change that for you?")
        if not change_core_pattern:
            return False
        else:
            with open("/proc/sys/kernel/core_pattern", "w") as core_patten_fp:
                core_patten_fp.write("core")
                return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start the building Process')
    parser.add_argument("-f", "--csvfile", required=True, type=str, help="The csv file with the configurations")
    parser.add_argument("-cd", "--configuration_dir", required=True, type=str,
                        help="The directory that contains the configurations")
    parser.add_argument("-di", "--base_image", required=True, type=str, help="Time pacman fuzzer image.")
    arguments = parser.parse_args()
    if not os.path.exists(arguments.configuration_dir) or not os.path.isdir(arguments.configuration_dir):
        raise NotADirectoryError("Configuration Path must be Directory!")
    if not sanity_checks():
        print("Can not perform fuzzing without passing sanity checks!")
    main(arguments.csvfile, arguments.configuration_dir, arguments.docker_image)
