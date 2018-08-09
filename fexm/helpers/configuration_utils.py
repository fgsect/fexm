import subprocess

import os
import re


def verify_afl_cov(binary_path: str) -> bool:
    """
    Checks if the given executable was compiled using the afl-cov compiler. 
    :param binary_path: The path to the binary
    :return: True if it was compiled using the afl-cov compiler, false if not. 
    """
    cmd = ['objdump -d ' + binary_path + ' | grep afl_maybe_log']
    try:
        subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError:
        # No afl-logger
        return False
    return True


def is_cli_executable(exec_path: str) -> bool:
    """
    Checks if the given executable has a command line interface
    :param exec_path: The path to the binary executable.
    :return: True if executable has a command line interface, False if not.
    """
    if not os.path.isfile(exec_path):
        # TODO: Raise Exception
        return False
    return True


def return_elf_binaries(path: str) -> [str]:
    """
    This function returns all ELF binaries that are found in the build repo.
    See here: 
    https://github.com/test-pipeline/orthrus/blob/7cc88733a997a124885c607b799af4f478c363dc/orthrusutils/orthrusutils.py
    """

    command = "find {} -type f ".format(path) + "-executable -exec file -i '{}' \; | " \
                                                "grep 'x-executable; charset=binary' | " \
                                                "cut -d':' -f1"
    output = subprocess.check_output(command, shell=True).decode("utf-8")

    return list(filter(None, output.split("\n")))


def find_afl_fuzzable_binaries_in_repo(repo_path: str) -> [(str, str)]:
    """
    Given a path to a repo, return all fuzzable binaries in that repo.
    :param repo_path: The path to the repo.
    :return: A list of fuzzable as tuples (binary_path,repo_path)
    """
    return_list = []
    command = "find {} -type f ".format(repo_path) + "-executable -exec file -i '{}' \; | " \
                                                     "grep 'x-executable; charset=binary' | " \
                                                     "cut -d':' -f1"
    output = subprocess.check_output(command, shell=True).decode("utf-8")
    tmp_elf_binares = list(filter(None, output.split("\n")))
    for bin in tmp_elf_binares:
        # TODO: Activate this function is QEMU false.
        # if verify_afl_cov(bin): # Since we are now using QEMU mode, every binary is fuzzable
        return_list.append((bin, repo_path))
    return return_list


def return_afl_fuzzable_binaries_for_all_repos(path: str) -> [(str, str)]:
    """
    Given a path to a dictionary that contains repos, return all fuzzable binaries in the repositories. 
    :param path: The path to the list of repos.
    :return: A list of fuzzable binaries as tuples (binary_path,repo_path)
    """
    list_dir = os.listdir(path)
    return_list = []
    for repo in list_dir:
        return_list += find_afl_fuzzable_binaries_in_repo(repo_path=path + "/" + repo)
    print(return_list)
    return return_list


def get_git_clone_link_from_repo_path(repo_path: str):
    """
    Given the path to a git repository, extract the link to clone it.
    :return: The link to the git.
    """
    if not repo_path:
        raise ValueError("repo_path is not set")
    output = str(subprocess.check_output(["git", "config", "--get", "remote.origin.url"], cwd=repo_path),
                 errors="ignore").strip()
    return output


def get_repo_name_from_git_download_link(download_link):
    """
    Get the repositories name from the git clone link.
    :param download_link: The git clone link.
    :return: The repository name.
    """
    m = re.search("https://github.com/(.*)/(.*)", download_link)
    if m:
        return m.groups(0)[1]


def get_author_name_from_git_download_link(download_link):
    """
    Get the author's name from the git clone link.
    :param download_link: The git clone link.
    :return: The author login.
    """
    m = re.search("https://github.com/(.*)/(.*)", download_link)
    if m:
        return m.groups(0)[0]


def get_relative_binary_path(binary_path: str, repo_path: str) -> str:
    """
    Given the absolute path to a repository and the absolute path to the repository, 
    return the relative path of the binary (relative to the repository).
    :param binary_path: The absolute path to the binary.
    :param repo_path: The relative path to the binary.
    :raises ValueError: If binary_path is not relative to repo_path
    :return: The relative path to the binary (relative to repository path)
    """
    common_prefix = os.path.commonprefix([binary_path, repo_path])
    if common_prefix:
        relpath = os.path.relpath(binary_path, common_prefix)
        return relpath
    else:
        raise ValueError("binary_path not relative to repo_path")
