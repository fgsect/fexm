import logging
import subprocess

import sh
from sh import aflize
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import configfinder.config_settings
import helpers.utils
from enum import Enum

try:
    # noinspection PyUnresolvedReferences
    from sh import pacman
except ImportError:
    from sh import apt_get, dpkg, dpkg_query


class PackageManager(Enum):
    PACMAN = 1
    APT = 2


class Builder:
    @staticmethod
    def detect_package_manager():
        if "apt_get" in globals():  # if os.path.exists("/etc/debian_version"):
            return PackageManager.APT
        elif "pacman" in globals():  # os.path.exists("/etc/arch-release"):
            return PackageManager.PACMAN
        return None

    def __init__(self, package: str, qemu=False, asan=False, overwrite=False):
        self.package = package
        self.qemu = qemu
        self.asan = asan
        self.overwrite = overwrite
        self.package_manager = Builder.detect_package_manager()
        self.package_dir = None
        self.installed = False

    def get_file_list(self):
        """
        If the package is already installed/build, returns the paths to the files
        that are shipped with the packages
        :return:
        """
        if self.installed:
            if self.package_manager == PackageManager.APT:

                query_command = dpkg_query("-L", self.package)  # type: sh.RunningCommand
                query_commmand_output = str(query_command).strip()[1:]  # starts with "./" apparently
                files = query_commmand_output.split("\n")
                return files
            else:
                query_command = pacman("-Ql", "--quiet", self.package)  # type: sh.RunningCommand
                query_command_output = str(query_command).strip()[1:]  # starts with "./" (not in pacman)
                files = query_command_output.split("\n")
                return files
        elif self.package_dir:
            return list(helpers.utils.absoluteFilePaths(self.package_dir))

    def install_with_pacman(self) -> bool:
        print("Trying to install {0} via pacman".format(self.package))
        try:
            install_command = pacman("-Sy", "--noconfirm", self.package,
                                     _env=configfinder.config_settings.newenv)  # _out=sys.stdout)
            self.qemu = True
        except sh.ErrorReturnCode as e:
            print("Could not install package {0}".format(self.package))
            return False
        if self.package_manager == PackageManager.PACMAN:
            self.install_opt_depends_for_pacman()
        self.installed = True
        return True

    def install_with_apt(self) -> None:
        install_command = apt_get.install("-y", self.package,
                                          _env=configfinder.config_settings.newenv)  # type: sh.RunningCommand
        if install_command.exit_code != 0:
            print("Could not install package, exiting")

    def try_build(self) -> bool:
        print("Trying to build {0}".format(self.package))
        logging.info("Starting to build {0}".format(self.package))
        try:
            newenv = configfinder.config_settings.newenv.copy()
            if self.asan:
                newenv["AFL_USE_ASAN"] = "1"
            install_command = aflize(self.package, _timeout=configfinder.config_settings.BUILD_TIMEOUT, _env=newenv)
            logging.info("Finished building {0}".format(self.package))
            print("Build success {0}!".format(self.package))
        except sh.ErrorReturnCode as e:
            print("Could not build package {0}".format(self.package))
            logging.info("Building {0} failed".format(self.package))
            logging.info("STDOUT {0} failed".format(e.stdout.decode("utf-8")))
            logging.info("STDERR {0} failed".format(e.stdout.decode("utf-8")))
            print("Error: ")
            print("STDOUT", e.stdout.decode("utf-8"))
            print("STDERR", e.stderr.decode("utf-8"))
            return False
        except sh.TimeoutException as e:
            print("Could not build package {0}: Timeout".format(self.package))
        if self.package_manager == PackageManager.PACMAN:
            self.install_opt_depends_for_pacman()
        self.package_dir = os.path.join("/build", self.package)
        self.installed = False
        return True

    def is_package_installed(self) -> bool:
        if self.package_manager == PackageManager.PACMAN:
            installed_query_command = pacman("-Qi", self.package, _ok_code=[0, 1],
                                             _env=configfinder.config_settings.newenv)  # type:sh.RunningCommand
        elif self.package_manager == PackageManager.APT:
            installed_query_command = dpkg("-s", self.package, _ok_code=[0, 1],
                                           _env=configfinder.config_settings.newenv)
        else:
            raise ValueError("No supported package manager found!")
        if installed_query_command.exit_code == 0:
            print("Package {0} is already installed!".format(self.package))
            return True
        elif installed_query_command.exit_code == 1:
            return False

    def install_deps(self):
        command = "pacman -Si {0} |grep \"Depends\"|cut -d: -f2 | sed -e \"s/ \+/ /g\" | sed -e \"s/ /\\n/g\" | sed -e 's/^[ \\t]*//' | xargs -I {{}} pacman -Sy --noconfirm {{}}".format(
            self.package)
        return subprocess.check_output(command, shell=True)  # TODO: Highly insecure

    def install_package_from_package_manager(self):
        if self.package_manager == PackageManager.PACMAN:
            return self.install_with_pacman()
        elif self.package_manager == PackageManager.APT:
            return self.install_with_apt()

    def install_opt_depends_for_pacman(self):
        from repo_crawlers.archcrawler import ArchCrawler
        ac = ArchCrawler(query="name={0}".format(self.package))
        packagedict = list(ac)[0]
        opt_dependencies = packagedict.get("optdepends")
        opt_dependencies = [dep.split(":")[0] for dep in opt_dependencies if
                            len(dep.split(":")) >= 1]  # Dependencies often have format package: description
        for dep in opt_dependencies:
            print("Trying to install dependency {0} via pacman".format(dep))
            try:
                install_command = pacman("pacman")("-Sy", "--needed", "--noconfirm", dep)  # _out=sys.stdout)
                self.qemu = True
            except sh.ErrorReturnCode as e:
                print("Could not install dependency {0}".format(dep))
            print("Successfully installed package {0}".format(dep))

    def install(self) -> bool:
        """
        Install the package, but only if not already installed
        :return: 
        """
        if self.is_package_installed() and not self.overwrite:
            return True
        print("Installing {0}".format(self.package), flush=True)
        if not self.qemu:
            if self.try_build():
                self.qemu = False
                return True
        if self.asan:
            return False
        self.qemu = True
        return self.install_package_from_package_manager()
