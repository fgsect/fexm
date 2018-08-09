import os
import unittest

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from docker.docker_wrapper import DockerWrapper
from docker.docker_image import DockerImage
import sh


class TestDockerWrapper(unittest.TestCase):
    """
    Unittesting the DockerWrapper class.
    """

    def test_run_command_in_docker_container_and_return_output(self):
        dw = DockerWrapper("busybox")
        output = dw.run_command_in_docker_container_and_return_output(["/bin/echo", "hello"]).strip()
        self.assertEqual(output, "hello")

    def test_run_command_in_docker_container_with_error(self):
        dw = DockerWrapper("busybox")
        with self.assertRaises(sh.TimeoutException):
            output = dw.run_command_in_docker_container_and_return_output(["sleep", "3"], _timeout=1).strip()
        with self.assertRaises(sh.ErrorReturnCode):
            output = dw.run_command_in_docker_container_and_return_output(["exit", "4"])


class TestDockerImage(unittest.TestCase):
    """
    Unittesting the DockerWrapper class.
    """

    def test_build_image_from_repo_path(self):
        di = DockerImage.create_afl_docker_image_from_repo_path(repo_path="/home/vincent/tmp/docker_tmp/ngrep",
                                                                seeds_path="/" + os.getcwd() + "/")


if __name__ == '__main__':
    unittest.main()
