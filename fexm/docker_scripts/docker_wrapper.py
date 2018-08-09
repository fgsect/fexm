import sh
from sh import docker


class DockerWrapper(object):
    """
    This class wraps docker calls to a certain image.
    """

    def __init__(self, docker_image: str):
        """
        :param docker_image: The name of the docker image. It should already exist.
        """
        self.docker_image = docker_image

    def run_command_in_docker_container_and_return_output(self, command: [str], *args, **kwargs):
        """
        Runs a command (with arguments) in the new docker container. 
        :param command: A list of strings, e.g., ["echo","hello"]
        :return: The output.
        """
        docker_command = docker.run("--rm=true", "--cap-add=SYS_PTRACE", self.docker_image, command,
                                    **kwargs)  # type: sh.RunningCommand
        return str(docker_command)
