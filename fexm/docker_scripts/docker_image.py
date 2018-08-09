import uuid

import os
import sh
from sh import docker


def process_output(line):
    print(line)


class DockerImage(object):
    """
    An object of this class represents a dockerimage.
    """
    BASE_IMAGE_NAME = "githubfuzzerbase"
    SEED_IMAGE_NAME = "githubfuzzer"

    def __init__(self, dockerfile_path: str, image_name: str):
        """
        :param dockerfile_path: The path to the dockerfile. 
        :param image_name: The name of the built image.
        """
        self.dockerfile_path = dockerfile_path
        if not os.path.exists(dockerfile_path) or not os.path.isfile(dockerfile_path):
            raise FileNotFoundError("dockerfile_path must be path to a file! Is {0} instead".format(dockerfile_path))
        self.image_name = image_name
        self.image_built = False
        self.build_image()

    def build_image(self):
        print("Running docker build", ["-t", self.image_name, os.path.dirname(self.dockerfile_path)])
        build_command = docker.build("-t", self.image_name, os.path.dirname(self.dockerfile_path),
                                     _out=process_output)  # type: sh.RunningCommand
        if build_command.exit_code == 0:
            self.image_built = True

    def delete_image(self):
        delete_command = docker.rmi(self.image_name)
        if delete_command.exit_code == 0:
            self.image_built = False

    @classmethod
    def create_afl_docker_image_from_repo_path(cls, repo_path: str):
        dockerfile_string = "FROM {0}\n".format(DockerImage.SEED_IMAGE_NAME)
        dockerfile_string += "\nCOPY . /" + repo_path
        with open(repo_path + "/dockerfile", "w") as dockerfile:
            dockerfile.write(dockerfile_string)
        image_name = "fuzz_" + os.path.basename(repo_path) + str(uuid.uuid1())
        image_name = image_name.lower()  # Docker images names must be in lower case
        return cls(dockerfile_path=repo_path + "/dockerfile", image_name=image_name)

    @classmethod
    def create_afl_base_image_from_seeds_path(cls, seeds_path: str, name: str):
        dockerfile_string = "FROM 0x6c7862/afl-fuzz\n"
        dockerfile_string += "RUN apt-get update && apt-get install -y libpcap-dev\n"
        dockerfile_string += "COPY . seeds/"
        print(seeds_path + "/dockerfile")
        with open(seeds_path + "/dockerfile", "w") as dockerfile:
            dockerfile.write(dockerfile_string)
        image_name = name
        di = DockerImage(dockerfile_path=seeds_path + "/dockerfile", image_name=image_name)
        print("Done###")
        return di

    @classmethod
    def create_afl_pacman_base_image_without_seeds(cls):
        di = DockerImage(dockerfile_path=os.path.dirname(__file__) + "/afl_base_image/Dockerfile",
                         image_name="pacman-afl-fuzz")
        return di

    @classmethod
    def create_afl_pacman_base_image_from_seeds_path(cls, seeds_path: str, name: str):
        di = DockerImage(dockerfile_path=os.path.dirname(__file__) + "/afl_base_image/Dockerfile",
                         image_name="pacman-afl-fuzz")
        dockerfile_string = "FROM pacman-afl-fuzz\n"
        dockerfile_string += "RUN mkdir /fuzz\n"
        dockerfile_string += "WORKDIR /fuzz/\n"
        dockerfile_string += "COPY . seeds/"
        print(seeds_path + "/dockerfile")
        with open(seeds_path + "/dockerfile", "w") as dockerfile:
            dockerfile.write(dockerfile_string)
        image_name = name
        di = DockerImage(dockerfile_path=seeds_path + "/dockerfile", image_name=image_name)
        print("Done###")
        return di

    @classmethod
    def create_githubfuzzer_image(cls, seeds_path: str):
        dockerfile_string = "FROM {0}\n".format(DockerImage.BASE_IMAGE_NAME)
        dockerfile_string += "COPY . seeds/"
        with open(seeds_path + "/dockerfile", "w") as dockerfile:
            dockerfile.write(dockerfile_string)
        image_name = DockerImage.SEED_IMAGE_NAME
        di = DockerImage(dockerfile_path=seeds_path + "/dockerfile", image_name=image_name)
        return di

    @classmethod
    def create_aptfuzzer_iamge(cls, baseimagename: str, image_name: str):
        dockerfile_string = "FROM {0}\n".format(baseimagename)
        dockerfile_string += "COPY . /inputinferer\n"
        dockerfile_string += 'ENTRYPOINT ["python3.5","inputinferer/config_finder_for_apt_package.py"]\n'
        with open(os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/dockerfile", "w") as dockerfp:
            dockerfp.write(dockerfile_string)
        with open(os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/.dockerignore", "w") as dockerfp:
            dockerfp.write("env")
        di = DockerImage(dockerfile_path=os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/dockerfile",
                         image_name=image_name)
        return di

    @staticmethod
    def check_if_base_image_exists() -> bool:
        if "githubfuzzer" in str(docker.images("-a")):
            return True
        else:
            return False
