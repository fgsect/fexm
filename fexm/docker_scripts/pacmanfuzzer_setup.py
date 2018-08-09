#!/usr/bin/env python3
"""
Call this script in order to set up the base image for fuzzing pacman packages.
"""
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from docker_scripts.docker_image import DockerImage
import argparse

PACMANFUZZ_SEED_IMAGE = "pacmanfuzzseeds"
PACMANFUZZER_IMAGE = "pacmanfuzzer"
"""
Set up the base iamge
"""


def init(update=False):
    if not update:
        di = DockerImage.create_afl_pacman_base_image_without_seeds()
        print("Finished building the seeds image")
    else:
        print("Update only: Updating")
    with open(os.path.dirname(os.path.realpath(__file__)) + "/../Dockerfile", "w") as dockerfp:
        dockerfp.write("FROM {0}\n".format("pacman-afl-fuzz"))
        dockerfp.write("RUN mkdir -p /fuzz\n")
        dockerfp.write("WORKDIR /fuzz/\n")
        dockerfp.write("RUN pacman -Sy && pacman -S --noconfirm strace python python-pip parallel\n")
        dockerfp.write("RUN pip3 install sh\n")
        dockerfp.write("RUN pip3 install scipy\n")
        dockerfp.write("RUN pip3 install matplotlib\n")
        dockerfp.write("RUN pip3 install pandas\n")
        dockerfp.write("RUN pip3 install requests\n")
        dockerfp.write("COPY . /inputinferer\n")
        dockerfp.write('ENTRYPOINT ["python","/inputinferer/configfinder/config_finder_for_pacman_package.py"]\n')
    import docker.errors
    docker_client = docker.from_env()
    old_image = None
    try:
        old_image = docker_client.images.get(PACMANFUZZER_IMAGE)
    except docker.errors.ImageNotFound:
        old_image = None
    di = DockerImage(dockerfile_path=os.path.dirname(os.path.realpath(__file__)) + "/../Dockerfile",
                     image_name=PACMANFUZZER_IMAGE)  # Create the base image with all the scripts, but without the seeds, Dockerfile should already be in this folder.
    # if old_image: TODO: Why does this not work?
    #    print("Removing the old {0} image".format(PACMANFUZZER_IMAGE))
    #    docker_client.images.remove(old_image.id)
    print("Finished building the base image.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Build the GithubFuzzer base image.')
    parser.add_argument("-U", dest="update", action="store_true", default=False,
                        help="Update the python code only.")
    args = parser.parse_args()
    init(update=args.update)
