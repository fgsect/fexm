#!/usr/bin/env python3
"""
Call this script in order to set up the base image for fuzzing github packages.
"""
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from docker_scripts.docker_image import DockerImage
import argparse

"""
Set up the base iamge
"""


def init(seeds_path: str):
    with open(os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/dockerfile", "w") as dockerfp:
        dockerfp.write("FROM 0x6c7862/afl-fuzz\n")
        dockerfp.write("RUN apt-get update && apt-get install -y libpcap-dev strace python3.5 python3-pip\n")
        dockerfp.write("COPY . /inputinferer\n")
        dockerfp.write('ENTRYPOINT ["python3.5","inputinferer/config_finder_for_binary.py"]\n')

    di = DockerImage(dockerfile_path=os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/dockerfile",
                     image_name=DockerImage.BASE_IMAGE_NAME)  # Create the base image with all the scripts, but without the seeds, Dockerfile should already be in this folder.
    print("Finished building the base image.")
    print("Starting to build the seeds image.")
    di = DockerImage.create_githubfuzzer_image(
        seeds_path + "/")  # Now: Create an image on top of that including the seeds


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Build the GithubFuzzer base image.')
    parser.add_argument('seed_path', metavar='Seed Path', type=str,
                        help='The path to the seed file')
    args = parser.parse_args()
    init(seeds_path=args.seed_path)
