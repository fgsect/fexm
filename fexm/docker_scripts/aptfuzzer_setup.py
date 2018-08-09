#!/usr/bin/env python3
"""
Call this script in order to set up the base image for fuzzing apt packages.
"""
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from docker_scripts.docker_image import DockerImage
import argparse

APTFUZZ_SEED_IMAGE = "aptfuzzseeds"
APTFUZZER_IMAGE = "aptfuzzer"
"""
Set up the base iamge
"""


def init(seeds_path: str):
    di = DockerImage.create_afl_base_image_from_seeds_path(seeds_path=seeds_path, name=APTFUZZ_SEED_IMAGE)
    print("Finished building the seeds image")

    with open(os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/dockerfile", "w") as dockerfp:
        dockerfp.write("FROM {0}\n".format(APTFUZZ_SEED_IMAGE))
        dockerfp.write("RUN apt-get update && apt-get install -y libpcap-dev strace python3.5 python3-pip\n")
        dockerfp.write("RUN pip3 install sh\n")
        dockerfp.write("RUN pip3 install sh\n")
        dockerfp.write("RUN pip3 install scipy\n")
        dockerfp.write("RUN pip3 install matplotlib\n")
        dockerfp.write("COPY . /inputinferer\n")
        dockerfp.write('ENTRYPOINT ["python3.5","inputinferer/config_finder_for_apt_package.py"]\n')

    # Create the base image with all the scripts, but without the seeds, Dockerfile should already be in this folder.
    di = DockerImage(dockerfile_path=os.path.dirname(os.path.realpath(__file__)) + "/../configfinder/dockerfile",
                     image_name=APTFUZZER_IMAGE)
    print("Finished building the base image.")
    print("Starting to build the seeds image.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Build the GithubFuzzer base image.')
    parser.add_argument('seed_path', metavar='Seed Path', type=str,
                        help='The path to the seed file')
    args = parser.parse_args()
    init(seeds_path=args.seed_path)
