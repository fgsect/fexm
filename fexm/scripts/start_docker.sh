#!/usr/bin/env bash

# This start a docker with the right mounts:
realpath_fuzzdata=$(realpath $1/fuzz_data)
realpath_buildata=$(realpath $1/build_data)
realpath_runconfigs=$(realpath $1/run_configurations)
realpath_seeds=$(realpath $2)
docker run -p 2800:2800 -p 2801:2801 -ti --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --privileged --rm --entrypoint /bin/bash -v $realpath_fuzzdata:/results -v $realpath_buildata:/build -v $realpath_runconfigs:/run_configurations -v $realpath_seeds:/fuzz/seeds pacmanfuzzer
