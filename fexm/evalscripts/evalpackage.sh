#!/usr/bin/env bash

if [ ${#@} -lt 5 ]; then
    echo "Usage: $0 package evaluation_dir binary_path parameter filetype"
    echo "* package: The package to test"
    echo "* evaluation_dir: The evaluation dir (to store the results)"
    echo "* binary_path: Binary Path"
    echo "* parameter: parameter binary"
    echo "* filetype: filetype"
    exit
fi
container_name="$1_build"
image_name="$1_image"
package=$1
evaluation_dir=$2
binary_path=$3
parameter=$4
filetype=$5
echo "docker run --rm --cap-add=SYS_PTRACE -v $evaluation_dir:/results/ --entrypoint python jhead_image /inputinferer/fuzzer_wrapper.py -p jhead -v /results/ -Q -s $5 --parameter=$4 -b $3 -afile jhead.afl_config"
docker rm -f $container_name
docker rmi $image_name
time docker run --name $container_name --entrypoint python pacmanfuzzer /inputinferer/builder_wrapper.py -p jhead -Q
time docker commit $container_name $image_name
time docker run --rm --cap-add=SYS_PTRACE -v $evaluation_dir:/results/ --entrypoint python jhead_image /inputinferer/config_finder_for_pacman_package.py -p jhead -v /results/ -Q
basename_result=$(basename $binary_path)
mkdir -p $evaluation_dir/$package/$basename_result
time docker run --rm --cap-add=SYS_PTRACE -v $evaluation_dir:/results/ --entrypoint python jhead_image /inputinferer/fuzzer_wrapper.py -p jhead -v /results/ -Q -s $5 --parameter=$4 -b $3 -afile jhead.afl_config