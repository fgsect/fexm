#!/bin/bash
cd $(pwd)
cd GithubFuzzer/celery_tasks
tmux new-session -d -s celery 'celery -A tasks worker --loglevel=info --concurrency=30'
cd ../
#Jhead builds without QEMU
#ncrack builds with qemu
env/bin/python tools/inference_manager_pacman.py -di pacmanfuzzer -cd $1 -p gif2png
#env/bin/python tools/inference_manager_pacman.py -di pacmanfuzzer -cd $1 -p ncrack
env/bin/python fuzz_manager/fuzz_manager_round_robin.py -di pacmanfuzzer -cd $1 -t 50 #-pt 30
#env/bin/python fuzz_manager/fuzz_manager_round_robin.py -di pacmanfuzzer -cd $1 -pt 60