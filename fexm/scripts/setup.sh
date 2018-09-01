#!/usr/bin/env bash
###
# Setup File -> Installs and sets all the things we need.
# Only run this on a live system if you understand the implications...
# Else: Install vagrant and run vagrant up to boot a FExM VM.
###

set -x
set -e
# sudo apt-get remove docker docker-engine docker.io
sudo apt-get update
sudo apt-get install \
     gcc \
     g++ \
     python3-dev \
     libdpkg-perl \
     apt-transport-https \
     ca-certificates \
     curl \
     virtualenv \
     virtualenvwrapper \
     gnupg2 \
     software-properties-common

curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
#sudo add-apt-repository "deb https://apt.dockerproject.org/repo ubuntu-$(lsb_release -cs) main"
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
sudo apt-get update
sudo apt-get install docker-ce rabbitmq-server 
sudo groupadd docker || true
sudo usermod -a -G docker ${USER}
sudo gpasswd -a ${USER} docker

sudo mkdir -p /etc/docker/
if sudo [ ! -f /etc/docker/daemon.json ]; then
  echo "{\"storage-driver\": \"overlay2\"}" | sudo tee /etc/docker/daemon.json &>/dev/null
fi

virtualenv -p python3 ${HOME}/.virtualenvs/FExM
source ${HOME}/.virtualenvs/FExM/bin/activate

pip install Cython
pip install --upgrade pip

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
pip install -r ${DIR}/../requirements.txt
pip install ipython

# Install own patched version of afl-utils
cd ${DIR}/../docker_scripts/afl_base_image/afl_utils/
python ./setup.py install
