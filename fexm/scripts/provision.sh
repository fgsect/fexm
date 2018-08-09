#!/bin/bash

#set -x
DEPS="vim git apt-transport-https ca-certificates curl fish \
    gnupg2 software-properties-common cpufrequtils docker-ce rabbitmq-server virtualenv gcc g++ \
    python3-dev python-pip \
    cmake zliblg-dev libtool-bin automake bison libglib2.0-dev libpixman-1-dev"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

echo -e "I am provisioning..."
sudo bash -c "date > /etc/vagrant_provisioned_at"

sudo apt-get -y upgrade && sudo apt-get -y dist-upgrade
export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true

cd /fexm

echo -e "Installing essential packages"
echo -e "This might take a while... Coffee, perhaps?"

yes | /fexm/scripts/setup.sh

sudo apt-get install -y ${DEPS} # &> /dev/null # $pkg &> /dev/null

# Setup VM for AFL (crash logs and performance cpu freq)
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils >/dev/null
sudo modprobe cpufreq_performance
sudo systemctl disable ondemand
sudo /etc/init.d/cpufrequtils restart

# Get core pattern to persist.
sudo sh -c "echo enabled=0 > /etc/default/apport"
sudo sh -c "echo kernel.core_pattern=core >> /etc/sysctl.conf"
sudo sh -c "echo sysctl -p > /etc/rc.local"
sudo sysctl -p

sudo chsh -s `which fish` $USER

echo "Linking folders"
ln -s /fexm ~/fexm || true
ln -s /data ~/data || true
ln -s /seeds ~/seeds || true

echo "Linking fexm to FExM env"
ln -s /fexm/fexm.py ~/.virtualenvs/FExM/bin/fexm || true

mkdir -p ~/.config/fish
touch ~/.config/fish/config.fish
echo "workon FExM" >> ~/.bashrc
echo "workon FExM" >> ~/.zshrc
echo "fish_prompt > /dev/null" >> ~/.config/fish/config.fish
echo "source ~/.virtualenvs/FExM/bin/activate.fish" >> ~/.config/fish/config.fish

echo "set fish_greeting \"Welcome to FuzzExMachina. Never send a human to do a machine's job.\"" >> ~/.config/fish/config.fish
echo "cd /fexm" >> ~/.config/fish/config.fish

sudo mkdir /data || true # in case we didn't forward the data folder

echo -e "Provisioning done. Run \"vagrant ssh\" to connect and \"fexm -h\" inside to get started. Welcome to FExM."
