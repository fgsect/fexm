#!/bin/bash
set -e
pacman -Syy #Synchronize package database
mkdir -p /build
chgrp nobody /build
chmod g+ws /build
#setfacl -m u::rwx,g::rwx /home/build
#setfacl -d --set u::rwx,g::rwx,o::- /home/build
cd /build
set +e
asp checkout $1
set -e
chmod -R 0777 $1
chmod -R 0777 .
cd $1
cd "$(dirname "$(find . -type f -name PKGBUILD | head -1)")" #Find the folder that contains the PKGBUILD file
chmod -R 0777 .
chown nonrootuser -R /build/$1
/usr/bin/setup-afl-clang-fast
set +e
sudo -u nonrootuser  -E makepkg -f --nocheck --syncdeps --skippgpcheck --skipchecksums --skipinteg --noconfirm CC=/usr/local/bin/afl-clang-fast CXX=/usr/local/bin/afl-clang-fast++
if [ "$?" -ne "0" ]
then
    # Build with afl-clang fast failed, let's try afl-gcc
    set -e
    /usr/bin/setup-afl-gcc
    sudo -u nonrootuser  -E makepkg -f --nocheck --syncdeps --skippgpcheck --skipchecksums --skipinteg --noconfirm CC=/usr/local/bin/afl-gcc CXX=/usr/local/bin/afl-g++ AFL_CC=/usr/bin/x86_64-pc-linux-gnu-gcc AFL_CXX=/usr/bin/x86_64-pc-linux-gnu-g++
fi
chown root -R /build/$1 # Give ownership back to root



