#!/usr/bin/env bash
# Prepares a directory with Debian packages compiled in a form ready for
# fuzzing with american fuzzy lop. See README.md for more details.
#
# AUTHOR: Jacek "d33tah" Wielemborek, licensed under WTFPL.
#
#./etc/profile.d/afl-sh-profile

set -e

if [ "$#" = "0" ]; then
    echo "ERROR: Running 'aflize' without parameters is not supported" 2>&1
    echo "anymore. Let me know if you need this feature." 2>&1
    exit 1
fi

#apt-get update

# TODO: figure out whether dpkg-buildpackage supports -J. On Ubuntu it might
# not and we could either turn it off or use -j instead. Use the following
# command line to check:
#
# dpkg-buildpackage -J 2>&1 | grep 'unknown option or argument'

for pkg in $@; do

        rm -rf ~/pkg
        mkdir ~/pkg

        # Building some source packages results in more than one .deb file.
        # There's no point building coreutils multiple times just because we
        # need mount, libmount1 and libmount1-dev, for example.
        if [ -f ~/pkgs/${pkg}_* ]; then
            echo "Skipping $pkg because it's already in ~/pkgs."
            continue
        fi

        echo "Aflizing $pkg"

        cd ~/pkg

        ATTEMPTS_START=3
        ATTEMPTS_REMAINING=$ATTEMPTS_START
        while true; do
            ATTEMPTS_REMAINING=$(( $ATTEMPTS_REMAINING - 1 ))
            if [ "$ATTEMPTS_REMAINING" -eq "0" ]; then
                echo "Breaking." 2>&1
                break
            fi
            apt-get build-dep -y $pkg 2>&1 && break
        done
        if [ "$ATTEMPTS_REMAINING" -eq "0" ]; then
            echo "Failed do download dependencies for $pkg." >&2
            exit 1
        fi

        echo -n "Success after " >&2
        echo -n $(( $ATTEMPTS_START - $ATTEMPTS_REMAINING )) >&2
        echo "  attempts." >&2

        apt-get source $pkg 2>&1
        cd */

        (CC=afl-clang-fast CXX=afl-clang-fast++ dpkg-buildpackage -uc -us -Jauto 2>&1 | \
            tee ~/logs/${pkg}.txt ) || ( echo $pkg >> ~/failed; exit 1 )
        echo "$pkg successful"
        mv ~/pkg/*.deb ~/pkgs

done | perl -pe '$|=1; print scalar(localtime()), ": ";'
#dpkg -i ~/pkgs/*.deb