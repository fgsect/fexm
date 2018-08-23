FROM base/archlinux
LABEL maintainer="Dominik Maier <domenukk@sect.tu-berlin.de>"

ENV REFRESHED_AT 2018-07-28

ENV DEBIAN_FRONTEND noninteractive

ENV AFL_INSTALL https://https://github.com/domenukk/afl-timewarp-qemu.git

# Update and install minimal
#
# afl:
#   build-essential, wget
#
# lidjpeg-turbo:
#   autoconf, automake, build-essential, libtool, nasm,
#   subversion, wget

RUN \
    pacman -Sy \
    && pacman -S --noconfirm \
    gcc \
    make \
    wget \
    git \
    python \
    python-pip \
    automake \
    autoconf \
    bison \
    patch \
    pkg-config \
    python \
    python-pip \
    python2 \
    asp \
    sudo \
    flex \
    openssh \
    clang \
    llvm \
    cmake \
    tmux \
    openbsd-netcat \
    fakeroot # For building packages manually 

# Some interactive tools
RUN pacman -Sy --noconfirm fish vim
RUN chsh -s `which fish`

# Get ready to build.
WORKDIR /tmp
# install afl-utils:
RUN pacman -S --noconfirm gdb
COPY ./exploitable exploitable
RUN cd exploitable && python setup.py install 
COPY ./afl_utils afl-utils
RUN cd afl-utils \
&& python setup.py install

# clone and build AFL.
COPY ./ssh /root/.ssh
RUN chmod 400 /root/.ssh/*

# SSH -i are hacks to get multiple deploy keys working. Instead, consider git clone --recursive once afl-timwarp-qemu is public
RUN git clone --recursive --depth 1 $AFL_INSTALL /tmp/afl-src

# Dependency for qemu
RUN pacman -Sy --noconfirm pixman

RUN cd /tmp/afl-src \
    && sed -i 's/^\/\/ #define USE_64BIT/#define USE_64BIT/gI' config.h \
    && make \
    && mkdir build || true \
    && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && cmake --build . \
    && cp fuzzwarp ../afl-fuzz \
    && cd .. \
    && make install \
    && cd /tmp/afl-src \
    && cd qemu_mode \
    && chmod +x ./build_afl_qemu_support.sh \
    && ./build_afl_qemu_support.sh \
    && cd ../llvm_mode \
    && LLVM_CONFIG=/usr/sbin/llvm-config make \
    && cd /tmp/afl-src \
    && make install

RUN mkdir /fuzz_dictionaries \
    && cp -r /tmp/afl-src/dictionaries/ /fuzz_dictionaries/ \
    && cp /fuzz_dictionaries/dictionaries/jpeg.dict /fuzz_dictionaries/dictionaries/jpg.dict \
    && rm /fuzz_dictionaries/dictionaries/README.dictionaries
    #&& cd /sys/devices/system/cpu \
    #&& echo performance | tee cpu*/cpufreq/scaling_governor
#    && rm -rf \
#        /tmp/afl-latest.tgz \
#        /tmp/afl-src
COPY ./aflize.sh /usr/bin/aflize
COPY ./afl_cmin_vincent.sh /usr/local/bin/afl_cmin_cov_only
COPY ./afl_probe.sh /usr/local/bin/afl_probe
RUN chmod +x /usr/bin/aflize
RUN chmod +x  /usr/local/bin/afl_probe
RUN chmod +x /usr/local/bin/afl_cmin_cov_only

COPY ./preeny /preeny
RUN cd /preeny \
    && pacman -Sy --noconfirm ding-libs \
    && make


RUN cd /tmp/afl-src/libdislocator && make && cp libdislocator.so /libdislocator.so

# Make sure afl-gcc will be run. This forces us to set AFL_CC and AFL_CXX or
# otherwise afl-gcc will be trying to call itself by calling gcc.
COPY ./afl-sh-profile /etc/profile.d/afl-sh-profile
RUN ln -s /etc/profile.d/afl-sh-profile /etc/profile.d/afl-sh-profile.sh
# It looks like /etc/profile.d isn't read for some reason, but .bashrc is.
# Let's include /etc/profile.d/afl-sh-profile from there.
RUN echo '. /etc/profile.d/afl-sh-profile' >> /root/.bashrc && chmod +x /root/.bashrc

RUN chmod +x /etc/profile.d/afl-sh-profile

COPY ./setup-afl-gcc /usr/bin/setup-afl-gcc
RUN chmod +x /usr/bin/setup-afl-gcc

COPY ./setup-afl-clang-fast /usr/bin/setup-afl-clang-fast
RUN chmod +x /usr/bin/setup-afl-clang-fast

RUN /usr/bin/setup-afl-clang-fast
RUN useradd nonrootuser
RUN echo "nonrootuser ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/nonrootuser && \
    chmod 0440 /etc/sudoers.d/nonrootuser
RUN pip3 install websockify
CMD ["bash"]
