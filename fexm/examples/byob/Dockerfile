FROM pacmanfuzzer
WORKDIR /data
#WORKDIR /data/build/byob/reviveme
COPY reviveme.c ./reviveme.c
COPY crashing_binary.c ./crashing_binary.c
RUN /usr/bin/x86_64-pc-linux-gnu-gcc reviveme.c -o reviveme
RUN rm -rf jhead
RUN git clone https://github.com/oelbrenner/jhead --depth=1
#RUN mkdir jhead
RUN cp reviveme jhead/
RUN cd jhead/ && AFL_USE_ASAN=1 make
#RUN gcc crashing_binary.c -o crashing_binary
ENTRYPOINT ["/bin/bash"]
