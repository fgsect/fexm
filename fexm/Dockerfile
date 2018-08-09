FROM pacman-afl-fuzz
RUN mkdir -p /fuzz
WORKDIR /fuzz/
RUN pacman -Sy && pacman -S --noconfirm strace python python-pip parallel
RUN pip3 install sh
RUN pip3 install scipy
RUN pip3 install matplotlib
RUN pip3 install pandas
RUN pip3 install requests
COPY . /inputinferer
ENTRYPOINT ["python","/inputinferer/configfinder/config_finder_for_pacman_package.py"]
