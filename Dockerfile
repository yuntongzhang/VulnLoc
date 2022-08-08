FROM ubuntu:18.04

# Dependencies
RUN apt update --fix-missing
RUN apt install -y build-essential software-properties-common
RUN apt install -y git vim unzip wget libssl-dev g++-multilib doxygen transfig imagemagick ghostscript zlib1g-dev valgrind 
# add this for installing latest version of python3.8
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt update

RUN apt install -y python3-pip gdb python3-dev python-dev python3.8

RUN python3.8 -m pip install pyelftools numpy==1.16.6

# prepare code
WORKDIR /opt/fuzzer
COPY . .

# RUN mkdir deps
RUN git submodule init
WORKDIR /opt/fuzzer/deps

# RUN mkdir -p /opt/fuzzer/pypackages/lib/python2.7/site-packages
# ENV PYTHONPATH="/opt/fuzzer/pypackages/lib/python2.7/site-packages:/opt/fuzzer/pypackages:${PYTHONPATH}"

# Installing numpy
# RUN wget https://github.com/numpy/numpy/releases/download/v1.16.6/numpy-1.16.6.zip
# RUN unzip numpy-1.16.6.zip
# RUN rm numpy-1.16.6.zip
# RUN mv numpy-1.16.6 numpy
# WORKDIR /opt/fuzzer/deps/numpy
# RUN python setup.py install --prefix=/opt/fuzzer/pypackages
# WORKDIR /opt/fuzzer/deps

# install pyelftools
# RUN pip install --target=/opt/fuzzer/pypackages pyelftools

# (YT: use e9patch instead of dynamorio)
# RUN wget -O e9patch.zip https://github.com/GJDuck/e9patch/archive/889a412ecdbf072d3626b1cc44e59439b030157c.zip
# RUN unzip e9patch.zip
# RUN rm e9patch.zip
# RUN mv e9patch-889a412ecdbf072d3626b1cc44e59439b030157c e9patch
WORKDIR /opt/fuzzer/deps/e9patch
RUN ./build.sh
RUN ./e9compile.sh /opt/fuzzer/code/printaddr.c
# COPY ./code/printaddr.c ./examples/
# RUN ./e9compile.sh examples/printaddr.c

# (YT: use redfat instead of Valgrind for detection)
# WORKDIR /opt/fuzzer/deps/
# RUN wget -O redfat.zip https://github.com/GJDuck/RedFat/archive/refs/tags/v0.1.0.zip
# RUN unzip redfat.zip
# RUN rm redfat.zip
# RUN mv RedFat-0.1.0 RedFat
WORKDIR /opt/fuzzer/deps/RedFat
RUN ./build.sh

# (YT: add setup of bugzilla-2633 for testing)
WORKDIR /opt/fuzzer/
RUN mkdir bugzilla-2633
WORKDIR /opt/fuzzer/bugzilla-2633
RUN mkdir vulnloc-output
COPY ./bugzilla_2633.config ./vulnloc-config
RUN wget -O exploit https://github.com/asarubbo/poc/raw/master/00107-libtiff-heapoverflow-PSDataColorContig
RUN git clone https://github.com/vadz/libtiff.git source
WORKDIR /opt/fuzzer/bugzilla-2633/source
RUN git checkout f3069a5
RUN ./configure
RUN make CFLAGS="-static" CXXFLAGS="-static" -j10
RUN cp tools/tiff2ps ../

WORKDIR /opt/fuzzer

# (YN: skipped setup of test cve)
## set up CVE-2016-5314
#RUN mkdir cves
#WORKDIR /opt/fuzzer/cves
#RUN mkdir cve_2016_5314
#WORKDIR /opt/fuzzer/cves/cve_2016_5314
#RUN apt install -y build-essential git vim unzip python-dev python-pip ipython zlib1g-dev
#COPY ./data/libtiff/cve_2016_5314/source.zip ./source.zip
#RUN unzip source.zip
#RUN rm source.zip
#WORKDIR /opt/fuzzer/cves/cve_2016_5314/source
#RUN ./configure
#RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"
## copy exploit
#WORKDIR /opt/fuzzer/cves/cve_2016_5314
#COPY ./data/libtiff/cve_2016_5314/exploit ./exploit

# # setup an exploit detector for cve-2016-5314 --- valgrind
# WORKDIR /opt/fuzzer/deps
# RUN apt install -y libc6-dbg
# RUN wget https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
# RUN tar xjf valgrind-3.15.0.tar.bz2
# RUN mv valgrind-3.15.0 valgrind
# WORKDIR /opt/fuzzer/deps/valgrind
# RUN ./configure
# RUN make
# RUN make install
