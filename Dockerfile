FROM ubuntu:16.04

# Dependencies
RUN apt update --fix-missing
RUN apt install -y build-essential
RUN apt install -y git vim unzip python-dev python-pip ipython wget libssl-dev g++-multilib doxygen transfig imagemagick ghostscript zlib1g-dev valgrind

WORKDIR /opt
RUN mkdir workspace
WORKDIR /opt/fuzzer
RUN mkdir deps
WORKDIR /opt/fuzzer/deps

RUN mkdir -p /opt/fuzzer/pypackages/lib/python2.7/site-packages
ENV PYTHONPATH="/opt/fuzzer/pypackages/lib/python2.7/site-packages:/opt/fuzzer/pypackages:${PYTHONPATH}"

# Installing numpy
RUN wget https://github.com/numpy/numpy/releases/download/v1.16.6/numpy-1.16.6.zip
RUN unzip numpy-1.16.6.zip
RUN rm numpy-1.16.6.zip
RUN mv numpy-1.16.6 numpy
WORKDIR /opt/fuzzer/deps/numpy
RUN python setup.py install --prefix=/opt/fuzzer/pypackages
WORKDIR /opt/fuzzer/deps

# install pyelftools
RUN pip install --target=/opt/fuzzer/pypackages pyelftools

# (YT: use e9patch instead of dynamorio)
RUN wget -O e9patch https://github.com/GJDuck/e9patch/archive/889a412ecdbf072d3626b1cc44e59439b030157c.zip
WORKDIR /opt/fuzzer/deps/e9patch
RUN ./build.sh
COPY ./code/printaddr.c ./examples/
RUN ./e9compile.sh examples/printaddr.c

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

# prepare code
WORKDIR /opt/fuzzer
RUN mkdir code
WORKDIR /opt/fuzzer/code
COPY ./code/fuzz ./
COPY ./code/fuzz.py ./
COPY ./code/parse_dwarf.py ./
COPY ./code/patchloc.py ./
COPY ./code/tracer.py ./
COPY ./code/utils.py ./
COPY ./code/env.py ./

WORKDIR /opt/fuzzer
