FROM ubuntu:16.04

# Dependencies
RUN apt update --fix-missing
RUN apt install -y build-essential
RUN apt install -y git vim unzip python-dev python-pip ipython wget libssl-dev g++-multilib doxygen transfig imagemagick ghostscript zlib1g-dev

WORKDIR /opt
RUN mkdir workspace
WORKDIR /opt/fuzzer
RUN mkdir deps
WORKDIR /opt/fuzzer/deps

# Installing numpy
RUN wget https://github.com/numpy/numpy/releases/download/v1.16.6/numpy-1.16.6.zip
RUN unzip numpy-1.16.6.zip
RUN rm numpy-1.16.6.zip
RUN mv numpy-1.16.6 numpy
WORKDIR /opt/fuzzer/deps/numpy
RUN python setup.py install
WORKDIR /opt/fuzzer/deps

# install pyelftools
RUN pip install pyelftools

# install CMake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.16.2/cmake-3.16.2.tar.gz
RUN tar -xvzf cmake-3.16.2.tar.gz
RUN rm cmake-3.16.2.tar.gz
RUN mv cmake-3.16.2 cmake
WORKDIR /opt/fuzzer/deps/cmake
RUN ./bootstrap
RUN make
RUN make install
WORKDIR /opt/fuzzer/deps

# install dynamorio
RUN git clone https://github.com/DynamoRIO/dynamorio.git
WORKDIR /opt/fuzzer/deps/dynamorio
RUN mkdir build
WORKDIR /opt/fuzzer/deps/dynamorio/build
RUN cmake ../
RUN make
WORKDIR /opt/fuzzer/deps

# set up the tracer
COPY ./code/iftracer.zip /opt/fuzzer/deps/iftracer.zip
RUN unzip iftracer.zip
RUN rm iftracer.zip
WORKDIR /opt/fuzzer/deps/iftracer/iftracer
RUN cmake CMakeLists.txt
RUN make
WORKDIR /opt/fuzzer/deps/iftracer/ifLineTracer
RUN cmake CMakeLists.txt
RUN make
WORKDIR /opt/fuzzer

# set up CVE-2016-5314
RUN mkdir cves
WORKDIR /opt/fuzzer/cves
RUN mkdir cve_2016_5314
WORKDIR /opt/fuzzer/cves/cve_2016_5314
RUN apt install -y build-essential git vim unzip python-dev python-pip ipython zlib1g-dev
COPY ./data/libtiff/cve_2016_5314/source.zip ./source.zip
RUN unzip source.zip
RUN rm source.zip
WORKDIR /opt/fuzzer/cves/cve_2016_5314/source
RUN ./configure
RUN make CFLAGS="-static -ggdb" CXXFLAGS="-static -ggdb"
# copy exploit
WORKDIR /opt/fuzzer/cves/cve_2016_5314
COPY ./data/libtiff/cve_2016_5314/exploit ./exploit
# setup an exploit detector for cve-2016-5314 --- valgrind
WORKDIR /opt/fuzzer/deps
RUN apt install -y libc6-dbg
RUN wget https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
RUN tar xjf valgrind-3.15.0.tar.bz2
RUN mv valgrind-3.15.0 valgrind
WORKDIR /opt/fuzzer/deps/valgrind
RUN ./configure
RUN make
RUN make install

# prepare code
WORKDIR /opt/fuzzer
RUN mkdir code
WORKDIR /opt/fuzzer/code
COPY ./code/fuzz.py ./
COPY ./code/parse_dwarf.py ./
COPY ./code/patchloc.py ./
COPY ./code/tracer.py ./
COPY ./code/utils.py ./
COPY ./code/env.py ./

WORKDIR /opt/fuzzer
