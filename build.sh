#!/bin/bash

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

set -e

ROOT=`pwd`

pushd $ROOT/deps

# (1) build e9patch
pushd e9patch
./build.sh
echo -e "${YELLOW}$0${OFF}: e9patch has been built!"

# (2) build trace instrumentation module
cp $ROOT/code/printaddr.c ./examples/
./e9compile.sh examples/printaddr.c
echo -e "${YELLOW}$0${OFF}: trace instrumentation module has been built!"
popd

# (3) build redfat
pushd RedFat
./build.sh
popd
echo -e "${YELLOW}$0${OFF}: RedFat has been built!"

popd

echo -e "${YELLOW}$0${OFF}: VulnLoc build finished."
