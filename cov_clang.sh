#!/bin/sh
VER=`echo $CXX|sed 's/clang++//'`
/home/ubuntu/connectedhomeip/.environment/cipd/packages/pigweed/bin/llvm-cov gcov $*
