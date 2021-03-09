#!/bin/bash
autoreconf --install
./configure --prefix=$PWD/build
make -j8
make install
