#!/bin/sh

aclocal
autoconf
automake -a -c
./configure --prefix=/usr/local
make

