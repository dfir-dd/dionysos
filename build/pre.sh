#!/bin/bash

echo "updating package metadata"
echo "============================================"
if [ -f /etc/alpine-release ]; then
    apk update
else 
    apt-get update
fi
echo "============================================"

echo "installing missing packages"
if [ -f /etc/alpine-release ]; then
    apk add autoconf automake libtool bison
    git clone https://github.com/VirusTotal/yara.git
    cd yara.git
    git checkout v4.2.1
    ./bootstrap.sh
    ./configure --enable-static
    make && make install
    cd ..

    curl https://astron.com/pub/file/file-5.42.tar.gz --output - | tar xz
    cd file-5.42
    ./configure --enable-static && make && make install
    cd ..

    cd ..

    apk add clang-static yara-dev clang-dev
else
    apt-get install -y libyara-dev clang
fi
echo "============================================"