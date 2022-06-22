#!/bin/bash

echo "updating package metadata"
echo "============================================"
apt-get update
echo "============================================"

echo "installing missing packages"
if [ -f /etc/alpine-release ]; then
    apt-get install clang-static
else
    apt-get install -y libyara-dev clang
fi
echo "============================================"