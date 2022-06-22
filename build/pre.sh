#!/bin/bash

echo "updating package metadata"
echo "============================================"
apt update
echo "============================================"

echo "installing missing packages"
apt-get install -y libyara-dev clang-13
echo "============================================"