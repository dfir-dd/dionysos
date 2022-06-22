#!/bin/bash

echo "updating Rust build environment"
echo "============================================"
rustup update stable
rustup show
echo "============================================"

echo "updating package metadata"
echo "============================================"
apt update
echo "============================================"

echo "installing missing packages"
apt-get install -y libyara-dev libclang-dev
echo "============================================"