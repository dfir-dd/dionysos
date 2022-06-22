#!/bin/bash

echo "updating Rust build toolchain"
echo "============================================"
rustup update stable
rustup default stable
rustup show
echo "============================================"

echo "updating package metadata"
echo "============================================"
apt update
echo "============================================"

echo "installing missing packages"
apt-get install -y libyara-dev libclang-dev
echo "============================================"