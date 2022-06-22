#!/bin/bash

echo "updating Rust build toolchain"
echo "============================================"
rustup update stable
rustup default stable
rustup target add x86_64-unknown-linux-musl
rustup show
echo "============================================"

echo "updating package metadata"
echo "============================================"
apt update
echo "============================================"

echo "installing missing packages"
apt-get install -y libyara-dev libclang-dev
echo "============================================"