#!/bin/sh
# build-deps.sh - build static (.a) versions of libmnl, libnfnetlink and
# libnetfilter_queue into ./deps/install so ra-rewrite can be statically
# linked against them (everything static except glibc).
#
# Copyright (C) 2026  ra-rewrite contributors
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Most distributions ship only the shared (.so) versions of these libraries,
# so we build the static archives ourselves from upstream source. This keeps
# the final binary self-contained: a single executable that runs on any glibc
# system without needing libnetfilter_queue/libnfnetlink/libmnl installed.

set -eu

LIBMNL_VER="${LIBMNL_VER:-1.0.5}"
LIBNFNETLINK_VER="${LIBNFNETLINK_VER:-1.0.2}"
LIBNFQ_VER="${LIBNFQ_VER:-1.0.5}"

BASE="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="$BASE/deps"
SRC="$DEPS/src"
PREFIX="$DEPS/install"

mkdir -p "$SRC" "$PREFIX"

NF="https://www.netfilter.org/projects"

fetch() {
    url="$1"; out="$2"
    if [ -f "$out" ]; then return 0; fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$out"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$out"
    else
        echo "need curl or wget" >&2; exit 1
    fi
}

build_one() {
    name="$1"; ver="$2"; url="$3"
    tarball="$SRC/$name-$ver.tar.bz2"
    dir="$SRC/$name-$ver"
    echo ">>> $name-$ver"
    fetch "$url" "$tarball"
    rm -rf "$dir"
    tar -C "$SRC" -xf "$tarball"
    cd "$dir"
    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" \
        ./configure --prefix="$PREFIX" \
                    --enable-static --disable-shared \
                    --with-pic
    make -j"$(nproc 2>/dev/null || echo 2)"
    make install
    cd "$BASE"
}

# Order matters: libmnl first, then libnfnetlink (uses libmnl), then
# libnetfilter_queue (uses both).
build_one libmnl            "$LIBMNL_VER"      "$NF/libmnl/files/libmnl-$LIBMNL_VER.tar.bz2"
build_one libnfnetlink      "$LIBNFNETLINK_VER" "$NF/libnfnetlink/files/libnfnetlink-$LIBNFNETLINK_VER.tar.bz2"
build_one libnetfilter_queue "$LIBNFQ_VER"     "$NF/libnetfilter_queue/files/libnetfilter_queue-$LIBNFQ_VER.tar.bz2"

echo
echo "Static libraries installed under: $PREFIX/lib"
ls -1 "$PREFIX"/lib/*.a 2>/dev/null || true
