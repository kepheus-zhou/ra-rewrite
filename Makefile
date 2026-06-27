# Makefile for ra-rewrite
#
# Copyright (C) 2026  ra-rewrite contributors
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Default target builds a binary that statically links libnetfilter_queue,
# libnfnetlink and libmnl, while leaving glibc dynamic. The static archives
# are produced by scripts/build-deps.sh into deps/install.
#
#   make            - build deps (if needed) then the static binary
#   make dynamic    - build against system shared libs instead
#   make test       - build and run the RA parse/build unit test
#   make clean      - remove build artifacts (keeps deps/)
#   make distclean  - also remove deps/

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=c11 -D_GNU_SOURCE
PREFIX  ?= /usr/local

DEPS_PREFIX := deps/install

SRC := src/main.c src/ra.c src/config.c
HDR := src/ra.h src/config.h
BIN := ra-rewrite

.PHONY: all static dynamic deps test clean distclean install uninstall

all: static

# --- Static build (default): everything static except glibc -------------
$(DEPS_PREFIX)/lib/libnetfilter_queue.a:
	sh scripts/build-deps.sh

deps: $(DEPS_PREFIX)/lib/libnetfilter_queue.a

static: deps
	$(CC) $(CFLAGS) -I$(DEPS_PREFIX)/include $(SRC) -o $(BIN) \
		-L$(DEPS_PREFIX)/lib \
		-Wl,-Bstatic -lnetfilter_queue -lnfnetlink -lmnl -Wl,-Bdynamic
	@echo "Built $(BIN) (static deps, dynamic glibc). Check with: ldd $(BIN)"

# --- Dynamic build: link against system shared libraries ----------------
dynamic:
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) \
		-lnetfilter_queue -lnfnetlink -lmnl
	@echo "Built $(BIN) (dynamic)."

# --- Unit test for the RA core (no privileges / netfilter needed) -------
test:
	$(CC) $(CFLAGS) -I. -o /tmp/ra-rewrite-test tests/test_ra.c src/ra.c
	/tmp/ra-rewrite-test

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	install -Dm644 systemd/ra-rewrite@.service \
		$(DESTDIR)/usr/lib/systemd/system/ra-rewrite@.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)
	rm -f $(DESTDIR)/usr/lib/systemd/system/ra-rewrite@.service

clean:
	rm -f $(BIN)

distclean: clean
	rm -rf deps
