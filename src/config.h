/* config.h - command-line configuration.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RA_REWRITE_CONFIG_H
#define RA_REWRITE_CONFIG_H

#include "ra.h"

struct config {
    unsigned int queue_num;   /* NFQUEUE number (default 0) */
    const char  *iface;       /* interface to inject the rewritten RA on */
    struct ra_override ov;    /* field overrides */
    bool verbose;
};

/* Parse argv into *cfg. Returns 0 on success, non-zero on error (after
 * printing a message). On --help, prints usage and returns 1. */
int config_parse(int argc, char **argv, struct config *cfg);

void config_usage(const char *prog);

#endif /* RA_REWRITE_CONFIG_H */
