/* config.c - command-line parsing.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

void config_usage(const char *prog)
{
    fprintf(stderr,
"Usage: %s --iface IFACE [--queue N] [field overrides...]\n"
"\n"
"Rewrites IPv6 Router Advertisements pulled from an nftables queue and\n"
"reinjects them on IFACE. For each field: a value given here OVERWRITES it;\n"
"otherwise the value is INFERRED from a related field when possible, else\n"
"PASSED THROUGH from the upstream RA unchanged.\n"
"\n"
"Required:\n"
"  --iface IFACE              WAN-side bridge member that receives upstream RAs\n"
"\n"
"General:\n"
"  --queue N                  NFQUEUE number to bind (default 0)\n"
"  --verbose                  log each rewritten RA\n"
"  --help                     show this help\n"
"\n"
"M/O flags (omit to pass through):\n"
"  --managed | --no-managed   set/clear the Managed (M) flag\n"
"  --other   | --no-other     set/clear the Other-config (O) flag\n"
"\n"
"Prefix Information (giving --prefix infers A=1 L=1 valid=3600 pref=1800):\n"
"  --prefix ADDR/LEN          inject/replace a prefix (e.g. 2001:db8::/64)\n"
"  --prefix-no-onlink         clear the L (on-link) bit (default inferred 1)\n"
"  --prefix-no-auto           clear the A (autonomous) bit (default inferred 1)\n"
"  --prefix-valid SECS        valid lifetime (default 3600)\n"
"  --prefix-preferred SECS    preferred lifetime (default 1800)\n"
"\n"
"RDNSS (RFC 8106; --rdnss may be repeated):\n"
"  --rdnss ADDR               add a recursive DNS server address\n"
"  --rdnss-lifetime SECS      RDNSS lifetime (default 600)\n"
"\n"
"Other RA header fields (omit to pass through):\n"
"  --mtu N                    MTU option value\n"
"  --router-lifetime SECS     router lifetime\n"
"  --cur-hop-limit N          current hop limit\n"
"  --reachable-time MS        reachable time (ms)\n"
"  --retrans-timer MS         retransmit timer (ms)\n"
"  --src-mac AA:BB:..         override source link-layer address\n"
"\n"
"Example (turn a Managed network into SLAAC + hijack DNS):\n"
"  %s --iface enp4s0 --no-managed --no-other \\\n"
"      --prefix 2001:db8:1234:5678::/64 --rdnss 2001:db8:1234:5678::1\n",
        prog, prog);
}

/* Parse "2001:db8::/64" into addr + len. Returns 0 on success. */
static int parse_prefix(const char *s, struct in6_addr *addr, uint8_t *len)
{
    char tmp[128];
    strncpy(tmp, s, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *slash = strchr(tmp, '/');
    if (!slash)
        return -1;
    *slash = '\0';
    long l = strtol(slash + 1, NULL, 10);
    if (l < 0 || l > 128)
        return -1;
    if (inet_pton(AF_INET6, tmp, addr) != 1)
        return -1;
    *len = (uint8_t)l;
    return 0;
}

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return -1;
        mac[i] = (uint8_t)b[i];
    }
    return 0;
}

enum {
    OPT_QUEUE = 1000, OPT_IFACE, OPT_VERBOSE, OPT_HELP,
    OPT_MANAGED, OPT_NO_MANAGED, OPT_OTHER, OPT_NO_OTHER,
    OPT_PREFIX, OPT_PREFIX_NO_ONLINK, OPT_PREFIX_NO_AUTO,
    OPT_PREFIX_VALID, OPT_PREFIX_PREFERRED,
    OPT_RDNSS, OPT_RDNSS_LIFETIME,
    OPT_MTU, OPT_ROUTER_LIFETIME, OPT_CUR_HOP_LIMIT,
    OPT_REACHABLE_TIME, OPT_RETRANS_TIMER, OPT_SRC_MAC,
};

int config_parse(int argc, char **argv, struct config *cfg)
{
    static const struct option longopts[] = {
        {"queue",            required_argument, 0, OPT_QUEUE},
        {"iface",            required_argument, 0, OPT_IFACE},
        {"verbose",          no_argument,       0, OPT_VERBOSE},
        {"help",             no_argument,       0, OPT_HELP},
        {"managed",          no_argument,       0, OPT_MANAGED},
        {"no-managed",       no_argument,       0, OPT_NO_MANAGED},
        {"other",            no_argument,       0, OPT_OTHER},
        {"no-other",         no_argument,       0, OPT_NO_OTHER},
        {"prefix",           required_argument, 0, OPT_PREFIX},
        {"prefix-no-onlink", no_argument,       0, OPT_PREFIX_NO_ONLINK},
        {"prefix-no-auto",   no_argument,       0, OPT_PREFIX_NO_AUTO},
        {"prefix-valid",     required_argument, 0, OPT_PREFIX_VALID},
        {"prefix-preferred", required_argument, 0, OPT_PREFIX_PREFERRED},
        {"rdnss",            required_argument, 0, OPT_RDNSS},
        {"rdnss-lifetime",   required_argument, 0, OPT_RDNSS_LIFETIME},
        {"mtu",              required_argument, 0, OPT_MTU},
        {"router-lifetime",  required_argument, 0, OPT_ROUTER_LIFETIME},
        {"cur-hop-limit",    required_argument, 0, OPT_CUR_HOP_LIMIT},
        {"reachable-time",   required_argument, 0, OPT_REACHABLE_TIME},
        {"retrans-timer",    required_argument, 0, OPT_RETRANS_TIMER},
        {"src-mac",          required_argument, 0, OPT_SRC_MAC},
        {0, 0, 0, 0},
    };

    memset(cfg, 0, sizeof(*cfg));
    cfg->queue_num = 0;

    int c;
    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        struct ra_override *ov = &cfg->ov;
        switch (c) {
        case OPT_QUEUE:   cfg->queue_num = (unsigned)strtoul(optarg, NULL, 10); break;
        case OPT_IFACE:   cfg->iface = optarg; break;
        case OPT_VERBOSE: cfg->verbose = true; break;
        case OPT_HELP:    config_usage(argv[0]); return 1;

        case OPT_MANAGED:    ov->set_managed = true; ov->managed = 1; break;
        case OPT_NO_MANAGED: ov->set_managed = true; ov->managed = 0; break;
        case OPT_OTHER:      ov->set_other = true; ov->other = 1; break;
        case OPT_NO_OTHER:   ov->set_other = true; ov->other = 0; break;

        case OPT_PREFIX:
            if (parse_prefix(optarg, &ov->prefix, &ov->prefix_len) != 0) {
                fprintf(stderr, "invalid --prefix: %s\n", optarg);
                return 2;
            }
            ov->set_prefix = true;
            break;
        case OPT_PREFIX_NO_ONLINK: ov->set_prefix_onlink = true; ov->prefix_onlink = 0; break;
        case OPT_PREFIX_NO_AUTO:   ov->set_prefix_auto = true; ov->prefix_auto = 0; break;
        case OPT_PREFIX_VALID:     ov->set_prefix_valid = true; ov->prefix_valid = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_PREFIX_PREFERRED: ov->set_prefix_preferred = true; ov->prefix_preferred = (uint32_t)strtoul(optarg, NULL, 10); break;

        case OPT_RDNSS:
            if (ov->rdnss_count >= RA_MAX_RDNSS) {
                fprintf(stderr, "too many --rdnss (max %d)\n", RA_MAX_RDNSS);
                return 2;
            }
            if (inet_pton(AF_INET6, optarg, &ov->rdnss[ov->rdnss_count]) != 1) {
                fprintf(stderr, "invalid --rdnss: %s\n", optarg);
                return 2;
            }
            ov->rdnss_count++;
            ov->set_rdnss = true;
            break;
        case OPT_RDNSS_LIFETIME: ov->set_rdnss_lifetime = true; ov->rdnss_lifetime = (uint32_t)strtoul(optarg, NULL, 10); break;

        case OPT_MTU:             ov->set_mtu = true; ov->mtu = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_ROUTER_LIFETIME: ov->set_router_lifetime = true; ov->router_lifetime = (uint16_t)strtoul(optarg, NULL, 10); break;
        case OPT_CUR_HOP_LIMIT:   ov->set_cur_hop_limit = true; ov->cur_hop_limit = (uint8_t)strtoul(optarg, NULL, 10); break;
        case OPT_REACHABLE_TIME:  ov->set_reachable_time = true; ov->reachable_time = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_RETRANS_TIMER:   ov->set_retrans_timer = true; ov->retrans_timer = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_SRC_MAC:
            if (parse_mac(optarg, ov->src_mac) != 0) {
                fprintf(stderr, "invalid --src-mac: %s\n", optarg);
                return 2;
            }
            ov->set_src_mac = true;
            break;

        default:
            config_usage(argv[0]);
            return 2;
        }
    }

    if (!cfg->iface) {
        fprintf(stderr, "error: --iface is required\n\n");
        config_usage(argv[0]);
        return 2;
    }
    return 0;
}
