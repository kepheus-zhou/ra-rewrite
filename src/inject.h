/* inject.h - reinject a rewritten RA as an Ethernet frame on an interface.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RA_REWRITE_INJECT_H
#define RA_REWRITE_INJECT_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

struct injector {
    int      fd;            /* AF_PACKET raw socket */
    int      ifindex;       /* interface index */
    uint8_t  ifmac[6];      /* interface MAC (fallback src when no SLLAO) */
    char     iface[16];     /* interface name, for logging */
};

/* Open an AF_PACKET socket bound to `iface`. Returns 0 on success. */
int injector_open(struct injector *inj, const char *iface);

void injector_close(struct injector *inj);

/*
 * Send an ICMPv6 RA. We build the full Ethernet + IPv6 + ICMPv6 frame:
 *   - Ethernet: src = src_mac, dst = 33:33:00:00:00:01 (all-nodes multicast)
 *   - IPv6:     src = src_ip (the upstream LLA, borrowed), dst = ff02::1,
 *               hop limit 255
 *   - payload:  the icmp6 message (already checksummed)
 *
 * Returns 0 on success.
 */
int injector_send_ra(struct injector *inj,
                     const uint8_t src_mac[6],
                     const struct in6_addr *src_ip,
                     const struct in6_addr *dst_ip,
                     const uint8_t *icmp6, size_t icmp6_len);

#endif /* RA_REWRITE_INJECT_H */
