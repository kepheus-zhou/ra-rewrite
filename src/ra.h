/* ra.h - Router Advertisement parsing, rewriting, and construction.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RA_REWRITE_RA_H
#define RA_REWRITE_RA_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

/* Maximum number of RDNSS servers we will emit in one option. */
#define RA_MAX_RDNSS 8

/* ICMPv6 Router Advertisement type. */
#define ICMP6_TYPE_RA 134

/* Neighbor Discovery option types (RFC 4861 / 8106). */
#define ND_OPT_SOURCE_LINKADDR 1
#define ND_OPT_PREFIX_INFO     3
#define ND_OPT_MTU             5
#define ND_OPT_RDNSS           25
#define ND_OPT_DNSSL           31

/*
 * The override table. For every field there is a `set_*` flag that records
 * whether the user explicitly asked to overwrite it on the command line.
 *
 * Semantics applied in ra_build():
 *   - set_*  == true   -> OVERWRITE with the value here
 *   - set_*  == false  -> INFER if a related field was given, otherwise
 *                         PASS THROROUGH the upstream value verbatim.
 *
 * The inference rules are documented at each field and implemented in
 * ra_build().
 */
struct ra_override {
    /* M / O flags ------------------------------------------------------ */
    bool set_managed;        int managed;   /* 0 or 1 */
    bool set_other;          int other;     /* 0 or 1 */

    /* Scalar RA header fields ------------------------------------------ */
    bool set_cur_hop_limit;  uint8_t  cur_hop_limit;
    bool set_router_lifetime; uint16_t router_lifetime;
    bool set_reachable_time;  uint32_t reachable_time;
    bool set_retrans_timer;   uint32_t retrans_timer;

    /* MTU option ------------------------------------------------------- */
    bool set_mtu;            uint32_t mtu;

    /* Prefix Information option (RFC 4861 4.6.2) ----------------------- */
    bool set_prefix;         struct in6_addr prefix;
    uint8_t prefix_len;
    /* The following are INFERRED to sensible defaults when --prefix is
     * given but they are not specified, and can still be overwritten. */
    bool set_prefix_onlink;  int prefix_onlink;   /* L bit, inferred 1 */
    bool set_prefix_auto;    int prefix_auto;     /* A bit, inferred 1 */
    bool set_prefix_valid;   uint32_t prefix_valid;     /* inferred 3600 */
    bool set_prefix_preferred; uint32_t prefix_preferred; /* inferred 1800 */

    /* RDNSS option (RFC 8106) ------------------------------------------ */
    bool set_rdnss;
    struct in6_addr rdnss[RA_MAX_RDNSS];
    int  rdnss_count;
    bool set_rdnss_lifetime; uint32_t rdnss_lifetime; /* inferred 600 */

    /* Source link-layer address: always passed through (borrowed shell),
     * but allow override for completeness. */
    bool set_src_mac;        uint8_t src_mac[6];
};

/*
 * Parsed view of an upstream RA. Pointers reference into the original
 * buffer; nothing is copied. `valid` is false if the buffer is not a
 * well-formed RA.
 */
struct ra_parsed {
    const uint8_t *buf;
    size_t len;

    /* RA header */
    uint8_t  cur_hop_limit;
    bool     managed;
    bool     other;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;

    /* Located options (NULL if absent) */
    const uint8_t *opt_sllao;   /* points at option header */
    const uint8_t *opt_mtu;
    const uint8_t *opt_prefix;
    const uint8_t *opt_rdnss;
};

/* Parse an ICMPv6 RA payload (starting at the ICMPv6 header, i.e. type
 * byte). Returns true on success and fills *out. */
bool ra_parse(const uint8_t *icmp6, size_t len, struct ra_parsed *out);

/*
 * Build a new RA ICMPv6 message into `out` (capacity `out_cap`), applying
 * the override table on top of the parsed upstream RA `up`.
 *
 * `src_ip` and `dst_ip` are the IPv6 source/destination used to compute the
 * ICMPv6 checksum (pseudo-header). The checksum is written into the message.
 *
 * Returns the number of bytes written, or -1 on error (e.g. buffer too
 * small).
 */
ssize_t ra_build(const struct ra_parsed *up,
                 const struct ra_override *ov,
                 const struct in6_addr *src_ip,
                 const struct in6_addr *dst_ip,
                 uint8_t *out, size_t out_cap);

#endif /* RA_REWRITE_RA_H */
