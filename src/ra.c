/* ra.c - Router Advertisement parsing, rewriting, and construction.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Semantics: for each field, OVERWRITE if the user set it, otherwise INFER
 * from a related field if possible, otherwise PASS THROUGH from upstream.
 */
#include "ra.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>

/* ---- ICMPv6 checksum over the IPv6 pseudo-header ---------------------- */

static uint16_t icmp6_checksum(const struct in6_addr *src,
                               const struct in6_addr *dst,
                               const uint8_t *icmp6, size_t len)
{
    uint32_t sum = 0;
    /* Pseudo-header: src(16) + dst(16) + upper-layer length(4) +
     * zeros(3) + next header(1 = 58). */
    const uint8_t *s = (const uint8_t *)src;
    const uint8_t *d = (const uint8_t *)dst;
    size_t i;

    for (i = 0; i < 16; i += 2)
        sum += (uint16_t)((s[i] << 8) | s[i + 1]);
    for (i = 0; i < 16; i += 2)
        sum += (uint16_t)((d[i] << 8) | d[i + 1]);

    sum += (uint32_t)(len >> 16) & 0xffff;
    sum += (uint32_t)(len & 0xffff);
    sum += 58; /* next header = ICMPv6 */

    /* ICMPv6 message, with checksum field assumed zero. */
    for (i = 0; i + 1 < len; i += 2)
        sum += (uint16_t)((icmp6[i] << 8) | icmp6[i + 1]);
    if (i < len)
        sum += (uint16_t)(icmp6[i] << 8);

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)(~sum);
}

/* ---- Parsing ---------------------------------------------------------- */

bool ra_parse(const uint8_t *icmp6, size_t len, struct ra_parsed *out)
{
    /* RA fixed part: type(1) code(1) cksum(2) curhop(1) flags(1)
     * lifetime(2) reachable(4) retrans(4) = 16 bytes. */
    if (len < 16)
        return false;
    if (icmp6[0] != ICMP6_TYPE_RA)
        return false;

    memset(out, 0, sizeof(*out));
    out->buf = icmp6;
    out->len = len;

    out->cur_hop_limit   = icmp6[4];
    out->managed         = (icmp6[5] & 0x80) != 0;
    out->other           = (icmp6[5] & 0x40) != 0;
    out->router_lifetime = (uint16_t)((icmp6[6] << 8) | icmp6[7]);
    out->reachable_time  = ((uint32_t)icmp6[8]  << 24) | ((uint32_t)icmp6[9]  << 16) |
                           ((uint32_t)icmp6[10] << 8)  |  (uint32_t)icmp6[11];
    out->retrans_timer   = ((uint32_t)icmp6[12] << 24) | ((uint32_t)icmp6[13] << 16) |
                           ((uint32_t)icmp6[14] << 8)  |  (uint32_t)icmp6[15];

    /* Walk options. Each option: type(1) len(1, in units of 8 bytes) ... */
    size_t off = 16;
    while (off + 2 <= len) {
        uint8_t otype = icmp6[off];
        uint8_t olen8 = icmp6[off + 1];
        if (olen8 == 0)
            return false; /* malformed: zero-length option */
        size_t obytes = (size_t)olen8 * 8;
        if (off + obytes > len)
            return false; /* truncated option */

        switch (otype) {
        case ND_OPT_SOURCE_LINKADDR: out->opt_sllao  = icmp6 + off; break;
        case ND_OPT_MTU:             out->opt_mtu    = icmp6 + off; break;
        case ND_OPT_PREFIX_INFO:     out->opt_prefix = icmp6 + off; break;
        case ND_OPT_RDNSS:           out->opt_rdnss  = icmp6 + off; break;
        default: break; /* unknown options are ignored for parsing */
        }
        off += obytes;
    }
    return true;
}

/* ---- Building helpers ------------------------------------------------- */

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff;
}

/* Append `n` bytes, bounds-checked. Returns false on overflow. */
static bool emit(uint8_t *out, size_t cap, size_t *pos,
                 const uint8_t *data, size_t n)
{
    if (*pos + n > cap)
        return false;
    memcpy(out + *pos, data, n);
    *pos += n;
    return true;
}

/* ---- Building --------------------------------------------------------- */

ssize_t ra_build(const struct ra_parsed *up,
                 const struct ra_override *ov,
                 const struct in6_addr *src_ip,
                 const struct in6_addr *dst_ip,
                 uint8_t *out, size_t out_cap)
{
    size_t pos = 0;
    uint8_t hdr[16];
    memset(hdr, 0, sizeof(hdr));

    /* --- RA fixed header --- */
    hdr[0] = ICMP6_TYPE_RA;
    hdr[1] = 0;             /* code */
    /* checksum (hdr[2..3]) left zero for now, filled after. */

    hdr[4] = ov->set_cur_hop_limit ? ov->cur_hop_limit : up->cur_hop_limit;

    uint8_t flags = 0;
    bool m = ov->set_managed ? (ov->managed != 0) : up->managed;
    bool o = ov->set_other   ? (ov->other   != 0) : up->other;
    if (m) flags |= 0x80;
    if (o) flags |= 0x40;
    hdr[5] = flags;

    uint16_t rlife = ov->set_router_lifetime ? ov->router_lifetime
                                              : up->router_lifetime;
    put_be16(hdr + 6, rlife);

    uint32_t reach = ov->set_reachable_time ? ov->reachable_time
                                            : up->reachable_time;
    put_be32(hdr + 8, reach);

    uint32_t retr = ov->set_retrans_timer ? ov->retrans_timer
                                          : up->retrans_timer;
    put_be32(hdr + 12, retr);

    if (!emit(out, out_cap, &pos, hdr, 16))
        return -1;

    /* --- Source link-layer address option ---
     * Pass through upstream's, or overwrite MAC if requested. Always emit
     * one if upstream had one (keeps the borrowed shell intact). */
    if (up->opt_sllao || ov->set_src_mac) {
        uint8_t sllao[8];
        sllao[0] = ND_OPT_SOURCE_LINKADDR;
        sllao[1] = 1; /* 8 bytes */
        if (ov->set_src_mac)
            memcpy(sllao + 2, ov->src_mac, 6);
        else
            memcpy(sllao + 2, up->opt_sllao + 2, 6);
        if (!emit(out, out_cap, &pos, sllao, 8))
            return -1;
    }

    /* --- MTU option ---
     * Overwrite if --mtu, else pass through upstream MTU option if present. */
    if (ov->set_mtu) {
        uint8_t mtu[8] = {0};
        mtu[0] = ND_OPT_MTU; mtu[1] = 1;
        put_be32(mtu + 4, ov->mtu);
        if (!emit(out, out_cap, &pos, mtu, 8))
            return -1;
    } else if (up->opt_mtu) {
        if (!emit(out, out_cap, &pos, up->opt_mtu, 8))
            return -1;
    }

    /* --- Prefix Information option ---
     * If --prefix given: emit, inferring A=1, L=1, valid=3600, pref=1800
     * unless individually overwritten.
     * Else: pass through upstream PIO if present (upstream here has none). */
    if (ov->set_prefix) {
        uint8_t pio[32] = {0};
        pio[0] = ND_OPT_PREFIX_INFO;
        pio[1] = 4;                 /* 32 bytes */
        pio[2] = ov->prefix_len;    /* prefix length */
        uint8_t pflags = 0;
        bool L = ov->set_prefix_onlink ? (ov->prefix_onlink != 0) : true; /* infer 1 */
        bool A = ov->set_prefix_auto   ? (ov->prefix_auto   != 0) : true; /* infer 1 */
        if (L) pflags |= 0x80;
        if (A) pflags |= 0x40;
        pio[3] = pflags;
        put_be32(pio + 4,  ov->set_prefix_valid     ? ov->prefix_valid     : 3600);
        put_be32(pio + 8,  ov->set_prefix_preferred ? ov->prefix_preferred : 1800);
        /* pio[12..15] reserved = 0 */
        memcpy(pio + 16, &ov->prefix, 16);
        if (!emit(out, out_cap, &pos, pio, 32))
            return -1;
    } else if (up->opt_prefix) {
        size_t n = (size_t)up->opt_prefix[1] * 8;
        if (!emit(out, out_cap, &pos, up->opt_prefix, n))
            return -1;
    }

    /* --- RDNSS option ---
     * If --rdnss given: emit with all addresses, lifetime inferred 600
     * unless overwritten. Else pass through upstream RDNSS if present. */
    if (ov->set_rdnss && ov->rdnss_count > 0) {
        /* length in 8-byte units: 1 (header+lifetime) + 2 per address. */
        uint8_t units = (uint8_t)(1 + 2 * ov->rdnss_count);
        size_t need = (size_t)units * 8;
        if (pos + need > out_cap)
            return -1;
        uint8_t *p = out + pos;
        memset(p, 0, need);
        p[0] = ND_OPT_RDNSS;
        p[1] = units;
        /* p[2..3] reserved */
        put_be32(p + 4, ov->set_rdnss_lifetime ? ov->rdnss_lifetime : 600);
        for (int i = 0; i < ov->rdnss_count; i++)
            memcpy(p + 8 + i * 16, &ov->rdnss[i], 16);
        pos += need;
    } else if (up->opt_rdnss) {
        size_t n = (size_t)up->opt_rdnss[1] * 8;
        if (!emit(out, out_cap, &pos, up->opt_rdnss, n))
            return -1;
    }

    /* --- Checksum --- */
    uint16_t csum = icmp6_checksum(src_ip, dst_ip, out, pos);
    put_be16(out + 2, csum);

    return (ssize_t)pos;
}
