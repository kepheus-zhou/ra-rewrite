/* main.c - NFQUEUE loop for ra-rewrite.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Flow:
 *   1. nftables queues incoming RAs (icmpv6 type 134) to this program.
 *   2. We receive the full IPv6 packet, parse the upstream RA.
 *   3. We rebuild the RA applying the override table (overwrite/infer/pass).
 *   4. We reinject the rewritten RA at L2 on --iface (borrowing the upstream
 *      source LLA/MAC so the default router is still upstream).
 *   5. We DROP the original packet so only our rewritten RA reaches clients.
 *
 * The nftables rule should use `bypass` so that if this daemon is not running
 * the original RA passes through unchanged rather than being dropped.
 */
#include "config.h"
#include "ra.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int s) { (void)s; g_stop = 1; }

struct context {
    struct config *cfg;
};

/* The IPv6 header is 40 bytes; ICMPv6 follows. Extract src/dst and the
 * icmp6 pointer. Returns 0 on success. */
static int split_ipv6(const uint8_t *pkt, size_t len,
                      struct in6_addr *src, struct in6_addr *dst,
                      const uint8_t **icmp6, size_t *icmp6_len)
{
    if (len < 40)
        return -1;
    if ((pkt[0] >> 4) != 6)
        return -1;
    /* We only handle the simple case: next header is ICMPv6 directly.
     * RAs normally have no extension headers. */
    if (pkt[6] != 58)
        return -1;
    memcpy(src, pkt + 8, 16);
    memcpy(dst, pkt + 24, 16);
    *icmp6 = pkt + 40;
    *icmp6_len = len - 40;
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    (void)nfmsg;
    struct context *ctx = data;
    struct config *cfg = ctx->cfg;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *payload = NULL;
    int plen = nfq_get_payload(nfa, &payload);
    if (plen < 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    struct in6_addr src, dst;
    const uint8_t *icmp6;
    size_t icmp6_len;
    if (split_ipv6(payload, (size_t)plen, &src, &dst, &icmp6, &icmp6_len) != 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    struct ra_parsed up;
    if (!ra_parse(icmp6, icmp6_len, &up))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    /* Build the rewritten ICMPv6 RA body. */
    uint8_t icmp6_out[1500];
    ssize_t icmp6_n = ra_build(&up, &cfg->ov, &src, &dst, icmp6_out, sizeof(icmp6_out));
    if (icmp6_n < 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    /* Reconstruct the full IPv6 packet: original 40-byte header + new ICMPv6.
     * NF_ACCEPT with non-NULL data replaces the packet in-flight; the bridge
     * forwards it to LAN ports using the original Ethernet frame header
     * (upstream router's MAC stays intact -- no AF_PACKET, no FDB pollution,
     * no re-queue loop). */
    uint8_t pkt_out[40 + sizeof(icmp6_out)];
    memcpy(pkt_out, payload, 40);
    pkt_out[4] = ((size_t)icmp6_n >> 8) & 0xff;
    pkt_out[5] =  (size_t)icmp6_n       & 0xff;
    memcpy(pkt_out + 40, icmp6_out, icmp6_n);

    if (cfg->verbose) {
        char sbuf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &src, sbuf, sizeof(sbuf));
        fprintf(stderr, "rewrote RA from %s (%zu -> %zu bytes) on %s\n",
                sbuf, icmp6_len, (size_t)icmp6_n, cfg->iface);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT,
                           (uint32_t)(40 + icmp6_n), pkt_out);
}

int main(int argc, char **argv)
{
    struct config cfg;
    int rc = config_parse(argc, argv, &cfg);
    if (rc != 0)
        return rc == 1 ? 0 : rc; /* --help returns 1 -> exit 0 */

    struct context ctx = { .cfg = &cfg };

    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "nfq_open failed\n");
        return 1;
    }

    /* AF_INET6 family binding. nfq_unbind_pf/bind_pf are legacy no-ops on
     * modern kernels but harmless. */
    nfq_unbind_pf(h, AF_INET6);
    if (nfq_bind_pf(h, AF_INET6) < 0) {
        fprintf(stderr, "nfq_bind_pf failed\n");
        nfq_close(h);
        return 1;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, cfg.queue_num, &cb, &ctx);
    if (!qh) {
        fprintf(stderr, "nfq_create_queue(%u) failed\n", cfg.queue_num);
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "nfq_set_mode failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int fd = nfq_fd(h);
    char buf[65536] __attribute__((aligned));

    if (cfg.verbose)
        fprintf(stderr, "ra-rewrite: bound to queue %u, watching %s\n",
                cfg.queue_num, cfg.iface);

    while (!g_stop) {
        ssize_t r = recv(fd, buf, sizeof(buf), 0);
        if (r >= 0) {
            nfq_handle_packet(h, buf, (int)r);
            continue;
        }
        if (errno == ENOBUFS) {
            /* Kernel queue overflow; keep going. */
            continue;
        }
        if (errno == EINTR)
            continue;
        perror("recv");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
