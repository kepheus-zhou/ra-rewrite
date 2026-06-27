/* inject.c - reinject a rewritten RA as an Ethernet frame.
 *
 * Copyright (C) 2026  ra-rewrite contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * We send at layer 2 with AF_PACKET so that the frame enters the bridge from
 * the bound interface exactly as if it had arrived from upstream. No routing
 * table lookup is involved (this is the whole point: NA/RA on a link must be
 * link-delivered, not routed).
 */
#include "inject.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

int injector_open(struct injector *inj, const char *iface)
{
    memset(inj, 0, sizeof(*inj));
    strncpy(inj->iface, iface, sizeof(inj->iface) - 1);

    inj->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    if (inj->fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(inj->fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(inj->fd);
        return -1;
    }
    inj->ifindex = ifr.ifr_ifindex;

    if (ioctl(inj->fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(inj->fd);
        return -1;
    }
    memcpy(inj->ifmac, ifr.ifr_hwaddr.sa_data, 6);

    return 0;
}

void injector_close(struct injector *inj)
{
    if (inj->fd >= 0)
        close(inj->fd);
    inj->fd = -1;
}

/* Same checksum used in ra.c, duplicated here to keep inject self-contained
 * when we build the IPv6 header. Actually the ICMPv6 checksum is already in
 * the payload; we only need to assemble the IPv6 header (no checksum field
 * in IPv6 itself). */

int injector_send_ra(struct injector *inj,
                     const uint8_t src_mac[6],
                     const struct in6_addr *src_ip,
                     const struct in6_addr *dst_ip,
                     const uint8_t *icmp6, size_t icmp6_len)
{
    uint8_t frame[1600];
    size_t pos = 0;

    if (14 + 40 + icmp6_len > sizeof(frame)) {
        fprintf(stderr, "frame too large\n");
        return -1;
    }

    /* --- Ethernet header --- */
    /* dst MAC for ff02::1 is 33:33:00:00:00:01 */
    static const uint8_t dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    memcpy(frame + pos, dst_mac, 6); pos += 6;
    memcpy(frame + pos, src_mac, 6); pos += 6;
    frame[pos++] = 0x86; frame[pos++] = 0xdd; /* EtherType IPv6 */

    /* --- IPv6 header (40 bytes) --- */
    uint8_t *ip6 = frame + pos;
    memset(ip6, 0, 40);
    /* version(4)=6, traffic class, flow label. Match upstream-ish: class 0xc0
     * is common for ND but 0 is fine. Use version=6 only. */
    ip6[0] = 0x60;
    /* payload length */
    ip6[4] = (icmp6_len >> 8) & 0xff;
    ip6[5] = icmp6_len & 0xff;
    ip6[6] = 58;   /* next header = ICMPv6 */
    ip6[7] = 255;  /* hop limit (ND requires 255) */
    memcpy(ip6 + 8, src_ip, 16);
    memcpy(ip6 + 24, dst_ip, 16);
    pos += 40;

    /* --- ICMPv6 payload (already checksummed by ra_build) --- */
    memcpy(frame + pos, icmp6, icmp6_len);
    pos += icmp6_len;

    /* --- Send --- */
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IPV6);
    sa.sll_ifindex  = inj->ifindex;
    sa.sll_halen    = 6;
    memcpy(sa.sll_addr, dst_mac, 6);

    ssize_t n = sendto(inj->fd, frame, pos, 0,
                       (struct sockaddr *)&sa, sizeof(sa));
    if (n < 0) {
        perror("sendto(AF_PACKET)");
        return -1;
    }
    return 0;
}
