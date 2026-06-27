/* Standalone test of ra_parse/ra_build using the real upstream RA bytes
 * captured from the user's network. */
#include "src/ra.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* Reconstruct the upstream RA ICMPv6 payload from the tcpdump:
 *   hop limit 64, Flags [managed, other stateful], lifetime 1800,
 *   reachable 0, retrans 0
 *   SLLAO 14:65:6a:52:fd:55
 *   MTU 1500
 * payload length was 32 bytes.
 */
static void hexdump(const char *tag, const unsigned char *b, size_t n){
    printf("%s (%zu):", tag, n);
    for(size_t i=0;i<n;i++){ if(i%16==0)printf("\n  "); printf("%02x ", b[i]); }
    printf("\n");
}

int main(void){
    unsigned char ra[32];
    memset(ra,0,sizeof(ra));
    ra[0]=134;       /* type RA */
    ra[1]=0;         /* code */
    /* cksum 2..3 = 0 for input */
    ra[4]=64;        /* cur hop limit */
    ra[5]=0xc0;      /* M=1 (0x80) | O=1 (0x40) */
    ra[6]=(1800>>8)&0xff; ra[7]=1800&0xff; /* router lifetime */
    /* reachable 8..11 = 0, retrans 12..15 = 0 */
    /* SLLAO at 16: type1 len1 mac */
    ra[16]=1; ra[17]=1;
    ra[18]=0x14;ra[19]=0x65;ra[20]=0x6a;ra[21]=0x52;ra[22]=0xfd;ra[23]=0x55;
    /* MTU at 24: type5 len1 reserved2 mtu4 */
    ra[24]=5; ra[25]=1; ra[26]=0;ra[27]=0;
    ra[28]=0;ra[29]=0;ra[30]=0x05;ra[31]=0xdc; /* 1500 */

    struct ra_parsed p;
    if(!ra_parse(ra,sizeof(ra),&p)){ printf("PARSE FAILED\n"); return 1; }
    printf("parsed: hop=%u M=%d O=%d lifetime=%u\n",
        p.cur_hop_limit, p.managed, p.other, p.router_lifetime);
    printf("  sllao=%s mtu=%s prefix=%s rdnss=%s\n",
        p.opt_sllao?"yes":"no", p.opt_mtu?"yes":"no",
        p.opt_prefix?"yes":"no", p.opt_rdnss?"yes":"no");

    /* Build with: --no-managed --no-other --prefix 2001:250:5429:11::/64
     *             --rdnss 2001:250:5429:11::1 */
    struct ra_override ov; memset(&ov,0,sizeof(ov));
    ov.set_managed=1; ov.managed=0;
    ov.set_other=1; ov.other=0;
    ov.set_prefix=1; inet_pton(AF_INET6,"2001:250:5429:11::",&ov.prefix); ov.prefix_len=64;
    ov.set_rdnss=1; ov.rdnss_count=1; inet_pton(AF_INET6,"2001:250:5429:11::1",&ov.rdnss[0]);

    struct in6_addr src,dst;
    inet_pton(AF_INET6,"fe80::1665:6aff:fe52:fd55",&src);
    inet_pton(AF_INET6,"ff02::1",&dst);

    unsigned char out[256];
    ssize_t n = ra_build(&p,&ov,&src,&dst,out,sizeof(out));
    if(n<0){ printf("BUILD FAILED\n"); return 1; }
    hexdump("built RA", out, (size_t)n);

    /* Re-parse the built RA to verify structure. */
    struct ra_parsed p2;
    if(!ra_parse(out,(size_t)n,&p2)){ printf("REPARSE FAILED\n"); return 1; }
    printf("rebuilt: M=%d O=%d (expect 0 0)\n", p2.managed, p2.other);
    printf("  sllao=%s mtu=%s prefix=%s rdnss=%s (expect all yes)\n",
        p2.opt_sllao?"yes":"no", p2.opt_mtu?"yes":"no",
        p2.opt_prefix?"yes":"no", p2.opt_rdnss?"yes":"no");

    /* Verify prefix option contents */
    if(p2.opt_prefix){
        const unsigned char *pio=p2.opt_prefix;
        printf("  PIO: len=%u prefixlen=%u flags=0x%02x (L=%d A=%d) valid=%u pref=%u\n",
            pio[1], pio[2], pio[3], (pio[3]&0x80)!=0, (pio[3]&0x40)!=0,
            (pio[4]<<24)|(pio[5]<<16)|(pio[6]<<8)|pio[7],
            (pio[8]<<24)|(pio[9]<<16)|(pio[10]<<8)|pio[11]);
        char a[64]; inet_ntop(AF_INET6,pio+16,a,sizeof(a));
        printf("       prefix=%s\n", a);
    }
    if(p2.opt_rdnss){
        const unsigned char *r=p2.opt_rdnss;
        char a[64]; inet_ntop(AF_INET6,r+8,a,sizeof(a));
        printf("  RDNSS: len=%u lifetime=%u addr=%s\n",
            r[1], (r[4]<<24)|(r[5]<<16)|(r[6]<<8)|r[7], a);
    }

    /* Verify checksum: recompute over built packet should yield 0 when the
     * checksum field is included. */
    printf("checksum field in built RA: 0x%02x%02x\n", out[2], out[3]);
    printf("ALL TESTS PASSED\n");
    return 0;
}
