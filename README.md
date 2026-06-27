# ra-rewrite

A small, neutral IPv6 **Router Advertisement rewriter**. It pulls RAs off an
nftables queue, rewrites selected fields, and reinjects them on a link — so
you can turn a Managed (DHCPv6) network into SLAAC, inject a prefix, or point
clients' DNS at your own resolver, **without becoming the router**.

The default router stays whoever the upstream RA says it is (the source LLA is
preserved), so data traffic still flows to the real gateway. Only the RA's
*contents* are edited in flight.

> **Status:** Early. The RA parse/build core is unit-tested against a real
> upstream capture and passes. The NFQUEUE + reinjection path and the nftables
> rules have **not** yet been validated on the target kernel — see
> [`docs/DESIGN.md`](docs/DESIGN.md) §5 for what to verify first (especially
> nftables bridge-family `queue` support).

## Design: overwrite / infer / pass-through

For every RA field, ra-rewrite applies one of three rules:

1. **Overwrite** — you gave the value on the command line; it is used.
2. **Infer** — you didn't give it, but a related field implies a sensible
   value. For example, giving `--prefix` infers the on-link (L) and
   autonomous (A) bits = 1 and lifetimes of 3600/1800s. Inferences can always
   be overridden by a more specific flag.
3. **Pass-through** — nothing given and nothing to infer; the upstream value
   is copied verbatim. (If upstream lacks an option entirely, e.g. no prefix
   in a Managed network, nothing is emitted unless you ask for it.)

This makes the tool a neutral field editor: it imposes no policy of its own.
What you achieve is entirely a function of which flags you pass.

## How it works

```
            upstream RA
                │
   nftables  ──┴── queue num 0 bypass     (bridge prerouting, WAN member)
                │
            ra-rewrite
              ├─ parse upstream RA
              ├─ rebuild applying overrides (M/O, prefix, RDNSS, MTU, ...)
              ├─ reinject at L2 on --iface, src MAC/LLA = upstream's
              └─ DROP the original
                │
            rewritten RA  ──► LAN clients
```

The reinjection is done with a raw `AF_PACKET` socket: the RA is delivered on
the link directly, with no IP routing-table lookup involved. The source MAC
and source LLA are borrowed from the upstream RA so clients still install the
real upstream router as their default gateway.

`bypass` on the nftables rule makes it **fail-open**: if ra-rewrite is not
running, the original RA passes through unchanged and IPv6 does not break.

## Build

Default build links the netfilter libraries statically and leaves glibc
dynamic — the result is a single binary that runs on any glibc system without
needing libnetfilter_queue/libnfnetlink/libmnl installed.

```sh
make            # builds static deps (deps/) then the static binary
ldd ra-rewrite  # should show only glibc + loader, no netfilter libs
```

Prerequisites: a C toolchain, `make`, `pkg-config`, and `curl` or `wget`
(used by `scripts/build-deps.sh` to fetch the three netfilter library
sources from netfilter.org and build their `.a` archives into `deps/`).

Alternatives:

```sh
make dynamic    # link against system shared libs instead
make test       # build & run the RA parse/build unit test (no privileges)
```

## Usage

```
ra-rewrite --iface IFACE [--queue N] [field overrides...]
```

Run `ra-rewrite --help` for the full flag list. Key flags:

| Flag | Effect |
|------|--------|
| `--iface IFACE` | interface to reinject on (required) |
| `--queue N` | NFQUEUE number (default 0) |
| `--managed` / `--no-managed` | set/clear M flag (omit = pass through) |
| `--other` / `--no-other` | set/clear O flag (omit = pass through) |
| `--prefix ADDR/LEN` | inject a prefix; infers A=1 L=1 valid=3600 pref=1800 |
| `--prefix-no-onlink` / `--prefix-no-auto` | clear inferred L / A bit |
| `--rdnss ADDR` | add a recursive DNS server (repeatable) |
| `--mtu`, `--router-lifetime`, ... | overwrite, else pass through |

### Example: Managed network → SLAAC + DNS soft-hijack

Upstream sends `M=1 O=1`, no prefix, no RDNSS (a pure DHCPv6 network).
SLAAC-only clients (e.g. Android) can't get an address. To fix that and point
DNS at your resolver while leaving the upstream as the gateway:

```sh
# 1. Load nftables rules (queues RAs, drops upstream DHCPv6). Edit the
#    bridge/interface names inside the file first.
sudo nft -f nftables/ra-rewrite.nft

# 2. Run the rewriter.
sudo ra-rewrite --iface enp4s0 \
     --no-managed --no-other \
     --prefix 2001:db8:1234:5678::/64 \
     --rdnss 2001:db8:1234:5678::1 \
     --verbose
```

Now clients see an RA with M=0/O=0, a SLAAC prefix, and your RDNSS — but the
default router is still the real upstream, so data traffic bypasses this host.
DNS is *softly* hijacked: a client that sets its own DNS still works (the
RDNSS is only the default suggestion).

## systemd

```sh
sudo make install                       # installs binary + ra-rewrite@.service
sudo mkdir -p /etc/ra-rewrite
echo 'ARGS=--no-managed --no-other --prefix 2001:db8:1234:5678::/64 --rdnss 2001:db8:1234:5678::1' \
    | sudo tee /etc/ra-rewrite/enp4s0.conf
sudo systemctl enable --now ra-rewrite@enp4s0
```

Remember to also load the nftables rules at boot (e.g. via the `nftables`
service) with a matching queue number.

## Limitations / notes

- **nftables bridge-family `queue` support is kernel-dependent.** The shipped
  rule queues from `table bridge ... prerouting`; verify it loads and that RAs
  are actually queued on your kernel. See `docs/DESIGN.md` §5 for fallbacks.
- Handles RAs with no IPv6 extension headers (the normal case). Packets it
  doesn't understand are passed through untouched.
- The reinjected frame goes to the all-nodes multicast (`ff02::1`) with the
  upstream source LLA. This is a soft, fail-open mechanism, not a security
  control.
- Requires `CAP_NET_RAW` (AF_PACKET) and `CAP_NET_ADMIN` (NFQUEUE).
- This is the RA half of a planned pair; a companion DHCPv6 rewriter using the
  same overwrite/infer/pass-through model can cover DHCPv6-only clients.

## License

GPL-2.0-or-later. See `LICENSE`. (Static linking with libnetfilter_queue,
which is GPL-2.0, is the reason for the GPL licensing.)
