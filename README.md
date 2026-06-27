# ra-rewrite

A small, neutral IPv6 **Router Advertisement rewriter**. It pulls RAs off an
nftables queue, rewrites selected fields, and reinjects them on a link — so
you can turn a Managed (DHCPv6) network into SLAAC, inject a prefix, or point
clients' DNS at your own resolver, **without becoming the router**.

The default router stays whoever the upstream RA says it is (the source LLA is
preserved), so data traffic still flows to the real gateway. Only the RA's
*contents* are edited in flight.

> **Status:** Tested on real hardware (Arch Linux, bridge setup). nftables
> bridge-family `queue` works on this kernel. The `NF_ACCEPT`-with-modified-
> payload approach avoids AF_PACKET reinjection entirely — no FDB pollution,
> no re-queue loop.

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
   nftables  ──┴── queue num 0     (bridge prerouting, WAN member iif)
                │
            ra-rewrite
              ├─ parse upstream RA
              ├─ rebuild applying overrides (M/O, prefix, RDNSS, MTU, ...)
              └─ NF_ACCEPT with modified IPv6 payload
                │   (original Ethernet header preserved — src MAC/LLA = upstream's)
            rewritten RA  ──► bridge floods to LAN ports
```

The verdict is `NF_ACCEPT` with the rewritten IPv6 payload substituted
in-place. The kernel retains the original Ethernet frame header (upstream
router's source MAC and LLA), so clients install the real upstream router as
their default gateway and data traffic bypasses this host entirely.

No AF_PACKET socket is involved: the frame never leaves the bridge software,
avoiding FDB pollution and re-queue loops.

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
| `--iface IFACE` | WAN-side bridge member that receives upstream RAs (required) |
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

## Installation

### Arch Linux (pacman)

A pre-built static binary and PKGBUILD are attached to each
[GitHub release](https://github.com/kepheus-zhou/ra-rewrite/releases).

```sh
# Option A: pre-built static binary from release
sudo install -Dm755 ra-rewrite-linux-x86_64 /usr/bin/ra-rewrite

# Option B: build from source via PKGBUILD (links against system libs)
cd pkg && makepkg -si
```

### Manual (any distro)

```sh
make            # static build; no system netfilter libs required
sudo make install
```

## systemd

```sh
sudo mkdir -p /etc/ra-rewrite
echo 'ARGS=--no-managed --no-other --prefix 2001:db8:1234:5678::/64 --rdnss 2001:db8:1234:5678::1' \
    | sudo tee /etc/ra-rewrite/enp4s0.conf
sudo systemctl enable --now nftables
sudo systemctl enable --now ra-rewrite@enp4s0
```

The template unit (`ra-rewrite@enp4s0`) takes the WAN-side bridge member as
the instance name. It reads arguments from `/etc/ra-rewrite/<iface>.conf` and
restarts automatically on failure. `PartOf=nftables.service` ensures it stops
when nftables is reloaded (and comes back up after).

## Limitations / notes

- **nftables bridge-family `queue` support is kernel-dependent.** The shipped
  rule queues from `table bridge ... prerouting`; verify it loads and that RAs
  are actually queued on your kernel (tested: Arch Linux, kernel 6.x).
- Handles RAs with no IPv6 extension headers (the normal case). Packets it
  doesn't understand are passed through untouched.
- The RDNSS is a *soft* suggestion; a client that sets its own DNS still works.
- Requires `CAP_NET_ADMIN` (NFQUEUE via netlink). No raw socket is needed.
- This is the RA half of a planned pair; a companion DHCPv6 rewriter using the
  same overwrite/infer/pass-through model can cover DHCPv6-only clients.

## License

GPL-2.0-or-later. See `LICENSE`. (Static linking with libnetfilter_queue,
which is GPL-2.0, is the reason for the GPL licensing.)
