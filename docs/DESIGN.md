# Design notes for ra-rewrite

This document captures the reasoning behind ra-rewrite so that anyone picking
up the project — including an AI coding assistant in a fresh session — has the
full context without needing the original design conversation. It records not
just *what* the tool does but *why* it is shaped this way, and which
alternatives were tried and rejected, so the same dead ends are not revisited.

## 1. The problem

The deployment environment is a campus/enterprise IPv6 network with these
properties:

- IPv6 addresses are handed out by **DHCPv6**. The upstream Router
  Advertisement has `M=1` (Managed) and `O=1` (Other-config): clients are told
  to get both address and other config (DNS) via DHCPv6.
- The upstream RA carries **no Prefix Information Option** and **no RDNSS** —
  the prefix and DNS come through DHCPv6, not through the RA. (Captured
  upstream RA contains only a Source Link-Layer Address option and an MTU
  option.)
- The /64 is effectively a shared layer-2 segment; DHCPv6 hands out /128s but
  the real on-link prefix is the shared /64.

Two concrete pain points motivated the project:

1. **SLAAC-only devices (e.g. Android) cannot get an address.** They do not do
   DHCPv6, and the upstream RA gives them no prefix, so they are stranded.
2. **DNS cannot be redirected.** Because DNS is delivered via DHCPv6 (and over
   IPv6 some clients prefer their own DNS), there is no way to point clients at
   a local resolver for split-DNS / transparent-proxy purposes. In particular
   the IPv6 DNS path is an escape hatch that bypasses any IPv4-side proxy.

The overarching goal is **DNS sovereignty**: make clients' DNS queries arrive
at a local resolver (which then decides what to proxy), while keeping IPv6
otherwise working — including for SLAAC-only devices.

## 2. Approaches considered and why this one was chosen

A long exploration converged on "rewrite the RA in flight." The alternatives
and why they were set aside:

### Routed relay (NDP proxy + policy routing) — works, but heavy

A full routing-mode design was actually built and made to work: the router
sends its own RA, runs two policy-routing tables keyed on ingress interface,
and uses an NDP proxy (`ndppd`) so upstream can reach LAN clients. It achieves
DNS sovereignty structurally (all traffic passes through the router).

It was set aside as the *primary* approach for this tool because:

- `ndppd` sends its proxy NAs through an ordinary `AF_INET6` socket, which
  triggers a **routing-table lookup**. On a deliberately "clean" transit
  interface (no GUA, no /64 connected route) that lookup fails with
  `Network is unreachable`. Working around it requires adding a link route per
  direction — a routing-table dependency that feels wrong for what should be a
  pure link-layer NA reply.
- The kernel's native `proxy_ndp` avoids the routing dependency (it replies at
  L2) but does not probe: it answers from a table you must maintain, which
  reintroduces a cold-start window for purely passive devices.
- The relay is structurally sound but its only clean NA-responder options each
  have a real wart, and the whole thing is more machinery than the actual goal
  (DNS sovereignty) strictly requires when the operator is willing to let data
  traffic flow straight to the upstream gateway.

### Bridge + forge a complete RA impersonating upstream — self-contradictory

In bridge mode, the upstream RA floods to the LAN; to make a forged RA win you
must filter the real RA, at which point you are no longer a transparent bridge.
And if you forge the source as upstream's LLA, clients resolve that LLA via
NS/NA (which transparently traverse the bridge) to the **real** upstream MAC,
so data traffic goes straight to upstream anyway — you cannot both "be the
gateway" and "stay out of the path" at layer 2. This is a physical
contradiction, not an implementation gap.

### Chosen approach: rewrite the RA, keep upstream as gateway

The operator decided they do **not** need to intercept data traffic — data may
flow straight to the upstream gateway. They only need three things on the LAN:
turn the network into SLAAC (so Android works), and softly point DNS at a local
resolver. That is a **soft hijack**: the RDNSS is a default suggestion; a
client that sets its own DNS still works (and that is desirable — a deliberate
user override is a feature, not a hole).

The key realization: editing the RA's *contents* while **preserving its source
LLA/MAC** lets you change M/O bits, inject a prefix, and inject RDNSS, while the
default router clients install is still the real upstream. Data traffic flows
to upstream (we are not in the path); only DNS is drawn to us by the RDNSS.

No standard RA daemon can do this, because a daemon's RA source is necessarily
its own LLA (which would make the daemon the gateway). The only way to emit an
RA whose *source is upstream* but whose *contents are ours* is to intercept the
real RA and rewrite it. Hence: NFQUEUE the upstream RA, rewrite, reinject,
drop the original.

## 3. Core semantics: overwrite / infer / pass-through

For each RA field, in order:

1. **Overwrite** — the user gave a value on the command line; use it.
2. **Infer** — the user did not give it, but a related field implies a sensible
   value. Giving `--prefix` infers the Prefix Information Option's A bit = 1,
   L bit = 1, valid lifetime = 3600, preferred = 1800. Inferences are always
   overridable by a more specific flag (`--prefix-no-auto`, etc.).
3. **Pass-through** — nothing given, nothing to infer; copy upstream verbatim.
   If upstream lacks the option entirely (e.g. no prefix in a Managed network),
   emit nothing unless asked.

This makes the tool a **neutral field editor** with no policy of its own. What
it achieves depends entirely on the flags. This is why it is publishable as a
general-purpose tool, not a one-off hack hardcoded to one network.

## 4. Key technical decisions and constraints

- **Borrow the upstream shell.** The reinjected RA keeps the upstream source
  LLA (IPv6) and source MAC (Ethernet, from the upstream SLLAO). This is why
  clients keep upstream as their default gateway and data traffic bypasses us.
- **Layer-2 injection via `AF_PACKET`.** The rewritten RA is sent as a full
  Ethernet frame (dst `33:33:00:00:00:01` for `ff02::1`, EtherType IPv6, hop
  limit 255). No IP routing-table lookup is involved — an RA/NA on a link must
  be link-delivered, not routed. This deliberately avoids the routing
  dependency that plagued the `ndppd` relay approach.
- **Fail-open via nftables `bypass`.** The nft rule uses `queue num 0 bypass`,
  so if ra-rewrite is not running the original RA passes through unchanged.
  IPv6 never fully breaks because the daemon is down.
- **ICMPv6 checksum** is recomputed over the IPv6 pseudo-header after editing;
  the build is verified by recomputing over the full packet (including the
  checksum field), which must yield zero.
- **No extension headers assumed.** RAs normally have none. Packets that are
  not a plain IPv6+ICMPv6 RA are passed through (verdict ACCEPT) untouched.
- **Static linking to the glibc boundary.** libnetfilter_queue / libnfnetlink /
  libmnl are linked statically (built from source into `deps/` by
  `scripts/build-deps.sh`); glibc stays dynamic. Rationale: avoid the
  per-distro `.so` naming/SONAME-version packaging hell for a tool meant to be
  downloaded and run anywhere; glibc is the one library that is stable and
  ubiquitous and does not statically link cleanly (NSS/getaddrinfo), so it is
  the right place to stop.

## 5. Known risks / things to verify on real hardware

These could not be tested in the environment where the code was written; they
are the first things to check when running on the target machine (ArchHFNL):

- **nftables `queue` from the bridge family.** The provided rule uses
  `table bridge ... hook prerouting ... queue num 0 bypass` with
  `meta ibrname` + `iif`. NFQUEUE verdict support and `queue` availability in
  the bridge family vary by kernel version. **Verify** that the rule loads
  (`nft list ruleset`) and that RAs are actually queued (the daemon receives
  them; `--verbose` logs each rewrite). If bridge-family queue does not work on
  the kernel, fallbacks to consider: an `ip6`/`inet` prerouting hook, or the
  `netdev`/ingress hook, depending on kernel support.
- **Reinjection direction.** The frame is injected on `--iface` (the WAN-side
  bridge member) so the bridge floods it to the LAN members as if it came from
  upstream. Confirm with a capture on a LAN port that clients see the rewritten
  RA (M=0, prefix present, RDNSS = local resolver) and not the original.
- **DHCPv6 suppression.** The companion nft table drops upstream DHCPv6
  (`udp sport 547`) so DHCPv6-capable clients fall back to SLAAC. Confirm
  Windows-type clients actually fall back rather than caching a prior DHCPv6
  lease.

## 6. Verification checklist (for the next session)

1. `make test` — RA parse/build unit test (no privileges; already passes,
   validated against the real captured upstream RA).
2. `make` — static build; `ldd ra-rewrite` should show only glibc + loader.
3. Load `nftables/ra-rewrite.nft` (edit bridge/interface names first);
   `nft list ruleset` to confirm it took.
4. Run `ra-rewrite --iface enp4s0 --no-managed --no-other --prefix <your/64>
   --rdnss <local-resolver> --verbose`.
5. Capture on a LAN port: confirm rewritten RA reaches clients with M=0/O=0,
   the injected prefix (A=1 L=1), and the RDNSS.
6. Confirm a SLAAC-only client (phone) gets a `<your/64>::...` address and its
   DNS points at the local resolver.
7. Confirm data traffic still egresses via the upstream gateway (we are not in
   the path) — e.g. traceroute / the upstream is still the default router.

## 7. Future work

- A companion **DHCPv6 rewriter** using the same overwrite/infer/pass-through
  model, to cover DHCPv6-only clients and fully close the DNS escape on both
  the SLAAC and DHCPv6 paths. The two tools compose: ra-rewrite handles the
  RA/SLAAC path, the DHCPv6 tool handles the DHCPv6 path.
- Optional: handle IPv6 extension headers in the parsed RA (currently assumed
  absent).
- Optional: a config-file mode in addition to command-line flags.
