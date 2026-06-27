# Notes for an AI assistant working on this repo

If you are an AI coding assistant opening this project in a fresh session,
read these first so you have the full context the original design conversation
carried:

1. **`docs/DESIGN.md`** — the complete background: the problem (DHCPv6 network
   where SLAAC-only devices can't get an address and DNS can't be redirected),
   the approaches that were tried and **rejected** (full routed relay with
   ndppd, forging a complete RA impersonating upstream in bridge mode), and why
   this approach (rewrite the RA in flight, preserving the upstream source LLA
   so upstream stays the gateway) was chosen. **Do not re-propose the rejected
   approaches** — DESIGN.md §2 explains why each fails.

2. **`README.md`** — what the tool does and how to build/use it.

3. **The code** — `src/ra.c` (parse/build core, unit-tested), `src/main.c`
   (NFQUEUE loop), `src/inject.c` (AF_PACKET L2 injection), `src/config.c`
   (CLI). The design principle is **overwrite / infer / pass-through** per
   field (DESIGN.md §3) — keep any new field handling consistent with that.

## Current state

- The RA parse/build core is unit-tested (`make test`) against a real captured
  upstream RA and passes, including ICMPv6 checksum validation.
- The NFQUEUE + injection path and the nftables rules have **not** been tested
  on real hardware yet. The target machine is "ArchHFNL" (Arch Linux), WAN-side
  bridge member `enp4s0`, bridge `lanBridge`, shared /64 `2001:250:5429:11::/64`,
  local resolver at `2001:250:5429:11::1`.

## Most likely first tasks

- `make` (builds static deps via `scripts/build-deps.sh`, then the binary).
- Verify static linkage: `ldd ra-rewrite` should show only glibc + loader.
- Load `nftables/ra-rewrite.nft` and confirm with `nft list ruleset`.
- **The single biggest unknown** (DESIGN.md §5): whether nftables `queue` works
  from the bridge family on this kernel. Test it; if not, try alternative hooks.
- Run with `--verbose` and capture on a LAN port to confirm clients receive the
  rewritten RA (M=0, injected prefix, RDNSS), while data traffic still egresses
  via the upstream gateway.

## Conventions

- License is GPL-2.0-or-later; keep SPDX headers on new source files.
- Replace `LICENSE.txt` (a placeholder) with the full GPL-2.0 text from
  https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt saved as `LICENSE`
  before publishing, if not already done.
- Documentation and examples use the `2001:db8::/64` documentation prefix, not
  the operator's real prefix — keep it that way in anything public-facing.
