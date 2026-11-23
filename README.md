# 🌐 dns-resolver

> A recursive DNS resolver written from scratch in Rust. No resolver libraries, no system DNS: it walks the DNS tree itself, from the root servers down.

![Rust](https://img.shields.io/badge/Rust-2024-b7410e?style=flat-square&logo=rust)
![Deps](https://img.shields.io/badge/deps-1%20(rand)-555?style=flat-square)

## ✨ Features

- **Fully recursive:** starts at the root servers and follows each referral down to the domain's own nameservers
- **Hand-rolled packets:** encodes and decodes DNS messages byte by byte, including name compression
- **CNAME chains:** follows aliases across zones, starting each hop at the closest zone it already knows
- **TTL-aware cache:** keeps answers, CNAMEs, NXDOMAINs and zone delegations until their TTL runs out
- **Delegation cache:** remembers each zone's nameservers, so a lookup skips the root and TLD when it can, and falls back to the root if the cached servers fail
- **No-glue nameservers:** looks up nameservers that live in other zones
- **EDNS0:** advertises a 4096-byte UDP payload so large replies aren't truncated
- **TCP fallback:** retries over TCP when a reply comes back truncated
- **A and AAAA** lookups, with a random query ID on every query
- **Quiet by default:** prints only the results; `-v` / `--verbose` shows every query, referral and cache hit

## 🚀 Usage

```bash
cargo run -- www.google.com          # A record
cargo run -- www.google.com AAAA     # AAAA record
cargo run -- -v www.amazon.com       # show each step of the lookup
```

```
$ cargo run -- www.amazon.com
Results:
  13.249.20.221
```

With `-v`, you can watch the delegation cache at work. After the first CNAME, each hop starts at a zone it already knows instead of at the root:

```
$ cargo run -- -v www.amazon.com
...
DEBUG: CNAME www.amazon.com -> tp.47cf2c8c9-frontier.amazon.com
DEBUG: Starting tp.47cf2c8c9-frontier.amazon.com at cached zone amazon.com (1 server(s))
...
DEBUG: CNAME tp.47cf2c8c9-frontier.amazon.com -> cf.47cf2c8c9-frontier.amazon.com
DEBUG: Starting cf.47cf2c8c9-frontier.amazon.com at cached zone 47cf2c8c9-frontier.amazon.com (1 server(s))
...
=== Resolution complete ===
Results:
  13.249.20.221
```

## 🧭 How it works

```
root (.)  ──►  .com TLD  ──►  amazon.com NS  ──►  answer
   │              │                 │
   └─ referral ───┴─── referral ────┴─ CNAME? restart at the closest cached zone
```

Every referral is cached as zone → nameserver IPs. A new lookup walks up the name's labels
(`cf.x.amazon.com` → `x.amazon.com` → `amazon.com` → `com`) and starts at the first zone it has
servers for. It starts at the root only when nothing is cached or the cached servers fail.

| File | Role |
|---|---|
| `src/packet.rs` | DNS wire format: header, questions, records, name compression |
| `src/transport.rs` | UDP queries with retries, TCP fallback |
| `src/resolver.rs` | Iterative resolution: referrals, glue, CNAMEs, closest-zone start |
| `src/cache.rs` | TTL cache: answers, CNAMEs, NXDOMAINs and zone delegations |
| `src/log.rs` | `-v` / `--verbose` switch and the `debug!` macro |
| `src/main.rs` | Command-line interface |

## 🗺️ Feature plan

> [!NOTE]
> Features are added one at a time. Each one ends with `cargo build`, a test run and a commit.
> The checks under each item are how to tell it works.

### Phase 1: Speed
- [x] **EDNS0:** add an OPT record (type 41, 4096-byte payload) so root replies fit in UDP.
  *Check: root replies show `TC=false`.*
- [ ] **First working nameserver:** use the first nameserver that resolves instead of resolving all of them.
  *Check: `www.amazon.com` takes far fewer queries.*
- [x] **TTL-aware cache:** remember answers and nameserver IPs until their TTL runs out.
  *Check: a second lookup in the same run skips the root.*
- [ ] **Faster failover:** shorter timeouts, and pick a random root server instead of always the first.

### Phase 2: Usability
- [x] **`-v` / `--verbose`:** hide the DEBUG lines unless asked.
- [ ] **More record types:** MX, TXT, NS, SOA and PTR (reverse lookups with `-x 8.8.8.8`).
- [ ] **`+trace` mode:** print the delegation path the way `dig +trace` does.
- [ ] **Short IPv6 formatting:** use `std::net::Ipv6Addr` (`2001:4860::8888`).
- [ ] **Timing:** show the total resolution time and the query count.
- [ ] **JSON output** (`--json`) for scripts.

### Phase 3: Robustness
- [ ] **Unit tests:** use saved packets for compression, referrals and CNAMEs.
- [ ] **Loop protection:** carry the depth and visited state into NS-name lookups.
- [ ] **Bailiwick checks:** ignore glue records for zones that aren't the one being referred to.
- [ ] **QNAME minimisation:** only send each server the part of the name it needs (RFC 9156).
- [ ] **IPv6 transport:** query servers over IPv6 when available.

### Phase 4: Server mode
- [ ] **Local DNS server:** listen on port 53 and answer real clients (your PC, your LAN).
- [ ] **Async with Tokio:** handle many queries at once.
- [ ] **Blocklist:** block ad and tracker domains, Pi-hole style.
- [ ] **Stats page:** a small web dashboard with queries, cache hit rate and the top domains.
- [ ] **DNSSEC validation:** verify signatures from the root down.
