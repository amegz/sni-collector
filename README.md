# sni-collector

A lightweight, **passive** TLS SNI collector for a Linux host that sits in
front of a known HTTP/HTTPS proxy. It watches the TCP traffic containers (or
any other black-box applications on the host) send to that proxy, reassembles
TLS `ClientHello` messages, and logs the SNI (`server_name`) each connection
asked for.

```text
containers
    |
    | TLS
    v
host  <-- sni-collector observes traffic here, passively
    |
    | TCP -> 198.51.100.10:3128
    v
proxy
```

`sni-collector` never modifies, delays, drops, or originates any packet. It
only reads from a passive packet capture (libpcap); the traffic between
applications and the proxy is unaffected in every way.

## What it does

- Captures only TCP traffic whose **destination** matches a configured
  `--proxy-ip:--proxy-port` (via a kernel BPF filter, applied before any
  packet reaches userspace).
- Reassembles the TCP byte stream per connection (handles out-of-order
  delivery, retransmissions, and a `ClientHello` split across many packets).
- Parses the plaintext TLS record/handshake framing just far enough to find
  the `server_name` (SNI) extension of the `ClientHello`. It never touches
  anything beyond the `ClientHello` — no decryption, no MITM, no HTTP
  parsing, no Application Data.
- Logs `timestamp`, `source IP`, optionally `source port`, and `SNI`.
  Nothing else is ever written to the log.
- Once a connection's outcome is known (SNI found, no SNI present, not TLS,
  or the buffer cap was hit), its buffered bytes are dropped immediately —
  the full stream is never retained.
- Optionally deduplicates repeated `(source IP, SNI)` pairs within a
  configurable TTL.

### What it deliberately does *not* do

- No NFQUEUE, no nftables/iptables changes, no routing changes, no inline
  proxying — pure `libpcap` read-only capture.
- No TLS decryption or MITM.
- No inspection of HTTP requests or TLS Application Data.
- No full-traffic DPI: only packets matching the BPF filter
  (`tcp and dst host <proxy-ip> and dst port <proxy-port>`) are ever looked
  at.
- If the `ClientHello` uses ECH (Encrypted Client Hello) and thus carries no
  plaintext SNI, the connection is simply skipped — this is treated as a
  normal outcome, not an error.

## Architecture

```text
packet capture (libpcap, BPF-filtered at the kernel)
    |
    v
TCP stream reassembly (per 5-tuple; gopacket/reassembly)
    |
    v
TLS ClientHello detection + SNI extraction (internal/tlssni, no gopacket
dependency — pure byte parsing, independently unit-testable)
    |
    v
dedup (optional, TTL-based) -> log line
```

Code layout:

| Path                        | Purpose                                                             |
|------------------------------|----------------------------------------------------------------------|
| `internal/tlssni`            | Pure, allocation-conscious `ClientHello`/SNI parser. No pcap/reassembly dependency; this is where malformed-input safety lives. |
| `internal/capture`            | Wires a `gopacket.PacketDataSource` (live `pcap.Handle` or an offline `pcapgo.Reader`) to TCP reassembly and the SNI parser. |
| `internal/dedup`               | TTL-based "have I logged this (source IP, SNI) recently" cache.     |
| `cmd/sni-collector`            | CLI, privilege handling, log output.                                |
| `deploy/`                      | Example systemd unit + environment file.                            |

## Building

Requires Go 1.25+ (the module pins `go 1.25.0`; `go build`/`go test` will
fetch the matching toolchain automatically if needed) and libpcap headers
(needed at build time only, for the cgo `pcap` binding):

```bash
sudo apt-get install -y libpcap-dev   # Debian/Ubuntu
# or: sudo dnf install -y libpcap-devel   # Fedora/RHEL

go build -o sni-collector ./cmd/sni-collector
```

This produces a single standalone binary (`libpcap.so` is still a runtime
shared-library dependency — it's part of virtually every Linux base image,
but if you need a fully static binary, build with
`CGO_ENABLED=1 go build -ldflags '-linkmode external -extldflags "-static"'`
against static libpcap).

### Building a .deb package

```bash
./packaging/build-deb.sh [version]   # default version: 1.0.0
```

Produces `dist/sni-collector_<version>_<arch>.deb`. The package:

- installs the binary to `/usr/bin/sni-collector`;
- installs `deploy/sni-collector.env`-equivalent config to
  `/etc/sni-collector/sni-collector.env` (marked as a conffile — local edits
  survive upgrades);
- installs the systemd unit to `/lib/systemd/system/sni-collector.service`;
- creates a dedicated system user/group `sni-collector` on install (`postinst`)
  and removes it on purge (`postrm`); stops/disables the service before
  removal (`prerm`);
- depends on `libpcap0.8t64 | libpcap0.8` (whichever the target distro
  provides), `adduser`, and `systemd`.

Install it with:

```bash
sudo apt install ./dist/sni-collector_1.0.0_amd64.deb
sudo editor /etc/sni-collector/sni-collector.env   # set --proxy-ip for your environment
sudo systemctl enable --now sni-collector
```

The service never needs root: capabilities are granted via the unit's
`AmbientCapabilities=`, matching the "Privileges" section below.

## Running

```bash
sni-collector \
  --interface any \
  --proxy-ip 198.51.100.10 \
  --proxy-port 3128 \
  --output /var/log/sni-collector.log \
  --deduplicate \
  --dedup-ttl 1h
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--interface` | `any` | Capture interface (`any` for all interfaces). |
| `--proxy-ip` | *(required)* | Destination IP of the proxy to watch. |
| `--proxy-port` | `3128` | Destination TCP port of the proxy to watch. |
| `--output` | stdout | Path to append SNI log lines to. |
| `--deduplicate` | off | Suppress repeated `(source IP, SNI)` lines within `--dedup-ttl`. |
| `--dedup-ttl` | `1h` | TTL for `--deduplicate`; after it elapses, the same SNI may be logged again. |
| `--log-source-port` | off | Also include the client's source TCP port in log lines. |
| `--idle-timeout` | `60s` | Drop per-connection state for flows idle longer than this. |
| `--max-buffer` | `32768` | Max bytes of one TCP flow buffered while looking for a `ClientHello`. |
| `--promisc` | off | Enable promiscuous mode on the capture interface. |
| `--drop-user` | *(none)* | If running as root, drop privileges to this user right after opening the capture handle. See "Privileges" below — prefer not needing this at all. |
| `--version` | | Print the version and exit. |

Run `sni-collector --help` for the same reference on the command line.

### Log format

```text
2026-08-25T12:39:29+02:00 192.0.2.10 registry.example.com
2026-08-25T12:39:30+02:00 192.0.2.10 storage.example.net
```

With `--log-source-port`:

```text
2026-08-25T12:39:29+02:00 192.0.2.10:51422 registry.example.com
```

Only timestamp, source IP, source port (optional), and SNI are ever written.
No TLS payload, HTTP data, cookies, or credentials are logged or retained.

## Privileges

Live packet capture needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for some
interface/BPF operations); `sni-collector` should **not** run as root beyond
that. Two ways to grant just those capabilities, in order of preference:

1. **File capabilities (simplest, no systemd required):**

   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/sni-collector
   ```

   The binary can then be run directly by an unprivileged user; the kernel
   grants the capabilities for the duration of that process only.

2. **systemd `AmbientCapabilities=`** (see `deploy/sni-collector.service`):
   grants the same two capabilities to the service process at exec time,
   without touching the binary's file capabilities at all. This is the
   approach used in the example unit.

If `sni-collector` is started as root anyway (e.g. an existing deployment
convention), pass `--drop-user <user>` to have it switch to an unprivileged
UID/GID immediately after the capture handle is opened and the BPF filter is
installed — everything from that point on (reassembly, parsing, logging)
runs unprivileged.

## Systemd deployment

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sni-collector
sudo install -m 0755 sni-collector /usr/local/bin/sni-collector
sudo install -d -m 0755 /etc/sni-collector
sudo install -m 0640 deploy/sni-collector.env /etc/sni-collector/sni-collector.env
sudo install -m 0644 deploy/sni-collector.service /etc/systemd/system/sni-collector.service

sudo systemctl daemon-reload
sudo systemctl enable --now sni-collector
sudo journalctl -u sni-collector -f
```

Edit `/etc/sni-collector/sni-collector.env` to set the real `--proxy-ip`.
The unit writes its log via `LogsDirectory=sni-collector`, i.e.
`/var/log/sni-collector/sni-collector.log`, and runs fully unprivileged
(`User=sni-collector`) using `AmbientCapabilities=` for capture access.

## Testing

```bash
go test ./...          # unit tests + integration test
go test ./... -race     # same, with the race detector
```

- `internal/tlssni`: unit tests covering TLS 1.2 and TLS 1.3 `ClientHello`s
  with SNI, `ClientHello` without SNI (including an ECH-shaped extension),
  fragmentation (down to one byte per write), multiple simultaneous/
  independent connections, malformed/truncated/garbage TLS input, and the
  buffer-limit give-up path.
- `internal/dedup`: TTL suppression and expiry.
- `internal/capture` (`TestIntegrationRealPcapTwoConnectionsWithReorderAndRetransmit`):
  an integration test that builds a **real `.pcap` file** (Ethernet/IPv4/TCP
  framing, written with `pcapgo` so the test needs no live capture
  privileges) reproducing a typical deployment capture — two connections from
  `192.0.2.10` to `198.51.100.10:3128` carrying SNI `registry.example.com`
  and `storage.example.net` — with one connection's
  `ClientHello` delivered out of order and with a retransmitted duplicate
  segment, interleaved with the other connection's packets. The test feeds
  the file through the exact same `capture.Run` code path used for live
  capture and asserts both SNIs (and their source IP/port) come out
  correctly and nothing else does.

## Notes on scope and edge cases

- Only the client→proxy direction is ever inspected (the BPF filter matches
  on *destination* IP/port), so there is exactly one relevant TCP flow
  direction per connection; the collector doesn't need to reassemble the
  proxy's replies at all.
- A `ClientHello` split across multiple TLS records (rather than multiple
  TCP segments of one record) is not supported — this does not happen in
  practice with real TLS stacks and is out of scope per the spec.
- Non-TLS traffic to the proxy port (e.g. a broken client speaking HTTP
  `CONNECT` first) is recognized as "not TLS" and its state is dropped
  immediately; it is never treated as an error.
- The collector may attach to a connection that was already established
  before it started (or restarted): it treats the first packet it observes
  on a new flow as the stream's start even without seeing a `SYN`, so it
  doesn't silently wait forever for a handshake it will never see.
