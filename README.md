# carscal

A terminal packet analyzer — a tiny Wireshark for the TUI, **in Rust**. carscal
is a Rust replica (and then some) of
[carcal](https://github.com/stricaud/carcal): it opens pcap/pcapng captures or
captures live, lists packets in a **table view**, shows the selected packet's
protocol layers in a **tree view** with a Wireshark-style **hex byte pane**, and
filters with a **Wireshark/tshark-compatible display filter**. New protocols can
be defined at runtime with libpcapng `.posa` files, and any protocol can be
decoded live from a **Lua script**.

Built on two Rust binding crates (which carscal also drives to be friendlier
upstream):

- **[gtcaca](https://crates.io/crates/gtcaca)** — libcaca TUI widget toolkit
  (table, tree, hexview, menu, dialog, line/bar/pie/scatter charts, mind map).
- **[libpcapng](https://crates.io/crates/libpcapng)** — pcapng I/O, the shared
  dissection engine, IP/TCP reassembly, `.posa` decoders, object extraction, and
  live capture.

## Install

### Homebrew (macOS & Linux)

```sh
brew install stricaud/tap/carscal
```

Homebrew pulls in the one external dependency (libcaca) automatically.

### One-line installer (prebuilt binaries)

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/stricaud/carscal/releases/latest/download/carscal-installer.sh | sh
```

Prebuilt for macOS (Apple Silicon & Intel) and Linux (x86-64 & arm64). These
binaries link libcaca dynamically, so install it if it isn't already present:
`apt install libcaca0` / `dnf install libcaca` / `brew install libcaca`.

### From crates.io (needs the Rust toolchain)

```sh
cargo install carscal
```

Build-time requirements: a C compiler, `pkg-config`, and libcaca development
files (`apt install libcaca-dev`, `dnf install libcaca-devel`, or
`brew install libcaca`).

### From source

```sh
git clone --recursive https://github.com/stricaud/carscal && cd carscal
cargo build --release
./target/release/carscal capture.pcapng
```

## After installing: capture privileges

Reading `.pcap`/`.pcapng` files and the headless / scripting modes need **no**
special privileges. **Live capture** (`-i <interface>`) does — the OS restricts
raw packet access:

- **Linux** — grant the binary the capability once (no sudo per run):

  ```sh
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v carscal)"
  ```

  or simply run `sudo carscal -i eth0`.

- **macOS** — access to `/dev/bpf*` is required. Either run with `sudo`, or
  install Wireshark's **ChmodBPF** helper (adds you to the `access_bpf` group so
  no sudo is needed afterwards).

List available interfaces with `carscal --interfaces`. If capture fails with a
permission error, carscal tells you exactly what to do.

## Using it (TUI)

Run `carscal` with a file (`carscal capture.pcapng`) or an interface
(`carscal -i eth0`), or bare `carscal` to open empty. The menu bar
(**F9**/**F10**) has File / Edit / View / Capture / Analyze / Statistics / Help.

| Key | Action |
|-----|--------|
| `/` | Jump to the display-filter box |
| `Enter` | Apply the filter (in the filter box) |
| `Tab` | Cycle focus: filter → packet table → detail tree → bytes |
| `↑ ↓ PgUp PgDn Home End` | Navigate the focused pane |
| `m` | Mark / unmark the selected packet |
| `C` | Toggle packet-list coloring |
| `F9` / `F10` | Open the menu bar |
| `q` / `^Q` | Quit (with confirmation) |

The lower area splits into the **detail tree** (left) and a **hex byte pane**
(right); selecting a field in the tree highlights its bytes, and moving the byte
cursor selects the matching field.

**Statistics** (interactive): IO Graph (multi-series, per-graph filters, colours,
styles, Y-axis modes, log-Y), Conversations (Hosts ▸ Conversations tree + packet
table), Endpoints, Entity Explorer, Protocol Hierarchy. **Analyze**: Apply as
Filter/Column, Conversation Filter, Follow TCP/UDP Stream, Decode As, Decoders.
**File**: Export HTTP / SMB Objects (carve transferred files).

## Headless (no terminal needed)

```sh
carscal --summary capture.pcapng "tcp.port == 443"   # one line per packet
carscal --dump    capture.pcapng "dns"               # full field tree
carscal --stats   conv capture.pcapng                # conv | endpoints | proto
carscal --export-objects http capture.pcapng ./out   # carve files (Export Objects)
carscal --find    capture.pcapng "hex:DE AD BE EF"   # find by text or bytes
carscal --protocols                                  # list loaded .posa decoders
carscal --check-decoders                             # load ~/.carscal/decoders and report errors
carscal --interfaces                                 # list capture interfaces
carscal --help
```

## Live scripting (Lua)

Give carscal a display filter and a Lua script to decode *any* protocol live —
the generalized MQS idea. See the tutorials:

- [docs/live-mysql-lua.md](docs/live-mysql-lua.md) — decode MySQL queries live.
- [docs/export-objects.md](docs/export-objects.md) — carve HTTP/SMB files live.

```sh
sudo carscal -s mysql-queries.lua -f "tcp.port == 3306" -i eth0
```

## Display filters

Wireshark/tshark syntax:

```
ip.addr == 192.168.1.0/24
tcp.port == 443 && ip.src != 10.0.0.1
udp and dns.qry.name contains "example"
icmp || arp
tcp.flags == 0x12
eth.src == aa:bb:cc:dd:ee:ff
```

Operators: `== eq`, `!= ne`, `> gt`, `< lt`, `>= ge`, `<= le`, `contains`,
`matches` (substring), `&& and`, `|| or`, `! not`, parentheses. A bare field
name is an existence test (`tcp`, `dns`). Aliases match either direction:
`ip.addr`, `ipv6.addr`, `tcp.port`, `udp.port`, `eth.addr`.

## Protocols & decoders

Built-in dissectors (via libpcapng): Ethernet/802.1Q, IPv4, IPv6, ARP, TCP, UDP,
ICMP/ICMPv6, DNS. Everything else is reachable through `.posa` decoders — the
bundled set (HTTP/2, TLS, SMB, MySQL, PostgreSQL, Kerberos, LDAP, Modbus, MQTT,
SIP, RTP, …) plus your own, loaded at startup from `~/.carscal/decoders/`, the
bundled `protos/`, or
`$CARSCAL_PROTOS_DIR` (carcal's `$CARCAL_PROTOS_DIR` also works). Validate a
decoder set without launching the UI with `carscal --check-decoders`.

`protos/` is a git submodule tracking
[stricaud/network.protos.posa](https://github.com/stricaud/network.protos.posa),
the shared `.posa` protocol collection — clone with `--recursive` (or run
`git submodule update --init`) to get it.

**Decode As** binds a port (or any display-filter condition) to a decoder;
pcapng **Custom Blocks** are surfaced and their payload dissected (labelled with
the block's Private Enterprise Number).

## Coloring rules

The packet list is colored by an ordered list of `<display filter> → fg/bg`
rules — **first match wins**, as in Wireshark. Rules come from three layers, most
specific first: your `<protos dir>/colorfilters` file, the `color …` lines
declared inside loaded `.posa` decoders, then carscal's built-in defaults. Toggle
coloring in the TUI with `C` (or View ▸ Coloring Rules to inspect them); a marked
packet always overrides its rule color.

```sh
carscal --colors capture.pcapng    # print the rules and which one paints each packet
```

## License

MIT.
