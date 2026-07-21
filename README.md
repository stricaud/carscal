# carscal

A terminal packet analyzer — a tiny Wireshark for the TUI, **in Rust**. carscal
is a Rust replica of [carcal](https://github.com/stricaud/carcal): it opens
pcap/pcapng captures, lists packets in a **table view**, shows the selected
packet's protocol layers in a **tree view** with a Wireshark-style **hex byte
pane**, and filters with a **Wireshark/tshark-compatible display filter**. New
protocols can be defined at runtime with libpcapng `.posa` files.

Built entirely on two Rust binding crates (which carscal also drives to be
friendlier upstream):

- **[gtcaca](https://crates.io/crates/gtcaca)** `0.0.1` — libcaca TUI widget
  toolkit (table, tree, hexview, statusbar, menu, dialog, line chart).
- **[libpcapng](https://crates.io/crates/libpcapng)** `0.15.1` — pcapng reading,
  the shared dissection engine, IP/TCP reassembly, and `.posa` decoders.

## Building

libcaca is found via `pkg-config`; the C sources of both libraries are compiled
by their `-sys` crates (bindgen needs libclang).

```sh
cargo build --release
./target/release/carscal capture.pcapng
```

## Using it (TUI)

| Key | Action |
|-----|--------|
| `/` | Jump to the display-filter box |
| `Enter` | Apply the filter (in the filter box) |
| `Tab` | Cycle focus: filter → packet table → detail tree → bytes |
| `↑ ↓ PgUp PgDn Home End` | Navigate the focused pane |
| `m` | Mark / unmark the selected packet |
| `q` / `^Q` | Quit |

The lower area splits into the **detail tree** (left) and a **hex byte pane**
(right); selecting a field in the tree highlights its bytes.

## Headless (no terminal needed)

```sh
carscal --summary capture.pcapng "tcp.port == 443"   # one line per packet
carscal --dump    capture.pcapng "dns"               # full field tree
carscal --protocols                                  # list loaded .posa decoders
carscal --help
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

## Protocols

Built-in dissectors (via libpcapng): Ethernet/802.1Q, IPv4, IPv6, ARP, TCP, UDP,
ICMP/ICMPv6, DNS. Everything else is reachable through `.posa` decoders loaded
from `protos/` at startup (TFTP, RDP, DHCP, DNS, HTTP, SMB, TLS, IGMP, …). Point
`CARSCAL_PROTOS_DIR` (or carcal's `CARCAL_PROTOS_DIR`) at your own decoders.

pcapng **Custom Blocks** are surfaced and their payload dissected (labelled with
the block's Private Enterprise Number).

## Coloring rules

The packet list is colored by an ordered list of `<display filter> → fg/bg`
rules — **first match wins**, as in Wireshark. Rules come from three layers,
most specific first: your `<protos dir>/colorfilters` file, the `color …` lines
declared inside loaded `.posa` decoders, then carscal's built-in defaults. Toggle
coloring in the TUI with `C`; a marked packet always overrides its rule color.

```sh
carscal --colors capture.pcapng    # print the rules and which one paints each packet
```

## Status

- ✅ Core engine: pcap + pcapng readers, Custom Blocks, the shared dissection
  engine, 18 `.posa` decoders, the full display-filter engine (unit-tested).
- ✅ Headless CLI (`--summary`, `--dump`, `--protocols`, `--colors`), verified
  on real captures.
- ✅ Coloring rules (first-match-wins, posa + user + defaults), unit-tested.
- ✅ TUI: table + detail tree + hex pane + filter box + status bar + row
  coloring, with focus cycling and navigation. (Needs a real terminal.)
- ✅ Both binding crates published: `gtcaca = "0.1.1"`, `libpcapng = "0.15.2"`.
- ⬜ Roadmap: Decode As…, Follow TCP/UDP stream, Find packet, IO graph, live
  capture, Lua scripting (the generalized MQS use-case), Apply-as-Column /
  Apply-as-Filter.
