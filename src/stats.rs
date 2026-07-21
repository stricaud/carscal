//! Capture statistics — Conversations, Endpoints, and Protocol Hierarchy.
//!
//! These summarize a capture the way Wireshark's Statistics menu does, and are
//! the analytical core for "processing" (not just reading) network data. They
//! reuse the L4 parser for flows and the dissection tree for protocols.

use crate::dissect;
use crate::l4;
use crate::model::Capture;
use std::collections::HashMap;

/// One conversation (bidirectional flow between two transport endpoints).
pub struct Conversation {
    pub proto: &'static str, // "TCP" / "UDP"
    pub a: String,           // "ip:port" of the endpoint seen first
    pub b: String,
    pub packets: u64,
    pub bytes: u64,
    pub a_to_b: u64, // packets a→b
    pub b_to_a: u64, // packets b→a
    pub first_us: u64,
    pub last_us: u64,
    /// A display filter selecting exactly this conversation's packets.
    pub filter: String,
}

impl Conversation {
    /// Duration in seconds.
    pub fn duration(&self) -> f64 {
        self.last_us.saturating_sub(self.first_us) as f64 / 1e6
    }
}

struct ConvAcc {
    proto: &'static str,
    a: String,
    b: String,
    a_raw: (Vec<u8>, u16),
    packets: u64,
    bytes: u64,
    a_to_b: u64,
    b_to_a: u64,
    first_us: u64,
    last_us: u64,
    filter: String,
}

/// All conversations, sorted by packet count (descending).
pub fn conversations(cap: &Capture) -> Vec<Conversation> {
    let mut map: HashMap<(u8, Vec<u8>, u16, Vec<u8>, u16), ConvAcc> = HashMap::new();

    for pkt in &cap.pkts {
        let l = match l4::locate(&pkt.data, pkt.linktype) {
            Some(l) => l,
            None => continue,
        };
        // Direction-independent key: order the two (ip, port) endpoints.
        let x = (l.src_ip_raw.clone(), l.src_port);
        let y = (l.dst_ip_raw.clone(), l.dst_port);
        let (lo, hi) = if x <= y { (&x, &y) } else { (&y, &x) };
        let key = (l.proto, lo.0.clone(), lo.1, hi.0.clone(), hi.1);
        let proto = if l.proto == 6 { "TCP" } else { "UDP" };

        let acc = map.entry(key).or_insert_with(|| {
            let ipk = if l.src_ip_raw.len() == 16 { "ipv6" } else { "ip" };
            let l4k = if l.proto == 6 { "tcp" } else { "udp" };
            let filter = format!(
                "{ipk}.addr == {} && {ipk}.addr == {} && {l4k}.port == {} && {l4k}.port == {}",
                l.src_ip, l.dst_ip, l.src_port, l.dst_port
            );
            ConvAcc {
                proto,
                a: format!("{}:{}", l.src_ip, l.src_port),
                b: format!("{}:{}", l.dst_ip, l.dst_port),
                a_raw: (l.src_ip_raw.clone(), l.src_port),
                packets: 0,
                bytes: 0,
                a_to_b: 0,
                b_to_a: 0,
                first_us: pkt.ts_us,
                last_us: pkt.ts_us,
                filter,
            }
        });
        acc.packets += 1;
        acc.bytes += pkt.origlen as u64;
        acc.first_us = acc.first_us.min(pkt.ts_us);
        acc.last_us = acc.last_us.max(pkt.ts_us);
        if (l.src_ip_raw.clone(), l.src_port) == acc.a_raw {
            acc.a_to_b += 1;
        } else {
            acc.b_to_a += 1;
        }
    }

    let mut out: Vec<Conversation> = map
        .into_values()
        .map(|c| Conversation {
            proto: c.proto,
            a: c.a,
            b: c.b,
            packets: c.packets,
            bytes: c.bytes,
            a_to_b: c.a_to_b,
            b_to_a: c.b_to_a,
            first_us: c.first_us,
            last_us: c.last_us,
            filter: c.filter,
        })
        .collect();
    out.sort_by(|x, y| y.packets.cmp(&x.packets));
    out
}

/// Per-endpoint (host:port) packet/byte totals, sorted by packets (descending).
pub fn endpoints(cap: &Capture) -> Vec<(String, u64, u64)> {
    let mut map: HashMap<String, (u64, u64)> = HashMap::new();
    for pkt in &cap.pkts {
        if let Some(l) = l4::locate(&pkt.data, pkt.linktype) {
            for ep in [format!("{}:{}", l.src_ip, l.src_port), format!("{}:{}", l.dst_ip, l.dst_port)] {
                let e = map.entry(ep).or_insert((0, 0));
                e.0 += 1;
                e.1 += pkt.origlen as u64;
            }
        }
    }
    let mut out: Vec<(String, u64, u64)> =
        map.into_iter().map(|(k, (p, b))| (k, p, b)).collect();
    out.sort_by(|x, y| y.1.cmp(&x.1));
    out
}

/// Per-protocol packet/byte counts (a flattened protocol hierarchy), sorted by
/// packet count. A packet counts once for each protocol layer it contains.
pub fn protocol_hierarchy(cap: &Capture) -> Vec<(String, u64, u64)> {
    let mut map: HashMap<String, (u64, u64)> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for pkt in &cap.pkts {
        let d = match dissect::dissect(pkt) {
            Some(d) => d,
            None => continue,
        };
        for layer in d.root().children() {
            let name = layer_name(&layer);
            if name.is_empty() {
                continue;
            }
            let e = map.entry(name.clone()).or_insert_with(|| {
                order.push(name.clone());
                (0, 0)
            });
            e.0 += 1;
            e.1 += pkt.origlen as u64;
        }
    }
    let mut out: Vec<(String, u64, u64)> =
        map.into_iter().map(|(k, (p, b))| (k, p, b)).collect();
    out.sort_by(|x, y| y.1.cmp(&x.1));
    out
}

/// A protocol layer's short name (abbrev prefix like "ip", or its label word).
fn layer_name(layer: &libpcapng::Field) -> String {
    for c in layer.children() {
        if let Some((prefix, _)) = c.abbrev().split_once('.') {
            return prefix.to_string();
        }
    }
    layer.label().split([',', ' ']).next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capture, Packet};

    fn tcp_frame(s: u8, d: u8, sp: u16, dp: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12] = 0x08;
        f[14] = 0x45;
        f[14 + 9] = 6;
        f[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, s]);
        f[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, d]);
        let t = 14 + 20;
        f[t..t + 2].copy_from_slice(&sp.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&dp.to_be_bytes());
        f[t + 12] = 5 << 4;
        f
    }

    #[test]
    fn one_conversation_both_directions() {
        let mut cap = Capture::default();
        cap.push(Packet::new(tcp_frame(1, 2, 5000, 80), 54, 0, 1, 0));
        cap.push(Packet::new(tcp_frame(2, 1, 80, 5000), 54, 1_000_000, 1, 0));
        cap.push(Packet::new(tcp_frame(1, 2, 5000, 80), 54, 2_000_000, 1, 0));
        let convs = conversations(&cap);
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].packets, 3);
        assert_eq!(convs[0].a_to_b, 2);
        assert_eq!(convs[0].b_to_a, 1);
        assert!((convs[0].duration() - 2.0).abs() < 1e-6);
    }
}
