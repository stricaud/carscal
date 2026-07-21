//! Conversation identification + "Follow Stream".
//!
//! The actual TCP reassembly is done by **libpcapng** (`TcpReasm`); carscal just
//! identifies the conversation, marshals each segment's 5-tuple + payload into
//! the library, and collects the per-direction result. UDP has no ordering to
//! reassemble, so its payloads are concatenated in capture order.

use crate::l4::{self, L4};
use crate::model::Capture;
use libpcapng::TcpReasm;

/// IPv4 dotted-quad → host-order u32 (for feeding the reassembler).
fn ipv4_u32(raw: &[u8]) -> u32 {
    if raw.len() == 4 {
        u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])
    } else {
        0
    }
}

/// A conversation key that is identical for both directions of a flow.
#[derive(Clone, PartialEq, Eq)]
pub struct ConvKey {
    pub proto: u8,
    a: (Vec<u8>, u16),
    b: (Vec<u8>, u16),
}

impl ConvKey {
    fn of(l4: &L4) -> ConvKey {
        let x = (l4.src_ip_raw.clone(), l4.src_port);
        let y = (l4.dst_ip_raw.clone(), l4.dst_port);
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        ConvKey { proto: l4.proto, a, b }
    }
}

/// The reassembled conversation.
pub struct Follow {
    pub proto: u8,
    pub client: (String, u16),
    pub server: (String, u16),
    /// In-order bytes, client→server and server→client.
    pub client_bytes: Vec<u8>,
    pub server_bytes: Vec<u8>,
    /// Number of packets in the conversation.
    pub packets: usize,
}

/// Reassemble the conversation that the packet at `index` belongs to, using
/// libpcapng's TCP reassembler for TCP and capture-order concatenation for UDP.
pub fn follow(cap: &Capture, index: usize) -> Option<Follow> {
    let sel = cap.pkts.get(index)?;
    let sel_l4 = l4::locate(&sel.data, sel.linktype)?;
    let key = ConvKey::of(&sel_l4);
    let is_tcp = sel_l4.proto == 6;

    // The "client" is whoever sent the first packet of this conversation.
    let mut client_ep: Option<(String, u16, Vec<u8>)> = None;
    let mut server_ep: Option<(String, u16)> = None;
    let mut packets = 0usize;

    let mut tcp = if is_tcp { Some(TcpReasm::new()) } else { None };
    // Latest cumulative buffer per libpcapng direction id, and which real
    // endpoint (ip,port) that direction is sourced from.
    let mut bufs: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut dir_src: [Option<(u32, u16)>; 2] = [None, None];
    // UDP: concatenated payloads per direction.
    let mut udp_client: Vec<u8> = Vec::new();
    let mut udp_server: Vec<u8> = Vec::new();

    for pkt in &cap.pkts {
        let l4 = match l4::locate(&pkt.data, pkt.linktype) {
            Some(l) => l,
            None => continue,
        };
        if ConvKey::of(&l4) != key {
            continue;
        }
        packets += 1;

        if client_ep.is_none() {
            client_ep = Some((l4.src_ip.clone(), l4.src_port, l4.src_ip_raw.clone()));
            server_ep = Some((l4.dst_ip.clone(), l4.dst_port));
        }
        let is_client = {
            let (cip, cport, craw) = client_ep.as_ref().unwrap();
            &l4.src_ip == cip && l4.src_port == *cport && &l4.src_ip_raw == craw
        };

        let payload = &pkt.data[l4.payload_off..l4.payload_off + l4.payload_len];

        if let Some(r) = tcp.as_mut() {
            let sip = ipv4_u32(&l4.src_ip_raw);
            let dip = ipv4_u32(&l4.dst_ip_raw);
            r.add(
                sip,
                dip,
                l4.src_port,
                l4.dst_port,
                l4.seq,
                l4.flags,
                payload,
                |b| {
                    let d = (b.dir & 1) as usize;
                    bufs[d] = b.all.to_vec();
                    dir_src[d] = Some((b.src_ip, b.src_port));
                },
            );
        } else if is_client {
            udp_client.extend_from_slice(payload);
        } else {
            udp_server.extend_from_slice(payload);
        }
    }

    let client = client_ep.clone().map(|(ip, p, _)| (ip, p))?;
    let server = server_ep?;

    let (client_bytes, server_bytes) = if is_tcp {
        // Map libpcapng's stable dir ids back onto client/server.
        let (cip, cport, craw) = client_ep.unwrap();
        let _ = (cip, cport);
        let client_key = (ipv4_u32(&craw), client.1);
        let client_dir = (0..2).find(|&d| dir_src[d] == Some(client_key));
        match client_dir {
            Some(d) => (std::mem::take(&mut bufs[d]), std::mem::take(&mut bufs[1 - d])),
            None => (std::mem::take(&mut bufs[0]), std::mem::take(&mut bufs[1])),
        }
    } else {
        (udp_client, udp_server)
    };

    Some(Follow {
        proto: sel_l4.proto,
        client,
        server,
        client_bytes,
        server_bytes,
        packets,
    })
}

/// A display-filter expression matching the selected packet's conversation
/// (the "Conversation Filter" / `c` key).
pub fn conversation_filter(cap: &Capture, index: usize) -> Option<String> {
    let pkt = cap.pkts.get(index)?;
    let l4 = l4::locate(&pkt.data, pkt.linktype)?;
    let ipk = if l4.src_ip_raw.len() == 16 { "ipv6" } else { "ip" };
    let l4k = if l4.proto == 6 { "tcp" } else { "udp" };
    Some(format!(
        "{ipk}.addr == {} && {ipk}.addr == {} && {l4k}.port == {} && {l4k}.port == {}",
        l4.src_ip, l4.dst_ip, l4.src_port, l4.dst_port
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4;

    #[test]
    fn conv_key_is_direction_independent() {
        // Same 4-tuple in both directions yields the same key.
        let a = l4::locate(&frame(10, 20, 1111, 80), 1).unwrap();
        let b = l4::locate(&frame(20, 10, 80, 1111), 1).unwrap();
        assert!(ConvKey::of(&a) == ConvKey::of(&b));
    }

    // Minimal Ethernet+IPv4+TCP frame for the test above.
    fn frame(s: u8, d: u8, sp: u16, dp: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12] = 0x08; // ethertype IPv4
        f[14] = 0x45; // ver/ihl
        f[14 + 9] = 6; // proto TCP
        f[14 + 12..14 + 16].copy_from_slice(&[10, 0, 0, s]);
        f[14 + 16..14 + 20].copy_from_slice(&[10, 0, 0, d]);
        let t = 14 + 20;
        f[t..t + 2].copy_from_slice(&sp.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&dp.to_be_bytes());
        f[t + 12] = 5 << 4; // data offset
        f
    }
}
