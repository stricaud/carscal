//! Locate the transport (TCP/UDP) header + payload within a raw frame.
//!
//! A small, self-contained parser (Ethernet/802.1Q → IPv4/IPv6 → TCP/UDP) used
//! by stream reassembly and conversation filtering. Mirrors carcal's
//! `carcal_locate_l4`. IPv6 extension headers are not walked (payload is taken
//! at a fixed 40-byte IPv6 header — good enough for the common case).

use crate::model::linktype as lt;

/// A located transport segment.
pub struct L4 {
    /// IP protocol number: 6 = TCP, 17 = UDP.
    pub proto: u8,
    /// Source / destination IP, formatted for display.
    pub src_ip: String,
    pub dst_ip: String,
    /// Canonical IP bytes (4 or 16) for conversation keys.
    pub src_ip_raw: Vec<u8>,
    pub dst_ip_raw: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP sequence number (0 for UDP).
    pub seq: u32,
    /// TCP flags (0 for UDP).
    pub flags: u8,
    /// Absolute offset + length of the L4 payload within the frame.
    pub payload_off: usize,
    pub payload_len: usize,
}

fn fmt_ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn fmt_ipv6(b: &[u8]) -> String {
    let mut groups = [0u16; 8];
    for (i, g) in groups.iter_mut().enumerate() {
        *g = u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
    }
    // Minimal (non-canonical) formatting; adequate for display/keys.
    groups.iter().map(|g| format!("{g:x}")).collect::<Vec<_>>().join(":")
}

/// Find the IP header offset for a given link type, returning `(ip_off, is_v6)`.
fn ip_offset(frame: &[u8], linktype: u16) -> Option<(usize, bool)> {
    match linktype {
        lt::ETHERNET => {
            if frame.len() < 14 {
                return None;
            }
            let mut off = 12;
            let mut et = u16::from_be_bytes([frame[off], frame[off + 1]]);
            off += 2;
            // Walk 802.1Q/802.1ad VLAN tags.
            while et == 0x8100 || et == 0x88a8 {
                if off + 4 > frame.len() {
                    return None;
                }
                et = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
                off += 4;
            }
            match et {
                0x0800 => Some((off, false)),
                0x86dd => Some((off, true)),
                _ => None,
            }
        }
        lt::RAW | lt::IPV4 | lt::IPV6 => {
            let b0 = *frame.first()?;
            let v6 = (b0 >> 4) == 6 || linktype == lt::IPV6;
            Some((0, v6))
        }
        lt::NULL => {
            // BSD loopback: 4-byte AF header; 2 = AF_INET.
            if frame.len() < 4 {
                return None;
            }
            Some((4, frame.get(0).copied().unwrap_or(0) != 2))
        }
        _ => None,
    }
}

/// Locate the transport segment in `frame`, or `None` if not TCP/UDP over IP.
pub fn locate(frame: &[u8], linktype: u16) -> Option<L4> {
    let (ip_off, v6) = ip_offset(frame, linktype)?;

    let (proto, src_ip, dst_ip, src_raw, dst_raw, l4_off) = if !v6 {
        if frame.len() < ip_off + 20 {
            return None;
        }
        let ihl = (frame[ip_off] & 0x0f) as usize * 4;
        if ihl < 20 || frame.len() < ip_off + ihl {
            return None;
        }
        let proto = frame[ip_off + 9];
        let src = &frame[ip_off + 12..ip_off + 16];
        let dst = &frame[ip_off + 16..ip_off + 20];
        (proto, fmt_ipv4(src), fmt_ipv4(dst), src.to_vec(), dst.to_vec(), ip_off + ihl)
    } else {
        if frame.len() < ip_off + 40 {
            return None;
        }
        let proto = frame[ip_off + 6];
        let src = &frame[ip_off + 8..ip_off + 24];
        let dst = &frame[ip_off + 24..ip_off + 40];
        (proto, fmt_ipv6(src), fmt_ipv6(dst), src.to_vec(), dst.to_vec(), ip_off + 40)
    };

    match proto {
        6 => {
            if frame.len() < l4_off + 20 {
                return None;
            }
            let sport = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
            let dport = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
            let seq = u32::from_be_bytes([
                frame[l4_off + 4],
                frame[l4_off + 5],
                frame[l4_off + 6],
                frame[l4_off + 7],
            ]);
            let data_off = ((frame[l4_off + 12] >> 4) as usize) * 4;
            let flags = frame[l4_off + 13];
            let payoff = l4_off + data_off.max(20);
            let paylen = frame.len().saturating_sub(payoff);
            Some(L4 {
                proto: 6,
                src_ip,
                dst_ip,
                src_ip_raw: src_raw,
                dst_ip_raw: dst_raw,
                src_port: sport,
                dst_port: dport,
                seq,
                flags,
                payload_off: payoff,
                payload_len: paylen,
            })
        }
        17 => {
            if frame.len() < l4_off + 8 {
                return None;
            }
            let sport = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
            let dport = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
            let payoff = l4_off + 8;
            let paylen = frame.len().saturating_sub(payoff);
            Some(L4 {
                proto: 17,
                src_ip,
                dst_ip,
                src_ip_raw: src_raw,
                dst_ip_raw: dst_raw,
                src_port: sport,
                dst_port: dport,
                seq: 0,
                flags: 0,
                payload_off: payoff,
                payload_len: paylen,
            })
        }
        _ => None,
    }
}
