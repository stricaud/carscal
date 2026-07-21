//! Load a capture file into a [`Capture`].
//!
//! pcapng is read via libpcapng's friendly packet reader; classic `.pcap` via a
//! small built-in reader (both byte orders, µs and ns timestamps).

use crate::model::{Capture, Packet};
use std::path::Path;

/// Load a capture file (pcapng or classic pcap), autodetecting the format.
pub fn load(path: &str) -> Result<Capture, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if bytes.len() < 4 {
        return Err(format!("{path}: file too short"));
    }
    let magic = &bytes[0..4];
    let mut cap = Capture { path: path.to_string(), ..Default::default() };

    // pcapng section header block magic: 0x0A0D0D0A.
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        load_pcapng(path, &mut cap)?;
        return Ok(cap);
    }
    // classic pcap magics (both endians, µs and ns).
    let m = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if matches!(m, 0xa1b2_c3d4 | 0xd4c3_b2a1 | 0xa1b2_3c4d | 0x4d3c_b2a1) {
        load_pcap(&bytes, &mut cap)?;
        return Ok(cap);
    }
    Err(format!("{path}: not a pcap or pcapng file"))
}

fn load_pcapng(path: &str, cap: &mut Capture) -> Result<(), String> {
    let path = Path::new(path).to_path_buf();
    libpcapng::read_packets(&path, |pkt| {
        let mut p = Packet::new(pkt.data.to_vec(), pkt.origlen, pkt.timestamp_us, pkt.linktype, 0);
        p.custom_pen = pkt.custom_pen;
        cap.push(p);
        true
    })
    .map_err(|e| format!("{}: {e}", path.display()))
}

fn load_pcap(bytes: &[u8], cap: &mut Capture) -> Result<(), String> {
    if bytes.len() < 24 {
        return Err("truncated pcap header".into());
    }
    let m = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // Byte order + timestamp resolution from the magic.
    let (little, nanos) = match m {
        0xa1b2_c3d4 => (true, false),
        0xd4c3_b2a1 => (false, false),
        0xa1b2_3c4d => (true, true),
        0x4d3c_b2a1 => (false, true),
        _ => return Err("unknown pcap magic".into()),
    };
    let rd32 = |b: &[u8]| {
        if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    // Global header: linktype is the last u32 (offset 20).
    let linktype = (rd32(&bytes[20..24]) & 0xffff) as u16;

    let mut off = 24usize;
    while off + 16 <= bytes.len() {
        let ts_sec = rd32(&bytes[off..off + 4]) as u64;
        let ts_frac = rd32(&bytes[off + 4..off + 8]) as u64;
        let caplen = rd32(&bytes[off + 8..off + 12]) as usize;
        let origlen = rd32(&bytes[off + 12..off + 16]);
        off += 16;
        if off + caplen > bytes.len() {
            break; // truncated final record
        }
        let ts_us = ts_sec * 1_000_000 + if nanos { ts_frac / 1000 } else { ts_frac };
        cap.push(Packet::new(bytes[off..off + caplen].to_vec(), origlen, ts_us, linktype, 0));
        off += caplen;
    }
    Ok(())
}
