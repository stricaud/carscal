//! Core data model, in Wireshark terms.
//!
//! A [`Capture`] is a list of [`Packet`]s (raw bytes + metadata + a lazily
//! computed summary). Dissecting a packet yields a field tree
//! ([`libpcapng::Dissection`]); the display filter (see [`crate::filter`])
//! evaluates against that tree.

/// One captured packet.
#[derive(Clone)]
pub struct Packet {
    /// Captured frame bytes (owned).
    pub data: Vec<u8>,
    /// Original on-wire length (>= `data.len()` if snapped short).
    pub origlen: u32,
    /// Timestamp, microseconds since the Unix epoch (0 if unknown).
    pub ts_us: u64,
    /// pcap/pcapng `LINKTYPE_*`.
    pub linktype: u16,
    /// 1-based position in the capture (the "No." column).
    pub number: u64,
    /// User mark (`m` in the UI); overrides coloring.
    pub marked: bool,
    /// `Some(pen)` if this is a pcapng Custom Block (not a captured frame): its
    /// Private Enterprise Number. Such blocks are skipped when saving.
    pub custom_pen: Option<u32>,
    /// Cached summary columns, filled on first display.
    pub summary: Option<Summary>,
}

impl Packet {
    pub fn new(data: Vec<u8>, origlen: u32, ts_us: u64, linktype: u16, number: u64) -> Packet {
        Packet {
            data,
            origlen,
            ts_us,
            linktype,
            number,
            marked: false,
            custom_pen: None,
            summary: None,
        }
    }
}

/// The Wireshark-style summary columns for a packet.
#[derive(Clone, Default)]
pub struct Summary {
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub info: String,
}

/// A loaded capture.
#[derive(Default)]
pub struct Capture {
    pub pkts: Vec<Packet>,
    /// Timestamp of the first packet, for the relative-time column.
    pub first_ts_us: u64,
    /// Source path (or a description for live captures).
    pub path: String,
}

impl Capture {
    pub fn len(&self) -> usize {
        self.pkts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pkts.is_empty()
    }

    /// Append a packet, assigning its 1-based number and tracking `first_ts_us`.
    pub fn push(&mut self, mut pkt: Packet) -> usize {
        if self.pkts.is_empty() {
            self.first_ts_us = pkt.ts_us;
        }
        pkt.number = self.pkts.len() as u64 + 1;
        self.pkts.push(pkt);
        self.pkts.len() - 1
    }
}

/// Common LINKTYPE values understood by the dissector. A small reference set;
/// not every one is referenced today.
#[allow(dead_code)]
pub mod linktype {
    pub const NULL: u16 = 0;
    pub const ETHERNET: u16 = 1;
    pub const RAW: u16 = 101;
    pub const LINUX_SLL: u16 = 113;
    pub const IPV4: u16 = 228;
    pub const IPV6: u16 = 229;
}
