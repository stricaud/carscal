//! Find packet — by text or by a hex byte pattern (`hex:DE AD BE EF`).
//!
//! Text matches the Info column (case-insensitive) or the raw frame bytes as
//! ASCII; a hex needle matches the raw frame bytes.

use crate::dissect;
use crate::model::Capture;

/// A compiled search needle.
pub enum Needle {
    Text(String),
    Hex(Vec<u8>),
}

impl Needle {
    /// Parse a query. `hex:` prefix → byte pattern; otherwise plain text.
    /// Returns `None` for an empty/invalid query.
    pub fn parse(q: &str) -> Option<Needle> {
        let q = q.trim();
        if let Some(rest) = q.strip_prefix("hex:") {
            let bytes = parse_hex(rest)?;
            if bytes.is_empty() {
                None
            } else {
                Some(Needle::Hex(bytes))
            }
        } else if q.is_empty() {
            None
        } else {
            Some(Needle::Text(q.to_string()))
        }
    }

    fn matches(&self, data: &[u8], info: &str) -> bool {
        match self {
            Needle::Text(t) => {
                let tl = t.to_lowercase();
                info.to_lowercase().contains(&tl) || contains(data, t.as_bytes())
            }
            Needle::Hex(h) => contains(data, h),
        }
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let b = cleaned.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Info column of a packet, without touching the summary cache.
fn info_of(cap: &Capture, i: usize) -> String {
    dissect::dissect(&cap.pkts[i]).map(|d| d.info().to_string()).unwrap_or_default()
}

/// Find the next packet index matching `needle`, starting the search *after*
/// `from` (or before it, when `forward` is false). Wraps around. Returns the
/// matching index, or `None` if nothing matches anywhere.
pub fn find(cap: &Capture, from: usize, needle: &Needle, forward: bool) -> Option<usize> {
    let n = cap.pkts.len();
    if n == 0 {
        return None;
    }
    for step in 1..=n {
        let i = if forward {
            (from + step) % n
        } else {
            (from + n - (step % n)) % n
        };
        if needle.matches(&cap.pkts[i].data, &info_of(cap, i)) {
            return Some(i);
        }
    }
    None
}

/// Every packet index matching `needle` (used by the headless `--find`).
pub fn find_all(cap: &Capture, needle: &Needle) -> Vec<usize> {
    let mut out = Vec::new();
    for i in 0..cap.pkts.len() {
        if needle.matches(&cap.pkts[i].data, &info_of(cap, i)) {
            out.push(i);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("DE AD BE EF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(parse_hex("de:ad"), Some(vec![0xde, 0xad]));
        assert_eq!(parse_hex("odd"), None);
    }

    #[test]
    fn needle_parse() {
        assert!(matches!(Needle::parse("hex:ff ff"), Some(Needle::Hex(_))));
        assert!(matches!(Needle::parse("dns"), Some(Needle::Text(_))));
        assert!(Needle::parse("").is_none());
    }

    #[test]
    fn byte_search() {
        assert!(contains(b"hello world", b"o w"));
        assert!(!contains(b"abc", b"xyz"));
    }
}
