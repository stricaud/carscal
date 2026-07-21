//! bytes → field tree, and the cheap summary columns.
//!
//! The heavy lifting is libpcapng's shared dissection engine (`pcapng_dissect`);
//! this module just wraps it in carscal's model and fills the summary columns.
//! Registered `.posa` decoders participate automatically for any port /
//! ethertype / ip-proto they bind with a `rule` line.

use crate::model::{Packet, Summary};
use libpcapng::{Dissection, Field, FieldType};

/// Dissect a packet into its field tree, or `None` on allocation failure.
///
/// After the built-in/port-bound dissection, any matching conditional
/// Decode-As rule ([`crate::decode`]) is applied, attaching its decoder's
/// subtree — so the extra fields show in the detail tree and are usable in
/// filters, just like natively-decoded ones.
pub fn dissect(pkt: &Packet) -> Option<Dissection> {
    let d = Dissection::new(&pkt.data, pkt.linktype)?;
    crate::decode::apply_rules(&d, pkt);
    Some(d)
}

/// Compute (or reuse) a packet's summary columns.
pub fn summarize(pkt: &mut Packet) -> Summary {
    if let Some(s) = &pkt.summary {
        return s.clone();
    }
    let s = match dissect(pkt) {
        Some(d) => {
            let mut s = Summary {
                proto: d.proto().to_string(),
                src: d.src().to_string(),
                dst: d.dst().to_string(),
                info: d.info().to_string(),
            };
            // A conditional Decode-As rule attaches its subtree after libpcapng
            // computes the summary, so reflect it in the Protocol column.
            if let Some(dec) = crate::decode::matched_decoder(&d) {
                s.proto = dec;
            }
            // A pcapng Custom Block: label it and note its PEN. Its payload is
            // still dissected above, so a custom-wrapped frame decodes normally.
            if let Some(pen) = pkt.custom_pen {
                if s.proto.is_empty() {
                    s.proto = "Custom".into();
                }
                s.info = if s.info.is_empty() {
                    format!("Custom Block (PEN {pen}, {} bytes)", pkt.data.len())
                } else {
                    format!("[Custom PEN {pen}] {}", s.info)
                };
            }
            s
        }
        None => Summary::default(),
    };
    pkt.summary = Some(s.clone());
    s
}

/// The printable value of a field, for an "Apply as Column" cell.
pub fn field_value(f: &Field) -> String {
    match f.ftype() {
        FieldType::Uint => f.uint().to_string(),
        FieldType::Str | FieldType::Ipv4 | FieldType::Ipv6 | FieldType::Mac => {
            f.str_value().to_string()
        }
        FieldType::Bytes => f
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(""),
        FieldType::None => String::new(),
    }
}

/// Render a field as a display-filter expression (`ip.src == 10.0.0.1`), the
/// primitive behind Apply-as-Filter / Apply-as-Column / coloring. Returns `None`
/// for a structural row that can't be expressed.
pub fn field_filter_expr(f: &Field) -> Option<String> {
    let abbrev = f.abbrev();
    if abbrev.is_empty() {
        return None;
    }
    let expr = match f.ftype() {
        FieldType::Uint => format!("{abbrev} == {}", f.uint()),
        FieldType::Ipv4 | FieldType::Mac => format!("{abbrev} == {}", f.str_value()),
        FieldType::Str | FieldType::Ipv6 => format!("{abbrev} == \"{}\"", f.str_value()),
        FieldType::Bytes | FieldType::None => return None,
    };
    Some(expr)
}
