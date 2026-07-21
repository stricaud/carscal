//! Decode As… — apply a `.posa` decoder to packets, either by a transport port
//! or by an arbitrary Wireshark-style condition.
//!
//! Two mechanisms:
//!
//! * **Port binding** ([`apply_spec`]) — for a plain `<tcp|udp> <port> <Proto>`,
//!   carscal registers a standalone libpcapng `rule` line; the library's
//!   dissector then applies it. No condition logic in carscal.
//!
//! * **Conditional rules** ([`add_rule`]) — for anything a port can't express
//!   (`tcp.port == 8080 && ip.src == 10.0.0.0/8 => HTTP_REQUEST`), carscal
//!   evaluates the condition with its own display-filter engine (which supports
//!   `&&` `||` `!` and parentheses) and, on a match, asks **libpcapng** to decode
//!   the transport payload (`pcapng_posa_dissect`) and attach the subtree. The
//!   library still does the decoding — carscal only decides when and where.

use crate::filter::Filter;
use crate::model::Packet;
use libpcapng::Dissection;
use std::ffi::CString;
use std::sync::RwLock;

/// A conditional decode rule: when `cond` matches a packet, decode its transport
/// payload as `decoder`.
struct DecodeRule {
    cond: Filter,
    decoder: String,
}

static DECODE_RULES: RwLock<Vec<DecodeRule>> = RwLock::new(Vec::new());

/// Register a conditional rule `"<display-filter condition> => <Decoder>"`.
/// The condition may use the full display-filter grammar (`&&`, `||`, `!`, `()`).
pub fn add_rule(spec: &str) -> Result<(), String> {
    let (cond_text, decoder) = spec
        .split_once("=>")
        .ok_or_else(|| format!("decode rule needs `<condition> => <Decoder>`, got {spec:?}"))?;
    let cond_text = cond_text.trim().to_string();
    let decoder = decoder.trim().to_string();
    if cond_text.is_empty() || decoder.is_empty() {
        return Err(format!("empty condition or decoder in {spec:?}"));
    }
    let cond = Filter::compile(&cond_text).map_err(|e| format!("bad condition: {e}"))?;
    DECODE_RULES.write().unwrap().push(DecodeRule { cond, decoder });
    Ok(())
}

/// Load a `decoders.rules` file: one `<condition> => <Decoder>` per line
/// (`#` comments allowed). Returns the number of rules added.
pub fn load_rules_file(path: &str) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let mut n = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if add_rule(line).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

/// The decoder name of the first conditional rule matching this dissection, if
/// any (used to label the Protocol column, since libpcapng computes the summary
/// before carscal attaches the rule's subtree).
pub fn matched_decoder(d: &Dissection) -> Option<String> {
    let rules = DECODE_RULES.read().unwrap();
    if rules.is_empty() {
        return None;
    }
    let root = d.root();
    rules.iter().find(|r| r.cond.eval(&root)).map(|r| r.decoder.clone())
}

/// Apply the first matching conditional rule to a freshly-dissected packet,
/// attaching the decoder's subtree to the dissection tree. No-op when no rule
/// matches or the packet has no TCP/UDP payload.
pub fn apply_rules(d: &Dissection, pkt: &Packet) {
    let rules = DECODE_RULES.read().unwrap();
    if rules.is_empty() {
        return;
    }
    let root = d.root();
    let rule = match rules.iter().find(|r| r.cond.eval(&root)) {
        Some(r) => r,
        None => return,
    };
    let l4 = match crate::l4::locate(&pkt.data, pkt.linktype) {
        Some(l) if l.payload_len > 0 => l,
        _ => return,
    };
    let payload = &pkt.data[l4.payload_off..l4.payload_off + l4.payload_len];
    let cname = match CString::new(rule.decoder.as_str()) {
        Ok(c) => c,
        Err(_) => return,
    };
    // libpcapng decodes the payload and attaches the subtree to the dissection
    // root at the payload's absolute offset (so field↔byte highlighting works).
    unsafe {
        libpcapng::ffi::pcapng_posa_dissect(
            cname.as_ptr(),
            payload.as_ptr(),
            payload.len() as i32,
            d.root_ptr(),
            l4.payload_off as i32,
            std::ptr::null_mut(),
            0,
        );
    }
}

/// Apply a Decode-As spec of the form `"<tcp|udp> <port> <Proto>"`.
///
/// `<Proto>` must be a loaded posa protocol (an `Object<…>` dispatcher or a
/// concrete one). Returns an error describing a malformed spec or unknown proto.
pub fn apply_spec(spec: &str) -> Result<(), String> {
    let parts: Vec<&str> = spec.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!(
            "bad decode-as spec {spec:?} — expected \"<tcp|udp> <port> <Proto>\""
        ));
    }
    let l4 = parts[0].to_ascii_lowercase();
    if l4 != "tcp" && l4 != "udp" {
        return Err(format!("decode-as transport must be tcp or udp, got {:?}", parts[0]));
    }
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| format!("decode-as port must be 0..65535, got {:?}", parts[1]))?;
    let proto = parts[2];
    // Note: we can't strictly validate `proto` here — an `Object<…>` group name
    // (e.g. "TFTP") is a valid decode target but isn't enumerated by
    // posa::protocols(). The dissector ignores a binding to a truly-unknown
    // name, so a typo simply leaves the packet undecoded (as in Wireshark).
    // A standalone rule line binds the port; libpcapng's dissector consults it.
    let rule = format!("rule {l4}.port == {port} => {proto}\n");
    libpcapng::posa::load_text(&rule).map(|_| ()).map_err(|e| e.to_string())
}
