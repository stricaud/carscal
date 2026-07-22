//! HTTP / SMB object (file) extraction — the engine behind "Export Objects".
//!
//! Reassembles TCP streams from a capture and carves out transferred files via
//! libpcapng's [`ObjectExtractor`]. Used by the `--export-objects` command and
//! the File ▸ Export … Objects menu items.

use crate::model::Capture;
use libpcapng::{Object, ObjectExtractor, ObjectProto};
use std::path::Path;

/// Parse a protocol name (`"http"` / `"smb"`).
pub fn proto_from_str(s: &str) -> Option<ObjectProto> {
    match s.to_ascii_lowercase().as_str() {
        "http" => Some(ObjectProto::Http),
        "smb" => Some(ObjectProto::Smb),
        _ => None,
    }
}

/// Extract all `proto` objects from a capture, in capture order.
pub fn extract(cap: &Capture, proto: ObjectProto) -> Vec<Object> {
    let mut ex = ObjectExtractor::new(proto);
    for p in &cap.pkts {
        ex.add_packet(p.number as i32, &p.data, p.linktype);
    }
    ex.finish();
    ex.objects()
}

/// A filesystem-safe, unique name for object `i` (falls back to `frame-N`).
pub fn safe_name(o: &Object, i: usize) -> String {
    let base = o.filename.rsplit(['/', '\\']).next().unwrap_or("").trim();
    let base = if base.is_empty() {
        format!("frame-{}", o.frame)
    } else {
        base.to_string()
    };
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || ".-_".contains(c) { c } else { '_' })
        .collect();
    format!("{i:03}_{cleaned}")
}

/// Write every object into `dir` (created if needed). Returns the count written.
pub fn save_all(objs: &[Object], dir: &Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(dir)?;
    for (i, o) in objs.iter().enumerate() {
        std::fs::write(dir.join(safe_name(o, i)), &o.data)?;
    }
    Ok(objs.len())
}
