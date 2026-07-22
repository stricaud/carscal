//! Tree models for the interactive Statistics windows — Protocol Hierarchy,
//! Conversations (NetFlow) and Entity Explorer — built as flat arenas so the
//! same [`ArenaModel`] drives gtcaca's tree widget for all three.

use crate::dissect;
use crate::l4;
use crate::model::Capture;
use gtcaca::TreeModel;
use std::ffi::c_void;

/// A flat arena of tree nodes. Node `i` has label `labels[i]` and children
/// `children[i]` (node indices); `roots` are the top-level nodes. `tag[i]`
/// carries an app id (e.g. a NetFlow flow index) or -1.
pub struct ArenaTree {
    labels: Vec<String>,
    children: Vec<Vec<usize>>,
    roots: Vec<usize>,
    tag: Vec<i64>,
}

impl ArenaTree {
    fn new() -> Self {
        ArenaTree { labels: Vec::new(), children: Vec::new(), roots: Vec::new(), tag: Vec::new() }
    }
    fn add(&mut self, label: String, tag: i64) -> usize {
        self.labels.push(label);
        self.children.push(Vec::new());
        self.tag.push(tag);
        self.labels.len() - 1
    }
    /// The app tag of a node handle, or -1.
    pub fn tag_of(&self, handle: *mut c_void) -> i64 {
        match Self::node(handle) {
            Some(i) if i < self.tag.len() => self.tag[i],
            _ => -1,
        }
    }
    fn node(handle: *mut c_void) -> Option<usize> {
        let h = handle as usize;
        if h == 0 { None } else { Some(h - 1) }
    }
    fn handle(i: usize) -> *mut c_void {
        (i + 1) as *mut c_void
    }
}

/// A [`TreeModel`] over a shared [`ArenaTree`].
pub struct ArenaModel(pub std::rc::Rc<ArenaTree>);

impl TreeModel for ArenaModel {
    fn child_count(&self, node: *mut c_void) -> i64 {
        match ArenaTree::node(node) {
            None => self.0.roots.len() as i64,
            Some(i) => self.0.children[i].len() as i64,
        }
    }
    fn child(&self, node: *mut c_void, index: i64) -> *mut c_void {
        let idx = index as usize;
        let child = match ArenaTree::node(node) {
            None => self.0.roots.get(idx).copied(),
            Some(i) => self.0.children.get(i).and_then(|c| c.get(idx)).copied(),
        };
        child.map(ArenaTree::handle).unwrap_or(std::ptr::null_mut())
    }
    fn has_children(&self, node: *mut c_void) -> bool {
        match ArenaTree::node(node) {
            None => !self.0.roots.is_empty(),
            Some(i) => !self.0.children[i].is_empty(),
        }
    }
    fn label(&self, node: *mut c_void) -> String {
        match ArenaTree::node(node) {
            None => String::new(),
            Some(i) => self.0.labels[i].clone(),
        }
    }
}

// ── Protocol Hierarchy ───────────────────────────────────────────────────────

/// Short protocol name for a dissection layer (e.g. "Internet Protocol v6").
fn layer_name(layer: &libpcapng::Field) -> String {
    let label = layer.label();
    let head = label.split(',').next().unwrap_or("").trim();
    if !head.is_empty() {
        // Trim a trailing "N bytes …" (the Frame layer) and cap the width.
        let n = head.find(" bytes").map(|_| "Frame").unwrap_or(head);
        return n.chars().take(28).collect();
    }
    for c in layer.children() {
        if let Some((p, _)) = c.abbrev().split_once('.') {
            return p.to_string();
        }
    }
    String::new()
}

/// A nested protocol tree (Frame ▸ Ethernet ▸ IP ▸ …) with per-node packet and
/// byte counts and a percentage of all packets, in the node labels.
pub fn build_proto_hierarchy(cap: &Capture) -> ArenaTree {
    struct N {
        name: String,
        pkts: u64,
        bytes: u64,
        kids: Vec<usize>,
    }
    let mut nodes: Vec<N> = Vec::new();
    let mut roots: Vec<usize> = Vec::new();

    for p in &cap.pkts {
        let Some(d) = dissect::dissect(p) else { continue };
        let mut parent: Option<usize> = None;
        for layer in d.root().children() {
            let name = layer_name(&layer);
            if name.is_empty() {
                continue;
            }
            let existing = match parent {
                None => roots.iter().find(|&&s| nodes[s].name == name).copied(),
                Some(pi) => nodes[pi].kids.iter().find(|&&s| nodes[s].name == name).copied(),
            };
            let idx = match existing {
                Some(i) => i,
                None => {
                    nodes.push(N { name: name.clone(), pkts: 0, bytes: 0, kids: Vec::new() });
                    let i = nodes.len() - 1;
                    match parent {
                        None => roots.push(i),
                        Some(pi) => nodes[pi].kids.push(i),
                    }
                    i
                }
            };
            nodes[idx].pkts += 1;
            nodes[idx].bytes += p.origlen as u64;
            parent = Some(idx);
        }
    }

    let total = cap.pkts.len().max(1) as u64;
    let mut t = ArenaTree::new();
    // Copy the nested `nodes` into the arena (same order → same indices).
    for n in &nodes {
        let pct = 100.0 * n.pkts as f64 / total as f64;
        t.add(
            format!("{:<28} {:>6} pk  {:>10} B  {:>3.0}%", n.name, n.pkts, n.bytes, pct),
            -1,
        );
    }
    for (i, n) in nodes.iter().enumerate() {
        t.children[i] = n.kids.clone();
    }
    t.roots = roots;
    t
}

// ── Conversations (NetFlow) + Entity Explorer ───────────────────────────────

struct Flow {
    proto: String,
    a: String, // "ip:port" (canonical, lower)
    b: String,
    rows: Vec<usize>, // row indices into the caller's `rows`
    bytes: u64,
}

fn endpoint(ip: &str, port: u16) -> String {
    if port == 0 {
        ip.to_string()
    } else if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

/// Aggregate the given rows into flows keyed by protocol + endpoint pair.
fn build_flows(cap: &Capture, rows: &[usize]) -> Vec<Flow> {
    use std::collections::HashMap;
    let mut map: HashMap<(String, String, String), usize> = HashMap::new();
    let mut flows: Vec<Flow> = Vec::new();
    for (row, &pi) in rows.iter().enumerate() {
        let p = &cap.pkts[pi];
        let (proto, mut ea, mut eb) = match l4::locate(&p.data, p.linktype) {
            Some(l) => {
                let proto = if l.proto == 6 { "TCP" } else { "UDP" }.to_string();
                (proto, endpoint(&l.src_ip, l.src_port), endpoint(&l.dst_ip, l.dst_port))
            }
            None => {
                let d = dissect::dissect(p);
                let (proto, src, dst) = d
                    .map(|d| (d.proto().to_string(), d.src().to_string(), d.dst().to_string()))
                    .unwrap_or_default();
                if src.is_empty() || dst.is_empty() {
                    continue;
                }
                (if proto.is_empty() { "?".into() } else { proto }, src, dst)
            }
        };
        if ea > eb {
            std::mem::swap(&mut ea, &mut eb);
        }
        let key = (proto.clone(), ea.clone(), eb.clone());
        let idx = *map.entry(key).or_insert_with(|| {
            flows.push(Flow { proto, a: ea, b: eb, rows: Vec::new(), bytes: 0 });
            flows.len() - 1
        });
        flows[idx].rows.push(row);
        flows[idx].bytes += p.origlen as u64;
    }
    flows
}

/// Host of an endpoint string (strips the `:port` / `[ipv6]:port`).
fn host_of(ep: &str) -> String {
    if let Some(inner) = ep.strip_prefix('[') {
        return inner.split(']').next().unwrap_or(ep).to_string();
    }
    match ep.rfind(':') {
        Some(i) if !ep[..i].contains(':') => ep[..i].to_string(),
        _ => ep.to_string(),
    }
}

/// Conversations tree: **Hosts ▸ Conversations**. Conversation nodes are tagged
/// with their flow index. Returns the tree plus each flow's row indices (for the
/// packet sub-table).
pub fn build_conversations(cap: &Capture, rows: &[usize]) -> (ArenaTree, Vec<Vec<usize>>) {
    let flows = build_flows(cap, rows);

    // Group flows by host.
    use std::collections::BTreeMap;
    let mut hosts: BTreeMap<String, (u64, Vec<usize>)> = BTreeMap::new(); // host -> (pkts, flow idxs)
    for (fi, f) in flows.iter().enumerate() {
        for ep in [&f.a, &f.b] {
            let h = host_of(ep);
            let e = hosts.entry(h).or_default();
            e.0 += f.rows.len() as u64;
            if !e.1.contains(&fi) {
                e.1.push(fi);
            }
        }
    }

    let mut t = ArenaTree::new();
    for (host, (npkts, flow_idxs)) in &hosts {
        let hnode = t.add(format!("{host}   ({npkts} pkts, {} flows)", flow_idxs.len()), -1);
        for &fi in flow_idxs {
            let f = &flows[fi];
            let other = if host_of(&f.a) == *host { &f.b } else { &f.a };
            let cnode = t.add(
                format!("{:<4} \u{2194} {:<28}  {} pkts  {} B", f.proto, other, f.rows.len(), f.bytes),
                fi as i64,
            );
            t.children[hnode].push(cnode);
        }
        t.roots.push(hnode);
    }
    let flow_rows: Vec<Vec<usize>> = flows.into_iter().map(|f| f.rows).collect();
    (t, flow_rows)
}

/// Entity Explorer tree: group by **service port**, each port ▸ its connections
/// (`proto  peer`). Mirrors carcal's connections view.
pub fn build_entity_explorer(cap: &Capture, rows: &[usize]) -> ArenaTree {
    let flows = build_flows(cap, rows);
    // Collect connections per port. A "port N" node lists flows whose lower
    // endpoint uses that port (typically the service side).
    use std::collections::BTreeMap;
    let mut ports: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
    let port_of = |ep: &str| -> u16 {
        ep.rsplit(':').next().and_then(|s| s.parse().ok()).unwrap_or(0)
    };
    for (fi, f) in flows.iter().enumerate() {
        // The "service" port is the smaller non-zero of the two endpoints.
        let svc = match (port_of(&f.a), port_of(&f.b)) {
            (0, 0) => 0,
            (0, p) | (p, 0) => p,
            (a, b) => a.min(b),
        };
        ports.entry(svc).or_default().push(fi);
    }

    let mut t = ArenaTree::new();
    for (port, flow_idxs) in &ports {
        let name = if *port == 0 { "no port".to_string() } else { format!("port {port}") };
        let pnode = t.add(format!("{name}   ({} connections)", flow_idxs.len()), -1);
        for &fi in flow_idxs {
            let f = &flows[fi];
            let cnode = t.add(format!("{:<4}  {} \u{2194} {}", f.proto, f.a, f.b), -1);
            t.children[pnode].push(cnode);
        }
        t.roots.push(pnode);
    }
    t
}
