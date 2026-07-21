//! A Wireshark/tshark-compatible display-filter engine.
//!
//! A faithful Rust port of carcal's `filter.c`, evaluating against a
//! [`libpcapng::Field`] tree. Supported:
//!   - field existence:  `tcp`   `ip.addr`   `dns.qry.name`
//!   - comparisons:      `ip.src == 10.0.0.1`   `tcp.port != 80`   `ip.ttl >= 64`
//!     operators:        `==` `eq`  `!=` `ne`  `>` `gt`  `<` `lt`  `>=` `ge`
//!                       `<=` `le`  `contains`  `matches` (substring)
//!   - boolean logic:    `&&` `and`   `||` `or`   `!` `not`   `( )`
//!   - value forms:      decimal / `0xHEX`, `"quoted"`, `1.2.3.4[/cidr]`,
//!                       `aa:bb:cc:dd:ee:ff`
//!   - field aliases:    `ip.addr`→{`ip.src`,`ip.dst`}, `tcp.port`→{srcport,dstport},
//!                       `udp.port`, `eth.addr`, `ipv6.addr` (Wireshark "any" match)

use libpcapng::{Field, FieldType};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    Matches,
}

#[derive(Debug)]
enum Node {
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Exists(String),
    Cmp { field: String, op: Op, value: String },
}

/// A compiled display filter.
pub struct Filter {
    root: Option<Node>,
    match_all: bool,
}

impl Filter {
    /// Compile an expression. An empty/blank expression matches everything.
    pub fn compile(expr: &str) -> Result<Filter, String> {
        if expr.trim().is_empty() {
            return Ok(Filter { root: None, match_all: true });
        }
        let mut lx = Lexer::new(expr);
        lx.advance();
        let root = parse_or(&mut lx)?;
        if lx.cur.kind != Tok::Eof {
            return Err(lx.err.clone().unwrap_or_else(|| "syntax error".into()));
        }
        Ok(Filter { root: Some(root), match_all: false })
    }

    /// Whether this filter matches everything (empty expression).
    pub fn is_match_all(&self) -> bool {
        self.match_all
    }

    /// Evaluate against a dissection's root field.
    pub fn eval(&self, root: &Field) -> bool {
        if self.match_all {
            return true;
        }
        match &self.root {
            Some(n) => eval(n, root),
            None => true,
        }
    }
}

// ── lexer ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Word,
    Str,
    Lp,
    Rp,
    And,
    Or,
    Not,
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Eof,
}

#[derive(Clone)]
struct Token {
    kind: Tok,
    s: String,
}

struct Lexer<'a> {
    b: &'a [u8],
    i: usize,
    cur: Token,
    err: Option<String>,
}

fn word_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-' | b'/')
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Lexer<'a> {
        Lexer { b: s.as_bytes(), i: 0, cur: Token { kind: Tok::Eof, s: String::new() }, err: None }
    }

    fn advance(&mut self) {
        while self.i < self.b.len() && (self.b[self.i] == b' ' || self.b[self.i] == b'\t') {
            self.i += 1;
        }
        if self.i >= self.b.len() {
            self.cur = Token { kind: Tok::Eof, s: String::new() };
            return;
        }
        let c = self.b[self.i];
        let peek = |o: usize| self.b.get(self.i + o).copied();
        match c {
            b'(' => {
                self.i += 1;
                self.cur = Token { kind: Tok::Lp, s: String::new() };
                return;
            }
            b')' => {
                self.i += 1;
                self.cur = Token { kind: Tok::Rp, s: String::new() };
                return;
            }
            b'&' if peek(1) == Some(b'&') => {
                self.i += 2;
                self.cur = Token { kind: Tok::And, s: String::new() };
                return;
            }
            b'|' if peek(1) == Some(b'|') => {
                self.i += 2;
                self.cur = Token { kind: Tok::Or, s: String::new() };
                return;
            }
            b'=' if peek(1) == Some(b'=') => {
                self.i += 2;
                self.cur = Token { kind: Tok::Eq, s: String::new() };
                return;
            }
            b'!' if peek(1) == Some(b'=') => {
                self.i += 2;
                self.cur = Token { kind: Tok::Ne, s: String::new() };
                return;
            }
            b'!' => {
                self.i += 1;
                self.cur = Token { kind: Tok::Not, s: String::new() };
                return;
            }
            b'>' if peek(1) == Some(b'=') => {
                self.i += 2;
                self.cur = Token { kind: Tok::Ge, s: String::new() };
                return;
            }
            b'>' => {
                self.i += 1;
                self.cur = Token { kind: Tok::Gt, s: String::new() };
                return;
            }
            b'<' if peek(1) == Some(b'=') => {
                self.i += 2;
                self.cur = Token { kind: Tok::Le, s: String::new() };
                return;
            }
            b'<' => {
                self.i += 1;
                self.cur = Token { kind: Tok::Lt, s: String::new() };
                return;
            }
            b'"' => {
                self.i += 1;
                let start = self.i;
                while self.i < self.b.len() && self.b[self.i] != b'"' {
                    self.i += 1;
                }
                let s = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
                if self.i < self.b.len() {
                    self.i += 1; // closing quote
                }
                self.cur = Token { kind: Tok::Str, s };
                return;
            }
            _ => {}
        }
        if word_char(c) {
            let start = self.i;
            while self.i < self.b.len() && word_char(self.b[self.i]) {
                self.i += 1;
            }
            let s = String::from_utf8_lossy(&self.b[start..self.i]).into_owned();
            let kind = match s.as_str() {
                "and" | "AND" => Tok::And,
                "or" | "OR" => Tok::Or,
                "not" | "NOT" => Tok::Not,
                _ => Tok::Word,
            };
            self.cur = Token { kind, s };
            return;
        }
        // unknown char — skip it
        self.i += 1;
        self.advance();
    }
}

fn word_op(s: &str) -> Option<Op> {
    Some(match s {
        "eq" => Op::Eq,
        "ne" => Op::Ne,
        "gt" => Op::Gt,
        "lt" => Op::Lt,
        "ge" => Op::Ge,
        "le" => Op::Le,
        "contains" => Op::Contains,
        "matches" => Op::Matches,
        _ => return None,
    })
}

// ── parser (or > and > not > primary) ────────────────────────────────────────

fn parse_or(lx: &mut Lexer) -> Result<Node, String> {
    let mut left = parse_and(lx)?;
    while lx.cur.kind == Tok::Or {
        lx.advance();
        let right = parse_and(lx)?;
        left = Node::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(lx: &mut Lexer) -> Result<Node, String> {
    let mut left = parse_not(lx)?;
    while lx.cur.kind == Tok::And {
        lx.advance();
        let right = parse_not(lx)?;
        left = Node::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_not(lx: &mut Lexer) -> Result<Node, String> {
    if lx.cur.kind == Tok::Not {
        lx.advance();
        let a = parse_not(lx)?;
        return Ok(Node::Not(Box::new(a)));
    }
    parse_primary(lx)
}

fn parse_primary(lx: &mut Lexer) -> Result<Node, String> {
    if lx.cur.kind == Tok::Lp {
        lx.advance();
        let n = parse_or(lx)?;
        if lx.cur.kind != Tok::Rp {
            lx.err = Some("expected ')'".into());
            return Err("expected ')'".into());
        }
        lx.advance();
        return Ok(n);
    }
    if lx.cur.kind != Tok::Word {
        lx.err = Some("expected a field name".into());
        return Err("expected a field name".into());
    }
    let field = lx.cur.s.clone();
    lx.advance();

    let op = match lx.cur.kind {
        Tok::Eq => Some(Op::Eq),
        Tok::Ne => Some(Op::Ne),
        Tok::Gt => Some(Op::Gt),
        Tok::Lt => Some(Op::Lt),
        Tok::Ge => Some(Op::Ge),
        Tok::Le => Some(Op::Le),
        Tok::Word => word_op(&lx.cur.s),
        _ => None,
    };

    if let Some(op) = op {
        lx.advance();
        if lx.cur.kind != Tok::Word && lx.cur.kind != Tok::Str {
            lx.err = Some("expected a value after operator".into());
            return Err("expected a value after operator".into());
        }
        let value = lx.cur.s.clone();
        lx.advance();
        Ok(Node::Cmp { field, op, value })
    } else {
        Ok(Node::Exists(field))
    }
}

// ── aliases ──────────────────────────────────────────────────────────────────

fn aliases(field: &str) -> Vec<&'static str> {
    match field {
        "ip.addr" => vec!["ip.src", "ip.dst"],
        "ipv6.addr" => vec!["ipv6.src", "ipv6.dst"],
        "tcp.port" => vec!["tcp.srcport", "tcp.dstport"],
        "udp.port" => vec!["udp.srcport", "udp.dstport"],
        "eth.addr" => vec!["eth.src", "eth.dst"],
        _ => vec![],
    }
}

/// Collect all fields matching `field`, alias-expanded.
fn collect<'a>(root: &Field<'a>, field: &str) -> Vec<Field<'a>> {
    let al = aliases(field);
    if al.is_empty() {
        root.collect(field)
    } else {
        let mut out = Vec::new();
        for a in al {
            out.extend(root.collect(a));
        }
        out
    }
}

// ── value comparison ─────────────────────────────────────────────────────────

fn to_num(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

fn parse_ipv4(s: &str) -> Option<([u8; 4], u32)> {
    let (addr, cidr) = match s.split_once('/') {
        Some((a, c)) => (a, c.parse::<i32>().unwrap_or(32)),
        None => (s, 32),
    };
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u16>().ok().filter(|&v| v <= 255)? as u8;
    }
    Some((out, cidr.clamp(0, 32) as u32))
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

fn cmp_op(op: Op, c: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::*;
    match op {
        Op::Eq => c == Equal,
        Op::Ne => c != Equal,
        Op::Gt => c == Greater,
        Op::Lt => c == Less,
        Op::Ge => c != Less,
        Op::Le => c != Greater,
        _ => c == Equal,
    }
}

fn field_matches(f: &Field, op: Op, val: &str) -> bool {
    match f.ftype() {
        FieldType::Uint => {
            if op == Op::Contains || op == Op::Matches {
                return false;
            }
            cmp_op(op, f.uint().cmp(&to_num(val)))
        }
        FieldType::Ipv4 => {
            let (ip, cidr) = match parse_ipv4(val) {
                Some(v) => v,
                None => return false,
            };
            let fb = f.bytes();
            if fb.len() < 4 {
                return false;
            }
            if op == Op::Eq || op == Op::Ne {
                let a = u32::from_be_bytes([fb[0], fb[1], fb[2], fb[3]]);
                let b = u32::from_be_bytes(ip);
                let mask = if cidr == 0 {
                    0
                } else if cidr >= 32 {
                    0xffff_ffff
                } else {
                    !((1u32 << (32 - cidr)) - 1)
                };
                let eq = (a & mask) == (b & mask);
                return if op == Op::Eq { eq } else { !eq };
            }
            cmp_op(op, fb[..4].cmp(&ip[..]))
        }
        FieldType::Mac => {
            let m = match parse_mac(val) {
                Some(v) => v,
                None => return false,
            };
            let fb = f.bytes();
            if fb.len() < 6 {
                return false;
            }
            cmp_op(op, fb[..6].cmp(&m[..]))
        }
        FieldType::Str | FieldType::Ipv6 => {
            if op == Op::Contains || op == Op::Matches {
                f.str_value().contains(val)
            } else {
                cmp_op(op, f.str_value().cmp(val))
            }
        }
        FieldType::Bytes | FieldType::None => false,
    }
}

fn eval(n: &Node, root: &Field) -> bool {
    match n {
        Node::And(a, b) => eval(a, root) && eval(b, root),
        Node::Or(a, b) => eval(a, root) || eval(b, root),
        Node::Not(a) => !eval(a, root),
        Node::Exists(field) => !collect(root, field).is_empty(),
        Node::Cmp { field, op, value } => {
            // "any" semantics: pass if any matching field satisfies the op.
            collect(root, field).iter().any(|f| field_matches(f, *op, value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_empty_matches_all() {
        assert!(Filter::compile("").unwrap().is_match_all());
        assert!(Filter::compile("   ").unwrap().is_match_all());
    }

    #[test]
    fn compile_errors() {
        assert!(Filter::compile("ip.src ==").is_err());
        assert!(Filter::compile("(tcp").is_err());
        assert!(Filter::compile("== 5").is_err());
    }

    #[test]
    fn compile_ok() {
        for e in [
            "tcp",
            "ip.addr == 192.168.1.0/24",
            "tcp.port == 443 && ip.src != 10.0.0.1",
            "udp and dns.qry.name contains \"example\"",
            "icmp || arp",
            "tcp.flags == 0x12",
            "eth.src == aa:bb:cc:dd:ee:ff",
            "!(tcp.port == 80)",
        ] {
            assert!(Filter::compile(e).is_ok(), "should compile: {e}");
        }
    }

    #[test]
    fn number_parsing() {
        assert_eq!(to_num("0x12"), 18);
        assert_eq!(to_num("443"), 443);
    }

    #[test]
    fn ipv4_cidr() {
        assert_eq!(parse_ipv4("192.168.1.0/24"), Some(([192, 168, 1, 0], 24)));
        assert_eq!(parse_ipv4("10.0.0.1"), Some(([10, 0, 0, 1], 32)));
        assert!(parse_ipv4("999.0.0.1").is_none());
    }
}
