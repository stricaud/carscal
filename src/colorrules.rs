//! Wireshark-style coloring rules for the packet list.
//!
//! An ordered list of `<display filter> => <fg> <bg>`; the **first** rule whose
//! filter matches a packet paints it (later rules are not consulted) — that's
//! why "bad TCP" sits above "TCP". A faithful port of carcal's `colorrules.c`.
//!
//! Rules are composed from three layers, most specific first:
//!   1. the user's `<protos dir>/colorfilters` file (overrides anything)
//!   2. `color …` lines declared inside the loaded `.posa` decoders
//!   3. the compiled-in defaults

use crate::filter::Filter;
use libpcapng::Field;
use std::path::Path;

// libcaca ANSI palette (mirrors `enum caca_color`).
pub mod caca {
    pub const BLACK: u8 = 0;
    pub const BLUE: u8 = 1;
    pub const GREEN: u8 = 2;
    pub const CYAN: u8 = 3;
    pub const RED: u8 = 4;
    pub const MAGENTA: u8 = 5;
    pub const BROWN: u8 = 6;
    pub const LIGHTGRAY: u8 = 7;
    pub const DARKGRAY: u8 = 8;
    pub const LIGHTBLUE: u8 = 9;
    pub const LIGHTGREEN: u8 = 10;
    pub const LIGHTCYAN: u8 = 11;
    pub const LIGHTRED: u8 = 12;
    pub const LIGHTMAGENTA: u8 = 13;
    pub const YELLOW: u8 = 14;
    pub const WHITE: u8 = 15;
    pub const DEFAULT: u8 = 16;
}

const NAMES: &[(&str, u8)] = &[
    ("black", caca::BLACK),
    ("blue", caca::BLUE),
    ("green", caca::GREEN),
    ("cyan", caca::CYAN),
    ("red", caca::RED),
    ("magenta", caca::MAGENTA),
    ("brown", caca::BROWN),
    ("lightgray", caca::LIGHTGRAY),
    ("darkgray", caca::DARKGRAY),
    ("lightblue", caca::LIGHTBLUE),
    ("lightgreen", caca::LIGHTGREEN),
    ("lightcyan", caca::LIGHTCYAN),
    ("lightred", caca::LIGHTRED),
    ("lightmagenta", caca::LIGHTMAGENTA),
    ("yellow", caca::YELLOW),
    ("white", caca::WHITE),
    ("default", caca::DEFAULT),
];

/// libcaca color code for a name (case-insensitive), or `None` if unknown.
pub fn color_by_name(s: &str) -> Option<u8> {
    let s = s.to_ascii_lowercase();
    NAMES.iter().find(|(n, _)| *n == s).map(|(_, v)| *v)
}

/// The canonical name for a color code.
pub fn color_name(v: u8) -> &'static str {
    NAMES.iter().find(|(_, c)| *c == v).map(|(n, _)| *n).unwrap_or("default")
}

struct Rule {
    expr: String,
    /// Compiled filter; `None` => the rule failed to compile and is disabled.
    cond: Option<Filter>,
    fg: u8,
    bg: u8,
}

/// The composed, ordered set of coloring rules.
pub struct ColorRules {
    rules: Vec<Rule>,
    enabled: bool,
}

impl Default for ColorRules {
    fn default() -> Self {
        ColorRules { rules: Vec::new(), enabled: true }
    }
}

impl ColorRules {
    pub fn new() -> ColorRules {
        ColorRules::default()
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }

    /// The rules as `(expr, fg, bg)` triples, for a viewer.
    pub fn list(&self) -> Vec<(String, u8, u8)> {
        self.rules.iter().map(|r| (r.expr.clone(), r.fg, r.bg)).collect()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Append a rule. A rule whose filter doesn't compile is kept but disabled,
    /// so a typo costs that one rule instead of silently vanishing.
    pub fn add(&mut self, expr: &str, fg: u8, bg: u8) {
        if expr.is_empty() {
            return;
        }
        let cond = Filter::compile(expr).ok();
        self.rules.push(Rule { expr: expr.to_string(), cond, fg, bg });
    }

    /// The compiled-in defaults: alarming things first, then chatty protocols,
    /// then the generic transports.
    pub fn add_defaults(&mut self) {
        use caca::*;
        self.add("tcp.flags.reset == 1", YELLOW, RED);
        self.add("icmp", BLACK, LIGHTMAGENTA);
        self.add("arp", BLACK, YELLOW);
        self.add("dns", WHITE, BLUE);
        self.add("http", BLACK, LIGHTGREEN);
        self.add("tcp.flags.syn == 1", BLACK, LIGHTCYAN);
        self.add("tcp", LIGHTGRAY, DEFAULT);
        self.add("udp", LIGHTBLUE, DEFAULT);
    }

    /// Import the `color …` lines declared by the loaded `.posa` decoders.
    /// Returns the number imported; unknown color names are skipped.
    pub fn add_from_posa(&mut self) -> usize {
        let mut n = 0;
        for (expr, fgs, bgs) in libpcapng::posa::colors() {
            if let (Some(fg), Some(bg)) = (color_by_name(&fgs), color_by_name(&bgs)) {
                if !expr.is_empty() {
                    self.add(&expr, fg, bg);
                    n += 1;
                }
            }
        }
        n
    }

    /// Load a `colorfilters` file (appending). Each non-comment line is
    /// `<display filter> <fg> <bg>`; the filter may contain spaces, so the last
    /// two tokens are the colors. Returns rules read, or `None` if absent.
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Option<usize> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Split off the last two whitespace tokens as fg/bg.
            let mut it = line.rsplitn(3, char::is_whitespace);
            let bgs = it.next().unwrap_or("");
            let fgs = it.next().unwrap_or("");
            let expr = it.next().unwrap_or("").trim();
            if expr.is_empty() {
                continue;
            }
            if let (Some(fg), Some(bg)) = (color_by_name(fgs), color_by_name(bgs)) {
                self.add(expr, fg, bg);
                n += 1;
            }
        }
        Some(n)
    }

    /// Compose the full rule set in first-match-wins order: user file, then the
    /// `.posa` decoders' own colors, then the compiled-in defaults. Call after
    /// the posa decoders are loaded.
    pub fn reload(&mut self, user_file: Option<&str>) {
        self.clear();
        if let Some(f) = user_file {
            if !f.is_empty() {
                self.load_file(f);
            }
        }
        self.add_from_posa();
        self.add_defaults();
    }

    /// The `(fg, bg)` of the first rule matching `root`, or `None`.
    pub fn match_row(&self, root: &Field) -> Option<(u8, u8)> {
        if !self.enabled {
            return None;
        }
        for r in &self.rules {
            if let Some(cond) = &r.cond {
                if cond.eval(root) {
                    return Some((r.fg, r.bg));
                }
            }
        }
        None
    }

    /// Iterate the rules as `(expr, fg, bg, enabled)` in consult order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u8, u8, bool)> {
        self.rules.iter().map(|r| (r.expr.as_str(), r.fg, r.bg, r.cond.is_some()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        assert_eq!(color_by_name("YELLOW"), Some(caca::YELLOW));
        assert_eq!(color_by_name("lightgray"), Some(caca::LIGHTGRAY));
        assert_eq!(color_by_name("nope"), None);
        assert_eq!(color_name(caca::RED), "red");
        assert_eq!(color_name(caca::DEFAULT), "default");
    }

    #[test]
    fn defaults_order_and_count() {
        let mut r = ColorRules::new();
        r.add_defaults();
        assert_eq!(r.count(), 8);
        // "bad TCP" (reset) must precede the generic "tcp".
        let exprs: Vec<&str> = r.iter().map(|(e, ..)| e).collect();
        let reset = exprs.iter().position(|e| e.contains("reset")).unwrap();
        let tcp = exprs.iter().position(|e| *e == "tcp").unwrap();
        assert!(reset < tcp);
    }

    #[test]
    fn disabled_returns_no_color() {
        let mut r = ColorRules::new();
        r.add_defaults();
        r.set_enabled(false);
        // We can't build a Field without a Dissection here; just check the gate.
        assert!(!r.is_enabled());
    }
}
