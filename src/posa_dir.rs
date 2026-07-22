//! Locate and load `.posa` decoders at startup.
//!
//! Search order (later wins on name clash, since redefining replaces):
//!   1. the bundled `protos/` dir next to the executable / in the source tree
//!   2. `$CARCAL_PROTOS_DIR` (compatible with carcal's env var)
//!   3. `$CARSCAL_PROTOS_DIR`

use std::path::PathBuf;

/// Load every `.posa` decoder we can find. Returns the number of protocols added.
/// Per-file load errors are reported to stderr.
pub fn load_all() -> i32 {
    load_all_reporting(false).protocols
}

/// The outcome of a decoder-loading pass.
pub struct LoadReport {
    pub protocols: i32,
    pub files_ok: i32,
    pub files_err: i32,
}

/// Load every `.posa` decoder from all candidate directories, one file at a time
/// so a broken file is named on stderr instead of silently skipped. With
/// `verbose`, also logs each directory scanned and each file loaded — used by
/// `--check-decoders` to test a decoder set without launching the UI.
pub fn load_all_reporting(verbose: bool) -> LoadReport {
    let mut r = LoadReport { protocols: 0, files_ok: 0, files_err: 0 };
    let mut seen = std::collections::HashSet::new();
    for dir in candidate_dirs() {
        if !dir.is_dir() {
            continue;
        }
        // Several candidates can resolve to the same directory (e.g. the exe's
        // ../protos and a relative "protos"); load each only once.
        let key = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if !seen.insert(key) {
            continue;
        }
        let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("posa")))
                .collect(),
            Err(e) => {
                eprintln!("carscal: cannot read decoder dir {}: {e}", dir.display());
                continue;
            }
        };
        files.sort();
        if verbose {
            eprintln!("carscal: scanning {} ({} .posa file{})", dir.display(), files.len(), if files.len() == 1 { "" } else { "s" });
        }
        for f in files {
            match libpcapng::posa::load_file(&f) {
                // A file may legitimately define 0 protocols (e.g. it only carries
                // coloring/display rules), so 0 is not an error.
                Ok(n) => {
                    r.protocols += n;
                    r.files_ok += 1;
                    if verbose {
                        eprintln!("  ok   {}  ({n} protocol{})", f.display(), if n == 1 { "" } else { "s" });
                    }
                }
                Err(e) => {
                    r.files_err += 1;
                    eprintln!("  FAIL {}: {e}", f.display());
                }
            }
        }
    }
    r
}

/// The user's `colorfilters` file (first found in a protos dir), if any.
pub fn colorfilters_file() -> Option<String> {
    named_file("colorfilters")
}

/// The user's `decoders.rules` file (conditional Decode-As rules), if any.
pub fn decoders_rules_file() -> Option<String> {
    named_file("decoders.rules")
}

fn named_file(name: &str) -> Option<String> {
    for dir in candidate_dirs() {
        let f = dir.join(name);
        if f.is_file() {
            return Some(f.to_string_lossy().into_owned());
        }
    }
    None
}

/// Locate a bundled asset (e.g. `about.png`) next to the binary or in the source
/// tree's `assets/` directory.
pub fn asset_file(name: &str) -> Option<String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(b) = exe.parent() {
            dirs.push(b.join("assets"));
            if let Some(u) = b.parent() {
                dirs.push(u.join("assets"));
                if let Some(u2) = u.parent() {
                    dirs.push(u2.join("assets"));
                }
            }
        }
    }
    dirs.push(PathBuf::from("assets"));
    for d in dirs {
        let f = d.join(name);
        if f.is_file() {
            return Some(f.to_string_lossy().into_owned());
        }
    }
    None
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Bundled protos next to the binary (…/bin/carscal -> …/protos) and the
    // dev tree (target/debug/carscal -> repo/protos).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bindir) = exe.parent() {
            dirs.push(bindir.join("protos"));
            if let Some(up) = bindir.parent() {
                dirs.push(up.join("protos"));
                if let Some(up2) = up.parent() {
                    dirs.push(up2.join("protos")); // repo/protos from target/debug/
                }
            }
        }
    }
    // Source tree fallback (running via `cargo run` from the repo root).
    dirs.push(PathBuf::from("protos"));

    // The user's personal decoders directory.
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            dirs.push(PathBuf::from(home).join(".carscal").join("decoders"));
        }
    }

    for var in ["CARCAL_PROTOS_DIR", "CARSCAL_PROTOS_DIR"] {
        if let Ok(d) = std::env::var(var) {
            if !d.is_empty() {
                dirs.push(PathBuf::from(d));
            }
        }
    }
    dirs
}
