//! Locate and load `.posa` decoders at startup.
//!
//! Search order (later wins on name clash, since redefining replaces):
//!   1. the bundled `protos/` dir next to the executable / in the source tree
//!   2. `$CARCAL_PROTOS_DIR` (compatible with carcal's env var)
//!   3. `$CARSCAL_PROTOS_DIR`

use std::path::PathBuf;

/// Load every `.posa` decoder we can find. Returns the number of protocols added.
pub fn load_all() -> i32 {
    let mut total = 0;
    for dir in candidate_dirs() {
        if dir.is_dir() {
            let n = libpcapng::posa::load_dir(&dir);
            if n > 0 {
                total += n;
            }
        }
    }
    total
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
