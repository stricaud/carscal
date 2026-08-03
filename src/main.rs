//! carscal — a terminal packet analyzer, a tiny Wireshark for the TUI.
//!
//! A Rust replica of [carcal](https://github.com/stricaud/carcal), built on the
//! `libpcapng` (pcapng I/O + dissection + `.posa` decoders) and `gtcaca`
//! (libcaca TUI widgets) binding crates.

mod colorrules;
mod decode;
mod dissect;
mod filter;
mod find;
mod l4;
mod model;
mod objects;
mod posa_dir;
mod script;
mod source;
mod statstree;
mod stats;
mod stream;
mod ui;

use filter::Filter;
use libpcapng::Field;
use model::Capture;

const USAGE: &str = "\
carscal — a terminal packet analyzer (a tiny Wireshark for the TUI)

USAGE:
    carscal <capture.pcapng>              open a capture in the TUI
    carscal --dump <capture> [filter]     headless: dissect to stdout and exit
    carscal --summary <capture> [filter]  headless: one line per packet (like tshark)
    carscal --list-protocols              list every loaded dissector: built-in
                                          C decoders + each .posa and its file
    carscal --check-decoders              load ~/.carscal/decoders/*.posa (+rules),
                                          report per-file errors, and exit
    carscal --colors [capture]            list coloring rules (and, with a
                                          capture, which rule paints each packet)
    carscal --follow <capture> <pkt#>     reassemble & print that packet's TCP/UDP
                                          conversation (Follow Stream)
    carscal --find <capture> <query>      list packets matching text or hex:DE AD..
    carscal --stats <what> <capture>      conv | endpoints | proto  (Statistics)
    carscal --export-objects <http|smb> <capture> [outdir]
                                          carve transferred files (Export Objects)
    carscal --interfaces                  list capture interfaces
    carscal -s <script.lua> -r <capture>  run a Lua script over the capture (MQS)
    carscal -i <interface>                capture live from an interface
    carscal --help                        show this help
    carscal -v, --version                 print the version and exit

OPTIONS (combine with any command or a capture file):
    -X \"<tcp|udp> <port> <Proto>\"          Decode As… — bind a port to a .posa
                                          decoder at load time (repeatable)
    -R \"<condition> => <Decoder>\"          conditional Decode As… — apply a decoder
                                          when a display filter matches, e.g.
                                          \"tcp.port==8080 && ip.src==10.0.0.1 => HTTP_REQUEST\"
                                          (full &&/||/! syntax; repeatable)
    -p <file.posa>                        load an extra .posa decoder (repeatable)

FILTER is a Wireshark/tshark-compatible display filter, e.g.:
    \"tcp.port == 443 && ip.src != 10.0.0.1\"
    \"udp and dns.qry.name contains example\"
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

fn run(args: &[String]) -> i32 {
    // `--version` answers from the crate metadata alone: no decoder loading.
    if matches!(args.first().map(String::as_str), Some("-v" | "--version")) {
        println!("carscal {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }

    // `--check-decoders` does its own verbose load and exits, so run it before
    // the silent startup load below (which would otherwise double-load).
    if matches!(args.first().map(String::as_str), Some("--check-decoders" | "--test-decoders")) {
        return cmd_check_decoders();
    }

    // Load bundled + user .posa decoders so they participate in dissection.
    // `--list-protocols` also wants to name the file each decoder came from, so
    // it asks the loader to record origins (an extra registry snapshot per file).
    if args.iter().any(|a| a == "--list-protocols" || a == "--protocols") {
        posa_dir::load_all_tracked();
    } else {
        posa_dir::load_all();
    }
    // Load any user conditional Decode-As rules (protos/decoders.rules).
    if let Some(f) = posa_dir::decoders_rules_file() {
        let _ = decode::load_rules_file(&f);
    }

    // Global options usable alongside any command / a capture file:
    //   -p <file.posa>          load an extra decoder (repeatable)
    //   -X "<tcp|udp> <port> <Proto>"   Decode As… at load time (repeatable)
    let mut rest: Vec<String> = Vec::new();
    let mut script_path: Option<String> = None;
    let mut read_path: Option<String> = None;
    let mut script_filter: Option<String> = None;
    let mut iface: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--script" => {
                script_path = args.get(i + 1).cloned();
                i += 1;
            }
            "-r" | "--read" => {
                read_path = args.get(i + 1).cloned();
                i += 1;
            }
            "-i" | "--interface" => {
                iface = args.get(i + 1).cloned();
                i += 1;
            }
            "-f" | "--filter" => {
                script_filter = args.get(i + 1).cloned();
                i += 1;
            }
            "-p" | "--posa" => {
                if let Some(f) = args.get(i + 1) {
                    if let Err(e) = posa_dir::load_extra(f) {
                        eprintln!("carscal: -p {f}: {e}");
                    }
                    i += 1;
                }
            }
            "-X" | "--decode-as" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Err(e) = decode::apply_spec(spec) {
                        eprintln!("carscal: {e}");
                    }
                    i += 1;
                }
            }
            "-R" | "--decode-rule" => {
                if let Some(spec) = args.get(i + 1) {
                    if let Err(e) = decode::add_rule(spec) {
                        eprintln!("carscal: {e}");
                    }
                    i += 1;
                }
            }
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    let args = &rest[..];

    // Interface listing (like `tcpdump -D`). Does not need privileges.
    if args.first().map(String::as_str) == Some("--interfaces")
        || args.first().map(String::as_str) == Some("-D")
    {
        return cmd_interfaces();
    }

    // Scripting mode (the generalized MQS): a script over a file (`-r`) or a
    // live interface (`-i`), optionally gated by a display filter (`-f`).
    if let Some(sp) = script_path {
        return cmd_script(&sp, read_path.as_deref(), iface.as_deref(), script_filter.as_deref());
    }

    // Live capture without a script → stream a summary to stdout (like tshark).
    if let Some(dev) = &iface {
        return cmd_live_summary(dev, script_filter.as_deref());
    }

    match args.first().map(String::as_str) {
        // No arguments: open an empty TUI (use F2 / ^O to open a capture),
        // exactly like carcal. Usage is shown only on explicit --help.
        None => match ui::run(model::Capture::default()) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("carscal: {e}");
                1
            }
        },
        Some("--help" | "-h") => {
            print!("{USAGE}");
            0
        }
        Some("-v" | "--version") => {
            println!("carscal {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("--list-protocols" | "--protocols") => {
            cmd_list_protocols();
            0
        }
        Some("--export-objects") => cmd_export_objects(&args[1..]),
        Some("--stats") => cmd_stats(&args[1..]),
        Some("--colors") => cmd_colors(&args[1..]),
        Some("--follow") => cmd_follow(&args[1..]),
        Some("--find") => cmd_find(&args[1..]),
        Some("--dump") => cmd_dump(&args[1..], true),
        Some("--summary") => cmd_dump(&args[1..], false),
        Some(flag) if flag.starts_with('-') => {
            eprintln!("carscal: unknown option '{flag}'\n");
            print!("{USAGE}");
            2
        }
        Some(path) => {
            // Default: open the file. The TUI is built in the `ui` module; until
            // it is wired in, fall back to a summary listing so the tool is
            // usable headless.
            match source::load(path) {
                Ok(cap) => match ui::run(cap) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("carscal: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("carscal: {e}");
                    1
                }
            }
        }
    }
}

/// `--check-decoders`: load every `.posa` decoder (and the conditional
/// `decoders.rules`) with verbose per-file reporting, print a summary, and exit
/// — without launching the UI. Exit status is non-zero if any file failed, so
/// it's usable as a CI/install check. Details + errors go to stderr; the summary
/// to stdout.
fn cmd_check_decoders() -> i32 {
    let r = posa_dir::load_all_reporting(true);
    let mut rule_err = false;
    if let Some(f) = posa_dir::decoders_rules_file() {
        match decode::load_rules_file(&f) {
            Ok(n) => eprintln!("  ok   {f}  ({n} decode rule{})", if n == 1 { "" } else { "s" }),
            Err(e) => {
                rule_err = true;
                eprintln!("  FAIL {f}: {e}");
            }
        }
    }
    println!(
        "{} protocols from {} file(s); {} file error(s)",
        r.protocols, r.files_ok, r.files_err
    );
    if r.files_err > 0 || rule_err { 1 } else { 0 }
}

/// `--export-objects <http|smb> <capture> [outdir]` — carve transferred files
/// (Wireshark's "Export Objects"). With an outdir the files are written there;
/// without one, the objects are just listed.
fn cmd_export_objects(args: &[String]) -> i32 {
    let proto = args.first().and_then(|s| objects::proto_from_str(s));
    let (proto, file) = match (proto, args.get(1)) {
        (Some(p), Some(f)) => (p, f),
        _ => {
            eprintln!("usage: carscal --export-objects <http|smb> <capture> [outdir]");
            return 2;
        }
    };
    let cap = match source::load(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };
    let objs = objects::extract(&cap, proto);
    match args.get(2) {
        Some(dir) => match objects::save_all(&objs, std::path::Path::new(dir)) {
            Ok(n) => {
                println!("wrote {n} object(s) to {dir}");
                0
            }
            Err(e) => {
                eprintln!("carscal: {e}");
                1
            }
        },
        None => {
            println!("{:>6}  {:<5} {:>10}  {:<5} {}", "frame", "proto", "bytes", "state", "name");
            for o in &objs {
                let name = if o.filename.is_empty() { &o.hostname } else { &o.filename };
                println!(
                    "{:>6}  {:<5} {:>10}  {:<5} {}",
                    o.frame,
                    o.proto,
                    o.data.len(),
                    if o.complete { "ok" } else { "part" },
                    name
                );
            }
            println!("{} object(s)", objs.len());
            0
        }
    }
}

/// `--list-protocols` — every dissector available to this build: the ones
/// compiled into libpcapng, then each `.posa` decoder with the file it came
/// from. A `.posa` decoder shadows a built-in of the same name (the engine
/// consults the posa registry first), so those are called out.
fn cmd_list_protocols() {
    let posa = libpcapng::posa::protocols();
    let origins = posa_dir::origins();
    let posa_names: std::collections::HashSet<&str> = posa.iter().map(String::as_str).collect();
    // One column width for both lists, so the sources line up throughout.
    let w = posa
        .iter()
        .map(|n| n.len())
        .chain(dissect::BUILTIN_PROTOCOLS.iter().map(|n| n.len()))
        .max()
        .unwrap_or(0);

    println!("Built-in dissectors ({}):", dissect::BUILTIN_PROTOCOLS.len());
    for name in dissect::BUILTIN_PROTOCOLS {
        match posa_names.contains(name).then(|| origins.get(*name)) {
            Some(Some(file)) => println!("  {name:<w$}  compiled in (overridden by {file})"),
            Some(None) => println!("  {name:<w$}  compiled in (overridden by a .posa decoder)"),
            None => println!("  {name:<w$}  compiled in"),
        }
    }

    println!("\n.posa decoders ({}):", posa.len());
    for name in &posa {
        match origins.get(name) {
            Some(file) => println!("  {name:<w$}  {file}"),
            None => println!("  {name}"),
        }
    }

    let files: std::collections::HashSet<&String> = origins.values().collect();
    println!(
        "\n{} dissector(s): {} built-in, {} from {} .posa file(s)",
        dissect::BUILTIN_PROTOCOLS.len() + posa.len(),
        dissect::BUILTIN_PROTOCOLS.len(),
        posa.len(),
        files.len()
    );
}

/// `--colors [capture]` — print the composed rules in consult order, and (if a
/// capture is given) which rule paints each packet. Coloring is otherwise only
/// observable by staring at a terminal, which makes a mistyped rule hard to debug.
fn cmd_colors(args: &[String]) -> i32 {
    let mut rules = colorrules::ColorRules::new();
    rules.reload(posa_dir::colorfilters_file().as_deref());

    println!("Coloring rules ({}), first match wins:", rules.count());
    for (i, (expr, fg, bg, ok)) in rules.iter().enumerate() {
        let flag = if ok { " " } else { "!" };
        println!(
            "  {flag}{i:>2}  {:<32}  {} / {}",
            expr,
            colorrules::color_name(fg),
            colorrules::color_name(bg)
        );
    }

    if let Some(path) = args.first() {
        let mut cap = match source::load(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("carscal: {e}");
                return 1;
            }
        };
        println!("\nPer-packet coloring for {path}:");
        for pkt in &mut cap.pkts {
            let d = match dissect::dissect(pkt) {
                Some(d) => d,
                None => continue,
            };
            let paint = match rules.match_row(&d.root()) {
                Some((fg, bg)) => {
                    format!("{} / {}", colorrules::color_name(fg), colorrules::color_name(bg))
                }
                None => "(default)".to_string(),
            };
            println!("  #{:<5} {:<8} {paint}", pkt.number, d.proto());
        }
    }
    0
}

/// `--stats <conv|endpoints|proto> <capture>` — print a statistics table.
fn cmd_stats(args: &[String]) -> i32 {
    let (what, path) = match (args.first(), args.get(1)) {
        (Some(w), Some(p)) => (w.as_str(), p),
        _ => {
            eprintln!("carscal: --stats needs <conv|endpoints|proto> <capture>");
            return 2;
        }
    };
    let cap = match source::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };
    match what {
        "conv" | "conversations" => {
            println!("{:<22} {:<22} {:>7} {:>10} {:>7} {:>7} {:>9}", "A", "B", "Packets", "Bytes", "A→B", "B→A", "Duration");
            for c in stats::conversations(&cap) {
                println!(
                    "{:<22} {:<22} {:>7} {:>10} {:>7} {:>7} {:>8.3}s  [{}]",
                    c.a, c.b, c.packets, c.bytes, c.a_to_b, c.b_to_a, c.duration(), c.proto
                );
            }
        }
        "endpoints" | "hosts" => {
            println!("{:<24} {:>8} {:>12}", "Endpoint", "Packets", "Bytes");
            for (ep, p, b) in stats::endpoints(&cap) {
                println!("{ep:<24} {p:>8} {b:>12}");
            }
        }
        "proto" | "protocols" | "hierarchy" => {
            println!("{:<12} {:>8} {:>12}", "Protocol", "Packets", "Bytes");
            for (name, p, b) in stats::protocol_hierarchy(&cap) {
                println!("{name:<12} {p:>8} {b:>12}");
            }
        }
        other => {
            eprintln!("carscal: unknown stats view '{other}' (want conv|endpoints|proto)");
            return 2;
        }
    }
    0
}

/// `--interfaces` / `-D` — list capture interfaces.
fn cmd_interfaces() -> i32 {
    match libpcapng::list_devices() {
        Ok(devs) => {
            let default = libpcapng::default_device();
            for d in devs {
                let star = if default.as_deref() == Some(d.name.as_str()) { "*" } else { " " };
                let lo = if d.loopback { " (loopback)" } else { "" };
                let desc = if d.description.is_empty() { String::new() } else { format!("  — {}", d.description) };
                println!(" {star} {}{lo}{desc}", d.name);
            }
            0
        }
        Err(e) => {
            eprintln!("carscal: {e}");
            1
        }
    }
}

/// `-s script.lua {-r capture | -i iface} [-f filter]` — run a Lua script (the
/// generalized MQS) over a capture file or a live interface. Decoded packets and
/// reassembled TCP streams are handed to the script's `packet()`/`stream()`.
fn cmd_script(script: &str, read: Option<&str>, iface: Option<&str>, filter: Option<&str>) -> i32 {
    let flt = match filter::Filter::compile(filter.unwrap_or("")) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("carscal: bad filter: {e}");
            return 2;
        }
    };
    let mut runner = match script::Runner::new(script, flt) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };

    if let Some(dev) = iface {
        // Live: feed each captured frame to the script until interrupted.
        return run_live(dev, filter, |data, lt, ts_us| runner.process(data, lt, ts_us))
            .map(|_| {
                let _ = runner.finish();
                0
            })
            .unwrap_or_else(|e| {
                eprintln!("carscal: {e}");
                1
            });
    }

    let path = match read {
        Some(p) => p,
        None => {
            eprintln!("carscal: -s needs a source: -r <file> or -i <interface>");
            return 2;
        }
    };
    let cap = match source::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };
    for pkt in &cap.pkts {
        if let Err(e) = runner.process(&pkt.data, pkt.linktype, pkt.ts_us) {
            eprintln!("carscal: {e}");
            return 1;
        }
    }
    let _ = runner.finish();
    0
}

/// `-i <iface> [-f filter]` without a script — stream a summary to stdout.
fn cmd_live_summary(dev: &str, filter: Option<&str>) -> i32 {
    let mut number = 0u64;
    let r = run_live(dev, filter, |data, lt, _ts| {
        number += 1;
        let mut pkt = model::Packet::new(data.to_vec(), data.len() as u32, 0, lt, number);
        let s = dissect::summarize(&mut pkt);
        println!(
            "{:>6}  {:<15} -> {:<15}  {:<8}  {}",
            number, s.src, s.dst, s.proto, s.info
        );
        Ok(())
    });
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("carscal: {e}");
            1
        }
    }
}

/// Open a live capture on `dev`, applying `filter` in-kernel, and call `f` per
/// captured frame (Ethernet link type) until interrupted.
fn run_live<F: FnMut(&[u8], u16, u64) -> Result<(), String>>(
    dev: &str,
    filter: Option<&str>,
    mut f: F,
) -> Result<(), String> {
    let cap = libpcapng::Capture::open(dev).map_err(|e| {
        format!("cannot open interface {dev}: {e} (live capture needs root / CAP_NET_RAW)")
    })?;
    if let Some(expr) = filter {
        if !expr.is_empty() {
            cap.set_filter(expr).map_err(|e| format!("capture filter: {e}"))?;
        }
    }
    eprintln!("carscal: capturing on {dev} (Ctrl-C to stop)…");
    let mut err: Option<String> = None;
    cap.run(0, |p| {
        if err.is_some() {
            return;
        }
        // Captured frames are Ethernet; timestamp ns → µs.
        if let Err(e) = f(p.data, model::linktype::ETHERNET, p.timestamp_ns / 1000) {
            err = Some(e);
            cap.break_loop();
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `--find <capture> <query>` — list packets matching text or `hex:` bytes.
fn cmd_find(args: &[String]) -> i32 {
    let (path, query) = match (args.first(), args.get(1)) {
        (Some(p), Some(q)) => (p, q),
        _ => {
            eprintln!("carscal: --find needs <capture> <query>");
            return 2;
        }
    };
    let needle = match find::Needle::parse(query) {
        Some(n) => n,
        None => {
            eprintln!("carscal: empty or invalid query");
            return 2;
        }
    };
    let mut cap = match source::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };
    let hits = find::find_all(&cap, &needle);
    for &i in &hits {
        let s = dissect::summarize(&mut cap.pkts[i]);
        println!("  #{:<5} {:<8} {}", cap.pkts[i].number, s.proto, s.info);
    }
    println!("{} match(es).", hits.len());
    0
}

/// `--follow <capture> <pkt#>` — reassemble and print a conversation.
fn cmd_follow(args: &[String]) -> i32 {
    let (path, num) = match (args.first(), args.get(1)) {
        (Some(p), Some(n)) => (p, n),
        _ => {
            eprintln!("carscal: --follow needs <capture> <packet-number>");
            return 2;
        }
    };
    let num: u64 = match num.parse() {
        Ok(n) if n >= 1 => n,
        _ => {
            eprintln!("carscal: packet number must be >= 1");
            return 2;
        }
    };
    let cap = match source::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };
    let idx = (num - 1) as usize;
    let f = match stream::follow(&cap, idx) {
        Some(f) => f,
        None => {
            eprintln!("carscal: packet {num} is not part of a TCP/UDP conversation");
            return 1;
        }
    };
    let proto = if f.proto == 6 { "TCP" } else { "UDP" };
    println!(
        "Follow {proto} Stream — {}:{} ⇄ {}:{}  ({} packets)",
        f.client.0, f.client.1, f.server.0, f.server.1, f.packets
    );
    println!(
        "  ▶ client→server {} bytes    ◀ server→client {} bytes\n",
        f.client_bytes.len(),
        f.server_bytes.len()
    );
    // The reassembled, in-order streams (this is what libpcapng ordered for us).
    println!("── client → server ──");
    println!("{}", render_bytes(&f.client_bytes));
    println!("\n── server → client ──");
    println!("{}", render_bytes(&f.server_bytes));
    0
}

/// Render bytes as text, replacing non-printable/control bytes with '.'.
fn render_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|&c| if (0x20..0x7f).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t' {
            c as char
        } else {
            '.'
        })
        .collect()
}

fn cmd_dump(args: &[String], tree: bool) -> i32 {
    let path = match args.first() {
        Some(p) => p,
        None => {
            eprintln!("carscal: --dump/--summary needs a capture file");
            return 2;
        }
    };
    let expr = args.get(1).map(String::as_str).unwrap_or("");
    let flt = match Filter::compile(expr) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("carscal: bad filter: {e}");
            return 2;
        }
    };
    let cap = match source::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("carscal: {e}");
            return 1;
        }
    };

    if tree {
        print_dump(cap, Some(flt));
    } else {
        print_summary(cap, Some(flt));
    }
    0
}

/// Print one summary line per (matching) packet.
fn print_summary(mut cap: Capture, flt: Option<Filter>) {
    let first_ts = cap.first_ts_us;
    for pkt in &mut cap.pkts {
        if let Some(f) = &flt {
            if !f.is_match_all() {
                match dissect::dissect(pkt) {
                    Some(d) if f.eval(&d.root()) => {}
                    _ => continue,
                }
            }
        }
        let s = dissect::summarize(pkt);
        let rel = (pkt.ts_us.saturating_sub(first_ts)) as f64 / 1_000_000.0;
        println!(
            "{:>6}  {:>12.6}  {:<15} -> {:<15}  {:<8}  {}",
            pkt.number, rel, s.src, s.dst, s.proto, s.info
        );
    }
}

/// Print the full field tree for each matching packet.
fn print_dump(mut cap: Capture, flt: Option<Filter>) {
    for pkt in &mut cap.pkts {
        let d = match dissect::dissect(pkt) {
            Some(d) => d,
            None => continue,
        };
        if let Some(f) = &flt {
            if !f.eval(&d.root()) {
                continue;
            }
        }
        println!("Packet #{} ({} bytes on wire)", pkt.number, pkt.origlen);
        for layer in d.root().children() {
            print_field(&layer, 1);
        }
        println!();
    }
}

fn print_field(f: &Field, depth: usize) {
    let indent = "  ".repeat(depth);
    println!("{indent}{}", f.label());
    for c in f.children() {
        print_field(&c, depth + 1);
    }
}
