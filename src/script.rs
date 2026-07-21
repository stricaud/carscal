//! Command-line scripting — the generalized MQS.
//!
//! Instead of decoding only one protocol and handing a string to a script,
//! carscal decodes *any* protocol and hands a script the fully decoded fields —
//! and libpcapng-reassembled IP datagrams and TCP streams — via Lua entry points:
//!
//! ```lua
//! function init()        end   -- once, before processing
//! function packet(pkt)   end   -- per (IP-defragmented) packet
//! function stream(s)     end   -- per reassembled in-order TCP chunk
//! function finish(stats) end   -- once, after processing
//! ```
//!
//! `pkt` carries `number,time,len,protocol,src,dst,info,srcport,dstport,payload,
//! raw,layers,fields` and the methods `pkt:has(abbrev)`, `pkt:get(abbrev)` and
//! `pkt:matches(display_filter)`. `s` carries `data` (new bytes), `all`
//! (cumulative), `src/dst/srcport/dstport/dir`. Globals: `carscal.hex(bytes)`,
//! `carscal.protocols()`, `carscal.dissect(bytes[,linktype])`.

use crate::filter::Filter;
use crate::l4;
use crate::model::linktype;
use libpcapng::{Dissection, FieldType, IpReasm, IpReasm4, TcpReasm};
use mlua::{Lua, Table, Value, Variadic};

/// An incremental script processor: feed it packets from any source (a file or
/// a live capture) and it drives the script's `packet()` / `stream()` entry
/// points, sharing one Lua state and one set of reassemblers.
pub struct Runner {
    lua: Lua,
    flt: Filter,
    ipr: IpReasm,
    tcp: TcpReasm,
    first_ts_us: u64,
    have_first: bool,
    seq: u64,
    n_packets: u64,
    n_streams: u64,
}

impl Runner {
    /// Load `script_path`, run its `init()`, and return a ready processor.
    pub fn new(script_path: &str, flt: Filter) -> Result<Runner, String> {
        let src = std::fs::read_to_string(script_path).map_err(|e| format!("{script_path}: {e}"))?;
        let lua = Lua::new();
        install_globals(&lua)?;
        lua.load(&src)
            .set_name(script_path)
            .exec()
            .map_err(|e| format!("{script_path}: {e}"))?;
        if let Ok(init) = lua.globals().get::<_, mlua::Function>("init") {
            init.call::<_, ()>(()).map_err(lua_err)?;
        }
        Ok(Runner {
            lua,
            flt,
            ipr: IpReasm::new(),
            tcp: TcpReasm::new(),
            first_ts_us: 0,
            have_first: false,
            seq: 0,
            n_packets: 0,
            n_streams: 0,
        })
    }

    /// Feed one packet (raw frame + link type + timestamp in µs).
    pub fn process(&mut self, data: &[u8], linktype: u16, ts_us: u64) -> Result<(), String> {
        if !self.have_first {
            self.first_ts_us = ts_us;
            self.have_first = true;
        }
        self.seq += 1;
        let number = self.seq;
        // Display filter gates which packets reach the script.
        if !self.flt.is_match_all() {
            match Dissection::new(data, linktype) {
                Some(d) if self.flt.eval(&d.root()) => {}
                _ => return Ok(()),
            }
        }
        // IP-defragment: a fragmented datagram reaches the script whole.
        let (frame, lt): (Vec<u8>, u16) = match self.ipr.add(data) {
            IpReasm4::Complete(dg) => (dg, linktype::IPV4),
            IpReasm4::Buffered => return Ok(()),
            IpReasm4::PassThrough => (data.to_vec(), linktype),
        };

        let g = self.lua.globals();
        if let Ok(pf) = g.get::<_, mlua::Function>("packet") {
            let t = build_packet(&self.lua, number, ts_us, self.first_ts_us, data.len() as u32, &frame, lt)?;
            pf.call::<_, ()>(t).map_err(lua_err)?;
            self.n_packets += 1;
        }

        if let Ok(sf) = g.get::<_, mlua::Function>("stream") {
            if let Some(l) = l4::locate(&frame, lt) {
                if l.proto == 6 {
                    let sip = ipv4_u32(&l.src_ip_raw);
                    let dip = ipv4_u32(&l.dst_ip_raw);
                    let payload = &frame[l.payload_off..l.payload_off + l.payload_len];
                    let (src_ip, dst_ip, sp, dp) = (l.src_ip.clone(), l.dst_ip.clone(), l.src_port, l.dst_port);
                    let lua = &self.lua;
                    let mut err: Option<mlua::Error> = None;
                    let mut delivered = 0u64;
                    self.tcp.add(sip, dip, sp, dp, l.seq, l.flags, payload, |b| {
                        if err.is_some() || b.data.is_empty() {
                            return;
                        }
                        match build_stream(lua, b, &src_ip, &dst_ip, sp, dp) {
                            Ok(t) => match sf.call::<_, ()>(t) {
                                Ok(()) => delivered += 1,
                                Err(e) => err = Some(e),
                            },
                            Err(e) => err = Some(e),
                        }
                    });
                    self.n_streams += delivered;
                    if let Some(e) = err {
                        return Err(lua_err(e));
                    }
                }
            }
        }
        Ok(())
    }

    /// Run the script's `finish(stats)` after the last packet.
    pub fn finish(&self) -> Result<(), String> {
        if let Ok(finish) = self.lua.globals().get::<_, mlua::Function>("finish") {
            let stats = self.lua.create_table().map_err(lua_err)?;
            stats.set("packets", self.n_packets).map_err(lua_err)?;
            stats.set("streams", self.n_streams).map_err(lua_err)?;
            finish.call::<_, ()>(stats).map_err(lua_err)?;
        }
        Ok(())
    }
}


fn lua_err(e: mlua::Error) -> String {
    format!("lua: {e}")
}

fn ipv4_u32(raw: &[u8]) -> u32 {
    if raw.len() == 4 {
        u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])
    } else {
        0
    }
}

/// The `carscal` global table.
fn install_globals(lua: &Lua) -> Result<(), String> {
    let t = lua.create_table().map_err(lua_err)?;

    t.set(
        "hex",
        lua.create_function(|_, s: mlua::String| {
            Ok(s.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>())
        })
        .map_err(lua_err)?,
    )
    .map_err(lua_err)?;

    t.set(
        "protocols",
        lua.create_function(|lua, ()| {
            let out = lua.create_table()?;
            for (i, name) in libpcapng::posa::protocols().into_iter().enumerate() {
                out.set(i + 1, name)?;
            }
            Ok(out)
        })
        .map_err(lua_err)?,
    )
    .map_err(lua_err)?;

    // carscal.dissect(bytes[, linktype]) -> { proto=, src=, dst=, info=, fields={} }
    t.set(
        "dissect",
        lua.create_function(|lua, args: Variadic<Value>| {
            let bytes = match args.first() {
                Some(Value::String(s)) => s.as_bytes().to_vec(),
                _ => return Ok(Value::Nil),
            };
            let lt = match args.get(1) {
                Some(Value::Integer(i)) => *i as u16,
                _ => linktype::ETHERNET,
            };
            match Dissection::new(&bytes, lt) {
                Some(d) => {
                    let out = lua.create_table()?;
                    out.set("proto", d.proto())?;
                    out.set("src", d.src())?;
                    out.set("dst", d.dst())?;
                    out.set("info", d.info())?;
                    let fields = lua.create_table()?;
                    collect_fields(&d.root(), &fields)?;
                    out.set("fields", fields)?;
                    Ok(Value::Table(out))
                }
                None => Ok(Value::Nil),
            }
        })
        .map_err(lua_err)?,
    )
    .map_err(lua_err)?;

    lua.globals().set("carscal", t).map_err(lua_err)?;
    Ok(())
}

/// Set `fields[abbrev] = natural value` for every field with an abbrev.
fn collect_fields(f: &libpcapng::Field, out: &Table) -> mlua::Result<()> {
    let ab = f.abbrev();
    if !ab.is_empty() {
        match f.ftype() {
            FieldType::Uint => out.set(ab, f.uint())?,
            FieldType::None | FieldType::Bytes => {}
            _ => out.set(ab, f.str_value())?,
        }
    }
    for c in f.children() {
        collect_fields(&c, out)?;
    }
    Ok(())
}

fn build_packet<'a>(
    lua: &'a Lua,
    number: u64,
    ts_us: u64,
    first_ts: u64,
    origlen: u32,
    frame: &[u8],
    lt: u16,
) -> Result<Table<'a>, String> {
    let d = Dissection::new(frame, lt);
    let t = lua.create_table().map_err(lua_err)?;
    t.set("number", number).map_err(lua_err)?;
    t.set("time", (ts_us.saturating_sub(first_ts)) as f64 / 1e6).map_err(lua_err)?;
    t.set("len", origlen).map_err(lua_err)?;
    t.set("raw", lua.create_string(frame).map_err(lua_err)?).map_err(lua_err)?;

    if let Some(d) = &d {
        t.set("protocol", d.proto()).map_err(lua_err)?;
        t.set("src", d.src()).map_err(lua_err)?;
        t.set("dst", d.dst()).map_err(lua_err)?;
        t.set("info", d.info()).map_err(lua_err)?;
        let layers = lua.create_table().map_err(lua_err)?;
        for (i, layer) in d.root().children().enumerate() {
            // Use the layer's abbrev prefix (before the first '.') or its label.
            let name = layer_name(&layer);
            layers.set(i + 1, name).map_err(lua_err)?;
        }
        t.set("layers", layers).map_err(lua_err)?;
        let fields = lua.create_table().map_err(lua_err)?;
        collect_fields(&d.root(), &fields).map_err(lua_err)?;
        t.set("fields", fields).map_err(lua_err)?;
    }

    // Transport payload + ports.
    if let Some(l) = l4::locate(frame, lt) {
        t.set("srcport", l.src_port).map_err(lua_err)?;
        t.set("dstport", l.dst_port).map_err(lua_err)?;
        t.set("l4", if l.proto == 6 { "tcp" } else { "udp" }).map_err(lua_err)?;
        let payload = &frame[l.payload_off..l.payload_off + l.payload_len];
        t.set("payload", lua.create_string(payload).map_err(lua_err)?).map_err(lua_err)?;
    }

    // pkt:has / pkt:matches (re-dissect the captured bytes on demand).
    let data = frame.to_vec();
    t.set(
        "has",
        lua.create_function(move |_, (_this, abbrev): (Table, String)| {
            Ok(Dissection::new(&data, lt).map(|d| d.root().find(&abbrev).is_some()).unwrap_or(false))
        })
        .map_err(lua_err)?,
    )
    .map_err(lua_err)?;

    let data2 = frame.to_vec();
    t.set(
        "matches",
        lua.create_function(move |_, (_this, expr): (Table, String)| {
            let ok = Filter::compile(&expr)
                .ok()
                .and_then(|f| Dissection::new(&data2, lt).map(|d| f.eval(&d.root())))
                .unwrap_or(false);
            Ok(ok)
        })
        .map_err(lua_err)?,
    )
    .map_err(lua_err)?;

    Ok(t)
}

fn layer_name(layer: &libpcapng::Field) -> String {
    // Prefer a child's abbrev prefix (e.g. "ip" from "ip.src"); fall back to label.
    for c in layer.children() {
        let ab = c.abbrev();
        if let Some((prefix, _)) = ab.split_once('.') {
            return prefix.to_string();
        }
    }
    layer.label().split(',').next().unwrap_or("").to_string()
}

fn build_stream<'a>(
    lua: &'a Lua,
    b: libpcapng::TcpBytes,
    src_ip: &str,
    dst_ip: &str,
    sp: u16,
    dp: u16,
) -> mlua::Result<Table<'a>> {
    let t = lua.create_table()?;
    t.set("data", lua.create_string(b.data)?)?;
    t.set("all", lua.create_string(b.all)?)?;
    t.set("dir", b.dir)?;
    // The callback reports this half-stream's real src/dst; fall back to the
    // conversation endpoints we fed in.
    t.set("src", if b.dir == 0 { src_ip } else { dst_ip })?;
    t.set("dst", if b.dir == 0 { dst_ip } else { src_ip })?;
    t.set("srcport", if b.dir == 0 { sp } else { dp })?;
    t.set("dstport", if b.dir == 0 { dp } else { sp })?;
    Ok(t)
}
