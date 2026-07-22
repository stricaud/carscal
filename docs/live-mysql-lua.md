# Live MySQL decoding with a Lua script

carscal has a **generalized scripting** engine (the idea behind `mqs`, but for
*any* protocol): you give it a display filter to select the traffic and a Lua
script to do something with it. The script sees fully-decoded packets and
libpcapng-reassembled TCP streams, so you can build a live decoder for a
protocol carscal doesn't ship — here, printing MySQL queries as they happen.

## Running a script

```sh
# From a capture file:
carscal -s mysql-queries.lua -f "tcp.port == 3306" -r dump.pcapng

# Live off an interface (needs capture privileges — sudo, or CAP_NET_RAW):
sudo carscal -s mysql-queries.lua -f "tcp.port == 3306" -i en0
```

- `-s <file.lua>` — the script.
- `-f "<display filter>"` — only packets matching it reach the script (optional
  but recommended; it uses carscal's full filter grammar: `&&`, `||`, `!`, `()`).
- `-r <file>` or `-i <iface>` — the source.

## The Lua interface

Your script defines any of these entry points:

```lua
function init()        end   -- once, before processing
function packet(pkt)   end   -- per (IP-defragmented) packet
function stream(s)     end   -- per reassembled, in-order TCP chunk
function finish(stats) end   -- once, after the last packet (stats.packets/.streams)
```

A `pkt` has `number, time, len, protocol, src, dst, info, srcport, dstport,
payload, raw, layers, fields`, plus `pkt:has(abbrev)`, `pkt:get(abbrev)` and
`pkt:matches("<display filter>")`. `pkt.payload` is the transport payload (the
bytes after TCP/UDP) as a Lua string.

A `stream` chunk `s` has `data` (the new in-order bytes), `all` (cumulative for
this direction), and `src, dst, srcport, dstport, dir`.

Handy globals: `carscal.hex(bytes)`, `carscal.protocols()`,
`carscal.dissect(bytes[, linktype])`.

## A little MySQL protocol

On the wire, MySQL frames its messages as:

```
+-----------+-----------+-------------------------+
| 3 bytes   | 1 byte    | <length> bytes          |
| length    | sequence  | message body            |
| (LE)      |           |                         |
+-----------+-----------+-------------------------+
```

For a command sent **client → server**, the first body byte is the command; the
one we want is `COM_QUERY` = `0x03`, whose remaining body bytes are the SQL text.
Queries travel to the server's port (3306 by default).

## The script

```lua
-- mysql-queries.lua — print MySQL queries as they go by.
--   carscal -s mysql-queries.lua -f "tcp.port == 3306" -r dump.pcapng

local COM_QUERY = 0x03
local n = 0

function init()
  print("watching for MySQL queries…")
end

function packet(pkt)
  -- Queries are sent to the MySQL port (client -> server).
  if pkt.dstport ~= 3306 then return end

  local p = pkt.payload
  if #p < 5 then return end            -- need length(3) + seq(1) + command(1)

  -- MySQL header: 3-byte little-endian length, one sequence byte, then the body.
  local blen = p:byte(1) + p:byte(2) * 256 + p:byte(3) * 65536
  local cmd  = p:byte(5)               -- first body byte = command

  if cmd == COM_QUERY then
    -- Body occupies positions 5 .. 4+blen; the SQL follows the command byte.
    local sql = p:sub(6, 4 + blen)
    n = n + 1
    print(string.format("%.3f  %s:%d  %s", pkt.time, pkt.src, pkt.srcport, sql))
  end
end

function finish(stats)
  print(string.format("done — %d queries in %d packets", n, stats.packets))
end
```

Run it and you'll see one line per query:

```
0.142  10.0.0.5:51920  SELECT id, name FROM users WHERE id = 42
0.147  10.0.0.5:51920  UPDATE sessions SET last_seen = NOW() WHERE token = '…'
```

## Large queries that span TCP segments

`packet()` sees one TCP segment at a time, so a query larger than one segment is
truncated. For those, use `stream()` — carscal hands it the **reassembled,
in-order** bytes, so you can parse whole MySQL packets out of `s.all`:

```lua
-- Re-scan the cumulative client->server stream for COM_QUERY packets.
local COM_QUERY = 0x03
local seen = {}   -- per-connection count of bytes already reported

function stream(s)
  if s.dstport ~= 3306 then return end
  local key = string.format("%s:%d>%s:%d", s.src, s.srcport, s.dst, s.dstport)
  local buf, off = s.all, seen[key] or 0

  while #buf - off >= 5 do
    local blen = buf:byte(off+1) + buf:byte(off+2)*256 + buf:byte(off+3)*65536
    if #buf - off < 4 + blen then break end        -- packet not fully arrived yet
    if buf:byte(off+5) == COM_QUERY then
      print(string.format("%s  %s", key, buf:sub(off+6, off+4+blen)))
    end
    off = off + 4 + blen
  end
  seen[key] = off
end
```

## Beyond queries

Because the script gets every decoded field, you can go further with the same
pattern — e.g. `pkt:get("mysql.query")` if a `.posa` decoder for MySQL is loaded
(carscal ships one; see `--check-decoders`), or `pkt:matches(...)` to branch on
any protocol. Swap the port/command checks and you have a live decoder for
Redis, Postgres, or anything else.
