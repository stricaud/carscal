# Export Objects — carving HTTP / SMB files from traffic

carscal can recover the actual files transferred over **HTTP** and **SMB2** in a
capture (the equivalent of Wireshark's *File ▸ Export Objects*). It reassembles
the TCP streams and parses the protocol to pull each object's bytes back out.
There are three ways to use it.

## 1. In the TUI

**File ▸ Export HTTP Objects…** or **File ▸ Export SMB Objects…**. carscal
carves the objects from the loaded capture, asks for a directory, writes each
file there, and shows a summary of what it saved.

## 2. From the command line

```sh
# List the objects (frame, protocol, size, complete?, name):
carscal --export-objects http capture.pcapng

# Write them to a directory:
carscal --export-objects smb  capture.pcapng ./smb-files
```

## 3. Live, from a Lua script

For live extraction (or custom handling — renaming, filtering, uploading, …),
the scripting engine exposes the same extractor. `carscal.objects("http"|"smb")`
returns a handle with two methods:

- `ex:add(pkt)` — feed one packet (in `packet(pkt)`).
- `ex:extract()` — reassemble and return the objects, each a table with
  `proto, frame, hostname, content_type, filename, data, complete`.

### Example: carve SMB files live

```lua
-- smb-files.lua — save files transferred over SMB2 as they go by.
--   sudo carscal -s smb-files.lua -f "tcp.port == 445" -i en0
--        carscal -s smb-files.lua -f "tcp.port == 445" -r capture.pcapng

local ex
local outdir = os.getenv("HOME") .. "/carscal-smb-objects"

function init()
  ex = carscal.objects("smb")               -- an SMB object extractor
  os.execute("mkdir -p '" .. outdir .. "'")
  print("carving SMB files -> " .. outdir)
end

function packet(pkt)
  ex:add(pkt)                                -- feed every packet to it
end

function finish()
  for i, o in ipairs(ex:extract()) do        -- parse streams -> objects
    local name = (o.filename ~= "" and o.filename or ("frame-" .. o.frame))
    name = name:gsub("[/\\]", "_")           -- keep it a single path element
    local path = string.format("%s/%03d_%s", outdir, i, name)
    local f = io.open(path, "wb")
    if f then
      f:write(o.data)
      f:close()
      print(string.format("  %-40s %9d bytes  %s",
        name, #o.data, o.complete and "complete" or "partial"))
    end
  end
end
```

Swap `"smb"` for `"http"` (and the filter for `tcp.port == 80`) to carve HTTP
downloads instead. Because you get each object's `content_type` and `hostname`
too, you can sort, rename, or filter them however you like — the script is just
plain Lua.

> **Note.** Extraction works on **unencrypted** traffic. HTTPS / SMB-over-QUIC
> and encrypted SMB3 payloads can't be carved without the keys.
