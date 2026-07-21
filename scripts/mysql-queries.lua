-- Sniff MariaDB/MySQL COM_QUERY statements from reassembled client streams —
-- the MQS use-case, generalized: carscal reassembles the TCP stream (libpcapng)
-- and hands us the in-order bytes; we pull out the SQL.
--
--   carscal -s scripts/mysql-queries.lua -r dump.pcapng -f "tcp.port == 3306"

local function u24(s, i)
  return string.byte(s, i) + string.byte(s, i + 1) * 256 + string.byte(s, i + 2) * 65536
end

function stream(s)
  if s.dstport ~= 3306 then return end        -- client → server only
  local data, i = s.data, 1
  while i + 4 <= #data do
    local len = u24(data, i)                   -- payload length (incl. command byte)
    local cmd = string.byte(data, i + 4)
    if cmd == 0x03 and len >= 1 then           -- COM_QUERY
      local q = string.sub(data, i + 5, i + 4 + len - 1)
      print(string.format("%s:%d  %s", s.src, s.srcport, q))
    end
    i = i + 4 + len
  end
end
