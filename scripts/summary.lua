-- One line per packet — the simplest example.
function packet(p)
  print(string.format("#%d  %-6s %s -> %s  %s", p.number, p.protocol or "?", p.src or "", p.dst or "", p.info or ""))
end
function finish(st) print(string.format("-- %d packets", st.packets)) end
