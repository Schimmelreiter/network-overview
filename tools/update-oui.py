#!/usr/bin/env python3
"""Regenerates src/NetworkOverview.Core/Devices/oui.txt.gz (MAC prefix -> vendor).

Source: Wireshark's generated manufacturer table (epan/manuf-data.c, GPL-2.0-or-later),
which is built from the IEEE public OUI registry. Usage:

    python3 tools/update-oui.py [path-or-url-to-manuf-data.c]
"""
import gzip, re, sys, urllib.request, pathlib

URL = "https://raw.githubusercontent.com/wireshark/wireshark/master/epan/manuf-data.c"
src = sys.argv[1] if len(sys.argv) > 1 else URL
text = urllib.request.urlopen(src).read().decode("utf-8") if src.startswith("http") else open(src, encoding="utf-8").read()
start = text.index("global_manuf_oui24_table[]")
end = text.index("};", start)
# whitespace between the fields varies (aligned columns), so match it loosely
# C string literals may contain escaped quotes (\")
STR = r'"((?:[^"\\]|\\.)*)"'
rx = re.compile(r'\{\s*\{\s*0x([0-9A-Fa-f]{2}),\s*0x([0-9A-Fa-f]{2}),\s*0x([0-9A-Fa-f]{2})\s*\},\s*' + STR + r',\s*' + STR + r'\s*\}')
unescape = lambda v: re.sub(r'\\(.)', r'\1', v)
lines = [f"{(m[1] + m[2] + m[3]).lower()}\t{(unescape(m[5]).strip() or unescape(m[4]))}" for m in rx.finditer(text, start, end)]
expected = text.count("{ {", start, end)
if len(lines) < expected:
    sys.exit(f"parsed only {len(lines)} of {expected} entries - format changed?")
out = pathlib.Path(__file__).resolve().parent.parent / "src/NetworkOverview.Core/Devices/oui.txt.gz"
with gzip.open(out, "wb", compresslevel=9) as f:
    f.write(("\n".join(lines) + "\n").encode("utf-8"))
print(f"{len(lines)} entries written to {out}")
