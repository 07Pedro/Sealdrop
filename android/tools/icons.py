"""Fetches Material Symbols (Rounded, Apache 2.0) and writes Android vector drawables.
Usage (from android/): python3 tools/icons.py app/src/main/res/drawable check_circle warning ..."""
import os
import re
import sys
import urllib.request

out, names = sys.argv[1], sys.argv[2:]
ok = re.compile(r"^[MmLlHhVvCcSsQqTtAaZz0-9.,\-\s]+$")
for n in names:
    url = f"https://fonts.gstatic.com/s/i/short-term/release/materialsymbolsrounded/{n}/default/24px.svg"
    svg = urllib.request.urlopen(url, timeout=30).read().decode()
    paths = re.findall(r'<path d="([^"]+)"', svg)
    assert paths and all(ok.match(d) for d in paths) and 'viewBox="0 -960 960 960"' in svg, n
    body = "\n".join(f'        <path android:fillColor="@android:color/white" android:pathData="{d}" />' for d in paths)
    xml = f'''<?xml version="1.0" encoding="utf-8"?>
<!-- Material Symbols Rounded "{n}" (Apache 2.0) -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp" android:height="24dp"
    android:viewportWidth="960" android:viewportHeight="960"
    android:tint="?android:attr/colorControlNormal">
    <group android:translateY="960">
{body}
    </group>
</vector>
'''
    open(os.path.join(out, f"ic_{n}.xml"), "w", encoding="utf-8").write(xml)
    print("ok", n)
