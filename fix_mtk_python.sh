#!/bin/bash
# Force python2 for MTK host scripts and make multiple_dtbo.py binary-safe
set -e
mkdir -p "$GITHUB_WORKSPACE/bin"
ln -sfn "$(command -v python2)" "$GITHUB_WORKSPACE/bin/python"
export PATH="$GITHUB_WORKSPACE/bin:$PATH"
echo "$GITHUB_WORKSPACE/bin" >> "$GITHUB_PATH"
python --version

python2 <<'PY'
from pathlib import Path
p = Path('kernel/scripts/multiple_dtbo.py')
t = p.read_text()
orig = t
t = t.replace("open(output_file, 'w')", "open(output_file, 'wb')")
t = t.replace("open(input_file, 'r')", "open(input_file, 'rb')")
t = t.replace('fo.write("%s" % item)', 'fo.write(item)')
# replace readlines loop with binary dump
old1 = "\t\twith open(input_file, 'rb') as fi:\n\t\t\tfor line in fi.readlines():\n\t\t\t\tfo.write(line)"
old2 = "\t\twith open(input_file, 'r') as fi:\n\t\t\tfor line in fi.readlines():\n\t\t\t\tfo.write(line)"
new = "\t\twith open(input_file, 'rb') as fi:\n\t\t\tfo.write(fi.read())"
if old1 in t:
    t = t.replace(old1, new)
elif old2 in t:
    t = t.replace(old2, new)
else:
    # last resort: if still has readlines after open(input_file
    if 'readlines()' in t and "open(input_file" in t:
        import re
        t = re.sub(
            r"with open\(input_file, 'r[b]?'\) as fi:\n\t\t\tfor line in fi\.readlines\(\):\n\t\t\t\tfo\.write\(line\)",
            "with open(input_file, 'rb') as fi:\n\t\t\tfo.write(fi.read())",
            t,
            count=1
        )
if t != orig:
    p.write_text(t)
    print('[+] patched multiple_dtbo.py binary I/O')
else:
    print('[!] no change to multiple_dtbo.py')
    for i,l in enumerate(orig.splitlines(),1):
        if 'open(output_file' in l or 'open(input_file' in l or 'readlines' in l or 'fo.write' in l:
            print(i, repr(l))
PY
