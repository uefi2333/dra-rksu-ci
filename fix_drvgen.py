#!/usr/bin/env python3
"""Fix Python 2 -> 3 compatibility in DrvGen.py for MediaTek DCT tool."""
import sys
import re

def fix_drvgen(path):
    with open(path) as f:
        c = f.read()
    c = c.replace("print \"\"\"", "print(\"\"\"")
    c = re.sub(r"\"\"\"
(?=
)", "\"\"\")
", c)
    c = c.replace("except Exception, e:", "except Exception as e:")
    with open(path, "w") as f:
        f.write(c)
    print(f"[+] Fixed {path}")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "kernel/tools/dct/DrvGen.py"
    fix_drvgen(path)
