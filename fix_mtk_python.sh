#!/bin/bash
# Force python2 for MTK host scripts (multiple_dtbo.py / DrvGen)
# Python2 str is bytes, so original text-mode open works on DTB.
set -e
mkdir -p "$GITHUB_WORKSPACE/bin"
ln -sfn "$(command -v python2)" "$GITHUB_WORKSPACE/bin/python"
echo "$GITHUB_WORKSPACE/bin" >> "$GITHUB_PATH"
export PATH="$GITHUB_WORKSPACE/bin:$PATH"
python --version
# also hard-rewrite shebang so env python cannot drift
if [ -f kernel/scripts/multiple_dtbo.py ]; then
  sed -i '1s|^#!.*|#!/usr/bin/env python2|' kernel/scripts/multiple_dtbo.py
  echo "[+] multiple_dtbo.py shebang -> python2"
fi
# any other MTK python scripts that use env python
find kernel/scripts kernel/tools -name '*.py' -type f 2>/dev/null | while read -r f; do
  if head -1 "$f" | grep -q '#!/usr/bin/env python$'; then
    sed -i '1s|^#!.*|#!/usr/bin/env python2|' "$f"
    echo "[+] shebang python2: $f"
  fi
done
echo "[+] python2 forced for MTK host scripts"
