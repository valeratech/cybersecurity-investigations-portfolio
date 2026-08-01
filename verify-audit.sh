#!/usr/bin/env bash
pass=0; fail=0
chk(){ if [ "$2" -eq 0 ]; then echo "  PASS  $1"; pass=$((pass+1));
       else echo "  FAIL  $1 ($2 offenders)"; fail=$((fail+1)); fi; }

bare_markers() {
python3 - << 'PY'
import glob
n = 0
for f in glob.glob('**/*.md', recursive=True):
    if '.git' in f:
        continue
    inf = False
    for l in open(f, encoding='utf-8', errors='replace').read().split('\n'):
        if l.lstrip().startswith('```'):
            inf = not inf
            continue
        if inf:
            continue
        for tok in ('<REDACTED>', '<sensitive>'):
            if tok in l and ('`' + tok) not in l:
                n += 1
print(n)
PY
}

chk "No whitespace in names"   $(find . -path ./.git -prune -o \( -name "* " -o -name " *" \) -print | wc -l)
chk "Code fences balanced"     $(find . -path ./.git -prune -o -name "*.md" -print | while read f; do c=$(grep -c '^```' "$f"); [ $((c % 2)) -ne 0 ] && echo x; done | wc -l)
chk "No cleartext password"    $(grep -rF --include=*.md 'MyPassw0rd123@' . | wc -l)
chk "No full NT hash"          $(grep -rF --include=*.md '2b52d3f28841abe8c3c1d0568d945fa9' . | wc -l)
chk "No live http:// URLs"     $(grep -rEh --include=*.md 'http://[0-9a-zA-Z]' . | wc -l)
chk "No smart quotes"          $(grep -rlP --include=*.md '[\x{2018}\x{2019}\x{201C}\x{201D}]' . 2>/dev/null | wc -l)
chk "README tree correct"      $(grep -c '0001-macro' README.md)
chk "No CRLF"                  $(find . -path ./.git -prune -o -name "*.md" -print | xargs file | grep -ci crlf)
chk "No bare HTML redaction markers" $(bare_markers)

echo; echo "  ---- $pass passed, $fail failed ----"
[ $fail -eq 0 ]

# link integrity (non-zero exit fails the check)
python3 check-links.py --quiet
