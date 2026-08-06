#!/usr/bin/env bash
pass=0; fail=0
chk(){ if [ "$2" -eq 0 ]; then echo "  PASS  $1"; pass=$((pass+1));
       else echo "  FAIL  $1 ($2 offenders)"; fail=$((fail+1)); fi; }

chk "No whitespace in names"   $(find . -path ./.git -prune -o \( -name "* " -o -name " *" \) -print | wc -l)
chk "Code fences balanced"     $(find . -path ./.git -prune -o -name "*.md" -print | while read f; do c=$(grep -c '^```' "$f"); [ $((c % 2)) -ne 0 ] && echo x; done | wc -l)
chk "No cleartext password"    $(grep -rF --include=*.md 'MyPassw0rd123@' . | wc -l)
chk "No full NT hash"          $(grep -rF --include=*.md '2b52d3f28841abe8c3c1d0568d945fa9' . | wc -l)
chk "No live http:// URLs"     $(grep -rEh --include=*.md 'http://[0-9a-zA-Z]' . | wc -l)
chk "No smart quotes"          $(grep -rlP --include=*.md '[\x{2018}\x{2019}\x{201C}\x{201D}]' . 2>/dev/null | wc -l)
chk "README tree correct"      $(grep -c '0001-macro' README.md)
chk "No CRLF"                  $(find . -path ./.git -prune -o -name "*.md" -print | xargs file | grep -ci crlf)

echo; echo "  ---- $pass passed, $fail failed ----"
[ $fail -eq 0 ] || exit 1

# link integrity (non-zero exit fails the check)
python3 check-links.py --quiet || exit 1

# schema validation, advisory mode: reports debt, exits non-zero only on
# fatal parse errors. Flip to --strict when the metadata migration completes.
python3 check-schema.py --quiet || exit 1

# publication safety: redaction-marker placement (blocking). Replaces the
# retired shell-embedded bare_markers() parser with a Markdown-aware checker.
python3 check-publication-safety.py --quiet || exit 1
