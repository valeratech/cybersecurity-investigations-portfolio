#!/usr/bin/env bash
# Repository gate. Runs these steps in order; each step's own exit status governs and the
# first failure stops the gate:
#   check-hygiene.py   whitespace in names, fences, local denylist, http:// URLs, smart quotes,
#                      retired README path, CRLF (locale-independent; unreadable input is fatal)
#   check-links.py --quiet
#   check-schema.py --quiet --strict      (profile notices never affect exit status)
#   check-publication-safety.py --quiet   (redaction-marker placement, raw IPv4)
# Arguments are passed to check-hygiene.py, for example --require-denylist.
# Run from the repository root. Exit 0 only if every step passes.
set -u
if [ -f check-hygiene.py ] && [ -f check-schema.py ]; then :; else
  echo "  FATAL run verify-audit.sh from the repository root"; exit 2
fi
python3 check-hygiene.py "$@" || exit 1
python3 check-links.py --quiet || exit 1
python3 check-schema.py --quiet --strict || exit 1
python3 check-publication-safety.py --quiet || exit 1
