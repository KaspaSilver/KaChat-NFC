#!/bin/sh
# The project's core promise: the card never generates keys. The applet may only import the
# framework classes it needs for storage and the SHA-256 save check, so a change that brings in
# randomness or key objects fails the build rather than slipping through a review.
set -eu

applet_dir="$(dirname "$0")/../applet/src"
failed=0

if grep -rnE 'RandomData|KeyBuilder|KeyPair|KeyAgreement|Signature|javacardx?\.crypto|\.Key\b' "$applet_dir"; then
    echo "The applet references randomness or key material. It must only store bytes." >&2
    failed=1
fi

unexpected=$(grep -rhE '^import ' "$applet_dir" | grep -vE '^import javacard\.framework\.[A-Za-z0-9]+;$|^import javacard\.security\.MessageDigest;$' || true)
if [ -n "$unexpected" ]; then
    echo "Unexpected applet imports:" >&2
    echo "$unexpected" >&2
    failed=1
fi

[ "$failed" -eq 0 ] && echo "Applet has no randomness or key material."
exit "$failed"
