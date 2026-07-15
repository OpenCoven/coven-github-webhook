#!/bin/sh
set -eu

manifest=/usr/share/coven/egress-ipv4.txt
test -s "$manifest"

state_limit=${COVEN_STATE_FILESYSTEM_MAX_BYTES:-8589934592}
case "$state_limit" in
  ""|*[!0-9]*) echo "invalid state filesystem limit" >&2; exit 78 ;;
esac
state_blocks=$(/usr/bin/stat -f -c %b /var/lib/coven)
state_block_bytes=$(/usr/bin/stat -f -c %S /var/lib/coven)
state_bytes=$((state_blocks * state_block_bytes))
if [ "$state_bytes" -gt "$state_limit" ]; then
  echo "state filesystem exceeds the configured hard limit" >&2
  exit 78
fi

elements=
while IFS= read -r address; do
  case "$address" in
    ""|*[!0-9.]*) echo "invalid immutable egress address" >&2; exit 78 ;;
  esac
  if [ -z "$elements" ]; then
    elements="$address"
  else
    elements="$elements, $address"
  fi
done < "$manifest"

test -n "$elements"

/usr/sbin/nft -f - <<EOF
table inet coven_egress {
  set allowed_ipv4 {
    type ipv4_addr
    flags interval
    elements = { $elements }
  }
  chain output {
    type filter hook output priority -100; policy drop;
    ct state established,related counter accept
    ip saddr 10.0.2.100 ip daddr 10.0.2.100 tcp dport 3000 counter accept
    ip daddr @allowed_ipv4 tcp dport 443 counter accept
  }
}
EOF

/usr/sbin/nft list table inet coven_egress >/dev/null

exec /usr/bin/setpriv \
  --no-new-privs \
  --reuid=1000 \
  --regid=1000 \
  --clear-groups \
  --bounding-set=-all \
  --inh-caps=-all \
  --ambient-caps=-all \
  /usr/bin/tini -- "$@"
