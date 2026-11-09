#!/bin/sh
set -eu
iptables -P OUTPUT DROP
# Permit only the container's own health endpoint on loopback.
iptables -I OUTPUT 1 -d 127.0.0.1 -p tcp --dport 8001 -j ACCEPT
# Docker may rewrite embedded DNS traffic to an ephemeral resolver port before
# OUTPUT filtering, so permit only the resolver address rather than port 53.
iptables -I OUTPUT 2 -d 127.0.0.11 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do iptables -A OUTPUT -d "$net" -j DROP; done
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
ip6tables -P OUTPUT DROP || true
exec setpriv --reuid=fetcher --regid=fetcher --clear-groups --bounding-set=-net_admin --inh-caps=-net_admin --ambient-caps=-net_admin uvicorn fetcher.app:app --host 0.0.0.0 --port 8001
