#!/bin/sh
set -eu
iptables -N DOCKER-USER 2>/dev/null || true
for interface in 'br+' docker0; do
    for destination in 169.254.0.0/16 10.0.0.0/8 192.168.0.0/16; do
        # Remove the previous blanket rule: it also drops established replies to
        # the HTTPS gateway when the gateway has a private source address.
        while iptables -C DOCKER-USER -i "$interface" -d "$destination" -m comment --comment msgctf-vm-boundary -j DROP 2>/dev/null; do
            iptables -D DOCKER-USER -i "$interface" -d "$destination" -m comment --comment msgctf-vm-boundary -j DROP
        done
        iptables -C DOCKER-USER -i "$interface" -d "$destination" -m conntrack --ctstate NEW -m comment --comment msgctf-vm-boundary -j DROP 2>/dev/null ||
            iptables -I DOCKER-USER -i "$interface" -d "$destination" -m conntrack --ctstate NEW -m comment --comment msgctf-vm-boundary -j DROP
    done
    iptables -C INPUT -i "$interface" -m conntrack --ctstate NEW -m comment --comment msgctf-vm-boundary -j DROP 2>/dev/null ||
        iptables -I INPUT -i "$interface" -m conntrack --ctstate NEW -m comment --comment msgctf-vm-boundary -j DROP
done
