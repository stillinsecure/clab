#!/bin/sh

iptables -F
iptables -t mangle -A PREROUTING -s 192.168.1.0/24 -d 10.0.0.0/24 -p icmp -j NFQUEUE --queue-num 0
iptables -t mangle -A PREROUTING -s 192.168.1.0/24 -d 10.0.0.0/24 -p tcp --match multiport --dports 22,80,443 -j NFQUEUE --queue-num 0
iptables -I OUTPUT -p tcp -s 192.168.1.9 --sport 5996 -j NFQUEUE --queue-num 0
