#!/bin/sh

echo "Initializing Container Firewall Rules..."

iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -m recent --update --seconds 60 --hitcount 30 -j DROP

echo "Firewall active. Starting Proxy..."
exec /app/proxy --config /app/config.yml
