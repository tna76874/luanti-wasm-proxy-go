#!/bin/sh
if iptables -L >/dev/null 2>&1; then
    iptables -P FORWARD DROP
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -m recent --update --seconds 60 --hitcount 30 -j DROP
else
    echo "NOTICE: NET_ADMIN not available. Skipping iptables (Go app security active)."
fi
exec /app/proxy
