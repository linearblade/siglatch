iptables -F


##################################
# ssh blocking
##################################
iptables -A INPUT -p TCP -s 207.115.64.151/32 --dport 22 -j ACCEPT
iptables -A INPUT -p TCP -s 207.115.64.77/32 --dport 22 -j ACCEPT
iptables -A INPUT -p TCP -s 207.115.90.236/32 --dport 22 -j ACCEPT
iptables -A INPUT -p TCP -s 209.147.112.0/24 --dport 22 -j ACCEPT

#henry aws
#backup
#iptables -A INPUT -p TCP -s 18.220.12.29/32 --dport 22 -j ACCEPT
iptables -A INPUT -p TCP -s 18.220.12.29/32 --dport 22 -j ACCEPT

# BEGIN GRANTED DYNAMIC RULES
iptables -A INPUT -p TCP -s 65.181.8.201/32 --dport 22 -j ACCEPT
# END GRANTED DYNAMIC RULES

iptables -A INPUT -p TCP --dport 22 -j DROP
