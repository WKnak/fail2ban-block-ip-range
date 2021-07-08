# fail2ban block ip/network range
A python script that group IPs into network range, to block attacks from a network range address, from CIDR /23 up to /31.

Please be carefull to not block youself!

crontab suggestion:

`*/5 * * * * /usr/bin/fail2ban-block-ip-range.py`


## Example:

Count and IPs found at last 1k lines of fail2ban.log

```
    151 sshd 193.56.28.160
    108 postfix-sasl 45.142.120.135
    107 postfix-sasl 45.142.120.62
    105 postfix-sasl 45.142.120.99
    105 postfix-sasl 45.142.120.93
    105 postfix-sasl 45.142.120.192
    104 postfix-sasl 45.142.120.87
    104 postfix-sasl 45.142.120.60
    104 postfix-sasl 45.142.120.209
    104 postfix-sasl 45.142.120.200
    104 postfix-sasl 45.142.120.133
    103 postfix-sasl 45.142.120.180
    103 postfix-sasl 45.142.120.149
    102 postfix-sasl 45.142.120.59
    100 postfix-sasl 45.142.120.215
     78 postfix-sasl 45.142.120.57
     78 postfix-sasl 45.142.120.11
     77 postfix-sasl 45.142.120.82
     77 postfix-sasl 45.142.120.20
     76 postfix-sasl 45.142.120.63
     76 postfix-sasl 45.142.120.34
     76 postfix-sasl 45.142.120.138
     73 postfix-sasl 45.142.120.65
     60 courier-auth 78.128.113.66
      6 apache-auth 45.150.206.113
      3 postfix-sasl 123.30.50.91
      2 sshd 5.188.206.204
      2 apache-auth 45.150.206.119
      2 apache-auth 45.150.206.115
      2 apache-auth 45.150.206.114
      1 sshd 51.210.127.200
```
      
Resulting blocked IP and IP Ranges (above 10 events):

```
fail2ban-client set courier-auth banip 78.128.113.66/32
fail2ban-client set postfix-sasl banip 45.142.120.0/24
fail2ban-client set sshd banip 193.56.28.160/32
fail2ban-client set apache-auth banip 45.150.206.112/29
```
