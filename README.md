# fail2ban block ip/network range
A python script that group IPs into network range, to block attacks from a network range address, from CIDR /23 up to /31.

Please be carefull to not block youself!

crontab suggestion:

`*/5 * * * * /usr/bin/python3 /usr/bin/fail2ban-block-ip-range.py`
