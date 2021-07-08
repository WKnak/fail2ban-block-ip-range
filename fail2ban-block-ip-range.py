#!/usr/bin/python3

from pprint import pprint
from subprocess import call
from ipaddress import IPv4Network
from collections import defaultdict

# PART 1: system script call, filtering messages and IPs
#
# 1.1) this script searches for SASL LOGIN fails at last 10000 lines of mail.log
# 1.2) then it egreps the IPs, sort and uniq and count, and sort again.
# 1.3) the IP result list is output to /tmp

script = 'tail -n 10000 /var/log/mail.log | grep "SASL LOGIN authentication failed" | egrep "[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}" -o | sort | uniq -c | sort -nr > /tmp/top-ip-ranges'

call(script, shell=True)

#
# PART 2: reads the ip list detected and iterate:
#
file1 = open('/tmp/top-ip-ranges', 'r')
Lines = file1.readlines()

mylist = defaultdict(int)
finalList = defaultdict(int)

# 2.1) iterate ips and count
for line in Lines:
    splitVect = line.strip().split(" ")
    ip = splitVect[1].strip()
    count = splitVect[0].strip()

    # 2.2) iterate from cidr/32 down to 23 (descending)
    for cidr in range(32, 23, -1):
        ipnet  = IPv4Network(ip + "/" + str(cidr), False)
        index = str(ipnet.network_address) + "/" + str(cidr)

        # 2.3) add the network and count of events into a dictionary
        mylist[index] += int(count)

# pprint(mylist)

#
# PART 3:  iterate IPs again, and get best choice network range
#
for line in Lines:
    splitVect = line.strip().split(" ")
    ip = splitVect[1].strip()
    count = splitVect[0].strip()
    maxCount = 0
    nextIndex = False

	# 3.2 iterate CIDR (now in ascending order)
    for cidr in range(22, 33):
        ipnet  = IPv4Network(ip + "/" + str(cidr), False)
        index = str(ipnet.network_address) + "/" + str(cidr)
        curCount = mylist[index]
        if(curCount >= maxCount):
            maxCount = curCount
            netIndex = index

        # 3.3 if count decreases, than we've already got our best range
        if(curCount < maxCount):
            # found good network
            continue

    # 3.4 if netIndex is set and maxCount is above 10, add range to list
    if(netIndex and maxCount > 10):
      finalList[netIndex] = maxCount


#
# PART 4: call fail2ban  (you can also call IPTABLES directly)
#
fail2ban_command = "fail2ban-client set postfix-sasl banip "

for ip in finalList:
    banIP_command = fail2ban_command + ip
    # print(banIP_command)
    call(banIP_command, shell=True)
