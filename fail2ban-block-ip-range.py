#!/usr/bin/python3

from pprint import pprint
from subprocess import call
from ipaddress import IPv4Network
from collections import defaultdict
from tempfile import mkstemp
import os

# PART 1: system script call, filtering messages and IPs
#
# 1.1) this script searches for fail2ban.log for detections (1000 last lines)
# 1.2) then it egreps the IPs, sort and uniq and count, and sort again.
# 1.3) the IP result list is output to /tmp

# Create temporary file, close it and let shell command write into it
tmpf = mkstemp()
os.close(tmpf[0])

script = 'tail -n 1000 /var/log/fail2ban.log | grep -E "fail2ban.filter.*\[[0-9]+\]:.*\[[^]]+\] Found ([0-9]{1,3}\.){3}[0-9]{1,3}" -o | sed -re "s/fail2ban.filter\s+\[[0-9]+\]:\sINFO\s+\[//; s/\]//; s/Found //;" | sort | uniq -c > ' + tmpf[1]
countLimit = 7

call(script, shell=True)

#
# PART 2: reads the ip list detected and iterate:
#
file1 = open(tmpf[1], 'r')
Lines = file1.readlines()

mylist = defaultdict(lambda: defaultdict(int))
finalList = defaultdict(lambda: defaultdict(int))

# 2.1) iterate ips and count
for line in Lines:
    splitVect = line.strip().split(" ")
    count = splitVect[0].strip()
    jail = splitVect[1].strip()
    ip = splitVect[2].strip()

    # 2.2) iterate from cidr/32 down to 23 (descending)
    for cidr in range(32, 23, -1):
        ipnet  = IPv4Network(ip + "/" + str(cidr), False)
        index = str(ipnet.network_address) + "/" + str(cidr)

        # 2.3) add the network, jail and count of events into a dictionary
        mylist[jail][index] += int(count)

# pprint(mylist)

#
# PART 3:  iterate IPs again, and get best choice network range
#
for line in Lines:
    splitVect = line.strip().split(" ")
    count = splitVect[0].strip()
    jail = splitVect[1].strip()
    ip = splitVect[2].strip()
    maxCount = 0
    nextIndex = False

	# 3.2 iterate CIDR (now in ascending order)
    for cidr in range(22, 33):
        ipnet  = IPv4Network(ip + "/" + str(cidr), False)
        index = str(ipnet.network_address) + "/" + str(cidr)
        curCount = mylist[jail][index]
        if(curCount >= maxCount):
            maxCount = curCount
            netIndex = index

        # 3.3 if count decreases, than we've already got our best range
        if(curCount < maxCount):
            # found good network
            continue

    # 3.4 if netIndex is set and maxCount is above 10, add range to list
    if(netIndex and maxCount > countLimit):
      finalList[jail][netIndex] = maxCount

# delete temporary file
os.remove(tmpf[1])

#
# PART 4: call fail2ban  (you can also call IPTABLES directly)
#
fail2ban_command = "fail2ban-client set {} banip {}"

for jail in finalList:
    for ip in finalList[jail]:
        banIP_command = fail2ban_command.format(jail, ip)
        #print(banIP_command)
        call(banIP_command, shell=True)
