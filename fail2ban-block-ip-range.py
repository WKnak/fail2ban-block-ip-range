#!/usr/bin/python3

from pprint import pprint
from subprocess import run, DEVNULL
from ipaddress import IPv4Network
from collections import defaultdict
from tempfile import mkstemp
import os
import argparse

parser = argparse.ArgumentParser(
    prog='fail2ban-block-ip-range.py',
    description='Scan /var/log/fail2ban.log and aggregate single banned IPs into banned networks'
)

parser.add_argument('-v', '--verbose', action='store_true')  # on/off flag
parser.add_argument('-q', '--quiet', action='store_true')  # on/off flag
parser.add_argument('--dry-run', action='store_true')  # on/off flag for dry-run mode
parser.add_argument('--output-file', default='already_banned_ips.txt', help='File to store already banned IPs')

args = parser.parse_args()

# PART 1: system script call, filtering messages and IPs
#
# 1.1) this script searches for fail2ban.log for detections (1000 last lines)
# 1.2) then it egreps the IPs, sort and uniq and count, and sort again.
# 1.3) the IP result list is output to /tmp

# Create temporary file, close it and let shell command write into it
tmpf = mkstemp()
os.close(tmpf[0])

script = 'tail -n 10000 /var/log/fail2ban.log | grep -E "fail2ban.filter.*\[[0-9]+\]:.*\[[^]]+\] Found ([0-9]{1,3}\.){3}[0-9]{1,3}" -o | sed -re "s/fail2ban.filter\s+\[[0-9]+\]:\sINFO\s+\[//; s/\]//; s/Found //;" | sort | uniq -c>
countLimit = 7

run(script, shell=True)
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
        ipnet = IPv4Network(ip + "/" + str(cidr), False)
        index = str(ipnet.network_address) + "/" + str(cidr)

        # 2.3) add the network, jail and count of events into a dictionary
        mylist[jail][index] += int(count)

# pprint(mylist)
#
# PART 3:  iterate IPs again, and get the best choice network range
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
        ipnet = IPv4Network(ip + "/" + str(cidr), False)
        index = str(ipnet.network_address) + "/" + str(cidr)
        curCount = mylist[jail][index]
        if curCount >= maxCount:
            maxCount = curCount
            netIndex = index

        # 3.3 if count decreases, than we've already got our best range
        if curCount < maxCount:
            # found good network
            continue

    # 3.4 if netIndex is set and maxCount is above the limit, add range to list
    if netIndex and maxCount > countLimit:
        if not netIndex.endswith("/32"):
            finalList[jail][netIndex] = maxCount

# delete temporary file
os.remove(tmpf[1])

#
# PART 4: call fail2ban  (you can also call IPTABLES directly)
#

fail2ban_command = "fail2ban-client set {} banip {}"
fail2ban_get = "fail2ban-client get {} banned {}"

for jail in finalList:
    for ip in finalList[jail]:
        getban_command = fail2ban_get.format(jail, ip)
        banned = run(getban_command, capture_output=True, text=True, shell=True)
        if banned.stdout.strip() == "0":
            banIP_command = fail2ban_command.format(jail, ip)
            result = run(banIP_command, capture_output=True, text=True, shell=True)
            if result.stdout.strip() == "1":
                if not args.quiet:
                    print(f"jail {jail} successful ban aggregated IP network: {ip}")
            else:
                print(f"jail {jail} unsuccessful try to ban aggregated IP network: {ip} (result: {result.stdout.strip()})")
        else:
            if args.verbose:
                print(f"jail {jail} aggregated IP network already banned: {ip}")

# Print final aggregated list for reference
if not args.quiet:
    print("\nFinal Aggregated List:")
    pprint(finalList)
