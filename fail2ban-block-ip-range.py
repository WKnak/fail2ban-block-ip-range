#!/usr/bin/python3
#
# Scan fail2ban log and aggregate single banned IPv4 addresses into banned networks
#
# (P) & (C) 2021-2024 William Knak <williamknak@gmail.com>
# (P) & (C) 2024-2024 Peter Bieringer <pb@bieringer.de>

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from ipaddress import IPv4Network

if sys.version_info < (3, 7, 0):
    from subprocess import PIPE, run
else:
    from subprocess import run


class Preferences:

    CONFIG_FILE = "/etc/fail2ban/fail2ban-block-ip-range.conf"

    def __init__(self):
        ## tip: don't change here, change in the conf file
        self.default = {
                "fail2ban_file":  "/var/log/fail2ban.log",
                "max_age":  "8h",
                "count_limit": 7
        }

        self._create_config_if_not_exists()
        self.read_config_file()

    def print_preferences(self):
        print(self.default)

    def __getattr__(self, attr_name):
        return self.default[attr_name]

    def read_config_file(self):
        try:
            with open(self.CONFIG_FILE) as config_file:
                self.default = json.loads(config_file.read())
        except Exception as e:
            print("Error was detected while reading %s: %s. Hard coded values will be applied" % (self.CONFIG_FILE, str(e)))

    def save_config_file(self):
        try:
            # conf_items = {k: v for k, v in vars(self).items() if isinstance(v, (int, float, str, list, dict))}
            with open(self.CONFIG_FILE, "w") as config_file:
                json.dump(self.default, config_file, sort_keys=False, indent=2)
        except Exception as e:
            print("Error was detected while saving %s: %s" % (self.CONFIG_FILE, str(e)))

    def _create_config_if_not_exists(self):
        if not os.path.isfile(self.CONFIG_FILE):
            self.save_config_file()


class Fail2BanHelper:

    CMD_IS_BANNED_NEW = "fail2ban-client get {} banned {}"
    CMD_IS_BANNED_OLD = "fail2ban-client get {} banip ,"
    CMD_BAN = "fail2ban-client set {} banip {}"

    def __init__(self):
        self.get_strategy = self._detect_banned_strategy()


    def ban(self, jail, ip):
        ban_ip_command = self.CMD_BAN.format(jail, ip)

        result = self._run_f2b_command(ban_ip_command)
        return result


    def check_is_already_banned(self, jail, ip):

        if self.get_strategy == "old":
            return self._check_is_already_banned_old(jail, ip)

        return self._check_is_already_banned_new(jail, ip)


    def print_info(self):
        if self.get_strategy == "old":
            print("Using Fail2Ban Old compatibility Get Ban command - uses more CPU")
        else:
            print("Using Fail2Ban New Get Banned command")


    def _check_is_already_banned_old(self, jail, ip):
        getban_command = self.CMD_IS_BANNED_OLD.format(jail, ip)
        result = self._run_f2b_command(getban_command)
        if result.returncode != 0:
            print("Unable to retrieve current status for jail '%s' %s: %s" % (jail, ip, result.stderr))
            return False
        is_banned = ip in result.stdout.strip()
        return is_banned

    def _check_is_already_banned_new(self, jail, ip):
        getban_command = self.CMD_IS_BANNED_NEW.format(jail, ip)
        result = self._run_f2b_command(getban_command)
        if result.returncode != 0:
            print("Unable to retrieve current status for jail '%s' %s: %s" % (jail, ip, result.stderr)) 
            return False

        is_banned = result.stdout.strip() == "1"
        return is_banned

    def _run_f2b_command(self, getban_command):
        if sys.version_info < (3, 7, 0):
            # fallback for Python < 3.7
            result = run(getban_command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
        else:
            result = run(getban_command, capture_output=True, text=True, shell=True)

        return result

    def _detect_banned_strategy(self):
        getban_command = self.CMD_IS_BANNED_NEW.format("sshd", "192.168.111.111")
        result = self._run_f2b_command(getban_command)

        if result.returncode != 0:
            command_not_implemented_error = "no get action or not yet implemented" in result.stderr
            if command_not_implemented_error:
                return "old"

        return "new"

class ArgumentsHelper():
    def __init__(self):
        self.parser = argparse.ArgumentParser(
                prog="fail2ban-block-ip-range.py",
                description="Scan fail2ban log and aggregate single banned IPv4 addresses into banned networks",
                epilog="Defaults: FILE=%s MAXAGE=%s COUNTLIMIT=%s" % (file_default, maxage_default, str(countlimit_default)),
                )
        self.parser.add_argument("-v", "--verbose"   , action="store_true")  # on/off flag
        self.parser.add_argument("-q", "--quiet"     , action="store_true")  # on/off flag
        self.parser.add_argument("-d", "--debug"     , action="store_true")  # on/off flag
        self.parser.add_argument("-D", "--dryrun"    , action="store_true")  # on/off flag
        self.parser.add_argument("-l", "--countlimit", action="store", type=int, default=countlimit_default)
        self.parser.add_argument("-f", "--file"      , action="store", type=str, default=file_default)
        self.parser.add_argument("-a", "--maxage"    , action="store", type=str, default=maxage_default)
        self.parser.add_argument("-i", "--include_jail", action="append", type=str, default=[], help="Jail inclusions can be used multile times. Inclusions override the default 'all'.")
        self.parser.add_argument("-x", "--exclude_jail", action="append", type=str, default=[], help="Jail exclusions can be used multile times. Excluding a jail that is also included is not supported.")
    
    def get_args(self):
        return self.parser.parse_args()


file_default = "/var/log/fail2ban.log"
maxage_default = "8h"
countlimit_default = 7

config = Preferences()

args = ArgumentsHelper().get_args()

helper = Fail2BanHelper()
if args.debug:
    helper.print_info()


if args.debug:
    config.print_preferences()

fail2ban_log_file = args.file
max_age = args.maxage
countLimit = args.countlimit
includeJail = args.include_jail
excludeJail = args.exclude_jail

# convert max_age into seconds
age_pattern = re.compile("^([0-9]+)([smhdw])$")
m = age_pattern.match(max_age)
seconds_per_unit = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 60 * 60 * 24,
    "w": 60 * 60 * 24 * 7,
}

if m:
    max_age_seconds = int(m.group(1)) * seconds_per_unit[m.group(2)]
    if args.debug:
        print("Filter entries older %s = %ss" % (max_age, max_age_seconds))
else:
    print("MAXAGE not valid: %s" % max_age)
    exit(1)

dt_now = datetime.now()

if not os.path.isfile(fail2ban_log_file):
    print("File not found: %s" % fail2ban_log_file)
    exit(1)

if args.debug:
    print("Logfile to analyze: %s" % fail2ban_log_file)
    print("Count limit: %s" % countLimit)

file = open(fail2ban_log_file, mode="r")

fail2ban_log_pattern = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}).* fail2ban.filter.*\[[0-9]+\]:.*\[([^]]+)\] Found ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")

if sys.version_info < (3, 7, 0):
    # fallback for Python < 3.7
    fail2ban_datetime_pattern = re.compile("^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$")
    if args.debug:
        print("Fallback code for Python < 3.7 activated")

myjailip = defaultdict(lambda: defaultdict(int))
mylist = defaultdict(lambda: defaultdict(int))
finalList = defaultdict(lambda: defaultdict(int))


##### Functions
def printdict(var):
    for jail in var:
        print(" jail '%s'" % jail)
        for ip in var[jail]:
            count = var[jail][ip]
            print("  %s: %s" % (ip, count))


# PART 1: filtering messages and IPs
#
# 1.1) this script searches for fail2ban.log for detections
# 1.2) then it extracts the IPs after filter log line by age
#
# PART 2: reads the IP list detected and iterate
#
# 2.1) iterate IPs and count

while True:
    line = file.readline()
    m = fail2ban_log_pattern.search(line)
    if m:
        timedate = m.group(1)
        if sys.version_info < (3, 7, 0):
            t = fail2ban_datetime_pattern.search(timedate)
            assert t is not None
            dt = datetime(int(t.group(1)), int(t.group(2)), int(t.group(3)), int(t.group(4)), int(t.group(5)), int(t.group(6)))
        else:
            # datetime.fromisoformat was added in Python 3.7
            dt = datetime.fromisoformat(timedate)

        jail = m.group(2)
        ip = m.group(3)
        dt_delta = int((dt_now - dt).total_seconds())
        if dt_delta > max_age_seconds:
            if args.debug:
                print("Found IPv4: %s %ss jail '%s' %s -> SKIP" % (timedate, dt_delta, jail, ip)) 
            continue

        if args.debug:
            print("Found IPv4: %s %ss jail '%s' %s -> JAIL-CHECK" % (timedate, dt_delta, jail, ip))

        if len(includeJail) > 0:
            if jail in includeJail:
                if args.debug:
                    print("Found IPv4: %s %ss jail '%s' included -> STORE" % (timedate, dt_delta, jail))
            else:
                if args.debug:
                    print("Found IPv4: %s %ss jail '%s' not included -> SKIP" % (timedate, dt_delta, jail))
                continue
        elif len(excludeJail) > 0:
            if jail in excludeJail:
                if args.debug:
                    print("Found IPv4: %s %ss jail '%s' excluded -> SKIP" % (timedate, dt_delta, jail))
                continue
            else:
                if args.debug:
                    print("Found IPv4: %s %ss jail '%s' not excluded -> STORE" % (timedate, dt_delta, jail))
        else:
            if args.debug:
                print("Found IPv4: %s %ss no jail in- or exclusions -> STORE" % (timedate,dt_delta))

        myjailip[jail][ip] += 1

        # 2.2) iterate from cidr/32 down to 23 (descending)
        for cidr in range(32, 23, -1):
            ipnet = IPv4Network(ip + "/" + str(cidr), False)
            index = str(ipnet.network_address) + "/" + str(cidr)

            # 2.3) add the network, jail and count of events into a dictionary
            mylist[jail][index] += 1

    if not line:
        break

file.close()

if args.debug:
    print("List per jail/ip:")
    printdict(myjailip)
    print("List per jail/index:")
    printdict(mylist)

#
# PART 3: iterate IPs again, and get the best choice network range
#
for jail in myjailip:
    for ip in myjailip[jail]:
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
        if netIndex:
            if not netIndex.endswith("/32"):
                if maxCount > countLimit:
                    finalList[jail][netIndex] = maxCount
                else:
                    if args.debug:
                        print("Skip IPv4: %s (count %s below limit %s)" % (netIndex, maxCount, countLimit))
            else:
                if args.debug:
                    print("Skip IPv4: %s (not a network)" % netIndex)

if args.debug:
    print("Final list of networks to block per jail:")
    printdict(finalList)

#
# PART 4: call fail2ban
#

for jail in finalList:
    for ip in finalList[jail]:

        is_banned = helper.check_is_already_banned(jail, ip) 
        if not is_banned:
            if not args.dryrun:
                result = helper.ban(jail, ip)

                if result.returncode != 0:
                    print("Unable to ban for jail '%s' %s: %s" % (jail, ip, result.stderr))
                    continue

                ban_succeeded = (result.stdout.strip() == "1") or (result.stdout.strip() == ip.strip())
                if ban_succeeded: 
                    if not args.quiet:
                        print("jail '%s' successful ban aggregated IPv4 network: %s" % (jail, ip))
                else:
                    print("jail '%s' unsuccessful try to ban aggregated IPv4 network: %s (result: %s)" % (jail, ip, result.stdout.strip()))
            else:
                print("jail '%s' would ban aggregated IPv4 network: %s (dry-run)" % (jail, ip))
        else:
            if args.verbose:
                print("jail '%s' aggregated IPv4 network already banned: %s" % (jail, ip))

