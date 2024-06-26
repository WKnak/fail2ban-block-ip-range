# fail2ban block ip/network range (ipv4 only)
A python script that group IPs into network range, to block attacks from a network range address, from CIDR /23 up to /31.

Please be carefull to not block youself!

## Requirements

### Python 3 (recommended 3.7+)

- Check Python version by running `python3 -V` or `python -V`

### fail2ban (recommended 0.11+ )
- Check fail2ban version by running `fail2ban-client -V`
  
## Installation

### Script

- Clone the source code to a local folder

```
cd /usr/local/src
git clone https://github.com/WKnak/fail2ban-block-ip-range.git
cd fail2ban-block-ip-range
```

- Copy main python script into bin directory
```
cp fail2ban-block-ip-range.py /usr/bin
```

- Make it executable
```
chmod a+x /usr/bin/fail2ban-block-ip-range.py
```

### Manual execution/testing

```
/usr/bin/fail2ban-block-ip-range.py
```

### Schedule periodic execution

#### Using cron

##### Alternative 1: extension of /etc/crontab

Add following extension to `/etc/crontab` using `crontab -e` command (check the proper user)

`*/5 * * * * /usr/bin/fail2ban-block-ip-range.py`

##### Alternative 2: sniplet in /etc/cron.d/fail2ban-block-ip-range

`*/5 * * * * root /usr/bin/fail2ban-block-ip-range.py`

##### Common:

- watch output of cron log (usually `/var/log/cron`)
- watch e-mails sent to root (in case of script send something to stdout/stderr)

#### By systemd/timer

- Store unit files into /usr/lib/systemd/system/
- Reload systemd with `systemctl daemon-reload`
- Run a one-shot for testinger with `systemctl enable fail2ban-block-ip-range.timer`
- Check journald with `journalctl -b 0 -u fail2ban-block-ip-range.service`
- Enable the timer with `systemctl enable fail2ban-block-ip-range.timer`
- Check journald with `journalctl -b 0 -u fail2ban-block-ip-range.timer`

Note: output of the script to stdout/stderr will be logged to journald

## Troubleshooting

### Error: Invalid command (no get action or not yet implemented)
Fail2Ban is too old, it does not know how to retrieve current status of a banned IP.

### SELinux

Active SELinux can prevent the script from being executed by cron/systemd!

Solution: toggle SELinux to run in permissive mode and create from all the logged events then a policy extension.

## Example:

Count and IPs found at last 1k lines of fail2ban.log

```
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
fail2ban-client set postfix-sasl banip 45.142.120.0/24
fail2ban-client set apache-auth banip 45.150.206.112/29
```
