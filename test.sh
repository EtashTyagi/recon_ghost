#!/bin/bash
# This script must run on attacker
# Run Using: ./test IP OPEN_PORT CLOSED_PORT

# CURL print only errors
curl --silent --output /dev/null --show-error --fail $1:$2 --connect-timeout 1  # Victim IP  and open http Port
printf "done curl $1:$2\n\n"
curl --silent --output /dev/null --show-error --fail $1:$3 --connect-timeout 5 # Victim IP and closed http Port
# ^ should result in TCP_SYN
printf "done curl $1:$3\n"

# TCP_ACK
printf '\nTCP_ACK\n'
nmap -sA $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
nmap -sW $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'

# TCP_XMAS
printf '\nTCP_XMAS\n'
nmap -sX $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'

# TCP_FIN
printf '\nTCP_FIN\n'
nmap -sF $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'

# TCP_NULL
printf '\nTCP_NULL\n'
nmap -sN $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'

# TCP_RFC_O
printf '\nTCP_RFC_O\n'
nmap --scanflags PSH    $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
nmap --scanflags URG    $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
nmap --scanflags PSHURG $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
nmap --scanflags PSHFIN $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
nmap --scanflags URGFIN $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'

# TCP_SYN
printf '\nTCP_SYN\n'
nmap -sS $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
nmap -sT $1 -p $2,$3 -oG - | awk '/tcp/{print $5 "\t;\t" $6}'
