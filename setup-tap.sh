#!/bin/bash

NAME=taplisp

ip tuntap add name $NAME mode tun user $(logname)
ip link set $NAME up
ip address add 192.168.25.1/24 dev $NAME
