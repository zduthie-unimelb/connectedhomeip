#!/usr/bin/env bash

# Network dump. Run on some container as lock-app / all-clusters-app
sudo tcpdump -w traffic.pcap -i eth0 port 5540