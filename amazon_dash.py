#!/usr/bin/env python3

# Requirements: Need to pip3 install scapy-python3
# 		Python3
#
# Takes ARP request upon pressing an Amazon Dash button
# Then forwards a custom packet to a listener.
# Script should be located in a port mirror (or where it
# can see the ARP messages.) mac_dict should house 
# Amazon Dash MAC addresses.
#
# Maker Thursday

from scapy.all import *
import os
import socket
import threading

# TODO
LISTENER_ADDR = '1.1.1.1' #IP OF WHERE YOU WANT TO CONNECT TO PUBLISH THE MESSAGE
LISTENER_PORT = 1337 

# one MAC and one name for each button
mac_dict = { "BUTTON MAC ADDRESS": "BUTTON NAME", }

def start_thread(pkt):
	t = threading.Thread(target=arp_display, args=(pkt))
	t.start()

def arp_display(pkt):
	if pkt[ARP].op == 1: #who-has (request)
		try:
			s.send(mac_dict[pkt[ARP].hwsrc].encode('utf-8'))
		except KeyError:
			print("Not Found: %s" % (pkt[ARP].hwsrc))
			
	
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((LISTENER_ADDR, LISTENER_PORT))

try:
	print (sniff(prn=start_thread, filter="arp", store=0, count=0))
except Exception as e:
	print(str(e))
	s.close()
