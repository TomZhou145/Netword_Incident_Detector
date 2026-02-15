#!/usr/bin/python3

from scapy.all import *
import argparse
import base64
from scapy.layers.inet import TCP

incident_number = 0

def identify_incident(flags):
    match flags:
        case "" | 0:
            return "NULL scan"
        case "F":
            return "FIN scan"
        case "FPU":
            return "Xmas scan"



def packetcallback(packet):
    global incident_number
    try:
        if packet.haslayer(IP):
            source_ip = packet[IP].src
        protocol = None
        payload = None
        incident = None

        check_password(packet)
        check_nikto(packet)
        check_smb(packet)
        check_rdp(packet)
        check_vnc(packet)

        if packet.haslayer(TCP):
            incident = identify_incident(str(packet[TCP].flags))
            protocol = packet[TCP].sport
            payload = packet[TCP].payload


        if incident != None:
            print_alerts(incident, protocol, payload, source_ip)

    except Exception as e:
        # Uncomment the below and comment out `pass` for debugging, find error(s)
        print(e)
        # pass

def print_alerts(incident, protocol, payload, source_ip):
    global incident_number
    incident_number += 1
    print(f"ALERT #{incident_number}: {incident} is detected from {source_ip} ({protocol}) ({payload})!")

def print_alert_pw(protocal, username, password):
    global incident_number
    incident_number += 1
    print(f"ALERT #{incident_number}: Usernames and passwords sent in-the-clear ({protocal}) (username:{username}, password:{password})")

def check_password(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        check_http(packet)
        check_ftp(packet)
        check_imap(packet)

def check_imap(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 143 or packet[TCP].sport == 143:
            payload = packet[Raw].load.decode(errors="ignore")

            if " LOGIN " in payload:
                parts = payload.strip().split()
                if len(parts) >= 4:
                    user = parts[2]
                    pwd = parts[3]
                    print_alert_pw("IMAP", user, pwd)

def check_ftp(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            payload = packet[Raw].load.decode(errors="ignore")
            username = None
            password = None
            if payload.startswith("USER "):
                username = payload.strip().split(" ")[1]

            if payload.startswith("PASS "):
                password = payload.strip().split(" ")[1]

            if username is not None and password is not None:
                print_alert_pw("FTP", username, password)
                username = None
                password = None

def check_http(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            payload = packet[Raw].load.decode(errors="ignore")

            if "Authorization: Basic " in payload:
                encoded = payload.split("Authorization: Basic ")[1].split("\r\n")[0]
                decoded = base64.b64decode(encoded).decode(errors="ignore")

                if ":" in decoded:
                    user, pwd = decoded.split(":", 1)
                    print_alert_pw("HTTP", user, pwd)

def check_nikto(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            payload = packet[Raw].load.decode(errors="ignore")
            if "Nikto" in payload:
                print_alerts("Nikto Scan", packet[TCP].sport, packet[TCP].payload, packet[IP].src)

def check_smb(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport in [445, 139] or packet[TCP].sport in [445, 139]:
            print_alerts("SMB protocal", packet[TCP].sport, packet[TCP].payload, source_ip=packet[IP].src)

def check_rdp(packet):
   if packet.haslayer(TCP):
       if packet[TCP].dport == 3389 or packet[TCP].sport == 3389:
           print_alerts("Remote Desktop Protocal", packet[TCP].sport, packet[TCP].payload, packet[IP].src)

def check_vnc(packet):
    if packet.haslayer(TCP):
        tcp = packet[TCP]

        if 5900 <= tcp.dport <= 5905 or 5900 <= tcp.sport <= 5905:
            print_alerts("Virtual Network Computing Instance", packet[TCP].sport, packet[TCP].payload, source_ip=packet[IP].src)




# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")