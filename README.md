# Network Incident Detector (with Scapy)

This project is an implementation of a working Python + Scapy network incident detection tool that analyzes:
1) a live stream of packets from a network interface, or
2) one or more PCAP files
to detect common scanning activity and cleartext credential leaks.

Detects:
1. **NULL scan**
2. **FIN scan**
3. **Xmas scan**
4. **Usernames and passwords sent in-the-clear** via:
   - HTTP Basic Authentication
   - FTP
   - IMAP
5. **Nikto scan**
6. **SMB protocol**
7. **RDP**
8. **VNC instance**

Usage:
usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]
