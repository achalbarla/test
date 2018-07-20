from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-sp", type=int, help="The source TCP port")
parser.add_argument("-dst", help="The destination IP")
parser.add_argument("-src", help="The source IP")
parser.parse_args()
args = parser.parse_args()

sourcePort = args.sp
destinationIp = args.dst
sourceIp = args.src

ip=IP(src=sourceIp, dst=destinationIp)

# TCP SYN
TCP_SYN=TCP(sport=sourcePort, dport=5060, flags="S", seq=100)
TCP_SYNACK=sr1(ip/TCP_SYN)

# TCP SYN+ACK
myAck = TCP_SYNACK.seq + 1
TCP_ACK=TCP(sport=sourcePort, dport=5060, flags="A", seq=101, ack=myAck)
send(ip/TCP_ACK)

# TCP PSH+ACK with Payload
myPayload=(
    'OPTIONS sip:{0}:5060;transport=tcp SIP/2.0\r\n'
    'Via: SIP/2.0/TCP 192.168.44.32:5060;branch=1234\r\n'
    'From: \"somedevice\"<sip:somedevice@1.1.1.1:5060>;tag=5678\r\n'
    'To: <sip:{0}:5060>\r\n'
    'Call-ID: 9abcd\r\n'
    'CSeq: 1 OPTIONS\r\n'
    'Max-Forwards: 0\r\n'
    'Content-Length: 0\r\n\r\n').format(destinationIp)
TCP_PUSH=TCP(sport=sourcePort, dport=5060, flags="PA", seq=101, ack=myAck)
send(ip/TCP_PUSH/myPayload)
